/**
 * The content scanner: walks a decoded artifact and applies the pattern rules.
 *
 * Kept separate from the rules themselves so that adding a rule is a data
 * change, and separate from the platform analysers so that Android and iOS share
 * one matcher rather than two that drift.
 *
 * Bounded on purpose, in three places: total files, bytes per file, and matches
 * recorded per rule. A decoded APK is tens of thousands of files, and an
 * unbounded scan of one is a memory problem and a very long HTTP request.
 */
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { dexContextFor } from './dexContext.ts';
import { entropyHits } from './entropy.ts';
import { readText } from './fileCache.ts';
import type { PatternRule } from './rules.ts';
import type { SastFinding, SastLocation, SnippetLine } from './types.ts';
import { redact } from './types.ts';

/**
 * A window of source around a matched line, redacted throughout.
 *
 * Both ends are clamped to the file, so a match on line 1 still produces a
 * readable window rather than negative indices.
 */
/**
 * Trims a source line for display.
 *
 * Kotlin compiles to a `@Metadata` annotation holding a few hundred characters
 * of encoded signature data, and jadx prints it verbatim. Left alone it fills
 * the snippet window with noise that tells a reader nothing, so it is collapsed
 * to a marker. Everything else is passed through unchanged — values are not
 * masked.
 */
function presentable(line: string): string {
  if (/^\s*@(kotlin\.)?Metadata\(/.test(line)) return '@Metadata(...)  // Kotlin signature data, elided';
  return redact(line).replace(/\t/g, '    ');
}

export function snippetAround(lines: string[], index: number): SnippetLine[] {
  const from = Math.max(0, index - SNIPPET_CONTEXT);
  const to = Math.min(lines.length - 1, index + SNIPPET_CONTEXT);
  const out: SnippetLine[] = [];
  for (let i = from; i <= to; i += 1) {
    out.push({
      line: i + 1,
      text: presentable(lines[i]),
      vulnerable: i === index,
    });
  }
  return out;
}

/** Files above this are skipped by the text scan; they are assets, not code. */
const MAX_FILE_BYTES = 3 * 1024 * 1024;
/** Locations kept per rule. The count is reported in full; the list is not. */
const MAX_LOCATIONS = 12;
/** Context lines either side of a match. Seven or eight lines total reads well. */
const SNIPPET_CONTEXT = 3;
/** Hard ceiling on files visited, so a pathological archive cannot hang a scan. */
const MAX_FILES = 60_000;

/** Extensions worth reading as text. Everything else is binary noise. */
const TEXT_EXTENSIONS = new Set([
  '.smali', '.java', '.kt', '.xml', '.json', '.js', '.jsx', '.ts', '.tsx',
  '.html', '.htm', '.css', '.txt', '.properties', '.yml', '.yaml', '.pem',
  '.cer', '.crt', '.key', '.plist', '.strings', '.m', '.h', '.swift', '.mm',
  '.gradle', '.cfg', '.conf', '.ini', '.md', '.sql', '.graphql', '.env',
]);

/** Directories that are never worth scanning. */
const SKIP_DIRS = new Set(['original', 'unknown', 'kotlin', 'META-INF']);

export type WalkedFile = { absolute: string; relative: string; size: number };

/** Lists every file under `root`, artifact-relative, bounded by MAX_FILES. */
export function walk(root: string): WalkedFile[] {
  const out: WalkedFile[] = [];
  const stack = [root];

  while (stack.length > 0 && out.length < MAX_FILES) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue; // unreadable directory: not a finding, just not scannable
    }
    for (const entry of entries) {
      const absolute = join(dir, entry);
      let stats;
      try {
        stats = statSync(absolute);
      } catch {
        continue;
      }
      if (stats.isDirectory()) {
        if (!SKIP_DIRS.has(entry)) stack.push(absolute);
      } else if (stats.isFile()) {
        out.push({ absolute, relative: relative(root, absolute).split(sep).join('/'), size: stats.size });
      }
    }
  }
  return out;
}

function isTextish(path: string): boolean {
  const dot = path.lastIndexOf('.');
  if (dot < 0) return false;
  return TEXT_EXTENSIONS.has(path.slice(dot).toLowerCase());
}

type Hit = { locations: SastLocation[]; occurrences: number; appLocations?: Set<SastLocation> };

/** What the live map is fed from the rule pass. */
export type LiveSink = {
  visit: (paths: string[]) => void;
  hit: (file: string, rule: PatternRule) => void;
};
const MAX_LIVE_HITS_PER_RULE = 12;

/**
 * Keeps at most MAX_LOCATIONS of a rule's hits, preferring the app's own code.
 *
 * A rule that matches a hundred places in a bundled SDK and one in the app would
 * otherwise keep the first twelve it met, which are whichever files the walk
 * reached first, and drop the one hit the app team can act on. Once the list is
 * full a first-party hit replaces a library one; the occurrence count still counts
 * every match.
 */
function recordLocation(hit: Hit, location: SastLocation, firstParty: boolean): void {
  if (hit.locations.length < MAX_LOCATIONS) {
    hit.locations.push(location);
    if (firstParty) (hit.appLocations ??= new Set()).add(location);
    return;
  }
  if (!firstParty) return;
  const app = (hit.appLocations ??= new Set());
  for (let i = hit.locations.length - 1; i >= 0; i -= 1) {
    if (!app.has(hit.locations[i])) {
      hit.locations[i] = location;
      app.add(location);
      return;
    }
  }
}

/**
 * Applies every rule to every candidate file, line by line.
 *
 * Line-oriented because `unless` — the suppression pattern that keeps
 * placeholders out of the secrets category — only makes sense against the same
 * line that matched, not against the whole file.
 */
export function scanFiles(
  root: string,
  files: WalkedFile[],
  rules: PatternRule[],
  /**
   * Called with the fraction of files examined.
   *
   * This loop is the one part of the scan whose progress is exactly known, so
   * it reports it rather than leaving the bar parked between two stages.
   */
  onProgress?: (fraction: number) => void,
  /** Whether a file belongs to the app itself rather than a library; its hits are kept first when a rule has more than it can list. */
  isFirstParty: (relativePath: string) => boolean = () => false,
  /** The live map's feed: files as they are read, and rule matches as they happen. */
  live?: LiveSink,
): SastFinding[] {
  const hits = new Map<string, Hit>();
  const batch: string[] = [];
  const flush = () => {
    if (batch.length > 0) live?.visit(batch.splice(0));
  };
  // A rule that matches in thousands of library files would flood the map; the report lists a few per rule too.
  const announced = new Map<string, number>();
  const announce = (file: string, rule: PatternRule, already: Set<string>) => {
    if (!live || already.has(rule.id)) return;
    already.add(rule.id);
    const n = announced.get(rule.id) ?? 0;
    if (n >= MAX_LIVE_HITS_PER_RULE) return;
    announced.set(rule.id, n + 1);
    live.hit(file, rule);
  };

  // Reported every few hundred files: the console polls once a second, and a
  // message per file on a thirteen-thousand-file tree is pure noise.
  const step = Math.max(1, Math.floor(files.length / 40));

  for (const [index, file] of files.entries()) {
    if (onProgress && index % step === 0) onProgress(index / files.length);
    if (live) {
      batch.push(file.relative);
      if (batch.length >= 150) flush();
    }
    if (file.size > MAX_FILE_BYTES || !isTextish(file.relative)) continue;

    const applicable = rules.filter((r) => !r.files || r.files.test(file.relative));
    if (applicable.length === 0) continue;

    let content: string;
    try {
      content = readText(file.absolute);
    } catch {
      continue;
    }
    // A file with no newlines and enormous length is minified or generated;
    // splitting it produces one useless "line 1" location for every hit.
    const lines = content.split('\n');
    const appFile = isFirstParty(file.relative);
    // An import or package line names a type; it never calls it. Rules written for calls
    // (`SQLiteDatabase`, `ClipboardManager`) would otherwise report every file that mentions one.
    const sourceFile = /\.(?:java|kt)$/.test(file.relative);
    const declaration = (line: string) => sourceFile && /^\s*(?:import|package)\s/.test(line);
    const announcedHere = new Set<string>();

    for (const rule of applicable) {
      // File-scoped combinators: every pattern of `allOf` (or any of `anyOf`)
      // must be present somewhere in this file. See the note on PatternRule.
      if (rule.allOf || rule.anyOf) {
        if (rule.unless?.test(content)) continue;
        if (rule.allOf && !rule.allOf.every((p) => p.test(content))) continue;
        if (rule.anyOf && !rule.anyOf.some((p) => p.test(content))) continue;

        // Record every line that matched a pattern, not a single "anchor".
        //
        // Picking one was always arbitrary and got it wrong in practice: for
        // `secret.aws_secret_key` the two patterns are the access key ID and
        // the 40-character secret, both matching exactly one line, so the tie
        // resolved to the first and the finding pointed at the ID rather than
        // the secret it exists to report. Showing both lines removes the guess
        // and is more informative anyway — a correlated rule is *about* the
        // relationship between them.
        const patterns = rule.allOf ?? rule.anyOf ?? [];
        const matchedLines: number[] = [];
        for (let i = 0; i < lines.length && matchedLines.length < MAX_LOCATIONS; i += 1) {
          if (!declaration(lines[i]) && patterns.some((p) => p.test(lines[i]))) matchedLines.push(i);
        }
        // The headline location is the first one; a rule can say which lines are the subject.
        if (rule.lead) {
          const lead = rule.lead;
          matchedLines.sort((x, y) => Number(lead.test(lines[y])) - Number(lead.test(lines[x])) || x - y);
        }

        const hit = hits.get(rule.id) ?? { locations: [], occurrences: 0 };
        hit.occurrences += 1;
        for (const index of matchedLines) {
          recordLocation(
            hit,
            {
              file: file.relative,
              line: index + 1,
              excerpt: redact(lines[index]),
              snippet: snippetAround(lines, index),
              ...dexContextFor(file.relative, lines, index),
            },
            appFile,
          );
        }
        hits.set(rule.id, hit);
        announce(file.relative, rule, announcedHere);
        continue;
      }

      if (!rule.pattern) continue;
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (declaration(line)) continue;
        if (!rule.pattern.test(line)) continue;
        if (rule.unless?.test(line)) continue;

        const hit = hits.get(rule.id) ?? { locations: [], occurrences: 0 };
        hit.occurrences += 1;
        // Built only when it will be kept: a rule that matches a hundred library lines
        // would otherwise build a hundred snippets to throw away.
        if (hit.locations.length < MAX_LOCATIONS || appFile) {
          recordLocation(
            hit,
            {
              file: file.relative,
              line: i + 1,
              excerpt: redact(line),
              snippet: snippetAround(lines, i),
              ...dexContextFor(file.relative, lines, i),
            },
            appFile,
          );
        }
        hits.set(rule.id, hit);
        announce(file.relative, rule, announcedHere);
      }
    }
  }
  flush();

  const findings = [...hits.entries()].map(([ruleId, hit]) => {
    const rule = rules.find((r) => r.id === ruleId)!;
    return findingFrom(rule, hit.locations, hit.occurrences);
  });

  // The entropy pass only runs when the caller is actually scanning for
  // secrets. `scanFiles` is called elsewhere with a filtered rule set — a
  // single crypto rule, say — and returning a secrets finding from that would
  // be a surprise the caller never asked for.
  if (!rules.some((r) => r.category === 'secrets')) return findings;

  // Values already named by a format or keyword rule are excluded from the
  // entropy pass, so one credential produces one finding per rule that
  // identifies it rather than an extra generic one on top.
  const claimed = new Set<string>();
  for (const finding of findings) {
    if (finding.category !== 'secrets' && !finding.ruleId.startsWith('crypto.hardcoded_key')) continue;
    for (const location of finding.locations) {
      const excerpt = location.excerpt ?? '';
      for (const match of excerpt.matchAll(/"([^"]{8,})"/g)) claimed.add(match[1]);
      // Unquoted too: an XML value (`<string name="google_api_key">AIza...</string>`) has no quotes.
      for (const match of excerpt.matchAll(/[A-Za-z0-9+/=_.-]{16,}/g)) claimed.add(match[0]);
    }
  }

  return [...findings, ...scanForEntropy(root, files, (value) => claimed.has(value))];
}

/**
 * High-entropy literals that no named rule claimed.
 *
 * Reported as a single hotspot rather than one finding per string: this is the
 * "looks like a credential, confirm it" bucket, and forty separate mediums
 * would drown the findings that are actually certain. Third-party code is
 * excluded — a random-looking constant inside a bundled library is nearly
 * always a lookup table, and including them produced far more noise than signal.
 */
function scanForEntropy(
  root: string,
  files: WalkedFile[],
  alreadyClaimed: (value: string) => boolean,
): SastFinding[] {
  const anonymous = { locations: [] as SastLocation[], total: 0 };
  const named = { locations: [] as SastLocation[], total: 0 };
  const seen = new Set<string>();

  for (const file of files) {
    if (file.size > MAX_FILE_BYTES || !isTextish(file.relative)) continue;
    if (THIRD_PARTY_PATH.test(file.relative) || UI_RESOURCE.test(file.relative)) continue;

    let content: string;
    try {
      content = readText(file.absolute);
    } catch {
      continue;
    }
    if (content.length > MAX_FILE_BYTES) continue;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      // Names of launch images, icons and the like: random-looking by construction, never secrets.
      if (/\b(?:UILaunchImage\w*|CFBundleIcon\w*|UIApplicationShortcutItem\w*|UIStatusBar\w*|UIInterfaceOrientation\w*|\w*ImageName|\w*IconFile\w*)\s*=/.test(lines[i])) continue;
      for (const hit of entropyHits(lines[i], alreadyClaimed)) {
        if (seen.has(hit.value)) continue;
        seen.add(hit.value);
        const bucket = hit.named ? named : anonymous;
        bucket.total += 1;
        if (bucket.locations.length >= MAX_LOCATIONS) continue;
        bucket.locations.push({
          file: file.relative,
          line: i + 1,
          excerpt: redact(lines[i]),
          snippet: snippetAround(lines, i),
          ...dexContextFor(file.relative, lines, i),
        });
      }
    }
  }

  const out: SastFinding[] = [];

  // The variable is named like a credential and holds a value shaped like one: the
  // strongest signal short of a recognisable format, so it is a defect rather than a hotspot.
  if (named.total > 0) {
    out.push({
      ruleId: 'secret.credential_literal',
      title: `${named.total} credential-named variable${named.total === 1 ? '' : 's'} holding a random-looking value`,
      category: 'secrets',
      severity: 'medium',
      description:
        'A variable named like a key, token, secret or password is assigned a literal that is random enough to be one. ' +
        'No format rule recognised the issuer, but the name and the value agree.',
      impact:
        'A credential found this way is exactly as exposed as one with a recognisable prefix: anyone who unzips the app can read it. ' +
        'If it is a cipher key or IV, everything encrypted with it can be decrypted by anyone.',
      remediation:
        'If it is a real key, token or password, revoke it and move the value server-side; for a cipher key, generate it in the ' +
        'platform keystore instead of compiling it in. If it is a public identifier or a test value, rename it so it stops looking like one.',
      masvs: 'MASVS-STORAGE-1',
      cwe: 'CWE-798',
      locations: named.locations,
      occurrences: named.total,
    });
  }

  if (anonymous.total > 0) {
    out.push({
      ruleId: 'secret.high_entropy_literal',
      title: `${anonymous.total} high-entropy literal${anonymous.total === 1 ? '' : 's'} that may be credentials`,
      category: 'secrets',
      severity: anonymous.total > 5 ? 'medium' : 'low',
      kind: 'hotspot',
      description:
        'These strings are random enough to be tokens rather than text, and no format rule recognised them. ' +
        'Hashes, UUIDs, certificate pins, encoded resources and package names are already excluded.',
      impact:
        'A credential found this way is exactly as exposed as one with a recognisable prefix — anyone who unzips ' +
        'the app can read it. The difference is only that its shape did not identify the issuer, so a human has to.',
      remediation:
        'Check each one. If it is a key, a token or a password, revoke it and move the value server-side. ' +
        'If it is a public identifier, a salt or a lookup constant, it is fine where it is.',
      masvs: 'MASVS-STORAGE-1',
      cwe: 'CWE-798',
      locations: anonymous.locations,
      occurrences: anonymous.total,
    });
  }
  return out;
}

/**
 * Android resources that describe how things look, not what they hold.
 *
 * Layouts, drawables, colours, animations, menus and the style/theme/attr/dimen
 * value files are made of resource references and identifiers (`@style/Theme.AppCompat`,
 * `material_personalized__highlighted_text`), which is where thousands of
 * random-looking "credentials" came from on a real app. A secret in a resource
 * lives in `strings.xml` or an asset, which this does not exclude.
 */
const UI_RESOURCE =
  /(^|\/)res\/(layout|drawable|color|anim|animator|interpolator|transition|menu|navigation|mipmap)[^/]*\/|(^|\/)res\/values[^/]*\/(styles|attrs|colors|dimens|public|ids|themes|integers|bools|plurals|arrays)[^/]*\.xml$|\.(?:storyboardc?|nib|xib|momd?|lproj|car)(?:\/|$)|(?:^|\/)(?:Assets\.car|LaunchScreen\w*|Base\.lproj)\//;

/** Bundled dependencies: constants there are almost never app credentials. */
const THIRD_PARTY_PATH =
  /(^|\/)(okio|okhttp3|retrofit2|kotlin|kotlinx|androidx|android\/support|com\/google|com\/squareup|org\/apache|org\/bouncycastle|io\/reactivex|com\/facebook|io\/flutter|org\/jetbrains|org\/intellij|org\/w3c|org\/xml|org\/json|javax|javassist|org\/conscrypt|com\/android\/tools)\//;

export function findingFrom(rule: PatternRule, locations: SastLocation[], occurrences: number): SastFinding {
  return {
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    // Carried through from the rule. Without these a rule declaring itself a
    // hotspot or a secure observation was still filed as a defect, because the
    // bucketing reads `kind` off the finding and nothing ever set it.
    kind: rule.kind,
    description: rule.description,
    impact: rule.impact,
    exploitation: rule.exploitation,
    remediation: rule.remediation,
    masvs: rule.masvs,
    cwe: rule.cwe,
    locations,
    occurrences,
  };
}

/** Where to persist the extracted strings so a finding resolves to something openable. */
export type BinaryStringsDump = {
  /** Absolute path to write the listing to. */
  writeTo: string;
  /** Path recorded on findings' locations, relative to the source root the console browses. */
  relativeFile: string;
};

/**
 * Scans raw binary content for printable strings, then applies rules to them.
 *
 * This is how an iOS binary (a Mach-O, with no decompiled source to read) and an
 * Android `classes.dex` are reached. It finds literals only — the string table
 * is exactly where credentials live, so for the `secrets` category it is nearly
 * as good as source, while for code-pattern rules it is much weaker. Rules that
 * depend on call syntax simply will not match here, and that is honest: the
 * report's `limitations` says so rather than implying full coverage.
 *
 * `anyOf` is evaluated per string: any one pattern matching any one string is
 * exactly as precise as running each pattern separately, so it is always safe
 * here. `allOf` is evaluated over the whole extracted string table rather than
 * skipped, because a flat binary has no per-file scope to require it within —
 * but that is a real loss of precision versus source, where "same file" means
 * "same class". A rule whose second pattern is a low-specificity token (a bare
 * three-digit number, a generic 40-character string) is not safe to run this
 * way and should not be tagged for this platform; `ios.ssl_pinning` is, because
 * both halves of its pair are specific API/keyword references.
 */
export function scanBinaryStrings(
  label: string,
  buffer: Buffer,
  rules: PatternRule[],
  minLength = 6,
  dump?: BinaryStringsDump,
): SastFinding[] {
  // Runs are sliced out of the buffer rather than accumulated as char codes.
  // `String.fromCharCode(...codes)` spreads every character as an argument, and
  // a DEX string table contains runs long enough to overflow the call stack —
  // which surfaced as a bogus "could not be extracted" error on classes2.dex.
  const strings: { text: string; offset: number }[] = [];
  let runStart = -1;

  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i];
    const printable = byte >= 0x20 && byte < 0x7f;
    if (printable) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      if (i - runStart >= minLength) strings.push({ text: buffer.subarray(runStart, i).toString('latin1'), offset: runStart });
      runStart = -1;
    }
  }
  if (runStart >= 0 && buffer.length - runStart >= minLength) {
    strings.push({ text: buffer.subarray(runStart).toString('latin1'), offset: runStart });
  }

  // A readable dump of every extracted string, one per line, so the console's
  // Explorer has something to open for a finding that lives only in a binary.
  // Without this, a location named "DVIA-v2 (Binary)" resolved to nothing —
  // that file is not text, so it was silently excluded from what the Explorer
  // could show, and every binary-string finding looked like it had no source.
  //
  // Bounded, because a real binary's string table can run well past what
  // `sources.ts` will retain for a single file (checked against a real IPA:
  // 8.5 MB of Mach-O produced a 3.5 MB dump). A finding whose match falls
  // past the budget falls back to the no-line form below rather than
  // pointing at a row that was never written — a dangling reference would be
  // worse than the plain excerpt this always had.
  const DUMP_BYTE_BUDGET = 6 * 1024 * 1024;
  let dumpLines: string[] | undefined;
  let dumpValidCount = 0;
  if (dump) {
    const allLines = strings.map((s) => `0x${s.offset.toString(16).padStart(8, '0')}  ${s.text}`);
    const kept: string[] = [];
    let bytes = 0;
    for (const line of allLines) {
      bytes += line.length + 1;
      if (bytes > DUMP_BYTE_BUDGET) break;
      kept.push(line);
    }
    dumpValidCount = kept.length;
    if (dumpValidCount < allLines.length) {
      kept.push(`... ${allLines.length - dumpValidCount} more strings not shown (truncated at ~${Math.round(DUMP_BYTE_BUDGET / (1024 * 1024))}MB) ...`);
    }
    try {
      mkdirSync(dirname(dump.writeTo), { recursive: true });
      writeFileSync(dump.writeTo, kept.join('\n'));
      dumpLines = kept;
    } catch {
      dumpLines = undefined; // best effort: findings still carry an excerpt without it
      dumpValidCount = 0;
    }
  }

  const locationFor = (index: number, text: string): SastLocation => {
    if (dump && dumpLines && index < dumpValidCount) {
      return {
        file: dump.relativeFile,
        line: index + 1,
        excerpt: redact(text),
        snippet: snippetAround(dumpLines, index),
      };
    }
    return {
      file: label,
      excerpt: redact(text),
      // The sweep reads the DEX directly, so the container is the file.
      ...(/^classes\d*\.dex$/.test(label) ? { dex: label } : {}),
    };
  };

  const hits = new Map<string, Hit>();

  for (const [index, { text }] of strings.entries()) {
    // A C symbol in a Mach-O string table carries a leading underscore
    // (`_dlopen`, `_NSLog`). Rules are written for the name as source spells it,
    // and `\bdlopen\b` cannot match inside `_dlopen` because `_` is a word
    // character, so every such rule was silently blind on a binary. Try the
    // name both ways.
    const forms = /^_[A-Za-z]/.test(text) ? [text, text.slice(1)] : [text];
    for (const rule of rules) {
      const single = forms.some((t) =>
        rule.pattern ? rule.pattern.test(t) : rule.anyOf ? rule.anyOf.some((p) => p.test(t)) : false,
      );
      if (!single) continue;
      if (rule.unless?.test(text)) continue;
      const hit = hits.get(rule.id) ?? { locations: [], occurrences: 0 };
      hit.occurrences += 1;
      if (hit.locations.length < MAX_LOCATIONS) hit.locations.push(locationFor(index, text));
      hits.set(rule.id, hit);
    }
  }

  // `allOf` only: correlated across the whole string table, once per rule
  // (there is one "file" here — the binary itself — so one match, not one per
  // string). See the note above on why this is not run for every allOf rule.
  const corpus = strings.map((s) => s.text).join('\n');
  for (const rule of rules) {
    if (!rule.allOf || hits.has(rule.id)) continue;
    if (rule.unless?.test(corpus)) continue;
    if (!rule.allOf.every((p) => p.test(corpus))) continue;

    const hit: Hit = { locations: [], occurrences: 1 };
    for (const [index, { text }] of strings.entries()) {
      if (hit.locations.length >= MAX_LOCATIONS) break;
      if (rule.allOf.some((p) => p.test(text))) hit.locations.push(locationFor(index, text));
    }
    hits.set(rule.id, hit);
  }

  return [...hits.entries()].map(([ruleId, hit]) =>
    findingFrom(rules.find((r) => r.id === ruleId)!, hit.locations, hit.occurrences),
  );
}

/**
 * Merges findings for the same rule discovered by different passes.
 *
 * The text walk and the binary-strings pass overlap — a secret in a resource
 * file is also in the DEX string table — and reporting it twice would inflate
 * both the count and the penalty for one mistake.
 */
export function mergeFindings(groups: SastFinding[][]): SastFinding[] {
  const merged = new Map<string, SastFinding>();
  for (const group of groups) {
    for (const finding of group) {
      const existing = merged.get(finding.ruleId);
      if (!existing) {
        merged.set(finding.ruleId, { ...finding, locations: [...finding.locations] });
        continue;
      }
      existing.occurrences += finding.occurrences;
      for (const location of finding.locations) {
        if (existing.locations.length >= MAX_LOCATIONS) break;
        const duplicate = existing.locations.some(
          (l) => l.file === location.file && l.line === location.line,
        );
        if (!duplicate) existing.locations.push(location);
      }

      // The string sweep and the source walk see the same thing from two sides:
      // a hit in `classes2.dex` and a hit in `smali_classes2/...` are one
      // problem, not two. Where the decompiled location exists it is strictly
      // more useful, so the bare DEX row is dropped rather than listed beside
      // it — and the occurrence count is corrected, because counting both
      // doubled every secret that appeared in source.
      const decompiled = new Set(
        existing.locations.map((l) => l.dex).filter((d): d is string => Boolean(d) && existing.locations.some((x) => x.dex === d && x.line !== undefined)),
      );
      const before = existing.locations.length;
      existing.locations = existing.locations.filter(
        (l) => !(l.line === undefined && l.dex && decompiled.has(l.dex)),
      );
      existing.occurrences -= before - existing.locations.length;
    }
  }
  return [...merged.values()];
}
