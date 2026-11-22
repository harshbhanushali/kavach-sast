/**
 * Keeping the decompiled source a finding points at, so it can be read later.
 *
 * The scan deletes its working directory the moment it finishes — it holds a
 * full decompiled copy of someone's application and keeping that around by
 * default would be both a storage problem and a liability. But a reviewer
 * reading "line 84 of KeychainModule.java" reasonably wants to open line 84,
 * and re-running a two-minute scan to see one file is a poor answer.
 *
 * So a bounded subset is retained: the files the findings actually reference,
 * plus the manifest. That is the set someone opens, and it is a few megabytes
 * rather than a few gigabytes. Everything else is still discarded, and the
 * console says so rather than presenting a partial tree as the whole artifact.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { peekText } from './fileCache.ts';
import { dirname, join, relative } from 'node:path';
import { BINARY_PLIST_NOTE, parsePlist, renderPlist } from './plist.ts';
import { scrubDecompilerNotes } from './redact.ts';
import type { SastFinding } from './types.ts';

export type RetainedFile = {
  /** Artifact-relative path, exactly as a finding's location spells it. */
  path: string;
  bytes: number;
  content: string;
};

/**
 * Ceilings, so one pathological artifact cannot fill the database.
 *
 * Sized from a real measurement rather than a guess: jadx on a 175 MB React
 * Native APK produces 13,038 Java files totalling 68 MB, with a median file of
 * 1.6 KB and three files above 512 KB. Gzip takes that to about 13 MB, which is
 * an acceptable cost for being able to open any class in the app.
 *
 * The earlier limit of 400 files kept the ones findings pointed at and dropped
 * the other 97% of the tree, which is why whole packages appeared to be
 * missing.
 */
const MAX_FILES = 20_000;
// 8 MB rather than 2: an iOS scan writes one synthetic file per binary — the
// extracted-strings dump `scanBinaryStrings` produces so its findings resolve
// to something openable — and that single file is bounded at 6 MB (see
// `DUMP_BYTE_BUDGET` in scanner.ts). 2 MB silently dropped it on a real IPA
// (DVIA-v2, 8.5 MB binary → 3.5 MB dump), which is exactly the "Explorer has
// nothing for this finding" gap this cap exists to close.
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 96 * 1024 * 1024;

/**
 * A file's contents in a form worth showing.
 *
 * iOS ships property lists in Apple's binary format: `Info.plist` opens as
 * `bplist00` followed by a page of mojibake, which is useless in a viewer and
 * is what the explorer showed until now. The same parser the scan already uses
 * converts it, so the file reads as the structure it actually is.
 */
function readable(full: string): string {
  // Decompiled Java was read by the rule pass already; reading it again from disk is the slow part of finishing.
  if (full.endsWith('.java')) {
    const seen = peekText(full);
    if (seen !== undefined) return scrubDecompilerNotes(seen);
  }
  const raw = readFileSync(full);
  // iOS `.strings` files are often UTF-16; read as UTF-8 they are a screen of NULs.
  if (raw[0] === 0xff && raw[1] === 0xfe) return raw.subarray(2).toString('utf16le');
  if (raw[0] === 0xfe && raw[1] === 0xff) return Buffer.from(raw.subarray(2)).swap16().toString('utf16le');
  if (!raw.subarray(0, 6).equals(Buffer.from('bplist'))) {
    const text = raw.toString('utf8');
    // The decompiler leaves notes in the code it writes. They are about the
    // decompile, not the app, and they name the tool.
    return full.endsWith('.java') ? scrubDecompilerNotes(text) : text;
  }
  try {
    return `${BINARY_PLIST_NOTE}${renderPlist(parsePlist(raw), 0)}`;
  } catch {
    // Better an honest note than a screen of binary.
    return '// Apple binary property list; this one could not be decoded.';
  }
}

/** Text we can show. A .so or a .png in a source viewer helps nobody. */
export function isReadable(path: string): boolean {
  return /\.(java|smali|xml|json|txt|properties|yml|yaml|pem|crt|cfg|conf|ini|md|kt|js|ts|html|css|plist|strings|xcprivacy|version|gradle|pro|entitlements|mobileprovision)$/i.test(
    path,
  );
}

/**
 * Files the decode tools write about themselves. They are not part of the app,
 * and listing one in the Explorer would name the tool that produced the tree.
 */
function isToolMetadata(name: string): boolean {
  return name === 'apktool.yml';
}

/** Ceiling on the walk, so indexing a huge decompile cannot run away. */
const MAX_INDEXED = 60_000;

/**
 * Every readable file under a root, indexed by its path relative to that root.
 *
 * Built once per root rather than resolving each wanted path on its own,
 * because the second lookup below is a suffix match and doing that with a
 * filesystem walk per file would be quadratic.
 */
function indexRoot(root: string, stripPrefix?: string, anyFile = false): Map<string, string> {
  const index = new Map<string, string>();
  const stack = [root];

  while (stack.length > 0 && index.size < MAX_INDEXED) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && (anyFile || isReadable(entry.name)) && !isToolMetadata(entry.name)) {
        const rel = relative(root, full);
        index.set(stripPrefix && rel.startsWith(stripPrefix) ? rel.slice(stripPrefix.length) : rel, full);
      }
    }
  }
  return index;
}

/**
 * Find a wanted path in an index.
 *
 * Android findings carry a path relative to the decode root, so the first
 * lookup hits. iOS findings carry a display name — `Info.plist`, not
 * `Payload/Foo.app/Info.plist` — because that is what reads well in a report,
 * so those need the suffix match.
 */
function lookup(index: Map<string, string>, wanted: string): string | undefined {
  const direct = index.get(wanted);
  if (direct) return direct;
  // A bare name can match many files (`Info.plist` is in every storyboard and
  // framework). The shallowest one is the bundle's own; taking whichever the
  // directory walk reached first could open a different file than the finding
  // describes, or one already kept under another name, so no button at all.
  let best: { depth: number; key: string; full: string } | undefined;
  for (const [relativePath, full] of index) {
    if (!relativePath.endsWith(`/${wanted}`)) continue;
    const depth = relativePath.split('/').length;
    if (!best || depth < best.depth || (depth === best.depth && relativePath < best.key)) {
      best = { depth, key: relativePath, full };
    }
  }
  return best?.full;
}

export type SourceSet = {
  files: RetainedFile[];
  /** How many readable files the decode held, before any cap was applied. */
  found: number;
  /** True when a cap stopped the collection short. */
  truncated: boolean;
};

export function collectSources(
  roots: (string | undefined)[],
  findingGroups: SastFinding[][],
  options: {
    /**
     * Dropped from the front of every retained path. An IPA keeps its app under
     * `Payload/`, a wrapper nobody reads; findings name `Foo.app/...`, and the
     * tree has to spell the same file the same way.
     */
    stripPrefix?: string;
    /**
     * Roots holding a readable rendering of an original binary file, written at
     * that file's own path (`lib/arm64-v8a/libfoo.so`, `META-INF/CERT.RSA`). Every
     * file in them is kept whatever its extension, and they are consulted first,
     * so a finding that names the original file opens its decoded form.
     */
    trustedRoots?: string[];
  } = {},
): SourceSet {
  const trusted = new Set(options.trustedRoots ?? []);
  const indexes = roots
    .filter((r): r is string => Boolean(r) && existsSync(r))
    .map((root) => ({ root, index: indexRoot(root, options.stripPrefix, trusted.has(root)) }))
    .sort((a, b) => Number(trusted.has(b.root)) - Number(trusted.has(a.root)));
  if (indexes.length === 0) return { files: [], found: 0, truncated: false };


  // What the findings point at. Kept first so that if a cap is ever reached,
  // the files this feature exists to open are the ones that survive.
  const referenced = new Set<string>();
  for (const group of findingGroups) {
    for (const finding of group) {
      for (const location of finding.locations) {
        if (isReadable(location.file)) referenced.add(location.file);
      }
    }
  }

  const kept = new Map<string, RetainedFile>();
  // Tracked by real path, not display path: an iOS finding names `Info.plist`
  // while the bulk pass would name the same file
  // `Payload/Foo.app/Info.plist`, and without this the tree shows both.
  const takenFullPaths = new Set<string>();
  let total = 0;
  let truncated = false;

  const take = (displayPath: string, full: string): void => {
    if (kept.has(displayPath) || takenFullPaths.has(full)) return;
    if (kept.size >= MAX_FILES || total >= MAX_TOTAL_BYTES) {
      truncated = true;
      return;
    }
    let size: number;
    try {
      size = statSync(full).size;
    } catch {
      return;
    }
    if (size > MAX_FILE_BYTES) {
      truncated = true;
      return;
    }
    try {
      kept.set(displayPath, { path: displayPath, bytes: size, content: readable(full) });
      takenFullPaths.add(full);
      total += size;
    } catch {
      // Binary despite the extension. The viewer has nothing to do with it.
    }
  };

  // 1. The files findings name, under the path the report spells them with, so
  //    the explorer and the finding agree on where something is.
  for (const wanted of [...referenced].sort()) {
    for (const { index } of indexes) {
      const full = lookup(index, wanted);
      if (!full) continue;
      take(wanted, full);
      break;
    }
  }

  // When jadx produced Java, the smali trees hold the same classes again in a
  // notation nobody reads by choice. Retaining both doubles the storage and
  // gives the explorer two entries for every class. The code rules already
  // scan one or the other and never both, for the same reason.
  //
  // Referenced smali files still come through step 1 above: the TrustManager
  // and hardcoded-key checks are method-body analyses that run on smali
  // regardless, so their findings point there and must stay openable.
  const haveJava = indexes.some(({ index }) =>
    [...index.keys()].some((k) => k.startsWith('sources/') && k.endsWith('.java')),
  );
  const isRedundantSmali = (path: string) => haveJava && /^smali(_classes\d+)?\//.test(path);

  // Counted after the exclusion above, so a scan that deliberately skips the
  // smali duplicates does not report itself as truncated. The referenced smali
  // files are added back, because those *are* retained — the method-body
  // checks run on smali whatever the decompiler did, and their findings have to
  // stay openable.
  const referencedSmali = [...referenced].filter((p) => isRedundantSmali(p)).length;
  const found =
    indexes.reduce(
      (n, { index }) => n + [...index.keys()].filter((k) => !isRedundantSmali(k)).length,
      0,
    ) + referencedSmali;

  // 2. Everything else that is readable. This is what makes the tree a real
  //    package browser rather than a list of the files that happened to be
  //    flagged — a reviewer following a call into a neighbouring class should
  //    not hit a dead end.
  for (const { index } of indexes) {
    for (const [relativePath, full] of index) {
      if (isRedundantSmali(relativePath)) continue;
      take(relativePath, full);
    }
  }

  return {
    files: [...kept.values()].sort((a, b) => a.path.localeCompare(b.path)),
    found,
    truncated,
  };
}
