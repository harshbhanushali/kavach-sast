/**
 * Finding secrets by their shape, not their variable name.
 *
 * The keyword rules catch `apiKey = "..."` and miss `k1 = "..."`. That is a real
 * gap and it showed up concretely: a live AWS secret key sat one line below a
 * detected access key and was only caught because the field happened to be
 * named `aws_secret_access_key`. Rename it and nothing fires.
 *
 * Two mechanisms close that:
 *
 * 1. **Format rules** (in `rules.ts`) for credentials with a recognisable
 *    shape. Highest confidence, no false positives worth speaking of.
 * 2. **Entropy**, here, for everything else. A random 32-character token looks
 *    nothing like English or like a class name, and Shannon entropy measures
 *    exactly that.
 *
 * Entropy alone is notoriously noisy — hashes, UUIDs, base64 images, minified
 * JavaScript and Android resource tables all score highly and none of them are
 * secrets. The suppression list below is therefore doing most of the work, and
 * the result is reported as a hotspot rather than a defect: "this looks like a
 * credential, confirm it" is the honest claim, not "this is one".
 */

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);

  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Below this a string is structured text rather than a random token. */
const MIN_ENTROPY = 3.6;
const MIN_LENGTH = 20;
const MAX_LENGTH = 200;

/**
 * When the variable's own name says "credential", the value is held to a lower bar:
 * the name has already done part of the work that length and entropy do for an
 * anonymous literal. Ten characters is the floor secret scanners such as gitleaks
 * use for their generic rule, and 3.2 bits keeps a hex or base64 key while still
 * rejecting words.
 */
const NAMED_MIN_LENGTH = 10;
const NAMED_MIN_ENTROPY = 3.2;

/**
 * Words that mark an identifier as holding a credential.
 *
 * Starts from the keyword set secret scanners use for a generic API-key rule
 * (access, api, auth, key, credential, creds, passwd, password, secret, token)
 * and adds the names crypto material goes by (salt, iv, nonce, passphrase).
 * Matched as whole words of the identifier, split on case and punctuation, so
 * `monkey` and `turkey` do not count as `key`.
 */
const CREDENTIAL_WORDS = new Set([
  'access', 'api', 'apikey', 'auth', 'authorization', 'bearer', 'credential', 'credentials', 'creds',
  'key', 'keys', 'passwd', 'password', 'passphrase', 'pwd', 'secret', 'secrets', 'token', 'tokens',
  'salt', 'iv', 'nonce',
]);

/** The words of an identifier: `apiKey`, `API_KEY` and `api-key` are all `api`, `key`. */
export function identifierWords(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

/** `key` followed by one of these is a different word: keychain, keystore, keyboard, keycode. */
const KEY_COMPOUNDS = new Set(['chain', 'store', 'board', 'code', 'pad', 'word', 'stroke', 'frame', 'guard', 'ring', 'hole', 'manager', 'bindings', 'binding']);

export function isCredentialName(identifier: string): boolean {
  const words = identifierWords(identifier);
  return words.some((w, i) => CREDENTIAL_WORDS.has(w) && !(w === 'key' && KEY_COMPOUNDS.has(words[i + 1] ?? '')));
}

/** A segment that reads as a word: `device`, `Classic`, `DATAST`, `mapPutValue`, `KeyChain`. */
const WORD_LIKE = /^(?:[a-z]{3,}|[A-Z][a-z]{2,}|[A-Z]{3,}|[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+){2,})$/;

/** Whether a value is words joined by separators, which is a name or a phrase rather than key material. */
function readsAsWords(value: string): boolean {
  return value.split(/[-_.:/+=\s]+/).filter((w) => WORD_LIKE.test(w)).length >= 2;
}

/**
 * Things that score high on entropy and are not secrets.
 *
 * Each entry earned its place against a real artifact; removing one brings its
 * noise straight back.
 */
const NOT_A_SECRET: { pattern: RegExp; because: string; /** Skipped when the variable is named like a credential: a hex string or a UUID there is a key. */ anonymousOnly?: boolean }[] = [
  { pattern: /^sha256\//, because: 'a certificate pin, which is public by design' },
  { pattern: /^[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+$/, because: 'a cipher transformation such as AES/ECB/PKCS5PADDING, which names an algorithm' },
  { pattern: /^[0-9a-f]{32}$/i, because: 'an MD5 digest', anonymousOnly: true },
  { pattern: /^[0-9a-f]{40}$/i, because: 'a SHA-1 digest', anonymousOnly: true },
  { pattern: /^[0-9a-f]{64}$/i, because: 'a SHA-256 digest', anonymousOnly: true },
  { pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, because: 'a UUID', anonymousOnly: true },
  { pattern: /^L[\w$/]+;$/, because: 'a JVM class descriptor' },
  { pattern: /^\([^)]*\)[\w$/;[]+$/, because: 'a JVM method signature' },
  { pattern: /^(https?|content|file|android\.resource):\/\//i, because: 'a URI' },
  { pattern: /^[/\\][\w./\\-]+$/, because: 'a filesystem path' },
  { pattern: /^(data:|iVBORw0KGgo|\/9j\/4AAQ|R0lGOD|PHN2Zy|AAAA)/, because: 'embedded binary or image data' },
  { pattern: /^[\w.]+\.(java|kt|xml|so|dex|png|jpg|webp|json|properties)$/i, because: 'a file name' },
  { pattern: /^(android|androidx|com|org|io|kotlin|kotlinx|java|javax)\.[\w.]+$/, because: 'a package name' },
  { pattern: /\s/, because: 'prose rather than a token' },
  { pattern: /[\[\](){}<>,;|\\'"`?&]/, because: 'code or markup punctuation, which no token contains' },
  { pattern: /(placeholder|changeme|your[_-]?(?:key|token|secret|api|password)|example|sample|dummy|insert[_-]?here|replace[_-]?me|^x+$|^\*+$|^\.+$)/i, because: 'a placeholder' },
  { pattern: /^[A-Z_]+$/, because: 'a constant name' },
  // A Kotlin @Metadata payload is escaped unicode, which scores very high.
  { pattern: /\\u[0-9a-f]{4}/i, because: 'encoded Kotlin metadata' },
  { pattern: /^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i, because: 'a SQL statement' },
  { pattern: /^get[A-Z]\w*\(/, because: 'a Kotlin intrinsic message naming a getter' },
  // These three came straight off a real scan: `androgoat_userpins.db`,
  // `vnd.android.cursor.dir/vnd.androgoat.pins` and `AndroGoatInvoice.txt`.
  // None is a credential and all three clear the entropy bar, because mixed
  // case with underscores and dots is genuinely irregular.
  { pattern: /^[\w.-]+\.[A-Za-z0-9]{1,5}$/, because: 'a file name' },
  { pattern: /^(vnd\.|application\/|text\/|image\/|audio\/|video\/|multipart\/)/i, because: 'a MIME type' },
  { pattern: /^\$?[a-z0-9]+(_+[a-z0-9]+)+$/i, because: 'a snake_case identifier', anonymousOnly: true },
  { pattern: /^[a-z]+([A-Z][a-z0-9]*)+$/, because: 'a camelCase identifier', anonymousOnly: true },
  { pattern: /^[A-Z][a-z]+([A-Z][a-z0-9]*)+$/, because: 'a PascalCase identifier', anonymousOnly: true },
  { pattern: /^[a-z0-9]+(-[a-z0-9]+)+$/, because: 'a kebab-case identifier', anonymousOnly: true },
  { pattern: /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$/, because: 'a dotted name', anonymousOnly: true },
  { pattern: /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+(\(\))?$/, because: 'a dotted identifier or method reference', anonymousOnly: true },
  { pattern: /^[@?][\w.]*[:/][\w./+-]+$/, because: 'an Android resource reference' },
  { pattern: /^\?[A-Za-z][\w.:]*$/, because: 'a theme attribute reference' },
  { pattern: /^'[\w.$]+'$/, because: 'a quoted identifier' },
  { pattern: /^__[\w.]+__$/, because: 'a dunder name', anonymousOnly: true },
  { pattern: /\(\?[:=!<]|\[\^?[a-zA-Z0-9-]+\]/, because: 'a regular expression' },
];

/**
 * Lines whose literals are compiler output, not app data.
 *
 * Kotlin emits `Intrinsics.checkNotNullExpressionValue(x, "getMainExecutor(this)")`
 * and a `@Metadata` annotation holding encoded signatures into essentially every
 * class it compiles. Both score high on entropy and neither is ever a
 * credential, so they are excluded by line rather than by value — the values
 * vary, the shape of the line does not.
 */
const COMPILER_GENERATED =
  /Lkotlin\/jvm\/internal\/Intrinsics|\bIntrinsics\s*\.|^\s*@(kotlin\.)?Metadata\(|@DebugMetadata\(|^\s*@SourceDebugExtension/;

export type EntropyHit = {
  value: string;
  entropy: number;
  /** The variable or field it was assigned to, when one is visible. */
  identifier?: string;
  /** The identifier names a credential, so this is more than a random-looking string. */
  named?: boolean;
};

/**
 * Whether a literal looks like a credential on shape alone.
 *
 * Returns the reason it was rejected when it does not, so the behaviour is
 * testable and a surprising miss can be explained rather than guessed at.
 */
export function classify(
  value: string,
  options: { named?: boolean } = {},
): { secret: boolean; entropy: number; because?: string } {
  const entropy = shannonEntropy(value);
  const minLength = options.named ? NAMED_MIN_LENGTH : MIN_LENGTH;
  const minEntropy = options.named ? NAMED_MIN_ENTROPY : MIN_ENTROPY;

  if (value.length < minLength) return { secret: false, entropy, because: 'too short to be a token' };

  // A credential-named variable is often a lookup name, not a credential: `AD_REPORT_KEY =
  // "mopub-intent-ad-report"`, `KEY_ALIAS = "device-classic-p384-key"`, `TASK_KEY =
  // "ReactNativeFirebaseMessagingHeadlessTask"`. The name does half the work here, so the
  // value must not read as a name itself: random key material has digits, and is not words
  // joined by separators.
  if (options.named && !/\d/.test(value)) return { secret: false, entropy, because: 'no digit: reads as a name' };
  // Random key material is not words, however they are joined. Applies to every literal: the
  // anonymous path was reporting `"utils:mapPutValue:unknownType:"` and `"DOCUMENT_START_SCRIPT:1"`.
  if (readsAsWords(value)) return { secret: false, entropy, because: 'words joined by separators: a name, not a key' };
  // An anonymous literal also needs a digit or base64 punctuation: a long run of letters alone is
  // an identifier or a sentence, and a random token without a single digit is very rare.
  if (!options.named && !/[\d+/=]/.test(value)) return { secret: false, entropy, because: 'letters only: reads as text' };
  if (value.length > MAX_LENGTH) return { secret: false, entropy, because: 'too long to be a credential' };

  for (const { pattern, because, anonymousOnly } of NOT_A_SECRET) {
    if (anonymousOnly && options.named) continue;
    if (pattern.test(value)) return { secret: false, entropy, because };
  }

  // A credential is drawn from a wide alphabet. Text that is only lowercase
  // letters is almost always an identifier, however long.
  const classes =
    Number(/[a-z]/.test(value)) + Number(/[A-Z]/.test(value)) +
    Number(/[0-9]/.test(value)) + Number(/[+/=_-]/.test(value));
  if (classes < 2) return { secret: false, entropy, because: 'a single character class' };

  if (entropy < minEntropy) {
    return { secret: false, entropy, because: `entropy ${entropy.toFixed(2)} is below ${minEntropy}` };
  }
  return { secret: true, entropy };
}

/** `String k1 = "..."` / `val k1 = "..."` — the name a literal is bound to. */
const ASSIGNMENT = /(?:^|\s)(?:val|var|final|static|private|public|protected|String|CharSequence)?\s*([\w$]+)\s*=\s*"([^"]+)"/;

/**
 * `name = "value"`, `name: "value"`, `"name": "value"`, `name => "value"` and `name := "value"`:
 * the forms a credential is bound to a name in Java, Kotlin, JSON, Dart and a decoded plist.
 */
const NAMED_ASSIGNMENT = /(["']?)([A-Za-z_$][\w$.-]*)\1\s*(?:=>|:=|=|:)\s*"([^"\\\s]{10,150})"/g;

/**
 * The ways an Android resource binds a name to a value.
 *
 * `<string name="algolia_api_key">value</string>` and `<meta-data android:name="..."
 * android:value="..."/>` are where SDK keys live in an Android app, and neither is an
 * assignment, so the pattern above never saw them. Each yields (name, value).
 */
const XML_NAMED: { pattern: RegExp; name: number; value: number }[] = [
  { pattern: /<string\s+name="([^"]+)"[^>]*>\s*([^<\s][^<]{9,149}?)\s*<\/string>/g, name: 1, value: 2 },
  { pattern: /android:name="([^"]+)"\s+android:value="([^"\s]{10,150})"/g, name: 1, value: 2 },
  { pattern: /android:value="([^"\s]{10,150})"\s+android:name="([^"]+)"/g, name: 2, value: 1 },
];

/** Literals in a line that look like credentials by shape, or by shape and the name they are bound to. */
export function entropyHits(line: string, alreadyClaimed?: (value: string) => boolean): EntropyHit[] {
  if (COMPILER_GENERATED.test(line)) return [];

  const hits: EntropyHit[] = [];
  const reported = new Set<string>();

  // A credential-named variable holding a random-looking value. The name earns it a lower bar.
  for (const match of line.matchAll(NAMED_ASSIGNMENT)) {
    const [, , identifier, value] = match;
    if (!isCredentialName(identifier)) continue;
    if (alreadyClaimed?.(value)) continue;
    const verdict = classify(value, { named: true });
    if (!verdict.secret) continue;
    reported.add(value);
    hits.push({ value, entropy: verdict.entropy, identifier, named: true });
  }

  for (const { pattern, name, value: valueAt } of XML_NAMED) {
    for (const match of line.matchAll(pattern)) {
      const identifier = match[name];
      const value = match[valueAt].replace(/&amp;/g, '&');
      if (!isCredentialName(identifier) || reported.has(value) || alreadyClaimed?.(value)) continue;
      const verdict = classify(value, { named: true });
      if (!verdict.secret) continue;
      reported.add(value);
      hits.push({ value, entropy: verdict.entropy, identifier, named: true });
    }
  }

  const assignment = line.match(ASSIGNMENT);
  for (const match of line.matchAll(/"([^"\\]{12,})"/g)) {
    const value = match[1];
    if (reported.has(value)) continue;
    // A value a named rule already reported does not need reporting twice:
    // the AWS key was appearing as an access-key finding, a secret-key finding
    // and a high-entropy finding all at once.
    if (alreadyClaimed?.(value)) continue;
    const verdict = classify(value);
    if (!verdict.secret) continue;
    hits.push({
      value,
      entropy: verdict.entropy,
      identifier: assignment?.[2] === value ? assignment[1] : undefined,
    });
  }
  return hits;
}
