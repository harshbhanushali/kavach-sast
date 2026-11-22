/**
 * Content rules: everything found by reading files rather than by parsing
 * structure.
 *
 * Structural facts (is this component exported? is the binary PIE?) are decided
 * in `android.ts` / `ios.ts`, where the parsed manifest and Mach-O headers live.
 * What is left — secrets, weak crypto, dangerous API use — is pattern matching
 * over decompiled code, resources and strings, and that is what this file holds.
 *
 * Two deliberate choices about false positives:
 *
 * 1. **Patterns are anchored to the thing that makes them dangerous**, not to
 *    the keyword. `MD5` alone appears in half of all dependency trees and means
 *    nothing; `MessageDigest.getInstance("MD5")` is a decision someone made.
 * 2. **Patterns match both notations.** The scanner reads jadx's Java output
 *    where jadx is installed and smali otherwise, so every pattern has to
 *    recognise `Runtime.getRuntime().exec` and `Ljava/lang/Runtime;->exec`
 *    alike. One rule set covering both beats two sets that drift.
 * 3. **Third-party code is scanned but attributed.** A weak cipher inside a
 *    bundled ad SDK is still shipped in your APK and still worth knowing about,
 *    but the report says which library it came from so it is not mistaken for
 *    first-party code. Suppressing it entirely would hide real exposure.
 */
import { secretFormatRules } from './secretFormats.ts';
import { CODE_RULES_EXTRA, FLOW_RULES } from './rulesFlow.ts';
import { IOS_FLOW_RULES, IOS_STRING_RULES } from './rulesIos.ts';
import type { FindingKind, SastCategory, SastSeverity } from './types.ts';

export type PatternRule = {
  id: string;
  title: string;
  category: SastCategory;
  severity: SastSeverity;
  /**
   * What sort of statement the rule makes; defaults to `defect`.
   *
   * `hotspot` for something a human must judge, `secure` for the app doing
   * the right thing. Both are carried onto the finding, which is what the
   * report buckets on.
   */
  kind?: FindingKind;
  description: string;
  impact: string;
  /** Concrete steps from the finding to harm, shown in the report. */
  exploitation?: string[];
  remediation: string;
  masvs?: string;
  cwe?: string;
  platforms: ('android' | 'ios')[];
  /** Matched against the artifact-relative path; omit to scan every text file. */
  files?: RegExp;
  /** Single-pattern, line-scoped. Mutually exclusive with `allOf`/`anyOf`. */
  pattern?: RegExp;
  /**
   * Every pattern must appear somewhere in the SAME FILE.
   *
   * This is the precision mechanism, and it is worth explaining because it is
   * the difference between a usable report and a noisy one. A single pattern
   * for "TLS validation disabled" matches `X509TrustManager`, which appears in
   * every HTTP library's type signatures — an earlier version of this scanner
   * fired 162 times on OkHttp for exactly that reason. Requiring
   * `javax.net.ssl` AND a trust-all class name together, in one file, keeps the
   * legitimate references out.
   *
   * File-scoped rather than line-scoped on purpose: the two halves of the
   * evidence are an import at the top and a call further down.
   */
  allOf?: RegExp[];
  /**
   * For a rule whose evidence is several lines: the pattern naming what the
   * finding is about. Lines it matches are listed first, so the headline
   * location is the thing reported and not merely the context beside it (the
   * secret, not the key ID that happens to sit above it).
   */
  lead?: RegExp;
  /** Any one pattern matching the file is enough. */
  anyOf?: RegExp[];
  /**
   * A second pattern that, if it also matches, suppresses the finding. Applied
   * to the line for `pattern`, and to the whole file for `allOf`/`anyOf`.
   * Used where the dangerous form and the safe form share a keyword.
   */
  unless?: RegExp;
};

/**
 * Credential patterns.
 *
 * Every one of these is a *format* match, not a keyword match: an AWS key is
 * `AKIA` followed by 16 uppercase alphanumerics, and nothing else looks like
 * that. Format matching is what keeps the secrets category from drowning in
 * every variable named `token`.
 */
const SECRET_RULES: PatternRule[] = [
  {
    id: 'secret.aws_access_key',
    title: 'AWS access key ID compiled into the app',
    category: 'secrets',
    severity: 'medium',
    description: 'A string matching the AWS access-key-ID format is present in the shipped artifact.',
    impact: 'Anyone who downloads the app can extract the key and, with the matching secret, call AWS as you.',
    remediation: 'Revoke the key now. Move the call server-side, or issue short-lived credentials via Cognito/STS.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: 'secret.private_key',
    title: 'Private key material in the artifact',
    category: 'secrets',
    severity: 'critical',
    description: 'A PEM-encoded private key block is bundled with the app.',
    impact: 'The key is not secret: it ships to every user. Any signing or decryption it protects is forgeable.',
    remediation: 'Remove the key and rotate it. Keys that must exist on-device belong in the Keystore/Secure Enclave, generated there and never exported.',
    masvs: 'MASVS-CRYPTO-2',
    cwe: 'CWE-321',
    platforms: ['android', 'ios'],
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
  {
    id: 'secret.google_api_key',
    title: 'Google API key compiled into the app',
    category: 'secrets',
    severity: 'medium',
    description: 'A string matching the Google API key format is present in the artifact.',
    impact: 'Unrestricted keys can be lifted and billed against your project by anyone who unzips the app.',
    remediation: 'Restrict the key by package name and signing certificate in the Google Cloud console, and scope it to the one API it needs.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    id: 'secret.slack_token',
    title: 'Slack token in the artifact',
    category: 'secrets',
    severity: 'high',
    description: 'A Slack bot, user or webhook token is embedded in the app.',
    impact: 'Read and post access to your workspace for anyone who extracts it.',
    remediation: 'Revoke the token and proxy Slack calls through your backend.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
  },
  {
    id: 'secret.stripe_key',
    title: 'Stripe secret key in the artifact',
    category: 'secrets',
    severity: 'critical',
    description: 'A Stripe live or test *secret* key is embedded in the app.',
    impact: 'Full API access to your Stripe account, including charges and refunds.',
    remediation: 'Roll the key immediately. Mobile apps use publishable keys only; secret keys stay on your server.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b/,
  },
  {
    id: 'secret.jwt',
    title: 'Hardcoded JSON Web Token',
    category: 'secrets',
    severity: 'medium',
    description: 'A complete JWT is compiled into the artifact rather than obtained at runtime.',
    impact: 'A baked-in token cannot be rotated per user and grants whatever its claims allow to anyone holding the app.',
    remediation: 'Obtain tokens at runtime from an authenticated session and keep them in the Keystore/Keychain.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    id: 'secret.firebase_url',
    title: 'Firebase database URL',
    category: 'secrets',
    severity: 'medium',
    description: 'A Firebase Realtime Database endpoint is referenced in the artifact.',
    impact: 'If the database rules are permissive, the endpoint alone is enough to read or write your data.',
    remediation: 'Confirm Firebase security rules deny unauthenticated access. The URL itself is not secret, the rules are what protect it.',
    cwe: 'CWE-284',
    platforms: ['android', 'ios'],
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/,
  },
  {
    id: 'secret.generic_credential',
    title: 'Credential-shaped assignment in code',
    category: 'secrets',
    severity: 'medium',
    description: 'A variable named like a credential is assigned a long literal string.',
    impact: 'If it is a real credential it ships to every user; if it is a placeholder it is noise that hides the real ones.',
    remediation: 'Move real credentials server-side. Remove or clearly name placeholders so this rule stays meaningful.',
    cwe: 'CWE-798',
    // Android only. This matches source syntax — `identifier = "literal"` —
    // and a compiled iOS binary's string table never contains that: Swift and
    // Obj-C both discard the assignment and the identifier at compile time,
    // leaving only the literal (which format rules above catch) or, for an
    // ivar/property, its name as a separate string with no literal attached.
    // Tagging this for iOS made it look covered while it could never fire —
    // confirmed against a real IPA, where it matched nothing all scan.
    platforms: ['android'],
    // The keyword may sit anywhere in the identifier, not just at its end:
    // `aws_secret_access_key = "..."` is exactly the shape this rule is for,
    // and requiring `secret` to touch the `=` missed a live AWS secret key
    // sitting one line below a detected access key.
    pattern: /\b\w*(password|passwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\w*\s*[=:]\s*["'][^"']{12,}["']/i,
    // Template placeholders, resource lookups and obvious dummies are not findings.
    // A value that is a regular expression (a password policy) is a rule about passwords, not one.
    unless: /(\$\{|@string\/|R\.string\.|xxx+|placeholder|example|changeme|your[_-]?|<[a-z_]+>|null|TODO|\(\?[=!<:]|\\\\[dDwWsS]|\[\^?[a-zA-Z0-9]-[a-zA-Z0-9]|\b(?:app|android|tools):\w+\s*=|["']@\w+\/)/i,
  },
];

/**
 * Cryptography rules.
 *
 * Anchored to the call that selects the primitive, so that merely *naming* an
 * algorithm — in a comment, a constant, or a library's string table — is not a
 * finding.
 */
const CRYPTO_RULES: PatternRule[] = [
  {
    id: 'crypto.weak_hash',
    title: 'Broken hash algorithm selected',
    category: 'crypto',
    severity: 'medium',
    description: 'MD5 or SHA-1 is requested from the platform digest API.',
    impact: 'Both are collision-broken. Used for integrity or signatures, they can be forged; for passwords they are far too fast.',
    remediation: 'Use SHA-256 or better for integrity. For passwords use Argon2id, scrypt or bcrypt — never a bare hash.',
    masvs: 'MASVS-CRYPTO-4',
    cwe: 'CWE-327',
    platforms: ['android', 'ios'],
    // Matches both notations: `MessageDigest.getInstance("MD5")` in Java and
    // `MessageDigest;->getInstance` in smali.
    pattern: /(MessageDigest[;.]?->?\s*getInstance\s*\(\s*"(MD5|SHA-?1)"|getInstance\(\s*"(MD5|SHA-?1)"\s*\)|CC_MD5|CC_SHA1|Insecure\.(MD5|SHA1))/i,
  },
  {
    id: 'crypto.hardcoded_key_constant',
    title: 'Encryption key stored in a constant',
    category: 'crypto',
    severity: 'high',
    description: 'A string constant named like a key, IV or salt holds a literal, and the same class builds a cipher key.',
    impact: 'The value ships inside the APK, so every user has it and anyone who unzips the app can read it. Data encrypted with it is encoded, not protected, and one extraction breaks every install.',
    exploitation: [
      'Unzip the APK and decompile it; the constant is a plain string in the class.',
      'Use that value as the key to decrypt anything the app encrypted with it, from any device.',
    ],
    remediation: 'Generate the key in the Android Keystore so it is created on-device and cannot be exported. Never derive a key from a compiled-in constant.',
    masvs: 'MASVS-CRYPTO-1',
    cwe: 'CWE-321',
    platforms: ['android'],
    // Both halves must be in one file: the declaration (a key-shaped name ending in
    // KEY, IV, SALT, SECRET, NONCE or PASSWORD, with a key-shaped literal) and a
    // cipher key being built. A name that merely contains KEY (KEY_ALIAS, PREF_KEY)
    // is a lookup name, not key material, so the keyword must end the name.
    allOf: [
      // The value must also look like key material: a digit, or mixed case. A lookup
      // name that happens to end in KEY (PREF_KEY = "user_token_pref") is plain snake_case.
      /\bfinal\s+(?:static\s+)?String\s+\w*(?:KEY|Key|key|IV|Iv|iv|SALT|Salt|salt|SECRET|Secret|secret|NONCE|Nonce|nonce|PASSPHRASE|Passphrase|passphrase|PASSWORD|Password|password|PWD|Pwd|pwd)\s*=\s*"(?=[^"]*\d|[^"]*[A-Z][^"]*[a-z]|[^"]*[a-z][^"]*[A-Z])[A-Za-z0-9+\/=_-]{8,64}"/,
      /new\s+(?:SecretKeySpec|IvParameterSpec|PBEKeySpec)\s*\(/,
    ],
    unless: /(\$\{|@string\/|R\.string\.|placeholder|changeme|your[_-]?|TODO)/i,
  },
  {
    id: 'crypto.weak_cipher',
    title: 'Broken or deprecated cipher selected',
    category: 'crypto',
    severity: 'high',
    description: 'DES, 3DES, RC2, RC4 or Blowfish is requested from the cipher API.',
    impact: 'These are breakable with commodity hardware; ciphertext protected by them should be treated as plaintext.',
    remediation: 'Use AES-256-GCM, or ChaCha20-Poly1305 where AES hardware is unavailable.',
    masvs: 'MASVS-CRYPTO-4',
    cwe: 'CWE-327',
    platforms: ['android', 'ios'],
    pattern: /getInstance\(\s*"(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)[^"]*"/i,
  },
  {
    id: 'crypto.ecb_mode',
    title: 'ECB block-cipher mode',
    category: 'crypto',
    severity: 'medium',
    description: 'A cipher is explicitly constructed in ECB mode.',
    impact: 'ECB encrypts identical plaintext blocks to identical ciphertext, so structure in the data survives encryption.',
    remediation: 'Use an authenticated mode: AES/GCM/NoPadding with a unique nonce per message.',
    masvs: 'MASVS-CRYPTO-3',
    cwe: 'CWE-327',
    platforms: ['android', 'ios'],
    pattern: /"AES\/ECB|"DES\/ECB|getInstance\(\s*"AES"\s*\)/i,
  },
  {
    id: 'crypto.insecure_random',
    title: 'Non-cryptographic random number generator constructed',
    category: 'crypto',
    // Lowered from medium, and narrowed. The first version also matched
    // `Math.random()`, which hit an animation class and a colour quantiser —
    // shuffling pixels is not a security decision. Nothing in the bytecode says
    // what the value will be used for, so this reports sites to review and is
    // priced accordingly.
    severity: 'low',
    description: 'java.util.Random is instantiated. Whether that matters depends on what the output is used for.',
    impact: 'If any of these values becomes a token, key, IV, nonce or password-reset code, it is predictable and an attacker can reproduce the sequence.',
    remediation: 'Use SecureRandom (Android) or SecRandomCopyBytes (iOS) wherever the value is security-relevant. Ordinary shuffling and animation may keep java.util.Random.',
    masvs: 'MASVS-CRYPTO-6',
    cwe: 'CWE-330',
    platforms: ['android', 'ios'],
    pattern: /(Ljava\/util\/Random;-><init>|new\s+(java\.util\.)?Random\s*\()/,
    // Platform UI and graphics libraries use Random for animation and layout.
    unless: /(androidx\/|com\/google\/android\/material\/|android\/support\/|kotlin\/random\/)/,
  },
  {
    id: 'crypto.hardcoded_iv',
    title: 'Hardcoded initialisation vector',
    category: 'crypto',
    severity: 'medium',
    description: 'An IvParameterSpec is built from a literal byte array or string constant.',
    impact: 'A fixed IV defeats semantic security: the same plaintext always produces the same ciphertext.',
    remediation: 'Generate a fresh random IV per encryption and transmit it alongside the ciphertext.',
    masvs: 'MASVS-CRYPTO-3',
    cwe: 'CWE-329',
    platforms: ['android'],
    pattern: /IvParameterSpec;-><init>|new\s+IvParameterSpec\s*\(\s*"/,
  },
];

/** Network and transport rules. */
const NETWORK_RULES: PatternRule[] = [
  // NOTE: the Android forms of "trust all certificates" and "accept any
  // hostname" are NOT here. They were, as regexes over `X509TrustManager` and
  // `HostnameVerifier;->verify`, and they fired 162 times on OkHttp — which
  // merely names those types in its signatures. Every hit was a false positive
  // sitting at the top of the report as a critical. Whether validation is
  // actually defeated is a property of the method *body*, so smali.ts decides
  // it by reading the body. See analyseSmali.
  {
    id: 'net.ios_cert_validation_disabled',
    title: 'Certificate validation explicitly disabled',
    category: 'network',
    // Unlike the ambiguous form below, this one has no legitimate reading:
    // `allowsAnyHTTPSCertificate` is a private NSURLRequest flag with exactly
    // one purpose, accepting a certificate chain that would otherwise fail.
    severity: 'high',
    description: 'The binary references allowsAnyHTTPSCertificate, the private API for disabling certificate validation.',
    impact: 'Any certificate is accepted, including a self-signed one presented by an attacker on the network path. TLS provides no protection while this is set.',
    remediation: 'Remove the call. If a self-signed certificate is needed for a staging build, pin that specific certificate instead of disabling validation outright.',
    masvs: 'MASVS-NETWORK-2',
    cwe: 'CWE-295',
    platforms: ['ios'],
    pattern: /allowsAnyHTTPSCertificate/,
  },
  {
    id: 'net.ios_trust_override',
    title: 'Custom TLS trust evaluation in the binary',
    category: 'network',
    // Deliberately low: the symbol's presence shows the app customises trust
    // evaluation, which is also what correct pinning looks like. It is a prompt
    // to review, not an accusation — an iOS binary carries no method bodies to
    // check, so the stronger claim cannot be justified.
    //
    // Confirmed on a real IPA (DVIA-v2) that this pattern's only hit was
    // `kCFStreamSSLValidatesCertificateChain` inside a bundled library's own
    // diagnostic string ("Security option unavailable - ... - You must use
    // manual trust evaluation"), not evidence the app called the API. That is
    // exactly the ambiguity this rule is scoped for, and why the unambiguous
    // `allowsAnyHTTPSCertificate` case was split out above instead of raising
    // this one's severity across the board.
    severity: 'low',
    kind: 'hotspot',
    description: 'The binary references APIs associated with overriding TLS trust evaluation.',
    impact: 'If the override accepts any certificate, TLS is defeated. If it implements pinning, it is a control rather than a weakness — the symbol alone does not distinguish them, and it may also be a bundled library merely naming the API in a log message.',
    remediation: 'Review the URLSession delegate. It must call SecTrustEvaluateWithError and reject the chain on failure; it must never complete the challenge unconditionally.',
    masvs: 'MASVS-NETWORK-1',
    cwe: 'CWE-295',
    platforms: ['ios'],
    pattern: /kCFStreamSSLValidatesCertificateChain|NSURLAuthenticationMethodServerTrust/,
  },
  {
    id: 'net.cleartext_url',
    title: 'Hardcoded http:// endpoint',
    category: 'network',
    severity: 'medium',
    description: 'A plain-HTTP URL to a non-local host is compiled into the app.',
    impact: 'Traffic to it is readable and modifiable by anyone on the network path.',
    remediation: 'Move the endpoint to HTTPS and remove any cleartext permission that was added for it.',
    masvs: 'MASVS-NETWORK-1',
    cwe: 'CWE-319',
    platforms: ['android', 'ios'],
    // Any delimiter, not just a quote. The old pattern required `"http://`,
    // which matches a Java string literal and nothing else — so a URL in XML
    // text content (`<string name="API_URL">http://host/</string>`) was never
    // seen, and resource files are exactly where these live.
    //
    // The excluded hosts are XML namespaces and loopback. Loopback is not a
    // cleartext risk because the traffic never leaves the device; shipping a
    // loopback URL at all is reported by the rule below instead.
    pattern: /(?:^|["'>=\s(])http:\/\/(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.[a-z0-9.-]+|www\.w3\.org|ns\.adobe\.com|apache\.org|[a-z]+\.apache\.org|java\.sun\.com|xmlpull\.org|www\.android\.com|tempuri\.org|purl\.org|www\.opengis\.net|www\.springframework\.org|www\.jboss\.org|xmlns\.|(?:[a-z0-9-]+\.)*(?:apple|digicert|verisign|symantec|entrust|globalsign|sectigo|comodo|comodoca|letsencrypt|identrust|usertrust|geotrust|thawte|godaddy|startssl|trustwave|certum|swisssign|google-analytics|crashlytics|goo|bit|github|stackoverflow|gnu|haxx|zlib|sqlite|openssl|ietf|iana|unicode|mozilla|cloudflare)\.(?:com|org|net|io|gov|ch|pl))[a-z0-9.-]+\.[a-z]{2,}/i,
  },
  {
    id: 'net.non_production_endpoint',
    title: 'Non-production endpoint shipped in the build',
    category: 'network',
    severity: 'medium',
    kind: 'hotspot',
    description:
      'The artifact carries URLs for development, QA, staging or demo environments alongside the production one.',
    impact:
      'Those environments are usually less hardened than production — weaker credentials, test data, verbose errors, sometimes no WAF. An attacker who reads the binary learns they exist and can point the app at them, or attack them directly.',
    exploitation: [
      'Unzip the APK and read res/values/strings.xml, where these URLs typically sit as plain resources.',
      'Hit the staging or QA host directly. It is often reachable from the internet and rarely monitored the way production is.',
      'If the app chooses its base URL from one of these at runtime, patch the selector or the string resource to repoint a real user at the weaker environment.',
    ],
    remediation:
      'Strip non-production endpoints from release builds — a build-type-specific resource or a BuildConfig field keeps them out of the shipped artifact entirely.',
    masvs: 'MASVS-CODE-2',
    cwe: 'CWE-489',
    platforms: ['android', 'ios'],
    // Matched on the host, so `api-staging.example.com` and `dev.example.com`
    // both count while a production path like `/v1/devices` does not.
    pattern:
      /https?:\/\/[a-z0-9.-]*\b(dev|development|qa|uat|staging|stage|stg|test|sandbox|demo|preprod|pre-prod|nonprod)\b[a-z0-9.-]*\.[a-z]{2,}|https?:\/\/(?:10\.0\.2\.2|127\.0\.0\.1|localhost)(?::\d+)?/i,
    unless: /schemas\.android\.com|www\.w3\.org|\.apache\.org|xmlpull\.org|developer\.android\.com|developers\.google\.com|github\.com/i,
  },
];

/**
 * iOS platform rules, matched against the Mach-O string and symbol tables.
 *
 * A stripped Objective-C or Swift binary still carries selector names, class
 * names and framework symbols, because the runtime needs them. That is what
 * these read. It is evidence that an API is *linked*, which is weaker than
 * evidence it is called on sensitive data — so most of these are hotspots
 * asking a question, not defects asserting a bug. Marking them all as defects
 * would produce a long list nobody trusts.
 *
 * The `secure` ones are as important as the rest: they are how a reader tells
 * "we checked and this app does it properly" from "we never looked".
 */
const IOS_PLATFORM_RULES: PatternRule[] = [
  {
    id: 'ios.nsuserdefaults_storage',
    title: 'NSUserDefaults used for storage',
    category: 'storage',
    severity: 'medium',
    kind: 'hotspot',
    description: 'The binary references NSUserDefaults, which writes to an unencrypted plist inside the app container.',
    impact: 'Anything stored there is readable from an unencrypted device backup and from the filesystem on a jailbroken device. It is the wrong place for tokens, PINs or personal data.',
    exploitation: [
      'Take an unencrypted iTunes/Finder backup of the device, or read the container directly on a jailbroken phone.',
      'Open Library/Preferences/<bundle-id>.plist inside the app container.',
      'Everything the app put in NSUserDefaults is there in plain text.',
    ],
    remediation: 'Keep credentials and personal data in the Keychain (SecItemAdd) with an appropriate accessibility class. NSUserDefaults is for preferences.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-312',
    platforms: ['ios'],
    pattern: /NSUserDefaults|standardUserDefaults|setObject:forKey:.{0,20}Defaults/,
  },
  {
    id: 'ios.no_file_protection',
    title: 'File written without data protection',
    category: 'storage',
    severity: 'medium',
    kind: 'hotspot',
    description: 'The binary references file writes with no data-protection class, or NSFileProtectionNone explicitly.',
    impact: 'A file without a protection class stays readable while the device is locked, which defeats the point of the passcode for data at rest.',
    remediation: 'Write with NSFileProtectionComplete (or CompleteUnlessOpen) so the file is encrypted with a key tied to the passcode.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-311',
    platforms: ['ios'],
    pattern: /NSFileProtectionNone|writeToFile:atomically:|NSDataWritingFileProtectionNone/,
  },
  {
    id: 'ios.cookie_storage',
    title: 'Cookies stored in the shared cookie jar',
    category: 'storage',
    severity: 'low',
    kind: 'hotspot',
    description: 'NSHTTPCookieStorage is referenced, which persists cookies to disk in the app container.',
    impact: 'A session cookie written there survives app restarts and appears in unencrypted backups.',
    remediation: 'For session tokens prefer an in-memory ephemeral URLSession configuration, or the Keychain if they must persist.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-312',
    platforms: ['ios'],
    pattern: /NSHTTPCookieStorage|sharedHTTPCookieStorage/,
  },
  {
    id: 'crypto.weak_key_size',
    title: 'Undersized asymmetric key',
    category: 'crypto',
    severity: 'medium',
    description: 'A key size of 1024 bits or less is configured for an asymmetric algorithm.',
    impact: 'RSA below 2048 bits is factorable by a well-resourced attacker and is rejected outright by modern platform policy.',
    remediation: 'Use at least 2048-bit RSA, or an elliptic-curve key (P-256 or better).',
    masvs: 'MASVS-CRYPTO-1',
    cwe: 'CWE-326',
    // Android only, for the same reason as the AWS-secret correlation above:
    // the second pattern is a bare number, and a whole binary's string table
    // contains "512", "768" or "1024" for unrelated reasons (buffer sizes,
    // image dimensions, page sizes) far too often for the correlation to mean
    // anything once there is no single small file to scope it to.
    platforms: ['android'],
    allOf: [
      /kSecAttrKeySizeInBits|KeyPairGeneratorSpec|RSAKeyGenParameterSpec|setKeySize/,
      /\b(512|768|1024)\b/,
    ],
  },
  {
    id: 'ios.dynamic_loading',
    title: 'Dynamic library loading',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'The binary calls dlopen/dlsym, which loads code at runtime.',
    impact: 'Code loaded by path can be substituted on a compromised device, and it is the usual mechanism a hooking framework uses to get itself in.',
    remediation: 'Link required libraries statically where possible. If dynamic loading is necessary, validate what is loaded and never build the path from input.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-494',
    platforms: ['ios'],
    pattern: /\bdlopen\b|\bdlsym\b|NSBundle.{0,12}load/,
  },
  {
    id: 'ios.command_execution',
    title: 'Shell command execution API is linked',
    category: 'code',
    severity: 'medium',
    kind: 'hotspot',
    description: 'system() or popen() is imported, which runs a command through the shell.',
    impact: 'A command built from anything an attacker influences (a URL, a file name, a server response) runs with the app\u2019s privileges. iOS apps rarely have a legitimate reason to start a shell, so it is worth knowing why this one does.',
    remediation: 'Remove the call, or replace it with the system API that does the job. If it must stay, never build the command string from input.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-78',
    platforms: ['ios'],
    pattern: /^_(system|popen)$/,
  },
  {
    id: 'ios.uncaught_exception_handler',
    title: 'Custom uncaught-exception handler',
    category: 'code',
    severity: 'info',
    kind: 'hotspot',
    description: 'NSSetUncaughtExceptionHandler is referenced.',
    impact: 'Crash handlers routinely capture stack traces and app state. Where that is shipped to a third party, it can carry user data off the device.',
    remediation: 'Confirm what the handler reports and where it sends it, and scrub personal data before transmission.',
    masvs: 'MASVS-PRIVACY-1',
    platforms: ['ios'],
    pattern: /NSSetUncaughtExceptionHandler/,
  },
  {
    id: 'ios.oslog_usage',
    title: 'Unified logging in the binary',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'os_log or NSLog is referenced in a release binary.',
    impact: 'Log output is readable over USB and via the Console app on a paired machine. Anything logged about a session or a user leaves the app that way.',
    remediation: 'Use os_log with the default privacy setting so interpolated values are redacted, and keep credentials out of log statements entirely.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-532',
    platforms: ['ios'],
    pattern: /\bos_log\b|_os_log_impl|\bNSLog\b/,
  },

  // --- the app doing things right -----------------------------------------
  {
    id: 'crypto.weak_prng_c',
    title: 'Non-cryptographic random number generator',
    category: 'crypto',
    severity: 'medium',
    description: 'rand(), random() or srand() is imported.',
    impact: 'These are deterministic given the seed and are predictable from a handful of outputs. A token, nonce or salt built from them is guessable.',
    remediation: 'Use SecRandomCopyBytes on iOS, or arc4random_buf. Both draw from the system CSPRNG.',
    masvs: 'MASVS-CRYPTO-6',
    cwe: 'CWE-338',
    platforms: ['ios'],
    // The imported symbol, whole: the string table also holds prose such as
    // "Failed to generate random bytes", which is not a call to random().
    pattern: /^_(rand|random|srand|srandom|drand48|lrand48|mrand48)$/,
  },
  {
    id: 'code.unsafe_c_string',
    title: 'Unbounded C string function',
    category: 'code',
    severity: 'medium',
    kind: 'hotspot',
    description: 'strcpy, strcat, sprintf or gets is linked.',
    impact: 'None of these bounds the destination, so a longer-than-expected input writes past the buffer. This is the classic stack overflow primitive.',
    remediation: 'Use the bounded forms — strlcpy, strlcat, snprintf — or Swift strings, which carry their own length.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-120',
    platforms: ['ios'],
    pattern: /\b_(strcpy|strcat|sprintf|gets|vsprintf)\b/,
  },
  {
    id: 'ios.coredata_unencrypted',
    title: 'Core Data store without a protection class',
    category: 'storage',
    severity: 'medium',
    kind: 'hotspot',
    description: 'Core Data persistence APIs are referenced with no NSPersistentStoreFileProtectionKey nearby.',
    impact: 'A Core Data store is an ordinary SQLite file in the container. Without a protection class it is readable from a backup and while the device is locked.',
    remediation: 'Set NSPersistentStoreFileProtectionKey to NSFileProtectionComplete on the store description, or keep sensitive entities out of Core Data.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-312',
    platforms: ['ios'],
    pattern: /addPersistentStoreWithType|NSPersistentStoreCoordinator|NSPersistentContainer/,
    unless: /NSPersistentStoreFileProtectionKey/,
  },
  {
    id: 'ios.sqlite_unencrypted',
    title: 'Raw SQLite database',
    category: 'storage',
    severity: 'low',
    kind: 'hotspot',
    description: 'sqlite3 APIs are linked without any reference to SQLCipher.',
    impact: 'A plain SQLite file in the app container is readable from an unencrypted backup and on a jailbroken device.',
    remediation: 'Use SQLCipher for sensitive tables, or set a file protection class on the database file.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-312',
    platforms: ['ios'],
    pattern: /\bsqlite3_(open|exec|prepare)/,
    unless: /sqlcipher|sqlite3_key/i,
  },
  {
    id: 'ios.idfa_tracking',
    title: 'Advertising identifier referenced',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'The IDFA (advertisingIdentifier / ASIdentifierManager) is referenced.',
    impact: 'The IDFA is a cross-app tracking identifier. Reading it without App Tracking Transparency consent breaches Apple policy and, in most jurisdictions, privacy law.',
    remediation: 'Request authorisation through ATTrackingManager first, and use identifierForVendor where a per-vendor id is sufficient.',
    masvs: 'MASVS-PRIVACY-1',
    platforms: ['ios'],
    pattern: /advertisingIdentifier|ASIdentifierManager|ATTrackingManager/,
  },
  {
    id: 'ios.location_tracking',
    title: 'Location services used',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'CLLocationManager APIs such as startUpdatingLocation or requestAlwaysAuthorization are referenced.',
    impact: 'Location is among the most sensitive data an app can hold. Always-on authorisation in particular needs a justification the user would accept.',
    remediation: 'Request the narrowest authorisation that works — when-in-use over always — and state the purpose clearly in the usage description.',
    masvs: 'MASVS-PRIVACY-1',
    platforms: ['ios'],
    pattern: /startUpdatingLocation|requestAlwaysAuthorization|CLLocationManager|startMonitoringSignificantLocation/,
  },
  {
    id: 'ios.health_data',
    title: 'HealthKit data access',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'HealthKit APIs are referenced.',
    impact: 'Health data is a special category under GDPR and HIPAA. It must not leave the device without explicit consent, and Apple forbids using it for advertising.',
    remediation: 'Confirm the data never reaches analytics or advertising, and that the consent flow names each type read.',
    masvs: 'MASVS-PRIVACY-1',
    platforms: ['ios'],
    pattern: /HKHealthStore|HKQuantityType|requestAuthorizationToShareTypes/,
  },
  {
    id: 'ios.webview_usage',
    title: 'WebView present',
    category: 'code',
    severity: 'low',
    kind: 'hotspot',
    description: 'WKWebView or the deprecated UIWebView is referenced.',
    impact: 'A WebView renders remote content inside the app. If it loads a URL from input, or exposes a JavaScript bridge, it becomes the way into the app.',
    remediation: 'Prefer WKWebView, disable JavaScript where it is not needed, and never build the loaded URL from untrusted input.',
    masvs: 'MASVS-PLATFORM-2',
    cwe: 'CWE-749',
    platforms: ['ios'],
    pattern: /WKWebView|UIWebView|WKUserContentController/,
  },
  {
    id: 'ios.temporary_file',
    title: 'Temporary directory used',
    category: 'storage',
    severity: 'info',
    kind: 'hotspot',
    description: 'NSTemporaryDirectory or a tmp path is referenced.',
    impact: 'Files in tmp are not encrypted by default and are not cleaned up on a schedule the app controls. Sensitive data written there can outlive the session.',
    remediation: 'Delete temporary files explicitly, and set a protection class if they hold anything sensitive.',
    masvs: 'MASVS-STORAGE-2',
    platforms: ['ios'],
    pattern: /NSTemporaryDirectory|\/tmp\//,
  },
  {
    id: 'ios.backup_exclusion',
    title: 'Backup exclusion configured',
    category: 'storage',
    severity: 'info',
    kind: 'hotspot',
    description: 'isExcludedFromBackup or NSURLIsExcludedFromBackupKey is referenced.',
    impact: 'Not a weakness in itself. Worth confirming the right files are excluded: an excluded file is kept out of iCloud, which is usually what you want for a credential cache.',
    remediation: 'Confirm every file holding sensitive data is excluded, and that nothing the user would expect restored is.',
    masvs: 'MASVS-STORAGE-2',
    platforms: ['ios'],
    pattern: /isExcludedFromBackup|NSURLIsExcludedFromBackupKey/,
  },
  {
    id: 'ios.background_screenshot',
    title: 'App state handler present — confirm screenshot protection',
    category: 'storage',
    severity: 'low',
    kind: 'hotspot',
    description: 'applicationDidEnterBackground: or applicationWillResignActive: is implemented.',
    impact: 'iOS snapshots the current screen for the app switcher. Without an overlay or blur applied in one of these callbacks, a snapshot of a sensitive screen (a balance, a form, a one-time code) is written to disk and readable from the snapshot cache.',
    remediation: 'In applicationWillResignActive:/applicationDidEnterBackground:, cover sensitive view controllers with a blank or blurred overlay before the snapshot is taken, and remove it in applicationWillEnterForeground:.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-200',
    platforms: ['ios'],
    pattern: /applicationDidEnterBackground|applicationWillResignActive/,
  },

  // --- more of the app doing things right ---------------------------------
  {
    id: 'ios.ssl_pinning',
    title: 'Certificate pinning implemented',
    category: 'network',
    severity: 'info',
    kind: 'secure',
    description: 'Pinning APIs are referenced — SecTrustEvaluate together with a pinned certificate or public key.',
    impact: 'Not a weakness. Pinning is what stops a user-installed root certificate from silently intercepting the app\u2019s traffic.',
    remediation: 'No action. Confirm the pin set includes a backup key, or a rotation will brick the app.',
    masvs: 'MASVS-NETWORK-4',
    platforms: ['ios'],
    allOf: [/SecTrustEvaluate|serverTrust|SecPolicyCreateSSL/, /pinn|SecCertificateCopyData|publicKey/i],
  },
  {
    id: 'ios.sqlcipher',
    title: 'SQLCipher used for the database',
    category: 'storage',
    severity: 'info',
    kind: 'secure',
    description: 'SQLCipher symbols are present, so the SQLite store is encrypted.',
    impact: 'Not a weakness. An encrypted store is unreadable from a backup or a jailbroken device without the key.',
    remediation: 'No action. Confirm the key comes from the Keychain rather than being compiled in.',
    masvs: 'MASVS-STORAGE-2',
    platforms: ['ios'],
    // Evidence that SQLCipher is really in the build: the keying API only it exports,
    // or settings only it understands. Words are not evidence: Couchbase Lite embeds
    // both "app not built with SQLCipher" and a `PRAGMA key` code path that is dead
    // without it.
    pattern: /^_?sqlite3_(key|key_v2|rekey|rekey_v2)$|\bcipher_(version|page_size|compatibility)\b/i,
  },
  {
    id: 'ios.realm_encryption',
    title: 'Realm database encrypted',
    category: 'storage',
    severity: 'info',
    kind: 'secure',
    description: 'A Realm configuration with an encryptionKey is referenced.',
    impact: 'Not a weakness. The Realm file is encrypted at rest.',
    remediation: 'No action. Confirm the key is stored in the Keychain.',
    masvs: 'MASVS-STORAGE-2',
    platforms: ['ios'],
    pattern: /encryptionKey|RLMRealmConfiguration.{0,24}encryption/,
  },
  {
    id: 'ios.anti_debug',
    title: 'Anti-debugging present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'ptrace with PT_DENY_ATTACH, or a sysctl P_TRACED check, is referenced.',
    impact: 'Not a weakness. It raises the cost of attaching a debugger to the running app.',
    remediation: 'No action. A single check is patched out easily; redundancy is what makes it cost time.',
    masvs: 'MASVS-RESILIENCE-2',
    platforms: ['ios'],
    pattern: /PT_DENY_ATTACH|ptrace|P_TRACED|sysctl.{0,20}KERN_PROC/,
  },
  {
    id: 'ios.file_protection_complete',
    title: 'Complete file protection used',
    category: 'storage',
    severity: 'info',
    kind: 'secure',
    description: 'NSFileProtectionComplete is referenced.',
    impact: 'Not a weakness. Files written with it are encrypted with a key derived from the passcode and unreadable while the device is locked.',
    remediation: 'No action.',
    masvs: 'MASVS-STORAGE-2',
    platforms: ['ios'],
    pattern: /NSFileProtectionComplete/,
  },
  {
    id: 'ios.secure_text_entry',
    title: 'Secure text entry on input fields',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'isSecureTextEntry is referenced.',
    impact: 'Not a weakness. It masks the field and keeps its contents out of the keyboard cache and out of screenshots.',
    remediation: 'No action. Confirm it is set on every credential field, not only the first.',
    masvs: 'MASVS-PLATFORM-3',
    platforms: ['ios'],
    pattern: /isSecureTextEntry|secureTextEntry/,
  },
  {
    id: 'ios.jailbreak_detection',
    title: 'Jailbreak detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The binary checks for jailbreak indicators such as Cydia, /bin/bash or sandbox escape paths.',
    impact: 'Not a weakness. Recorded so a reader can tell an app that checks from one that was never examined.',
    remediation: 'No action. Keep the checks varied and redundant — a single check is trivially patched out.',
    masvs: 'MASVS-RESILIENCE-1',
    platforms: ['ios'],
    // Whole-word frida: a bare substring matched "blackFriday" and made a shopping string read as jailbreak detection.
    pattern: /cydia|MobileSubstrate|\/bin\/bash|\/usr\/sbin\/sshd|jailbr(oken|eak)|\bfrida\b|libsubstrate/i,
  },
  {
    id: 'ios.biometric_auth',
    title: 'Biometric authentication used',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'LocalAuthentication is linked and evaluatePolicy is referenced.',
    impact: 'Not a weakness. Worth confirming the result gates something real rather than only hiding a screen.',
    remediation: 'No action, provided the biometric result unlocks a Keychain item rather than merely setting a boolean an attacker can flip.',
    masvs: 'MASVS-AUTH-2',
    platforms: ['ios'],
    pattern: /LAContext|evaluatePolicy|LAPolicyDeviceOwnerAuthentication/,
  },
  {
    id: 'ios.keychain_used',
    title: 'Keychain used for storage',
    category: 'storage',
    severity: 'info',
    kind: 'secure',
    description: 'SecItemAdd or SecItemCopyMatching is referenced, so the app stores at least some data in the Keychain.',
    impact: 'Not a weakness. The Keychain is the right place for credentials on iOS.',
    remediation: 'No action. Check the accessibility class is no broader than the app needs.',
    masvs: 'MASVS-STORAGE-1',
    platforms: ['ios'],
    pattern: /SecItemAdd|SecItemCopyMatching|SecItemUpdate/,
  },
];

/** Code-level injection and platform-misuse rules. */
const CODE_RULES: PatternRule[] = [
  {
    id: 'code.webview_js_interface',
    title: 'JavaScript bridge exposed to WebView content',
    category: 'code',
    severity: 'medium',
    description: 'addJavascriptInterface exposes native methods to page JavaScript.',
    impact: 'On any page the WebView can be steered to, script gains the exposed native capability.',
    remediation: 'Remove the bridge, or restrict the WebView to a fixed allowlist of first-party HTTPS origins.',
    masvs: 'MASVS-PLATFORM-2',
    cwe: 'CWE-749',
    platforms: ['android'],
    pattern: /addJavascriptInterface/,
  },
  {
    id: 'code.webview_file_access',
    title: 'WebView granted filesystem access',
    category: 'code',
    severity: 'medium',
    description: 'setAllowFileAccessFromFileURLs or setAllowUniversalAccessFromFileURLs is enabled.',
    impact: 'A file:// page can read other local files, including the app sandbox, and exfiltrate them.',
    remediation: 'Leave both false. Load content over https:// or via WebViewAssetLoader.',
    masvs: 'MASVS-PLATFORM-2',
    cwe: 'CWE-200',
    platforms: ['android'],
    pattern: /setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs/,
  },
  {
    id: 'code.sql_concatenation',
    title: 'SQL built by string concatenation',
    category: 'code',
    severity: 'medium',
    description: 'rawQuery/execSQL is called with a concatenated or formatted string.',
    impact: 'Attacker-controlled input reaching the query changes its meaning — local SQL injection.',
    remediation: 'Use parameter binding: pass ? placeholders and an argument array.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-89',
    platforms: ['android'],
    pattern: /(rawQuery|execSQL)\s*\(\s*[^,)]*(\+|format|StringBuilder|append)/,
  },
  {
    id: 'code.world_accessible_file',
    title: 'File created world-readable or world-writable',
    category: 'storage',
    severity: 'medium',
    description: 'MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE is used to open a file or preference store.',
    impact: 'Any other app on the device can read — or rewrite — that data. Both modes have been deprecated since API 17.',
    remediation: 'Use MODE_PRIVATE. Share data through a ContentProvider with a permission, or FileProvider grants.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-732',
    platforms: ['android'],
    // jadx writes the constant's value (1, 2, 3), so the numeric form is matched too.
    pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|\b(?:getSharedPreferences|openFileOutput|getDir)\s*\([^()]*(?:\([^()]*\)[^()]*)*,\s*[123]\s*\)/,
  },
  {
    id: 'code.external_storage_write',
    title: 'Shared external storage used',
    category: 'storage',
    severity: 'medium',
    description: 'getExternalStorageDirectory, getExternalStoragePublicDirectory or a public download destination is used for app files.',
    impact: 'Shared storage is world-readable to apps holding the storage permission and survives uninstall.',
    remediation: 'Use the app-private directory (getFilesDir), or scoped storage via MediaStore for user media.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-312',
    platforms: ['android'],
    pattern: /getExternalStorageDirectory|getExternalStoragePublicDirectory|setDestinationInExternalPublicDir/,
  },
  {
    id: 'code.logging_in_release',
    title: 'Verbose logging left in the build',
    category: 'code',
    severity: 'low',
    description: 'android.util.Log or NSLog calls are present in the shipped artifact.',
    impact: 'Logs frequently carry tokens, identifiers and request bodies, readable by tooling on the device.',
    remediation: 'Strip logs in release via ProGuard/R8 -assumenosideeffects, or route them through a no-op release logger.',
    masvs: 'MASVS-STORAGE-3',
    cwe: 'CWE-532',
    platforms: ['android', 'ios'],
    pattern: /Landroid\/util\/Log;->(d|v|i|w|e)\(|\bLog\s*\.\s*[dviwe]\s*\(|\bNSLog\s*\(/,
  },
  {
    id: 'code.runtime_exec',
    title: 'Shell command execution',
    category: 'code',
    severity: 'medium',
    description: 'Runtime.exec or ProcessBuilder is used to spawn a process.',
    impact: 'If any part of the command is attacker-influenced this becomes command injection; on rooted devices it is also a privilege path.',
    remediation: 'Replace with a platform API. Where a process is genuinely required, pass a fixed argument array, never a shell string.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-78',
    platforms: ['android'],
    // Smali only. In Java the flow pass reports a command that is not a constant, so
    // `exec(new String[]{"which", "su"})` for root detection is not a shell injection candidate.
    files: /^smali/,
    pattern: /Ljava\/lang\/Runtime;->exec|ProcessBuilder;-><init>/,
  },
  {
    id: 'code.dynamic_dex_load',
    title: 'Code loaded at runtime',
    category: 'code',
    severity: 'medium',
    description: 'DexClassLoader or PathClassLoader loads a DEX from outside the APK.',
    impact: 'Code not covered by the APK signature executes with full app permissions; if the source is writable this is remote code execution.',
    remediation: 'Ship all code inside the signed APK. If dynamic loading is unavoidable, verify a signature over the payload before loading it.',
    masvs: 'MASVS-CODE-2',
    cwe: 'CWE-494',
    platforms: ['android'],
    pattern: /DexClassLoader|PathClassLoader;-><init>|BaseDexClassLoader;-><init>|new\s+(Dex|Path|BaseDex)ClassLoader\s*\(/,
  },
  {
    id: 'code.ios_pasteboard',
    title: 'Pasteboard API referenced',
    category: 'storage',
    severity: 'low',
    kind: 'hotspot',
    description: 'UIPasteboard is referenced in the binary.',
    // `UIPasteboard.generalPasteboard` never appears as one string in a
    // compiled binary — the class name and the selector are stored
    // separately, so a pattern requiring both together (the previous version
    // of this rule) could never match. Confirmed against a real IPA: the
    // class is referenced, `generalPasteboard`/`UIPasteboard.general` as a
    // joined literal is not. Matching the class reference alone is weaker
    // evidence, which is why this is a hotspot rather than a defect — the
    // same trade the other "API referenced, confirm usage" rules make.
    impact: 'The general pasteboard is readable by every app on the device and syncs across devices via Handoff. Sensitive values (passwords, tokens) copied to it leak beyond the app.',
    remediation: 'Confirm sensitive values use a named, app-scoped pasteboard rather than `UIPasteboard.general`, and set an expiry on anything copied there.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-200',
    platforms: ['ios'],
    pattern: /UIPasteboard|generalPasteboard/,
  },
  {
    id: 'code.ios_weak_keychain_accessibility',
    title: 'Keychain item available without device lock',
    category: 'storage',
    severity: 'medium',
    description: 'kSecAttrAccessibleAlways or ...AlwaysThisDeviceOnly is used for a Keychain item.',
    impact: 'The item is readable while the device is locked, which removes the protection the Keychain exists to provide.',
    remediation: 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly, or ...AfterFirstUnlockThisDeviceOnly for background access.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-311',
    platforms: ['ios'],
    pattern: /kSecAttrAccessibleAlways/,
  },
];


/**
 * Rules for well-known Android weaknesses.
 *
 * The weaknesses are well known; the rules are this project's own. The patterns, the impact and
 * remediation sentences and the severities were written here, and the class, method and package names they
 * match are the platform's. Each rule carries an impact sentence and a remediation instead of a number,
 * because a number between 0 and 10 does not tell anyone what to change.
 */
const COMMON_RULES: PatternRule[] = [
  {
    id: 'net.webview_ignore_ssl',
    title: 'WebView proceeds past TLS certificate errors',
    category: 'network',
    severity: 'high',
    description: 'onReceivedSslError calls handler.proceed(), which accepts a certificate the platform rejected.',
    impact: 'Every page the WebView loads can be intercepted with any certificate. It is the WebView equivalent of a trust-all TrustManager.',
    remediation: 'Delete the override, or call handler.cancel(). Never call proceed() on an SSL error in a shipped build.',
    masvs: 'MASVS-NETWORK-1',
    cwe: 'CWE-295',
    platforms: ['android'],
    // Both halves must be in the same class: the callback and the proceed call.
    allOf: [/onReceivedSslError/, /->proceed\s*\(|\.proceed\s*\(/],
  },
  {
    id: 'net.ssl_socket_factory_insecure',
    title: 'Insecure SSLSocketFactory or hostname verifier',
    category: 'network',
    severity: 'high',
    description: 'A known permissive socket factory or hostname verifier is referenced alongside javax.net.ssl.',
    impact: 'These factories accept self-signed or mismatched certificates, so TLS provides encryption without authentication — which is no protection against an active attacker.',
    remediation: 'Use the platform default SSLSocketFactory and HostnameVerifier. For a private CA, configure it in network_security_config.',
    masvs: 'MASVS-NETWORK-1',
    cwe: 'CWE-295',
    platforms: ['android'],
    allOf: [
      /javax\/net\/ssl|javax\.net\.ssl/,
      /AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|NonValidatingSSLSocketFactory|AllTrustSSLSocketFactory|TrustAllSSLSocketFactory|NullHostnameVerifier/,
    ],
  },
  {
    id: 'crypto.cbc_pkcs5',
    title: 'CBC mode with PKCS5/PKCS7 padding',
    category: 'crypto',
    severity: 'medium',
    description: 'A cipher is constructed as CBC with PKCS5Padding or PKCS7Padding.',
    impact: 'Unauthenticated CBC is vulnerable to padding-oracle attacks, which recover plaintext without the key when the receiver leaks whether padding was valid.',
    remediation: 'Use AES/GCM/NoPadding. If CBC is unavoidable, add an encrypt-then-MAC construction and verify the MAC before decrypting.',
    masvs: 'MASVS-CRYPTO-3',
    cwe: 'CWE-649',
    platforms: ['android'],
    anyOf: [/getInstance\([^)]{0,48}\/CBC\/PKCS5Padding/, /getInstance\([^)]{0,48}\/CBC\/PKCS7Padding/],
  },
  {
    id: 'crypto.rsa_no_oaep',
    title: 'RSA without OAEP padding',
    category: 'crypto',
    severity: 'medium',
    description: 'RSA is used with PKCS1 padding or none at all rather than OAEP.',
    impact: 'Textbook and PKCS1 v1.5 RSA are malleable and vulnerable to Bleichenbacher-style chosen-ciphertext attacks.',
    remediation: 'Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding, or prefer an authenticated symmetric scheme with a wrapped key.',
    masvs: 'MASVS-CRYPTO-3',
    cwe: 'CWE-780',
    platforms: ['android'],
    anyOf: [/RSA\/ECB\/NoPadding/, /RSA\/ECB\/PKCS1Padding/, /RSA\/None\/NoPadding/],
  },
  {
    id: 'crypto.weak_iv',
    title: 'Predictable initialisation vector',
    category: 'crypto',
    severity: 'medium',
    description: 'An all-zero or sequential IV constant is present.',
    impact: 'A fixed IV makes identical plaintexts encrypt identically, which leaks structure and, in CTR-like modes, can expose the keystream.',
    remediation: 'Generate the IV from SecureRandom for every message and send it alongside the ciphertext.',
    masvs: 'MASVS-CRYPTO-3',
    cwe: 'CWE-329',
    platforms: ['android'],
    anyOf: [
      /0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00/,
      /0x01,\s*0x02,\s*0x03,\s*0x04,\s*0x05,\s*0x06,\s*0x07/,
    ],
  },
  {
    id: 'code.webview_debug',
    title: 'WebView remote debugging enabled',
    category: 'code',
    severity: 'medium',
    description: 'setWebContentsDebuggingEnabled(true) is called.',
    impact: 'Any app or user with adb access can inspect and script the WebView through Chrome DevTools, including reading session tokens from it.',
    remediation: 'Guard the call with BuildConfig.DEBUG, or remove it.',
    masvs: 'MASVS-RESILIENCE-2',
    cwe: 'CWE-489',
    platforms: ['android'],
    allOf: [/setWebContentsDebuggingEnabled/, /0x1|true/],
  },
  {
    id: 'code.webview_mixed_content',
    title: 'WebView allows mixed content',
    category: 'network',
    severity: 'medium',
    description: 'setMixedContentMode is set to MIXED_CONTENT_ALWAYS_ALLOW.',
    impact: 'An HTTPS page may load scripts over plain HTTP, so a network attacker can inject code into a page the user believes is secure.',
    remediation: 'Use MIXED_CONTENT_NEVER_ALLOW and serve every subresource over HTTPS.',
    masvs: 'MASVS-NETWORK-1',
    cwe: 'CWE-319',
    platforms: ['android'],
    allOf: [/setMixedContentMode/, /MIXED_CONTENT_ALWAYS_ALLOW|0x0\b/],
  },
  {
    id: 'storage.clipboard',
    title: 'Clipboard read or monitored',
    category: 'storage',
    severity: 'low',
    description: 'The app reads from, listens for changes on, or copies a sensitive-looking value to the system clipboard.',
    impact: 'The clipboard is shared with every app on the device. Anything placed there — passwords, OTPs, account numbers — is readable by all of them.',
    remediation: 'Avoid the clipboard for sensitive values. Where a copy action is a product requirement, mark the clip sensitive (EXTRA_IS_SENSITIVE) and clear it after use.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-200',
    platforms: ['android'],
    // Reading the clipboard, or listening to it, is what exposes other apps' data to this one. Copying
    // to it is reported by the flow pass only when what is copied looks sensitive: a copy button for a
    // public address is not a leak.
    anyOf: [/OnPrimaryClipChangedListener/, /ClipboardManager;->getPrimaryClip/, /\.\s*getPrimaryClip\s*\(/],
  },
  {
    id: 'storage.temp_file',
    title: 'Temporary file created',
    category: 'storage',
    severity: 'low',
    kind: 'hotspot',
    description: 'File.createTempFile is used.',
    impact: 'Temporary files are easy to leave behind unencrypted and, in a shared directory, readable by other apps.',
    remediation: 'Write to the app-private cache directory and delete deterministically; never place sensitive data in a world-accessible temp path.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-378',
    platforms: ['android'],
    pattern: /createTempFile/,
  },
  {
    id: 'code.jackson_deserialization',
    title: 'Jackson polymorphic deserialization enabled',
    category: 'code',
    severity: 'high',
    description: 'enableDefaultTyping() is called on an ObjectMapper.',
    impact: 'Untrusted JSON can name arbitrary classes to instantiate, which is a well-established remote code execution path.',
    remediation: 'Remove enableDefaultTyping. Use @JsonTypeInfo with an explicit allowlist of permitted subtypes.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-502',
    platforms: ['android'],
    pattern: /enableDefaultTyping/,
  },
  {
    id: 'code.tapjacking_unguarded',
    title: 'No tapjacking protection on sensitive views',
    category: 'code',
    // Informational: its absence is only a defect for screens that authorise
    // something, and static analysis cannot tell which those are.
    severity: 'info',
    description: 'The app never sets filterTouchesWhenObscured or an onFilterTouchEventForSecurity handler.',
    impact: 'A malicious overlay can sit above your UI and harvest taps the user believes are going to your app, which is how consent and transfer screens get hijacked.',
    remediation: 'Set android:filterTouchesWhenObscured="true" on any view that confirms a payment, a permission or a transfer.',
    masvs: 'MASVS-PLATFORM-1',
    cwe: 'CWE-1021',
    platforms: ['android'],
    // Inverted rule: reported by the absence check in android.ts, not here.
    pattern: /filterTouchesWhenObscured/,
  },
  {
    id: 'storage.sqlite_unencrypted',
    title: 'SQLite database opened without encryption',
    category: 'storage',
    severity: 'low',
    description: 'openOrCreateDatabase / SQLiteOpenHelper is used with no SQLCipher key.',
    impact: 'The database file is plaintext on disk. On a rooted device, or via an adb backup, its whole contents are readable.',
    remediation: 'Use SQLCipher with a key from the Android Keystore, or store nothing sensitive in the database.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-311',
    platforms: ['android'],
    allOf: [/openOrCreateDatabase|SQLiteOpenHelper/],
    // An app that links SQLCipher is doing the right thing already.
    unless: /net\/sqlcipher|net\.sqlcipher/,
  },
  {
    id: 'code.ios_webview_js',
    title: 'JavaScript enabled in a web view',
    category: 'code',
    severity: 'low',
    description: 'A WKWebView or UIWebView is configured with JavaScript enabled.',
    impact: 'Combined with a script message handler, page content can reach native capability. UIWebView additionally has no process isolation.',
    remediation: 'Prefer WKWebView, disable JavaScript where the content does not need it, and restrict loads to an allowlist of first-party origins.',
    masvs: 'MASVS-PLATFORM-2',
    cwe: 'CWE-749',
    platforms: ['ios'],
    anyOf: [/javaScriptEnabled/, /UIWebView/],
  },
];


/**
 * Gaps found on a later audit of this scanner's own coverage.
 *
 * Each is a vulnerability class common in shipped Android apps that the rule set
 * above had no equivalent for. Listed separately so it stays visible that they
 * were added after the fact rather than designed in.
 */
const GAP_RULES: PatternRule[] = [
  {
    id: 'code.mutable_pending_intent',
    title: 'Mutable PendingIntent',
    category: 'code',
    severity: 'medium',
    description: 'A PendingIntent is created with FLAG_MUTABLE, or on a pre-Android-12 target with neither FLAG_MUTABLE nor FLAG_IMMUTABLE.',
    impact: 'A mutable PendingIntent handed to another app can have its unfilled fields rewritten, so the receiving app makes your app perform an action of its choosing — with your identity and your permissions. Android 12 made the flag mandatory precisely because this was so widely wrong.',
    remediation: 'Pass FLAG_IMMUTABLE. Only use FLAG_MUTABLE where the receiver genuinely must fill in a field (inline notification replies), and set an explicit component on the wrapped Intent so it cannot be redirected.',
    masvs: 'MASVS-PLATFORM-1',
    cwe: 'CWE-927',
    platforms: ['android'],
    allOf: [
      /PendingIntent[;.]?->?\s*(getActivity|getBroadcast|getService|getForegroundService)/,
      /FLAG_MUTABLE|0x2000000|33554432/,
    ],
  },
  // NOTE: `crypto.hardcoded_key` is NOT here. As a file-scoped AND rule it
  // required only that a file mention SecretKeySpec and contain any quoted
  // string — and every smali file contains `.source "Foo.kt"`. It degenerated
  // into "does this file reference SecretKeySpec", which matched okio's HMAC
  // helpers. Whether the key comes from a literal is a question about
  // instructions near the constructor, so smali.ts decides it by reading the
  // method body. See analyseSmali.
  {
    id: 'code.intent_redirection',
    title: 'Intent read from an Intent and started',
    category: 'code',
    severity: 'high',
    description: 'A nested Intent is extracted from an incoming Intent and passed straight to startActivity or sendBroadcast.',
    impact: 'This is the intent-redirection pattern: a malicious app sends you an Intent containing another Intent, and your app launches it. Because your process is the caller, the target sees your identity — so components and URIs the attacker could not reach directly become reachable through you.',
    remediation: 'Do not forward an Intent supplied by a caller. If a redirect is genuinely required, verify the resolved component against an allowlist and strip granted URI permissions before starting it.',
    masvs: 'MASVS-PLATFORM-1',
    cwe: 'CWE-926',
    platforms: ['android'],
    allOf: [
      /getParcelableExtra|getParcelable\(/,
      /Landroid\/content\/Intent;/,
      /startActivity|startService|sendBroadcast/,
    ],
  },
  {
    id: 'code.webview_content_access',
    title: 'WebView allowed to read content:// providers',
    category: 'code',
    severity: 'medium',
    description: 'setAllowContentAccess(true) lets page script reach content provider URIs.',
    impact: 'A page loaded in the WebView can request content:// URIs, which reaches any provider the app can read — including your own, and any other app\'s that is exported.',
    remediation: 'Call setAllowContentAccess(false) unless the WebView genuinely renders provider-backed content, and restrict it to first-party origins.',
    masvs: 'MASVS-PLATFORM-2',
    cwe: 'CWE-200',
    platforms: ['android'],
    allOf: [/setAllowContentAccess/, /0x1|true/],
  },
  {
    id: 'code.biometric_no_crypto',
    title: 'Biometric prompt without a CryptoObject',
    category: 'code',
    severity: 'medium',
    description: 'BiometricPrompt.authenticate is called without a CryptoObject.',
    impact: 'Without a CryptoObject the result is only a boolean returned by the app to itself, which a hooking framework flips in one line. Binding the prompt to a Keystore key makes the sensitive operation impossible without a real authentication, rather than merely gated behind one.',
    remediation: 'Create a Keystore key with setUserAuthenticationRequired(true), wrap it in a CryptoObject, pass it to authenticate(), and perform the sensitive operation with the unlocked cipher.',
    masvs: 'MASVS-AUTH-2',
    cwe: 'CWE-287',
    platforms: ['android'],
    allOf: [/BiometricPrompt/, /authenticate\(/],
    // The safe form names the CryptoObject in the same class.
    unless: /CryptoObject/,
  },
  {
    id: 'storage.zip_slip',
    title: 'Archive entry written without path validation',
    category: 'storage',
    severity: 'medium',
    description: 'A ZipEntry name is used to build an output path with no check for parent-directory segments.',
    impact: 'A crafted archive with ../ in an entry name writes outside the target directory — into the app sandbox, over shared preferences, or over code the app later loads. Known as Zip Slip.',
    remediation: 'Resolve each entry against the target directory and reject anything whose canonical path falls outside it, before opening the output stream.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-22',
    platforms: ['android'],
    allOf: [
      /ZipEntry[;.]?->?\s*getName|\.getName\s*\(\s*\)/,
      /FileOutputStream;-><init>|new\s+FileOutputStream\s*\(|File;-><init>|new\s+File\s*\(/,
    ],
    unless: /getCanonicalPath|startsWith|normalize/,
  },
];


/**
 * Credentials recognisable by their shape alone.
 *
 * These matter because the keyword rule only fires when the *variable* is named
 * helpfully. Rename `aws_secret_access_key` to `k1` and it goes quiet; these
 * rules do not care what it is called.
 */
const FORMAT_SECRET_RULES: PatternRule[] = [
  {
    id: 'secret.aws_secret_key',
    title: 'AWS secret access key alongside an access key ID',
    category: 'secrets',
    severity: 'critical',
    description: 'A 40-character base64 string appears in the same file as an AWS access key ID.',
    impact: 'The access key ID alone is only an identifier; paired with the secret it is a working AWS credential. Anyone who unzips the app has both halves and can call AWS as you.',
    remediation: 'Revoke the key pair immediately in IAM — it must be assumed compromised the moment it shipped. Move the call server-side, or issue short-lived credentials through Cognito or STS.',
    masvs: 'MASVS-STORAGE-1',
    cwe: 'CWE-798',
    // Android only. "Same file" is what makes this correlation trustworthy —
    // in decompiled Android source, that means "same class". A compiled iOS
    // binary has no per-file scope, only one flat string table for the whole
    // app, and a bare 40-character alphanumeric string (a hash, an encoded
    // asset, a UUID without dashes) is common enough to turn up somewhere in
    // any nontrivial binary. Correlating across the whole binary would make
    // this a frequent false "critical" rather than the near-certain match it
    // is on Android.
    platforms: ['android'],
    // Correlated on purpose. A bare 40-character base64 string matches far too
    // much on its own; requiring an AKIA identifier in the same file makes it
    // near-certain and costs nothing, because the two are always shipped
    // together to be usable.
    allOf: [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/, /["'][A-Za-z0-9/+=]{40}["']/],
    lead: /["'][A-Za-z0-9/+=]{40}["']/,
  },
  {
    id: 'secret.openai_key',
    title: 'OpenAI API key',
    category: 'secrets',
    severity: 'high',
    description: 'A string matching the OpenAI secret key format is present.',
    impact: 'The key bills against your account and can be used to read any assistant or file it has access to. OpenAI keys carry no per-device scoping.',
    remediation: 'Revoke it in the OpenAI dashboard and proxy model calls through your own backend, which can authenticate the user and rate-limit per account.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'secret.anthropic_key',
    title: 'Anthropic API key',
    category: 'secrets',
    severity: 'high',
    description: 'A string matching the Anthropic API key format is present.',
    impact: 'Billable API access to your account for anyone who extracts it.',
    remediation: 'Revoke it in the Anthropic console and move model calls behind your own authenticated backend.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'secret.github_token',
    title: 'GitHub token',
    category: 'secrets',
    severity: 'critical',
    description: 'A GitHub personal access, OAuth, app or refresh token is embedded.',
    impact: 'Depending on its scopes: read or write access to source, the ability to push code, and access to Actions secrets.',
    remediation: 'Revoke the token on GitHub immediately and audit recent activity on the account it belongs to.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  },
  {
    id: 'secret.google_oauth',
    title: 'Google OAuth client secret',
    category: 'secrets',
    severity: 'medium',
    description: 'A Google OAuth client secret is embedded in the artifact.',
    impact: 'A client secret in a mobile app is not secret and lets an attacker impersonate your OAuth client, which undermines the consent screen users rely on.',
    remediation: 'Use an installed-app OAuth client, which has no secret, with PKCE. Revoke the existing client secret.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'secret.fcm_server_key',
    title: 'Firebase Cloud Messaging server key',
    category: 'secrets',
    severity: 'high',
    description: 'A legacy FCM server key is present in the artifact.',
    impact: 'The server key can send a push notification to every user of your app. It is a server credential and must never ship in a client.',
    remediation: 'Delete the key in the Firebase console and send notifications from your backend using the HTTP v1 API with a service account.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bAAAA[A-Za-z0-9_-]{7}:APA91[A-Za-z0-9_-]{100,}\b/,
  },
  {
    id: 'secret.twilio',
    title: 'Twilio credential',
    category: 'secrets',
    severity: 'high',
    description: 'A Twilio account SID or API key is embedded.',
    impact: 'Paired with its auth token this sends SMS and places calls billed to your account, and can read message history.',
    remediation: 'Rotate the credential in the Twilio console and move messaging behind your backend.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\b(AC|SK)[0-9a-f]{32}\b/,
  },
  {
    id: 'secret.sendgrid',
    title: 'SendGrid API key',
    category: 'secrets',
    severity: 'high',
    description: 'A SendGrid API key is embedded.',
    impact: 'Lets anyone send mail from your verified domain, which is a phishing capability wearing your brand.',
    remediation: 'Revoke the key in SendGrid and send mail from your backend only.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'secret.connection_string',
    title: 'Database connection string with credentials',
    category: 'secrets',
    severity: 'critical',
    description: 'A database URI containing a username and password is embedded.',
    impact: 'Direct database access from anywhere the host is reachable, bypassing every check your API performs.',
    remediation: 'Remove it and rotate the database password. A mobile client must never hold database credentials; it talks to your API, which talks to the database.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^\s:@"']+:[^\s:@"']+@/i,
  },
  {
    id: 'secret.basic_auth_header',
    title: 'Hardcoded HTTP Basic credentials',
    category: 'secrets',
    severity: 'high',
    description: 'An Authorization header value with Basic or Bearer credentials is compiled in.',
    impact: 'A fixed credential shared by every install: it cannot be rotated per user, and extracting it from one device compromises the endpoint for all of them.',
    remediation: 'Obtain a token per session after authenticating the user, and keep it in the Keystore or Keychain rather than in code.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /["']\s*(Basic\s+[A-Za-z0-9+/=]{16,}|Bearer\s+[A-Za-z0-9._-]{20,})\s*["']/,
  },
  {
    id: 'secret.slack_webhook',
    title: 'Slack webhook URL',
    category: 'secrets',
    severity: 'medium',
    description: 'An incoming-webhook URL for Slack is embedded.',
    impact: 'Anyone holding it can post messages into your workspace channel, which is a convincing internal-phishing primitive.',
    remediation: 'Revoke the webhook and post to Slack from your backend.',
    cwe: 'CWE-798',
    platforms: ['android', 'ios'],
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_+/]+/,
  },
  {
    id: 'secret.ssh_private_key',
    title: 'SSH private key material',
    category: 'secrets',
    severity: 'critical',
    description: 'An OpenSSH private key block is bundled with the app.',
    impact: 'Whatever that key authenticates to — a deployment host, a git remote, an internal service — is reachable by anyone who unzips the app.',
    remediation: 'Remove it, rotate the key, and audit access on whatever it authenticated to.',
    masvs: 'MASVS-CRYPTO-2',
    cwe: 'CWE-321',
    platforms: ['android', 'ios'],
    pattern: /ssh-rsa\s+AAAA[A-Za-z0-9+/]{100,}|-----BEGIN OPENSSH PRIVATE KEY-----/,
  },
];

/**
 * Resilience and protection controls, recorded as `secure` observations.
 *
 * These feed the security-controls section: each is a protection an app can
 * implement, so finding the reference is a statement that it exists and nothing
 * more. Whether the check is reachable and whether its result is acted on needs
 * a human or a dynamic test, and the report says so.
 */
const CONTROL_RULES: PatternRule[] = [
  {
    id: 'android.root_detection',
    title: 'Root detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The code looks for root indicators such as su binaries, Superuser or Magisk packages, or a RootBeer-style helper.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-1',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /\/system\/(x?bin|app)\/su\b|\/sbin\/su\b|Superuser\.apk|com\.noshufou\.android\.su|eu\.chainfire\.supersu|com\.topjohnwu\.magisk|RootBeer|isDeviceRooted|isRooted\(|checkRootMethod|RootDetector/,
  },
  {
    id: 'android.debugger_detection',
    title: 'Debugger detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The code checks whether a debugger is attached (Debug.isDebuggerConnected, TracerPid or the debuggable flag).',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-2',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /Debug\.(isDebuggerConnected|waitingForDebugger)|TracerPid|FLAG_DEBUGGABLE/,
  },
  {
    id: 'android.emulator_detection',
    title: 'Emulator detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The code inspects build properties or system properties that distinguish an emulator from a device.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-5',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /ro\.kernel\.qemu|goldfish|ranchu|isEmulator\(|Build\.(FINGERPRINT|HARDWARE|PRODUCT)[^;\n]{0,60}(generic|vbox|google_sdk|sdk_gphone)/i,
  },
  {
    id: 'android.hook_detection',
    title: 'Instrumentation / hooking-framework detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The code looks for Frida, Xposed or Substrate artefacts.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-4',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /gum-js-loop|re\.frida|frida-server|frida-agent|de\.robv\.android\.xposed|com\.saurik\.substrate|LSPosed/,
  },
  {
    id: 'android.device_attestation',
    title: 'Hardware / Play Integrity attestation referenced',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The Play Integrity, SafetyNet or key-attestation APIs are referenced.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-1',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /IntegrityManager|IntegrityTokenRequest|com\.google\.android\.play\.core\.integrity|com\.google\.android\.play\.integrity|SafetyNetApi|SafetyNetClient|setAttestationChallenge/,
  },
  {
    id: 'android.signature_check',
    title: 'App signature verified at runtime',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The code reads its own signing certificate through PackageManager, the usual first step of a tamper check.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-2',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    allOf: [/PackageManager/, /GET_SIGNATURES|GET_SIGNING_CERTIFICATES|getSigningInfo|getApkContentsSigners/],
  },
  {
    id: 'android.screen_protection',
    title: 'Screen capture blocked (FLAG_SECURE)',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'FLAG_SECURE is applied to a window, which blocks screenshots and hides the screen in the recents view.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-PLATFORM-3',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /FLAG_SECURE/,
  },
  {
    id: 'android.keystore_used',
    title: 'Android Keystore / encrypted storage referenced',
    category: 'storage',
    severity: 'info',
    kind: 'secure',
    description: 'AndroidKeyStore, EncryptedSharedPreferences or a MasterKey is referenced.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-STORAGE-1',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /AndroidKeyStore|EncryptedSharedPreferences|EncryptedFile|MasterKey\b|setIsStrongBoxBacked/,
  },
  {
    id: 'android.pinning_code',
    title: 'Certificate pinning in code',
    category: 'network',
    severity: 'info',
    kind: 'secure',
    description: 'A CertificatePinner, TrustKit or a literal sha256/ pin is present in the code.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-NETWORK-4',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /CertificatePinner\.Builder|TrustKit|sha256\/[A-Za-z0-9+\/]{43}=/,
  },
  {
    id: 'android.biometric_prompt',
    title: 'Biometric authentication used',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'BiometricPrompt or FingerprintManager is referenced.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-AUTH-2',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    pattern: /BiometricPrompt|FingerprintManager/,
  },
  {
    id: 'android.biometric_crypto',
    title: 'Biometric result bound to a cryptographic key',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'BiometricPrompt is used together with a CryptoObject, so the result is tied to a Keystore key rather than a boolean.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-AUTH-2',
    platforms: ['android'],
    files: /\.(java|smali|kt)$/,
    allOf: [/BiometricPrompt/, /CryptoObject/],
  },
  {
    id: 'ios.device_attestation',
    title: 'App Attest / DeviceCheck referenced',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'DCAppAttestService or DCDevice is referenced, so the app can ask Apple to vouch for the device and the app instance.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-1',
    platforms: ['ios'],
    pattern: /DCAppAttestService|DCDevice\b|generateAssertion|attestKey/,
  },
  {
    id: 'ios.hook_detection',
    title: 'Hooking / instrumentation detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'The binary inspects loaded images or looks for Frida and Substrate artefacts.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-RESILIENCE-4',
    platforms: ['ios'],
    pattern: /_dyld_image_count|_dyld_get_image_name|gum-js-loop|frida-agent|FridaGadget|libsubstrate|SubstrateLoader/,
  },
  {
    id: 'ios.screen_capture_detection',
    title: 'Screen capture / screenshot detection present',
    category: 'code',
    severity: 'info',
    kind: 'secure',
    description: 'UIScreen.isCaptured or the screenshot notification is referenced.',
    impact: 'Not a weakness. Recorded so the controls section can say which protections the app references; it does not prove the check is reachable or acted on.',
    remediation: 'No action. See the security controls section for how this kind of check is typically bypassed and how to raise the bar.',
    masvs: 'MASVS-PLATFORM-3',
    platforms: ['ios'],
    pattern: /UIScreenCapturedDidChange|isCaptured|userDidTakeScreenshot/,
  },
];

export const PATTERN_RULES: PatternRule[] = [
  ...SECRET_RULES,
  ...CRYPTO_RULES,
  ...NETWORK_RULES,
  ...CODE_RULES,
  ...COMMON_RULES,
  ...GAP_RULES,
  ...FORMAT_SECRET_RULES,
  ...IOS_PLATFORM_RULES,
  ...CONTROL_RULES,
  ...secretFormatRules(),
  ...FLOW_RULES,
  ...CODE_RULES_EXTRA,
  ...IOS_STRING_RULES,
  ...IOS_FLOW_RULES,
];

export function rulesFor(platform: 'android' | 'ios'): PatternRule[] {
  return PATTERN_RULES.filter((r) => r.platforms.includes(platform));
}

/**
 * Third-party SDKs worth naming in the report.
 *
 * Not a vulnerability list — it is context. Knowing an ad SDK is present
 * explains why a finding sits in code nobody on the team wrote, and it is the
 * starting point for the dependency review the scorecard asks for.
 */
export const LIBRARY_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'Firebase', pattern: /^smali[^/]*\/com\/google\/firebase\// },
  { name: 'Google Play Services', pattern: /^smali[^/]*\/com\/google\/android\/gms\// },
  { name: 'OkHttp', pattern: /^smali[^/]*\/okhttp3\// },
  { name: 'Retrofit', pattern: /^smali[^/]*\/retrofit2\// },
  { name: 'Gson', pattern: /^smali[^/]*\/com\/google\/gson\// },
  { name: 'Jackson', pattern: /^smali[^/]*\/com\/fasterxml\/jackson\// },
  { name: 'Glide', pattern: /^smali[^/]*\/com\/bumptech\/glide\// },
  { name: 'Picasso', pattern: /^smali[^/]*\/com\/squareup\/picasso\// },
  { name: 'RxJava', pattern: /^smali[^/]*\/io\/reactivex\// },
  { name: 'Kotlin stdlib', pattern: /^smali[^/]*\/kotlin\// },
  { name: 'Facebook SDK', pattern: /^smali[^/]*\/com\/facebook\// },
  { name: 'Crashlytics', pattern: /^smali[^/]*\/com\/crashlytics\// },
  { name: 'AppsFlyer', pattern: /^smali[^/]*\/com\/appsflyer\// },
  { name: 'Adjust', pattern: /^smali[^/]*\/com\/adjust\/sdk\// },
  { name: 'Realm', pattern: /^smali[^/]*\/io\/realm\// },
  { name: 'SQLCipher', pattern: /^smali[^/]*\/net\/sqlcipher\// },
  { name: 'Flutter', pattern: /^(smali[^/]*\/io\/flutter\/|.*libflutter\.so)/ },
  { name: 'React Native', pattern: /^(smali[^/]*\/com\/facebook\/react\/|.*libreactnative.*\.so)/ },
  { name: 'Unity', pattern: /libunity\.so|^smali[^/]*\/com\/unity3d\// },
  { name: 'Cordova', pattern: /^smali[^/]*\/org\/apache\/cordova\// },
  { name: 'Kavach', pattern: /^smali[^/]*\/ai\/kavach\// },
];

/**
 * Android permissions that materially expand what a compromise can reach.
 *
 * Requesting one is not a finding by itself — a camera app needs the camera.
 * The report lists them so a reviewer can ask whether each is justified.
 */
export const DANGEROUS_PERMISSIONS = new Set([
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.CALL_PHONE',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.READ_PHONE_STATE',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.GET_ACCOUNTS',
  'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION',
  'android.permission.QUERY_ALL_PACKAGES',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
]);
