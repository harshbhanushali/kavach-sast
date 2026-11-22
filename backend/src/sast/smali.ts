/**
 * Method-body analysis over smali.
 *
 * Some of the most serious Android findings cannot be expressed as a line
 * pattern, and trying anyway produces noise that discredits the whole report.
 * The motivating case: `net.trust_all_certs` matched the string
 * `X509TrustManager` and fired 162 times on OkHttp, which merely *names* the
 * type in its signatures. Every one of those was a false positive, and it sat at
 * the top of the report as a critical.
 *
 * What actually indicates defeated TLS validation is a `checkServerTrusted`
 * whose body does nothing — it accepts the chain by returning without inspecting
 * it. That is a statement about a method body, so it is decided here, by reading
 * the body, rather than by a regex over one line.
 *
 * The same shape covers `HostnameVerifier.verify` that unconditionally returns
 * true.
 */
import { readFileSync } from 'node:fs';
import type { WalkedFile } from './scanner.ts';
import { dexContextFor } from './dexContext.ts';
import type { SastFinding, SastLocation } from './types.ts';

/** Directives and debug metadata that carry no behaviour. */
const NOISE = /^\.(locals?|registers|param|line|prologue|local|end local|restart local|source|annotation|end annotation|catch|catchall)\b/;

type Method = { name: string; descriptor: string; body: string[]; line: number };

/** Splits a smali file into its methods, with the lines of each body. */
function methodsOf(source: string): Method[] {
  const lines = source.split('\n');
  const methods: Method[] = [];
  let current: Method | null = null;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (line.startsWith('.method ')) {
      // `.method public final verify(Ljava/lang/String;...)Z`
      const match = line.match(/\.method[^(]*?([\w$<>]+)(\([^)]*\).+)$/);
      current = match
        ? { name: match[1], descriptor: match[2], body: [], line: i + 1 }
        : null;
    } else if (line.startsWith('.end method')) {
      if (current) methods.push(current);
      current = null;
    } else if (current && line.length > 0 && !NOISE.test(line) && !line.startsWith('#')) {
      current.body.push(line);
    }
  }
  return methods;
}

/**
 * A body that returns without doing anything else.
 *
 * `checkServerTrusted` is declared to throw on an invalid chain. A body that
 * cannot throw has accepted every certificate it will ever see.
 */
function isEmptyVoid(body: string[]): boolean {
  return body.length === 1 && body[0] === 'return-void';
}

/**
 * A body that loads a constant 1 and returns it, with nothing in between.
 *
 * This is `return true` after the optimiser has had it: two instructions, no
 * comparison, no call.
 */
function isAlwaysTrue(body: string[]): boolean {
  if (body.length !== 2) return false;
  return /^const(\/4|\/16)?\s+([vp]\d+),\s*(0x1|1)$/.test(body[0]) && /^return\s+[vp]\d+$/.test(body[1]);
}

/**
 * Package prefixes belonging to bundled third-party code.
 *
 * Whether a TLS finding is a defect depends on who wrote it. OkHttp ships
 * `ConscryptPlatform$DisabledHostnameVerifier`, a verifier that genuinely
 * returns true — because when Conscrypt is the TLS provider it performs
 * hostname verification itself, and the Java-level verifier is disabled by
 * design. The pattern matches, and reporting it as a critical defect in
 * someone's app would be wrong.
 *
 * So the match is kept and attributed rather than suppressed: library code is
 * still shipped code and the reader should see it, but it is not presented as
 * their mistake.
 */
const THIRD_PARTY = /^smali[^/]*\/(okhttp3|retrofit2|okio|com\/google|androidx|android\/support|kotlin|kotlinx|io\/reactivex|com\/squareup|org\/apache|org\/bouncycastle|com\/facebook|io\/flutter|com\/android|org\/jetbrains|javax|org\/conscrypt)\//;

function isThirdParty(location: SastLocation): boolean {
  return THIRD_PARTY.test(location.file);
}

/** The library a path belongs to, for the finding text. */
function libraryOf(location: SastLocation): string {
  return location.file.match(THIRD_PARTY)?.[1]?.replace(/\//g, '.') ?? 'a bundled library';
}

/**
 * A key constructed from a literal in the same method.
 *
 * Proximity is the whole question and it cannot be expressed as a file-scoped
 * AND: `SecretKeySpec` appearing somewhere in a file that also contains a quoted
 * string says nothing, because every smali file contains `.source "Foo.kt"`.
 * What matters is a `const-string` feeding the constructor a few instructions
 * later, inside one method body.
 */
function literalKeyConstruction(method: Method): string | undefined {
  const WINDOW = 12;

  for (let i = 0; i < method.body.length; i += 1) {
    if (!/SecretKeySpec;-><init>|IvParameterSpec;-><init>/.test(method.body[i])) continue;

    const from = Math.max(0, i - WINDOW);
    for (let j = i - 1; j >= from; j -= 1) {
      const literal = method.body[j].match(/const-string\s+([vp]\d+),\s*"([^"]{8,})"/);
      if (!literal) continue;

      const [, register, value] = literal;

      // An algorithm or charset name is not key material.
      if (/^(AES|DES|DESede|RSA|Blowfish|UTF-8|US-ASCII|ISO-8859-1|SHA-?\d+|MD5|HmacSHA\d+|PBKDF2\w*|AndroidKeyStore)$/i.test(value)) {
        continue;
      }

      // Kotlin emits a const-string of the PARAMETER NAME before every
      // null-check intrinsic, in every method it compiles. That put okio's
      // `Intrinsics.checkNotNullParameter(p1, "sink")` a few instructions from
      // a SecretKeySpec whose key actually arrives as a parameter, and the
      // check reported a hardcoded key in a library that has none. If the
      // literal is consumed by an intrinsic, it is a parameter name.
      const consumedByIntrinsic = method.body
        .slice(j + 1, j + 3)
        .some((line) => /Lkotlin\/jvm\/internal\/Intrinsics;->/.test(line) && line.includes(register));
      if (consumedByIntrinsic) continue;

      // The literal must actually reach the constructor: either its own
      // register appears in the invoke, or it is converted on the way (the
      // usual `getBytes()` hop) and that result does.
      const reachesInit = registerReaches(method.body, j, i, register);
      if (reachesInit) return value;
    }
  }
  return undefined;
}

/**
 * Whether a value produced at `from` is still an input at `to`.
 *
 * Follows a single move/result hop, which covers the ordinary
 * `const-string -> getBytes() -> move-result-object -> <init>` shape without
 * attempting real dataflow analysis. Conservative: an unfollowed hop means the
 * finding is not reported, which is the right way to be wrong here.
 */
function registerReaches(body: string[], from: number, to: number, register: string): boolean {
  const live = new Set([register]);

  for (let i = from + 1; i <= to; i += 1) {
    const line = body[i];
    const uses = [...live].some((r) => new RegExp(`\\b${r}\\b`).test(line));

    if (i === to) return uses;
    if (!uses) continue;

    // A result of an operation that consumed a live register is also live.
    const result = body[i + 1]?.match(/^move-result(?:-object)?\s+([vp]\d+)/);
    if (result) live.add(result[1]);
  }
  return false;
}

export type SmaliFindings = { findings: SastFinding[] };

/** Needles as text, for looking in the decompiled Java of the same class. */
const NEEDLE_TEXT = ['checkServerTrusted', 'verify(', 'SecretKeySpec', 'IvParameterSpec'];
/**
 * What jadx writes where a method body is missing from its output. Its other warnings ("unsupported loop
 * pattern") note a body that is there, only awkward, and are on a quarter of the classes of an obfuscated app.
 */
const UNDECOMPILED = /Method not decompiled|Code restructure failed|Method dump skipped|decompilation failed|Can't load method/;

/**
 * The smali files worth reading, chosen without reading any of them.
 *
 * The decompiled Java of a class mentions the same method names and types its smali does, and the scan has
 * already read every Java file. So only the smali of classes whose Java mentions a needle is read, plus
 * the smali of classes the decompiler gave up on (where the Java cannot be trusted to say) and of classes
 * with no Java file at all. Everything else is skipped, which on a large app is nearly all of it.
 */
export function smaliToRead(files: WalkedFile[], javaFiles: WalkedFile[], textOf: (file: WalkedFile) => string): WalkedFile[] {
  const wanted = new Set<string>();
  const hasJava = new Set<string>();
  for (const j of javaFiles) {
    if (!j.relative.endsWith('.java')) continue;
    const key = j.relative.replace(/^sources\//, '').replace(/\.java$/, '');
    hasJava.add(key);
    let text: string;
    try {
      text = textOf(j);
    } catch {
      wanted.add(key);
      continue;
    }
    if (NEEDLE_TEXT.some((n) => text.includes(n)) || UNDECOMPILED.test(text)) wanted.add(key);
  }
  return files.filter((f) => {
    // A nested class (`Outer$Inner.smali`) lives inside its outer class's Java file.
    const m = /^smali(?:_classes\d+)?\/(.+?)(?:\$[^/]*)?\.smali$/.exec(f.relative);
    if (!m) return false;
    return wanted.has(m[1]) || !hasJava.has(m[1]);
  });
}

/** What a smali file must mention to be worth parsing. */
const NEEDLES = ['checkServerTrusted', 'verify(', 'SecretKeySpec', 'IvParameterSpec'].map((n) => Buffer.from(n));

export function analyseSmali(files: WalkedFile[]): SmaliFindings {
  const trustAll: SastLocation[] = [];
  const hostnameAll: SastLocation[] = [];
  const literalKeys: SastLocation[] = [];

  for (const file of files) {
    if (!file.relative.endsWith('.smali') || !file.relative.startsWith('smali')) continue;

    // Read as bytes and look for the needles there: decoding every class of a large app as text just to
    // discard nearly all of it was fifteen seconds of a fifty-second scan.
    let raw: Buffer;
    try {
      raw = readFileSync(file.absolute);
    } catch {
      continue;
    }
    // Cheap pre-filter: parsing every method of every class in a large app is
    // wasted work when the file cannot contain either target.
    if (!NEEDLES.some((needle) => raw.includes(needle))) continue;
    const source = raw.toString('utf8');

    for (const method of methodsOf(source)) {
      if (method.name === 'checkServerTrusted' && isEmptyVoid(method.body)) {
        trustAll.push({
          file: file.relative,
          line: method.line,
          excerpt: `checkServerTrusted${method.descriptor} { return-void }`,
        });
      }
      const keyLiteral = literalKeyConstruction(method);
      if (keyLiteral !== undefined) {
        literalKeys.push({
          file: file.relative,
          line: method.line,
          // The key itself, so the report says what leaked and the Java view can find where it is declared.
          excerpt: `${method.name}${method.descriptor} builds a key from the literal "${keyLiteral.slice(0, 64)}"`,
          ...dexContextFor(file.relative, source.split('\n'), method.line - 1),
        });
      }

      // The HostnameVerifier signature, specifically: (String, SSLSession)Z.
      if (
        method.name === 'verify' &&
        /\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z/.test(method.descriptor) &&
        isAlwaysTrue(method.body)
      ) {
        hostnameAll.push({
          file: file.relative,
          line: method.line,
          excerpt: 'verify(String, SSLSession) { return true }',
        });
      }
    }
  }

  const findings: SastFinding[] = [];

  if (literalKeys.length > 0) {
    const firstParty = literalKeys.filter((l) => !isThirdParty(l));
    const inAppCode = firstParty.length > 0;
    findings.push({
      ruleId: 'crypto.hardcoded_key',
      title: inAppCode
        ? 'Encryption key built from a string literal'
        : `Key built from a literal inside ${libraryOf(literalKeys[0])}`,
      category: 'crypto',
      severity: inAppCode ? 'critical' : 'low',
      description:
        'A SecretKeySpec or IvParameterSpec is constructed a few instructions after a const-string in the same method, so the key material is a compiled-in constant.',
      impact: inAppCode
        ? 'The key ships inside the APK, so every user has it and anyone who unzips the app has it. Data encrypted with it is encoded, not protected — and because the key is identical for every install, one extraction breaks every user at once.'
        : 'The construction is inside bundled library code, where a fixed constant is often a test vector or a protocol constant rather than a key protecting your data.',
      remediation: inAppCode
        ? 'Generate the key in the Android Keystore so it is created on-device and cannot be exported. Never derive a key from a compiled-in constant.'
        : 'Confirm the library is not using this path for data your app relies on being confidential.',
      masvs: 'MASVS-CRYPTO-1',
      cwe: 'CWE-321',
      locations: (inAppCode ? firstParty : literalKeys).slice(0, 12),
      occurrences: inAppCode ? firstParty.length : literalKeys.length,
    });
  }

  if (trustAll.length > 0) {
    const firstParty = trustAll.filter((l) => !isThirdParty(l));
    const inAppCode = firstParty.length > 0;
    findings.push({
      ruleId: 'net.trust_all_certs',
      title: inAppCode
        ? 'TrustManager accepts every certificate'
        : `TrustManager with an empty body inside ${libraryOf(trustAll[0])}`,
      category: 'network',
      severity: inAppCode ? 'critical' : 'low',
      description: inAppCode
        ? 'A checkServerTrusted implementation in application code has an empty body, so it validates nothing.'
        : 'A checkServerTrusted implementation with an empty body was found, but only inside bundled library code.',
      impact: inAppCode
        ? 'Every TLS connection the app makes can be intercepted with any self-signed certificate. This one method defeats HTTPS completely.'
        : 'Whether this is reachable depends on the library\'s own configuration. Some libraries ship such a class for a provider that performs validation elsewhere, so it is not necessarily a defect — but it is code you ship.',
      remediation: inAppCode
        ? 'Delete the custom TrustManager and use the platform default. For a private CA, add it through network_security_config — never by disabling validation.'
        : 'Confirm the library uses this only where another layer validates the chain, and that your own code never installs it directly.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-295',
      locations: (inAppCode ? firstParty : trustAll).slice(0, 12),
      occurrences: inAppCode ? firstParty.length : trustAll.length,
    });
  }

  if (hostnameAll.length > 0) {
    const firstParty = hostnameAll.filter((l) => !isThirdParty(l));
    const inAppCode = firstParty.length > 0;
    findings.push({
      ruleId: 'net.allow_all_hostnames',
      title: inAppCode
        ? 'HostnameVerifier accepts every hostname'
        : `Permissive HostnameVerifier inside ${libraryOf(hostnameAll[0])}`,
      category: 'network',
      severity: inAppCode ? 'critical' : 'low',
      description: inAppCode
        ? 'A HostnameVerifier.verify implementation in application code returns true unconditionally.'
        : 'A HostnameVerifier returning true unconditionally was found, but only inside bundled library code.',
      impact: inAppCode
        ? 'A certificate legitimately issued for any domain is accepted for yours, so interception costs an attacker the price of a certificate.'
        : 'Libraries ship these for TLS providers that verify the hostname themselves, so this is usually not a defect. It is reported because it is code in your artifact, not because it is known to be exploitable.',
      remediation: inAppCode
        ? 'Remove the custom verifier. The platform default checks the hostname against the certificate correctly.'
        : 'Confirm your own code never installs this verifier on an OkHttpClient or HttpsURLConnection.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-297',
      locations: (inAppCode ? firstParty : hostnameAll).slice(0, 12),
      occurrences: inAppCode ? firstParty.length : hostnameAll.length,
    });
  }

  return { findings };
}
