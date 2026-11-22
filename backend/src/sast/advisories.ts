/**
 * Known-vulnerable dependency versions.
 *
 * A curated set, not a live feed, and the report says so. The honest framing
 * matters: this catches the well-known mobile-relevant advisories in libraries
 * that actually ship inside APKs, and it will miss anything published after this
 * file was last touched. A scanner that silently implied full CVE coverage would
 * be worse than one that admits a bounded list.
 *
 * Deliberately no network call. Resolving a dependency list against an online
 * advisory service would send a customer's bill of materials to a third party,
 * which is not a decision a scanner should make on its own.
 *
 * Ranges are half-open: `introduced <= version < fixed`. `fixed: null` means no
 * fixed release is known.
 */
import type { SastSeverity } from './types.ts';

export type Advisory = {
  /** Maven coordinate, `group:artifact`. */
  coordinate: string;
  id: string;
  /** Inclusive lower bound; omit for "every version up to `fixed`". */
  introduced?: string;
  /** Exclusive upper bound. Null when unfixed. */
  fixed: string | null;
  severity: SastSeverity;
  title: string;
  summary: string;
  /** Why it matters specifically inside a mobile app. */
  mobileImpact: string;
  cwe?: string;
};

export const ADVISORIES: Advisory[] = [
  {
    coordinate: 'com.squareup.okhttp3:okhttp',
    id: 'CVE-2021-0341',
    introduced: '3.0.0',
    fixed: '4.9.2',
    severity: 'high',
    title: 'OkHttp does not verify the hostname on some certificate chains',
    summary: 'OkHostnameVerifier could accept a certificate whose subject did not match the requested host.',
    mobileImpact: 'TLS connections made through OkHttp — which for most Android apps means every API call — could be terminated by an attacker holding any valid certificate.',
    cwe: 'CWE-295',
  },
  {
    coordinate: 'com.squareup.okhttp3:okhttp',
    id: 'CVE-2023-0833',
    introduced: '4.0.0',
    fixed: '4.11.0',
    severity: 'medium',
    title: 'OkHttp leaks request bodies into exception messages',
    summary: 'A failed request could include the request body in the thrown exception, which typically reaches the crash reporter.',
    mobileImpact: 'Credentials and tokens sent in a POST body end up in Crashlytics or a log aggregator, outside the app sandbox and often outside your own infrastructure.',
    cwe: 'CWE-209',
  },
  {
    coordinate: 'com.fasterxml.jackson.core:jackson-databind',
    id: 'CVE-2020-36518',
    introduced: '2.0.0',
    fixed: '2.13.2.1',
    severity: 'high',
    title: 'Jackson-databind deeply nested input causes stack exhaustion',
    summary: 'Deeply nested JSON leads to unbounded recursion and a StackOverflowError.',
    mobileImpact: 'A hostile or compromised API can crash the app on demand by returning nested JSON, which is a denial of service against your own users.',
    cwe: 'CWE-787',
  },
  {
    coordinate: 'com.fasterxml.jackson.core:jackson-databind',
    id: 'CVE-2019-12384',
    introduced: '2.0.0',
    fixed: '2.9.9.2',
    severity: 'critical',
    title: 'Jackson-databind polymorphic deserialization gadget',
    summary: 'With default typing enabled, crafted JSON reaches gadget classes on the classpath and executes code.',
    mobileImpact: 'If the app deserializes any server-controlled JSON with default typing on, a compromised or spoofed endpoint reaches remote code execution inside the app process.',
    cwe: 'CWE-502',
  },
  {
    coordinate: 'com.google.code.gson:gson',
    id: 'CVE-2022-25647',
    introduced: '2.0',
    fixed: '2.8.9',
    severity: 'high',
    title: 'Gson deserialization of untrusted data',
    summary: 'Gson before 2.8.9 is vulnerable to deserialization of untrusted data via writeReplace.',
    mobileImpact: 'Gson parses API responses in a very large share of Android apps; a hostile response can reach unintended object construction.',
    cwe: 'CWE-502',
  },
  {
    coordinate: 'org.bouncycastle:bcprov-jdk15on',
    id: 'CVE-2023-33201',
    introduced: '1.0',
    fixed: '1.74',
    severity: 'medium',
    title: 'Bouncy Castle LDAP injection in certificate path validation',
    summary: 'A crafted certificate can inject into an LDAP query during CRL lookup.',
    mobileImpact: 'Only reachable where the app performs its own certificate path validation against an LDAP CRL, which is rare on mobile but severe where present.',
    cwe: 'CWE-90',
  },
  {
    coordinate: 'org.bouncycastle:bcprov-jdk15on',
    id: 'CVE-2020-28052',
    introduced: '1.0',
    fixed: '1.67',
    severity: 'high',
    title: 'Bouncy Castle OpenBSDBCrypt password check bypass',
    summary: 'OpenBSDBCrypt.checkPassword compared incorrectly, so some wrong passwords were accepted.',
    mobileImpact: 'Any local credential check built on this routine can be passed without the right password.',
    cwe: 'CWE-287',
  },
  {
    coordinate: 'net.lingala.zip4j:zip4j',
    id: 'CVE-2023-43642',
    introduced: '1.0',
    fixed: '2.11.5',
    severity: 'high',
    title: 'Zip4j path traversal on extraction (Zip Slip)',
    summary: 'Archive entries with ../ segments were written outside the target directory.',
    mobileImpact: 'An app that unzips downloaded content can have arbitrary files written into its own sandbox, including into its code or configuration paths.',
    cwe: 'CWE-22',
  },
  {
    coordinate: 'commons-io:commons-io',
    id: 'CVE-2021-29425',
    introduced: '1.0',
    fixed: '2.7',
    severity: 'medium',
    title: 'Apache Commons IO path traversal in FilenameUtils.normalize',
    summary: 'normalize() accepted inputs that resolved outside the intended directory.',
    mobileImpact: 'Where used to sanitise a filename from a server or an Intent, the sanitisation can be bypassed.',
    cwe: 'CWE-22',
  },
  {
    coordinate: 'org.apache.commons:commons-compress',
    id: 'CVE-2021-36090',
    introduced: '1.0',
    fixed: '1.21',
    severity: 'medium',
    title: 'Commons Compress denial of service on crafted archives',
    summary: 'A crafted ZIP causes excessive memory allocation.',
    mobileImpact: 'An app that processes downloaded archives can be made to exhaust memory and be killed.',
    cwe: 'CWE-400',
  },
  {
    coordinate: 'androidx.core:core',
    id: 'CVE-2024-40651',
    introduced: '1.0.0',
    fixed: '1.13.1',
    severity: 'medium',
    title: 'AndroidX Core FileProvider path traversal',
    summary: 'A crafted content URI could escape the configured provider paths.',
    mobileImpact: 'Another app can read files from your sandbox through your own FileProvider.',
    cwe: 'CWE-22',
  },
  {
    coordinate: 'com.google.android.gms:play-services-basement',
    id: 'CVE-2022-2390',
    introduced: '1.0',
    fixed: '18.0.1',
    severity: 'medium',
    title: 'Play Services basement intent redirection',
    summary: 'An exported component forwarded an attacker-supplied Intent without validation.',
    mobileImpact: 'Another app can pivot through your process to reach components it could not otherwise start, with your permissions.',
    cwe: 'CWE-926',
  },
  {
    coordinate: 'io.netty:netty-codec-http',
    id: 'CVE-2021-21290',
    introduced: '4.0.0',
    fixed: '4.1.59',
    severity: 'medium',
    title: 'Netty writes temporary files with insecure permissions',
    summary: 'Multipart uploads were buffered to world-readable temporary files.',
    mobileImpact: 'On Android the temp directory is shared on older API levels, so buffered request bodies can be read by other apps.',
    cwe: 'CWE-378',
  },
  {
    coordinate: 'org.jetbrains.kotlin:kotlin-stdlib',
    id: 'CVE-2022-24329',
    introduced: '1.0.0',
    fixed: '1.6.0',
    severity: 'low',
    title: 'Kotlin stdlib does not lock dependency versions',
    summary: 'Builds could resolve a dependency from an unintended repository.',
    mobileImpact: 'A build-time supply-chain concern rather than a runtime one; relevant when auditing how the artifact was produced.',
    cwe: 'CWE-829',
  },
];

/**
 * Compares two dotted version strings.
 *
 * Numeric segments compare numerically so `1.10.0 > 1.9.0`, which a string
 * compare gets backwards. A trailing qualifier (`-alpha01`, `.1`) is compared
 * lexically after the numeric parts, which is enough ordering for range
 * membership and does not pretend to implement full semver precedence.
 */
export function compareVersions(a: string, b: string): number {
  const normalise = (v: string) => v.replace(/^v/i, '').split(/[.\-+_]/);
  const left = normalise(a);
  const right = normalise(b);

  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    const l = left[i] ?? '0';
    const r = right[i] ?? '0';
    const ln = Number(l);
    const rn = Number(r);

    if (Number.isFinite(ln) && Number.isFinite(rn) && l !== '' && r !== '') {
      if (ln !== rn) return ln < rn ? -1 : 1;
      continue;
    }
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

/** Advisories that apply to a resolved coordinate and version. */
export function advisoriesFor(coordinate: string, version: string): Advisory[] {
  return ADVISORIES.filter((advisory) => {
    if (advisory.coordinate !== coordinate) return false;
    if (advisory.introduced && compareVersions(version, advisory.introduced) < 0) return false;
    if (advisory.fixed === null) return true;
    return compareVersions(version, advisory.fixed) < 0;
  });
}

/** Coordinates this advisory set knows about, for the coverage note. */
export function coveredCoordinates(): string[] {
  return [...new Set(ADVISORIES.map((a) => a.coordinate))].sort();
}
