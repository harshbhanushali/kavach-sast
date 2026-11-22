/**
 * Attack chains: the findings of one scan, read as paths.
 *
 * A finding says one thing is wrong. The question a reviewer actually has is which of those things are wrong
 * *together*: an exported content provider is a medium on its own, a SQL string built from input is a medium
 * on its own, and a provider whose own query is built from input is a way into the database. Each chain here
 * is a short list of links (how an attacker gets in, the flaw they use, what makes it worse) with a rule for
 * which findings fill each one. A chain exists only when every required link is filled, so a lone finding
 * never produces one and a chain is never padded.
 *
 * Three things keep this honest:
 *
 * - **It is derived, never scored.** Chains are computed from the findings already in the scan and add
 *   nothing to the score or the grade; they are a way of reading what is there. They are also computed on
 *   read for scans stored before this existed, which is why this takes a scan and not a scanner's raw hits.
 * - **Static analysis cannot prove a path is reachable.** A chain is `possible` when its parts are merely in
 *   the same app. It is `likely`, and one level more severe, only when the entry point and the flaw sit in
 *   the same class, which is the closest a pattern scanner gets to "this component runs that code".
 * - **Absence is evidence only where the scan looked.** "No signature self-check" is a link only because the
 *   scanner has a rule for it and found none; it is read from the list of things done right, never guessed.
 */
import { SAST_SEVERITIES, SAST_SEVERITY_RANK } from './types.ts';
import type { AttackChain, ChainItem, ChainLink, SastFinding, SastScan, SastSeverity } from './types.ts';

/** What a chain needs of a scan. Narrower than `SastScan`, so tests and old documents can supply it. */
export type ChainInput = Pick<SastScan, 'findings' | 'hotspots' | 'secure'> & {
  domains?: SastScan['domains'];
  artifact: Pick<SastScan['artifact'], 'platform'> & Partial<Pick<SastScan['artifact'], 'packageName' | 'minSdk'>>;
};

/** How many items a link carries; `total` says how many matched. */
const ITEMS_PER_LINK = 8;

type Place = { file: string; line?: number };
/** An item plus every place it matched, so the best one can be picked once the whole chain is known. */
type Hit = ChainItem & { places: Place[] };

type Slot = {
  role: ChainLink['role'];
  label: string;
  /** Defaults to true. An optional slot is shown when something fills it and ignored when nothing does. */
  required?: boolean;
  /** Findings and hotspots whose rule id is one of these (or one of these followed by `:component`). */
  rules?: string[];
  /** Facts read from the scan rather than findings. */
  facts?: (scan: ChainInput) => Hit[];
  /** Filled when none of these rules appears among the things the app does right. */
  absent?: string[];
};

type Ctx = {
  scan: ChainInput;
  /** What filled each slot, aligned with the definition's `slots`. */
  hits: Hit[][];
  /** The entry point and the flaw are in the same class. */
  colocated: boolean;
  has: (slot: number) => boolean;
  /** `Foo.java:20` for the first item of a slot, or a plain description when it has no place. */
  where: (slot: number) => string;
  /** The component named by the first item of a slot, as written in the manifest. */
  component: (slot: number) => string;
  /** Whether any item of a slot came from this rule. */
  from: (slot: number, rule: string) => boolean;
};

type Def = {
  id: string;
  title: string;
  platform: 'android' | 'ios';
  slots: Slot[];
  /** Prefer the entry point and flaw that share a class (`[entrySlot, flawSlot]`), and say so. */
  colocate?: [number, number];
  severity: (c: Ctx) => SastSeverity;
  summary: (c: Ctx) => string;
  steps: (c: Ctx) => string[];
  breakpoint: (c: Ctx) => string;
  masvs?: string;
  cwe?: string[];
};

/* ----------------------------------------------------------------- helpers */

const matches = (ruleId: string, ids: string[]) => ids.some((id) => ruleId === id || ruleId.startsWith(`${id}:`));

const bump = (s: SastSeverity, by = 1): SastSeverity =>
  SAST_SEVERITIES[Math.max(0, Math.min(SAST_SEVERITIES.length - 1, SAST_SEVERITY_RANK[s] + by))];

const short = (name: string) => name.split('.').pop() ?? name;
const componentOf = (ruleId?: string) => (ruleId && ruleId.includes(':') ? ruleId.slice(ruleId.indexOf(':') + 1) : undefined);
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Source files a class can be told apart by. A binary's string table is one file for everything, so it says nothing. */
const isClassFile = (file: string) => /\.(java|kt|smali)$/.test(file);

/**
 * A finding as a chain item, or nothing when it is in a bundled library.
 *
 * A path through okhttp's internals or AndroidX's MultiDex is not a path through the app, and a chain built
 * on one would be a confident false alarm. The score already counts a library's findings at a quarter for the
 * same reason. Only places the scan attributes to a library are dropped: code it could not attribute stays,
 * so nothing is left out on a guess.
 */
function hitFrom(f: SastFinding): Hit | null {
  if (f.origin === 'third-party') return null;
  const own = f.locations.filter((l) => l.provenance?.origin !== 'third-party');
  if (f.locations.length > 0 && own.length === 0) return null;
  const places = own.map((l) => ({ file: l.file, ...(l.line ? { line: l.line } : {}) }));
  return {
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    kind: f.kind === 'hotspot' ? 'hotspot' : 'defect',
    ...(places[0] ? { location: places[0] } : {}),
    places,
  };
}

/**
 * Whether code at `place` is in the class `component` (a manifest name such as `com.foo.Bar`).
 * `com/foo/Bar.java`, `com/foo/Bar$1.java` and `smali/com/foo/Bar.smali` all count; `com/foo/BarBaz.java` does not.
 */
function inClass(place: Place, component: string): boolean {
  if (!isClassFile(place.file)) return false;
  return new RegExp(`${escapeRe(component.replace(/\./g, '/'))}(?:[.$]|$)`).test(place.file);
}

/**
 * Moves the entry point and the flaw that share a class to the front of their slots, and points the flaw's
 * location at the shared code. Returns whether such a pair exists.
 */
function preferColocated(entries: Hit[], flaws: Hit[]): boolean {
  for (const [ei, entry] of entries.entries()) {
    const component = componentOf(entry.ruleId);
    if (!component) continue;
    for (const [fi, flaw] of flaws.entries()) {
      const place = flaw.places.find((p) => inClass(p, component));
      if (!place) continue;
      entries.unshift(...entries.splice(ei, 1));
      flaws.unshift(...flaws.splice(fi, 1));
      flaws[0] = { ...flaws[0], location: place };
      return true;
    }
  }
  return false;
}

/** Two findings in the same decompiled file: the weakest honest form of "the same code". */
function preferSameFile(a: Hit[], b: Hit[]): boolean {
  for (const [ai, x] of a.entries()) {
    for (const [bi, y] of b.entries()) {
      const place = y.places.find((p) => isClassFile(p.file) && x.places.some((q) => q.file === p.file));
      if (!place) continue;
      a.unshift(...a.splice(ai, 1));
      b.unshift(...b.splice(bi, 1));
      b[0] = { ...b[0], location: place };
      return true;
    }
  }
  return false;
}

/** The hosts a network attacker would be reading: production ones when the scan can tell, otherwise any non-local HTTPS host. */
function httpsHosts(scan: ChainInput): Hit[] {
  const rows = (scan.domains ?? []).filter((d) => d.schemes.includes('https') && d.environment !== 'local');
  const production = rows.filter((d) => d.environment === 'production');
  return (production.length > 0 ? production : rows).map((d) => ({ title: d.host, kind: 'fact' as const, places: [] }));
}

/** Production hosts the app reaches over plain HTTP. */
function cleartextHosts(scan: ChainInput): Hit[] {
  return (scan.domains ?? [])
    .filter((d) => d.cleartext && d.environment === 'production')
    .map((d) => ({ title: d.host, kind: 'fact' as const, places: [] }));
}

/** `minSdkVersion` when it is low enough for a device with the Janus flaw (Android 5.0 to 8.0, API 21-26) to install the app. */
function janusExposure(scan: ChainInput): Hit[] {
  const sdk = Number.parseInt(scan.artifact.minSdk ?? '', 10);
  return Number.isFinite(sdk) && sdk <= 26
    ? [{ title: `minSdkVersion ${sdk}: installs on Android 5.0 to 8.0`, kind: 'fact', places: [] }]
    : [];
}

/**
 * The entry point, as the first step of a story. When the flaw is in that component's own class it is named;
 * otherwise the story would be claiming a link the scan did not find, so it says how many are exposed.
 */
const entryName = (c: Ctx, slot: number) => {
  const first = componentOf(c.hits[slot][0]?.ruleId) ?? c.hits[slot][0]?.title ?? 'a component';
  const n = c.hits[slot].length;
  return c.colocated || n === 1 ? first : `one of the ${n} exported components (${short(first)} is one)`;
};

const EXPORTED = [
  'manifest.exported_activity',
  'manifest.exported_activity_alias',
  'manifest.exported_service',
  'manifest.exported_receiver',
  'manifest.exported_provider',
];

const entryReach = (rules: string[]): Slot => ({ role: 'entry', label: 'Reachable by any other app on the device', rules });

/* ------------------------------------------------------------- the catalogue */

const DEFS: Def[] = [
  {
    id: 'chain.intent_to_command',
    title: 'A crafted Intent runs a command as the app',
    platform: 'android',
    slots: [
      entryReach(EXPORTED),
      { role: 'weakness', label: 'An operating-system command is built from outside input', rules: ['code.command_injection'] },
    ],
    colocate: [0, 1],
    severity: () => 'critical',
    summary: () => 'Another app on the device runs operating-system commands with this app\'s identity.',
    steps: (c) => [
      `A malicious app on the same device sends ${entryName(c, 0)} an Intent it has written.`,
      `The app builds an operating-system command from data that came in from outside (${c.where(1)}).`,
      'The command runs as this app: its files, its permissions, its network access.',
    ],
    breakpoint: (c) =>
      `Set android:exported="false" on ${short(c.component(0))}. If it has to stay public, require a signature-level permission and stop building commands from Intent data.`,
    masvs: 'MASVS-CODE-4',
    cwe: ['CWE-78'],
  },
  {
    id: 'chain.provider_sql_injection',
    title: 'An exported provider is open to SQL injection',
    platform: 'android',
    slots: [
      { role: 'entry', label: 'A content provider any app can query', rules: ['manifest.exported_provider'] },
      { role: 'weakness', label: 'SQL is built from outside input', rules: ['code.sql_injection', 'code.sql_concatenation'] },
      { role: 'amplifier', label: 'The database holds sensitive columns', required: false, rules: ['storage.sensitive_in_sqlite'] },
    ],
    colocate: [0, 1],
    severity: (c) => (c.has(2) ? 'critical' : 'high'),
    summary: () => 'Another app reads, or rewrites, rows it was never meant to see.',
    steps: (c) => [
      `A malicious app queries the content:// address of ${entryName(c, 0)} with a selection of its own choosing.`,
      `What the caller sends reaches an SQL statement without being bound as a parameter (${c.where(1)}), so it becomes part of the SQL.`,
      c.has(2)
        ? 'It reads other tables and columns, including the sensitive ones the database keeps in the clear.'
        : 'It reads other tables and columns, or changes them.',
    ],
    breakpoint: (c) =>
      `Pass the selection to the query as bound arguments (? placeholders) at ${c.where(1)}, and set android:exported="false" on ${short(c.component(0))} if nothing outside the app needs it.`,
    masvs: 'MASVS-PLATFORM-1',
    cwe: ['CWE-89'],
  },
  {
    id: 'chain.provider_file_exposure',
    title: 'An exported provider hands out the app\'s private files',
    platform: 'android',
    slots: [
      { role: 'entry', label: 'A content provider any app can reach', rules: ['manifest.exported_provider'] },
      {
        role: 'weakness',
        label: 'Paths are not confined to a safe folder',
        rules: ['code.path_traversal', 'storage.fileprovider_overbroad', 'manifest.provider_grant_uri'],
      },
    ],
    colocate: [0, 1],
    severity: () => 'critical',
    summary: () => 'Another app reads files from the app\'s private storage: databases, preferences, tokens.',
    steps: (c) => [
      `A malicious app opens a content:// address on ${entryName(c, 0)} and puts ../ in the path.`,
      `The provider resolves it without keeping it inside one folder (${c.where(1)}).`,
      'The attacker reads files from the app\'s private directory that no other app can normally open.',
    ],
    breakpoint: (c) =>
      `Resolve the requested path, check it still sits under the folder you meant to share, and narrow the paths you declare. Set android:exported="false" on ${short(c.component(0))} if it does not need to be public.`,
    masvs: 'MASVS-PLATFORM-1',
    cwe: ['CWE-22'],
  },
  {
    id: 'chain.intent_redirection',
    title: 'An exported component starts whatever Intent it is handed',
    platform: 'android',
    slots: [
      entryReach(EXPORTED.filter((id) => id !== 'manifest.exported_provider')),
      { role: 'weakness', label: 'An Intent taken from an Intent is started', rules: ['code.intent_redirection'] },
      { role: 'amplifier', label: 'A mutable PendingIntent is also in use', required: false, rules: ['code.mutable_pending_intent'] },
    ],
    colocate: [0, 1],
    severity: (c) => (c.has(2) ? 'critical' : 'high'),
    summary: () => 'Another app reaches screens and data that were kept private to this app.',
    steps: (c) => [
      `A malicious app sends ${entryName(c, 0)} an Intent that carries a second Intent inside it.`,
      `The app starts the inner Intent with its own identity (${c.where(1)}).`,
      'The attacker reaches components that are not exported, or gets a URI permission over the app\'s files.',
    ],
    breakpoint: (c) =>
      `Do not start an Intent that came from outside. If you must, check it resolves to a component you own and clear its flags. Or set android:exported="false" on ${short(c.component(0))}.`,
    masvs: 'MASVS-PLATFORM-1',
  },
  {
    id: 'chain.deeplink_webview',
    title: 'A web link loads attacker content into the app\'s WebView',
    platform: 'android',
    slots: [
      { role: 'entry', label: 'Opened from a web link, a message or a QR code', rules: ['manifest.browsable_deeplink'] },
      { role: 'weakness', label: 'The WebView loads a URL that came from outside', rules: ['code.webview_untrusted_url', 'code.webview_dynamic_url'] },
      { role: 'weakness', label: 'JavaScript runs in that WebView', rules: ['code.webview_js_enabled'] },
      { role: 'amplifier', label: 'JavaScript can call into the app', required: false, rules: ['code.webview_js_interface'] },
      { role: 'amplifier', label: 'The page can read local files', required: false, rules: ['code.webview_file_access_enabled'] },
    ],
    severity: (c) => ((c.has(3) || c.has(4)) && c.from(1, 'code.webview_untrusted_url') ? 'critical' : 'high'),
    summary: (c) =>
      c.has(3) || c.has(4)
        ? 'A page the attacker controls runs inside the app and reaches its code or its files.'
        : 'A page the attacker controls runs JavaScript inside the app.',
    steps: (c) => [
      'The attacker gets a link in front of the user: a web page, a message, a QR code.',
      `Android opens the app on that link (${short(c.component(0)) || 'a browsable activity'}).`,
      `The app passes what the link carried to a WebView (${c.where(1)}), with JavaScript on (${c.where(2)}).`,
      ...(c.has(3) ? [`The page calls the exposed JavaScript bridge (${c.where(3)}) and reaches the app's own functions.`] : []),
      ...(c.has(4) ? [`The page reads local files through file:// (${c.where(4)}).`] : []),
    ],
    breakpoint: (c) =>
      `Check the host of the URL against an allow-list before it reaches the WebView at ${c.where(1)}, and refuse anything else.`,
    masvs: 'MASVS-PLATFORM-2',
    cwe: ['CWE-939'],
  },
  {
    id: 'chain.tls_intercept',
    title: 'Anyone on the network can read the app\'s HTTPS traffic',
    platform: 'android',
    slots: [
      {
        role: 'weakness',
        label: 'Certificate checks are switched off',
        rules: [
          'net.trust_manager_accepts_all',
          'net.hostname_verifier_disabled',
          'net.ssl_socket_factory_insecure',
          'net.webview_ignore_ssl',
        ],
      },
      { role: 'impact', label: 'Hosts the app talks to over HTTPS', facts: httpsHosts },
      { role: 'amplifier', label: 'No pinning as a second line of defence', required: false, rules: ['manifest.no_pinning'] },
    ],
    severity: (c) => (c.from(0, 'net.trust_manager_accepts_all') ? 'critical' : 'high'),
    summary: () => 'A person on the same network reads and rewrites traffic the app believes is private.',
    steps: (c) => [
      'The attacker joins the same Wi-Fi, or runs a rogue hotspot, and sits between the phone and the server.',
      `The app is asked to trust a certificate that was never issued for ${c.hits[1][0]?.title ?? 'the server'}, and accepts it (${c.where(0)}).`,
      'Requests, credentials and tokens pass through in the clear, and responses can be changed on the way back.',
    ],
    breakpoint: (c) =>
      `Remove the permissive check at ${c.where(0)} so the platform validates the certificate, then pin the certificate for ${c.hits[1][0]?.title ?? 'your servers'}.`,
    masvs: 'MASVS-NETWORK-1',
    cwe: ['CWE-295'],
  },
  {
    id: 'chain.cleartext_traffic',
    title: 'The app sends data over plain HTTP, and allows it to',
    platform: 'android',
    slots: [
      {
        role: 'weakness',
        label: 'The app permits cleartext traffic',
        rules: ['manifest.cleartext_traffic', 'manifest.nsc_cleartext', 'manifest.cleartext_default'],
      },
      { role: 'weakness', label: 'The code uses http:// addresses', rules: ['net.cleartext_url', 'net.cleartext_scheme_prefix'] },
      { role: 'impact', label: 'Production hosts reached over HTTP', required: false, facts: cleartextHosts },
    ],
    severity: (c) => (c.has(2) ? 'high' : 'medium'),
    summary: () => 'Anyone on the path can read, or change, what these requests carry.',
    steps: (c) => [
      `The app requests an http:// address (${c.where(1)}).`,
      `Its configuration allows that (${c.where(0)}), so Android does not stop it.`,
      c.has(2)
        ? `Anyone on the path to ${c.hits[2][0].title} reads the request and the response, and can alter either.`
        : 'Anyone on the path reads the request and the response, and can alter either.',
    ],
    breakpoint: (c) =>
      `Serve ${c.has(2) ? c.hits[2][0].title : 'these endpoints'} over HTTPS and turn cleartext off (usesCleartextTraffic="false", or cleartextTrafficPermitted="false" in the network security config).`,
    masvs: 'MASVS-NETWORK-1',
    cwe: ['CWE-319'],
  },
  {
    id: 'chain.local_data_extraction',
    title: 'App data can be copied off the device, and it is not protected',
    platform: 'android',
    slots: [
      { role: 'entry', label: 'The app\'s data can be pulled off the device', rules: ['manifest.allow_backup', 'manifest.debuggable'] },
      {
        role: 'weakness',
        label: 'Sensitive values are stored in plain files',
        rules: ['storage.sensitive_in_preferences', 'storage.sensitive_in_sqlite'],
      },
      { role: 'amplifier', label: 'Files are open to other apps as well', required: false, rules: ['code.world_accessible_file', 'code.file_world_permissions'] },
    ],
    severity: (c) => (c.from(0, 'manifest.debuggable') ? 'high' : 'medium'),
    summary: () => 'Someone with the phone, a cable or a backup reads what the app stored.',
    steps: (c) => [
      c.from(0, 'manifest.debuggable')
        ? `The attacker connects a cable and runs: adb shell run-as ${c.scan.artifact.packageName ?? '<package>'}. A debuggable app gives its whole data folder to the shell.`
        : `The attacker takes a backup of the app (adb backup, or a device-to-device or cloud restore) because ${c.where(0)} allows it.`,
      `They open shared_prefs and databases (${c.hits[1].slice(0, 2).map((h) => h.title).join('; ')}).`,
      'Nothing is encrypted, so the values are readable as they are.',
    ],
    breakpoint: (c) =>
      c.from(0, 'manifest.debuggable')
        ? 'Ship with android:debuggable off, and keep sensitive values in the Android Keystore or an encrypted store rather than in plain preferences or tables.'
        : 'Set android:allowBackup="false" (or exclude those files in the data extraction rules), and keep sensitive values in the Android Keystore or an encrypted store.',
    masvs: 'MASVS-STORAGE-1',
    cwe: ['CWE-312'],
  },
  {
    id: 'chain.writable_code_loading',
    title: 'The app loads code from a place other apps can write to',
    platform: 'android',
    slots: [
      { role: 'entry', label: 'Code is loaded at runtime', rules: ['code.dynamic_dex_load', 'code.package_context_code_loading'] },
      {
        role: 'weakness',
        label: 'Files are written where other apps can reach them',
        rules: ['code.external_storage_write', 'code.world_accessible_file', 'code.file_world_permissions', 'storage.zip_slip'],
      },
    ],
    colocate: [0, 1],
    severity: () => 'critical',
    summary: () => 'Another app swaps in its own code, which then runs with this app\'s permissions.',
    steps: (c) => [
      `The app loads code at runtime (${c.where(0)}).`,
      `It also keeps files somewhere other apps, or the user, can change (${c.where(1)}).`,
      'A malicious app replaces the file before it is loaded, and its code runs inside this app.',
    ],
    breakpoint: (c) =>
      `Load code only from app-private storage (getCodeCacheDir), make the file read-only before loading it, and verify its signature. Stop writing to ${c.where(1)}.`,
    masvs: 'MASVS-CODE-4',
    cwe: ['CWE-829'],
  },
  {
    id: 'chain.debug_signing_repackage',
    title: 'Anyone can re-sign a modified copy of the app as its own',
    platform: 'android',
    slots: [
      { role: 'weakness', label: 'Signed with the public Android debug key', rules: ['signing.debug_certificate'] },
      { role: 'amplifier', label: 'No signature self-check found', required: false, absent: ['android.signature_check'] },
      { role: 'amplifier', label: 'No device or app attestation found', required: false, absent: ['android.device_attestation'] },
    ],
    severity: (c) => (c.has(1) && c.has(2) ? 'critical' : 'high'),
    summary: () => 'A tampered build is signed with the same key, installs as the real app, and nothing in the app notices.',
    steps: (c) => [
      'The attacker downloads the APK, adds malware or removes a check, and rebuilds it.',
      'They sign it with the Android debug key, which is the same on every developer machine and is public.',
      c.has(1) && c.has(2)
        ? 'The app has no signature check and no attestation, so it cannot tell the copy from the original.'
        : c.has(2)
          ? 'The app\'s own signature check compares against a key the attacker is also using, and nothing off the device vouches for the build.'
          : c.has(1)
            ? 'Nothing in the app checks which key it was signed with.'
            : 'The copy installs as a build signed by the same key.',
    ],
    breakpoint: () =>
      'Sign release builds with a private key kept off developer machines. Add a signature check or Play Integrity so a repackaged copy is noticed.',
    masvs: 'MASVS-RESILIENCE-2',
    cwe: ['CWE-347'],
  },
  {
    id: 'chain.janus_repackage',
    title: 'A v1-only signature can be bypassed on older Android versions',
    platform: 'android',
    slots: [
      { role: 'weakness', label: 'Signed with the v1 scheme only', rules: ['signing.v1_only'] },
      { role: 'entry', label: 'Installs on Android versions with the Janus flaw', facts: janusExposure },
      { role: 'amplifier', label: 'No signature self-check found', required: false, absent: ['android.signature_check'] },
    ],
    severity: (c) => (c.has(2) ? 'high' : 'medium'),
    summary: () => 'A modified build passes signature verification on Android 5.0 to 8.0 and installs as an update.',
    steps: () => [
      'On Android 5.0 to 8.0 an APK can carry extra DEX code in front of its ZIP data, and the v1 check never looks at it (CVE-2017-13156, "Janus").',
      'The attacker prepends their own DEX to the genuine APK. The v1 signature still verifies.',
      'The device installs it over the real app, and the attacker\'s code runs with the app\'s permissions.',
    ],
    breakpoint: () => 'Sign with v2 or later as well, and raise minSdkVersion above 26 when the app no longer needs to support those versions.',
    masvs: 'MASVS-RESILIENCE-2',
    cwe: ['CWE-347'],
  },
  {
    id: 'chain.ios_tls_intercept',
    title: 'Anyone on the network can read the app\'s HTTPS traffic',
    platform: 'ios',
    slots: [
      { role: 'weakness', label: 'Certificate checks are switched off', rules: ['net.ios_cert_validation_disabled'] },
      { role: 'impact', label: 'Hosts the app talks to over HTTPS', facts: httpsHosts },
      {
        role: 'amplifier',
        label: 'App Transport Security is relaxed as well',
        required: false,
        rules: ['ios.ats_arbitrary_loads', 'ios.ats_insecure_domain', 'ios.ats_webcontent'],
      },
    ],
    severity: () => 'critical',
    summary: () => 'A person on the same network reads and rewrites traffic the app believes is private.',
    steps: (c) => [
      'The attacker joins the same Wi-Fi, or runs a rogue hotspot, and sits between the phone and the server.',
      `The app is shown a certificate that was never issued for ${c.hits[1][0]?.title ?? 'the server'}, and accepts it.`,
      c.has(2)
        ? 'App Transport Security is relaxed too, so plain HTTP to those hosts goes through as well.'
        : 'Requests, credentials and tokens pass through in the clear.',
    ],
    breakpoint: (c) =>
      `Remove the code that accepts any server trust, so the system validates the certificate, then pin the certificate for ${c.hits[1][0]?.title ?? 'your servers'}.`,
    masvs: 'MASVS-NETWORK-1',
    cwe: ['CWE-295'],
  },
  {
    id: 'chain.ios_scheme_webview',
    title: 'Another app can drive a web view through the URL scheme',
    platform: 'ios',
    slots: [
      { role: 'entry', label: 'A URL handler acts on what another app sends', rules: ['ios.url_scheme_handler'] },
      { role: 'amplifier', label: 'A custom URL scheme is registered', required: false, rules: ['ios.custom_url_scheme'] },
      { role: 'weakness', label: 'JavaScript is enabled in a web view', rules: ['code.ios_webview_js'] },
    ],
    severity: () => 'medium',
    summary: () => 'A link, or another app, makes the app load content the attacker chose.',
    steps: () => [
      'The attacker sends the user a link that uses the app\'s URL scheme, or opens it from another app.',
      'The URL handler acts on what the link carries.',
      'If that reaches the web view, the attacker\'s page runs JavaScript inside the app.',
    ],
    breakpoint: () =>
      'Validate the URL handler\'s input against an allow-list before anything is loaded, and prefer universal links, which another app cannot claim.',
    masvs: 'MASVS-PLATFORM-1',
    cwe: ['CWE-939'],
  },
  {
    id: 'chain.ios_local_data',
    title: 'Files shared with the Files app are not encrypted at rest',
    platform: 'ios',
    slots: [
      { role: 'entry', label: 'The Documents folder is shared with iTunes and the Files app', rules: ['ios.file_sharing'] },
      {
        role: 'weakness',
        label: 'Data is written without protection',
        rules: [
          'ios.no_file_protection',
          'ios.sqlite_unencrypted',
          'ios.embedded_database_unencrypted',
          'ios.coredata_unencrypted',
          'ios.sensitive_file_write',
        ],
      },
    ],
    severity: () => 'medium',
    summary: () => 'Someone with the phone and a cable copies out data the app did not protect.',
    steps: () => [
      'The attacker connects the unlocked phone to a computer, or opens the Files app on it.',
      'File sharing exposes the app\'s Documents folder.',
      'Databases and files written without data protection or encryption are readable as they are.',
    ],
    breakpoint: () =>
      'Turn UIFileSharingEnabled off unless users need it, and write sensitive data with complete file protection or into an encrypted store.',
    masvs: 'MASVS-STORAGE-1',
    cwe: ['CWE-312'],
  },
];

/** What the catalogue holds, for tests and for anything that wants to list the chains the scanner knows. */
export const CHAIN_CATALOGUE = DEFS.map(({ id, title, platform }) => ({ id, title, platform }));

/* -------------------------------------------------------------------- engine */

export function chainsOf(scan: ChainInput): AttackChain[] {
  const pool = [...scan.findings, ...scan.hotspots].filter((f) => f.kind !== 'secure');
  const done = new Set(scan.secure.map((f) => f.ruleId));
  const found: { chain: AttackChain; order: number }[] = [];

  for (const [order, def] of DEFS.entries()) {
    if (def.platform !== scan.artifact.platform) continue;

    // What fills each slot. A required slot with nothing in it ends the chain here.
    const hits: Hit[][] = [];
    const satisfied: boolean[] = [];
    let complete = true;
    for (const slot of def.slots) {
      const required = slot.required !== false;
      let filled: Hit[] = [];
      let ok: boolean;
      if (slot.absent) {
        ok = !slot.absent.some((id) => done.has(id));
      } else {
        filled = slot.facts ? slot.facts(scan) : pool.filter((f) => matches(f.ruleId, slot.rules ?? [])).map(hitFrom).filter((h): h is Hit => h !== null);
        ok = filled.length > 0;
      }
      hits.push(filled);
      satisfied.push(ok);
      if (required && !ok) complete = false;
    }
    if (!complete) continue;

    let colocated = false;
    if (def.colocate) {
      const [a, b] = def.colocate;
      colocated = preferColocated(hits[a], hits[b]) || preferSameFile(hits[a], hits[b]);
    }

    const ctx: Ctx = {
      scan,
      hits,
      colocated,
      has: (i) => satisfied[i] && (def.slots[i].absent ? true : hits[i].length > 0),
      where: (i) => {
        const place = hits[i][0]?.location ?? hits[i][0]?.places[0];
        if (place) return place.line ? `${place.file}:${place.line}` : place.file;
        return hits[i][0]?.title ?? def.slots[i].label.toLowerCase();
      },
      component: (i) => componentOf(hits[i][0]?.ruleId) ?? '',
      from: (i, rule) => hits[i].some((h) => h.ruleId !== undefined && matches(h.ruleId, [rule])),
    };

    const links: ChainLink[] = [];
    for (const [i, slot] of def.slots.entries()) {
      if (!satisfied[i]) continue;
      const absence = slot.absent !== undefined;
      links.push({
        role: slot.role,
        label: slot.label,
        required: slot.required !== false,
        items: hits[i].slice(0, ITEMS_PER_LINK).map(({ places: _places, ...item }) => item),
        total: hits[i].length,
        ...(absence ? { absence: true } : {}),
      });
    }

    // A definition gives the severity of the path if it is real. Where the entry point and the flaw are only
    // "somewhere in the same app" rather than the same class, that is a level lower: the engine applies it, once
    // and the same way for every chain that has a notion of closeness.
    const base = def.severity(ctx);
    const severity = def.colocate && !colocated ? bump(base, -1) : base;

    found.push({
      order,
      chain: {
        id: def.id,
        title: def.title,
        severity,
        confidence: colocated ? 'likely' : 'possible',
        summary: def.summary(ctx),
        steps: def.steps(ctx),
        links,
        breakpoint: def.breakpoint(ctx),
        ...(def.masvs ? { masvs: def.masvs } : {}),
        ...(def.cwe ? { cwe: def.cwe } : {}),
      },
    });
  }

  return found
    .sort(
      (x, y) =>
        SAST_SEVERITY_RANK[y.chain.severity] - SAST_SEVERITY_RANK[x.chain.severity] ||
        Number(y.chain.confidence === 'likely') - Number(x.chain.confidence === 'likely') ||
        x.order - y.order,
    )
    .map((f) => f.chain);
}
