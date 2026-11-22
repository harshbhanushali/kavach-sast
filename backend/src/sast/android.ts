/**
 * Android static analysis.
 *
 * Structural findings live here — the ones that need a parsed manifest, a
 * signing certificate or a file listing rather than a regex over source. The
 * content rules in `rules.ts` are applied by the shared scanner; this module
 * contributes what only a parser can decide.
 *
 * The decode step reuses apktool, which the injector already depends on, so a
 * deployment that can protect an APK can also scan one. Where apktool is absent
 * the scan degrades to the zip listing plus a DEX string sweep and says so in
 * `limitations` — a partial scan that admits what it skipped is useful; one that
 * silently returns "no findings" is worse than none.
 */
import { execFileSync } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { resolveToolchain } from '../toolchain.ts';
import { DANGEROUS_PERMISSIONS, LIBRARY_SIGNATURES, rulesFor } from './rules.ts';
import { mergeFindings, scanBinaryStrings, scanFiles, walk } from './scanner.ts';
import type { LiveSink, WalkedFile } from './scanner.ts';
import { scanJavaFlow } from './javaFlow.ts';
import { analyseSmali, smaliToRead } from './smali.ts';
import { readText } from './fileCache.ts';
import { warmCache } from './prefetch.ts';
import type { ProgressSink } from './progress.ts';
import { analyseNativeLibraries } from './nativeLibs.ts';
import { readApkSignatures } from './apkSignature.ts';
import { mapSmaliLocations, mapSmaliToJava } from './javaMapping.ts';
import type { JavaFiles } from './javaMapping.ts';
import type { SignatureReport } from './apkSignature.ts';
import { binaryStub, renderElfView } from './nativeView.ts';
import { isReadable } from './sources.ts';
import { androidFactsOf, extraManifestFindings, inventoryOf, secureFindings } from './androidExtras.ts';
import { describeAll } from './permissions.ts';
import { androidIcon } from './appIcon.ts';
import { runRecon } from './recon.ts';
import { analyseDependencies } from './dependencies.ts';
import { appRoots, packageOf } from './provenance.ts';
import type { AndroidFacts, ComponentInventory, ReconSection } from './types.ts';
import type { SastFinding, SastLocation } from './types.ts';
import { attr, findAll, findFirst, parseXml } from './xml.ts';
import type { XmlNode } from './xml.ts';

export type AndroidAnalysis = {
  findings: SastFinding[];
  /** The manifest as structure, and the launcher icon; see `AndroidFacts`. */
  android?: AndroidFacts;
  iconDataUrl?: string;
  /** Entries in the APK archive. */
  fileCount?: number;
  /** Which decompiler produced the code snippets. */
  decompiler: 'java' | 'smali' | 'none';
  /**
   * The directories a finding's path is relative to.
   *
   * Surfaced so the caller can retain the referenced sources before the working
   * directory is deleted. Nothing else uses them.
   */
  sourceRoots: (string | undefined)[];
  /** Readable renderings of binary files, written at those files' own paths; see `collectSources`. */
  syntheticRoot?: string;
  javaFileCount: number;
  dependencies: { coordinate: string; version: string; source: string; advisoryCount: number }[];
  secure: SastFinding[];
  hotspots: SastFinding[];
  recon: ReconSection;
  components: ComponentInventory;
  permissionDetail: { name: string; level: string; description: string }[];
  nativeLibraryDetail: {
    name: string; pie: boolean; nx: boolean; stackCanary: boolean;
    relro: 'full' | 'partial' | 'none'; symbolsStripped: boolean; fortified: boolean;
  }[];
  /**
   * How many native libraries were actually read as ELF.
   *
   * Carried out so the scorecard can tell "seven hardening rules looked and
   * found nothing" apart from "this app ships no native code, so nothing
   * looked" — which must not render as a pass.
   */
  nativeInspected: number;
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  permissions: string[];
  signers: string[];
  signatureSchemes: string[];
  nativeLibraries: string[];
  detectedLibraries: string[];
  limitations: string[];
};

const COMPONENT_TAGS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'] as const;

/** True when the network security config declares at least one certificate pin. */
function manifestDeclaresPinning(manifest: XmlNode, decodedRoot: string): boolean {
  const application = findFirst(manifest, 'application');
  const ref = application ? attr(application, 'networkSecurityConfig') : undefined;
  if (!ref) return false;
  const path = join(decodedRoot, 'res', 'xml', `${ref.replace(/^@xml\//, '')}.xml`);
  if (!existsSync(path)) return false;
  try {
    return findAll(parseXml(readFileSync(path, 'utf8')), 'pin').length > 0;
  } catch {
    return false;
  }
}

function soEntriesPresent(entries: string[]): boolean {
  return entries.some((e) => /^lib\/[^/]+\/.+\.so$/.test(e));
}

/**
 * Runs a tool with the toolchain's JAVA_HOME on the environment.
 *
 * apktool and apksigner are shell wrappers around JARs. Without JAVA_HOME they
 * exit with "Unable to locate a Java Runtime" on a machine whose system Java is
 * only the Apple stub — which is every stock macOS. The injector already passes
 * it for the same reason.
 */
function run(command: string, args: string[], timeoutMs = 240_000): string {
  return execFileSync(command, args, {
    timeout: timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, JAVA_HOME: resolveToolchain().javaHome ?? process.env.JAVA_HOME ?? '' },
  }).toString();
}

/**
 * Whether a component is reachable from other apps.
 *
 * The rule changed at API 31: before it, a component with an intent-filter
 * defaulted to exported; from 31 the attribute is mandatory when a filter is
 * present. Both cases are treated as exported here, because the question the
 * report answers is "can another app reach this", and an unset attribute on an
 * older target means yes.
 */
function isExported(node: XmlNode): boolean {
  const explicit = attr(node, 'exported');
  if (explicit !== undefined) return explicit === 'true';
  return findAll(node, 'intent-filter').length > 0;
}

/** A component is protected if it demands a permission to reach it. */
function hasPermission(node: XmlNode): boolean {
  return attr(node, 'permission') !== undefined || attr(node, 'readPermission') !== undefined;
}

/**
 * Components that only ever receive system broadcasts or the launcher intent
 * are exported by necessity, not by mistake.
 */
function isSystemFacing(node: XmlNode): boolean {
  const actions = findAll(node, 'action')
    .map((a) => attr(a, 'name') ?? '')
    .filter(Boolean);
  if (actions.length === 0) return false;
  return actions.every(
    (a) =>
      a.startsWith('android.intent.action.MAIN') ||
      a.startsWith('android.intent.action.BOOT_COMPLETED') ||
      a.startsWith('com.google.android.c2dm') ||
      a.startsWith('com.google.firebase') ||
      a.startsWith('android.media.action') ||
      a.startsWith('android.appwidget.action'),
  );
}

/**
 * A location pointing at the element that caused a finding.
 *
 * Findings used to carry the bare filename, which left a reviewer scrolling a
 * few hundred lines of generated manifest to find the attribute in question.
 * The line and the verbatim tag remove that step.
 */
function at(node: XmlNode, note?: string): { file: string; line: number; excerpt: string } {
  // A generated <application> tag carries a dozen attributes and wraps to
  // twelve lines in the report, which buries the one attribute that matters.
  // Long tags collapse to the element name plus the attribute being reported.
  const tag = node.raw.length > MAX_RAW
    ? `<${node.name} \u2026${nameAttribute(node)}>`
    : node.raw;
  return {
    file: 'AndroidManifest.xml',
    line: node.line,
    excerpt: note ? `${tag}   \u2190 ${note}` : tag,
  };
}

/** minSdkVersion from the manifest, falling back to what apktool recorded. */
function minSdkOf(manifest: XmlNode, fromYml?: string): string | undefined {
  const usesSdk = findFirst(manifest, 'uses-sdk');
  return (usesSdk ? attr(usesSdk, 'minSdkVersion') : undefined) ?? fromYml;
}

function targetSdkOf(manifest: XmlNode, fromYml?: string): string | undefined {
  const usesSdk = findFirst(manifest, 'uses-sdk');
  return (usesSdk ? attr(usesSdk, 'targetSdkVersion') : undefined) ?? fromYml;
}

/** `android:name="..."` if present, since it is what identifies the element. */
function nameAttribute(node: XmlNode): string {
  const name = attr(node, 'name');
  return name ? ` android:name="${name}"` : '';
}

const MAX_RAW = 110;

/**
 * Native libraries swept for secrets.
 *
 * Bounded: an app can ship the same library for four ABIs plus a large game
 * engine, and sweeping every one multiplies the work without adding coverage.
 */
const MAX_NATIVE_SWEEP = 12;

/**
 * The concrete route into an exported component.
 *
 * Written as the commands someone would run, because "reachable by other apps"
 * is abstract and `adb shell am start -n ...` is not. Everything here needs only
 * adb or a twenty-line app — no root, no exploit.
 */
function exploitFor(tag: string, name: string, actions: string[], schemes: string[]): string[] {
  const viaAdb = (cmd: string) => `Anyone with adb access reaches it directly: ${cmd}`;
  const viaApp = 'A malicious app installed alongside yours does the same thing with no adb and no prompt, because no permission guards it.';

  switch (tag) {
    case 'provider':
      return [
        viaAdb(`adb shell content query --uri content://<authority>`),
        'The same URI accepts insert, update and delete, so the data behind this provider can be read, altered or destroyed by any other app.',
        'If the provider serves files, a crafted URI with ../ segments often walks outside the intended directory and reads other files in the sandbox.',
        viaApp,
      ];
    case 'service':
      return [
        viaAdb(`adb shell am startservice -n <package>/${name}`),
        'A malicious app can also bind to it and call the methods the service exposes, running that code inside your process with your permissions.',
        'Any extra the service reads from the Intent is attacker-chosen, so logic that assumes the caller is your own app is not protected.',
      ];
    case 'receiver':
      return [
        viaAdb(`adb shell am broadcast -n <package>/${name} --es key value`),
        'Every field of that Intent is attacker-controlled input arriving directly at your code.',
        'If the receiver acts on what it is told — starting work, writing a preference, toggling a flag — that action is now callable by any app on the device.',
      ];
    default:
      return [
        viaAdb(`adb shell am start -n <package>/${name}`),
        ...(schemes.length > 0
          ? [`It is also reachable from a web page or a message, with no installed app required: ${schemes[0]}://... opened in a browser launches this screen directly.`]
          : []),
        'Launching it directly skips whatever screen normally precedes it. If the flow assumes the user already passed a login, a PIN or a consent screen, that assumption does not hold here.',
        ...(actions.length > 0 ? [`Reachable actions: ${actions.join(', ')}.`] : []),
      ];
  }
}

function manifestFindings(manifest: XmlNode, decodedRoot: string, sdkFromYml?: string, targetFromYml?: string): SastFinding[] {
  const findings: SastFinding[] = [];
  const application = findFirst(manifest, 'application');

  const add = (f: SastFinding) => findings.push(f);

  if (application && attr(application, 'debuggable') === 'true') {
    add({
      ruleId: 'manifest.debuggable',
      title: 'Application is debuggable',
      category: 'manifest',
      severity: 'high',
      description: 'android:debuggable="true" is set on <application>.',
      impact: 'Anyone can attach a debugger to the running app on any device, read its memory and step through its code. This is the single most damaging manifest mistake.',
      remediation: 'Remove the attribute. Let the build system set it — debug builds get it automatically, release builds must not.',
      exploitation: [
        'No root, no exploit and no special tooling is needed — only a USB cable and adb.',
        'The app appears in: adb shell run-as <package> — giving a shell inside its private data directory, where the databases, shared preferences and token cache live.',
        'Its JDWP port is exposed: adb jdwp lists the process, and a debugger attaches to it with jdb or Android Studio.',
        'From the debugger an attacker reads any variable, calls any method, and changes control flow live — so a client-side check ("is the user entitled?", "did biometrics pass?") can simply be made to return true.',
        'Memory is readable in full, which means keys held in memory, session tokens and decrypted payloads are all recoverable.',
      ],
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-489',
      locations: [at(application!, 'android:debuggable="true"')],
      occurrences: 1,
    });
  }

  if (application && attr(application, 'allowBackup') !== 'false') {
    add({
      ruleId: 'manifest.allow_backup',
      title: 'Application data is backed up',
      category: 'manifest',
      severity: 'medium',
      description: 'android:allowBackup is not set to false, so it defaults to true.',
      impact: 'On a device with USB debugging enabled, `adb backup` extracts the app\'s private data without root.',
      remediation: 'Set android:allowBackup="false", or define dataExtractionRules/fullBackupContent that exclude credentials and tokens.',
      masvs: 'MASVS-STORAGE-1',
      cwe: 'CWE-530',
      locations: [at(application!, attr(application!, 'allowBackup') === undefined
        ? 'android:allowBackup is absent, so it defaults to true'
        : 'android:allowBackup="true"')],
      occurrences: 1,
    });
  }

  // usesCleartextTraffic defaults to false from API 28. Only an explicit true is
  // a finding; an unset value on a modern target is correct.
  if (application && attr(application, 'usesCleartextTraffic') === 'true') {
    add({
      ruleId: 'manifest.cleartext_traffic',
      title: 'Cleartext HTTP traffic permitted',
      category: 'network',
      severity: 'medium',
      description: 'android:usesCleartextTraffic="true" allows plain HTTP for the whole app.',
      impact: 'Any request the app makes over http:// is readable and modifiable by anyone on the network path.',
      remediation: 'Remove the attribute and move endpoints to HTTPS. If one host genuinely needs cleartext, allow only that host in a network security config.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: [at(application!, 'android:usesCleartextTraffic="true"')],
      occurrences: 1,
    });
  }

  // Cleartext is permitted BY DEFAULT for apps that target below API 28.
  //
  // The default belongs to the app's targetSdkVersion, not to the device and not to
  // minSdkVersion: an app that targets 28 or higher has it off whatever the lowest
  // supported version is. An app with an old target and no network security config
  // permits plain HTTP everywhere and says nothing about it in the manifest, which
  // is the configuration most likely to be wrong. A target that is not declared
  // defaults to minSdkVersion.
  const minSdkValue = Number(minSdkOf(manifest, sdkFromYml) ?? 0);
  const targetSdkValue = Number(targetSdkOf(manifest, targetFromYml) ?? 0) || minSdkValue;
  const declaresCleartext = application && attr(application, 'usesCleartextTraffic') !== undefined;
  const hasNsc = application ? attr(application, 'networkSecurityConfig') !== undefined : false;

  if (targetSdkValue > 0 && targetSdkValue < 28 && !declaresCleartext && !hasNsc) {
    add({
      ruleId: 'manifest.cleartext_default',
      title: `Cleartext HTTP is permitted by default (targetSdk ${targetSdkValue})`,
      category: 'network',
      severity: 'medium',
      description:
        `The platform default for android:usesCleartextTraffic is true for apps that target below API 28, and this app ` +
        `targets API ${targetSdkValue} with neither the attribute set nor a network security config. ` +
        'Plain HTTP is therefore allowed to every host.',
      impact:
        'Every request the app makes can be sent unencrypted, and nothing in the manifest signals it. ' +
        'An attacker on the network path reads and rewrites traffic with no certificate and no prompt.',
      exploitation: [
        'Install the app on a device and put it on a network you control: a hotspot, or an ARP-spoofed position on the same subnet.',
        'Any request the app makes over http:// is readable in full — tokens, request bodies, account identifiers.',
        'Responses are rewritable, so a balance, an entitlement flag or an update URL can be changed in transit.',
        'Because the manifest declares nothing, a code review of the manifest alone will not show this.',
      ],
      remediation:
        'Set android:usesCleartextTraffic="false" on <application>, or add a network security config with ' +
        'cleartextTrafficPermitted="false" in its base-config. Raising targetSdkVersion to 28 or above also changes the default, ' +
        'but stating it explicitly is better than relying on a platform default that varies by API level.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: [at(application ?? manifest, `targetSdkVersion ${targetSdkValue}, no usesCleartextTraffic and no networkSecurityConfig`)],
      occurrences: 1,
    });
  }

  // Network security config: absence is not a finding, but a permissive one is.
  const nscRef = application ? attr(application, 'networkSecurityConfig') : undefined;
  if (nscRef) {
    const nscName = nscRef.replace(/^@xml\//, '');
    const nscPath = join(decodedRoot, 'res', 'xml', `${nscName}.xml`);
    if (existsSync(nscPath)) {
      const nsc = parseXml(readFileSync(nscPath, 'utf8'));
      const cleartextNodes = findAll(nsc, 'domain-config')
        .concat(findAll(nsc, 'base-config'))
        .filter((c) => attr(c, 'cleartextTrafficPermitted') === 'true');
      if (cleartextNodes.length > 0) {
        // Name the domains, not just the file: which hosts are exempt is the
        // whole question a reviewer has about a cleartext exception.
        const domains = cleartextNodes.flatMap((c) =>
          findAll(c, 'domain').map((d) => d.children.length === 0 ? (attr(d, 'includeSubdomains') === 'true' ? '*.' : '') : ''),
        );
        void domains;
        add({
          ruleId: 'manifest.nsc_cleartext',
          title: 'Network security config permits cleartext',
          category: 'network',
          severity: 'medium',
          description: `${nscName}.xml sets cleartextTrafficPermitted="true".`,
          impact: 'Traffic to the configured domains is sent in the clear regardless of the application-level setting.',
          remediation: 'Set cleartextTrafficPermitted="false" and serve those domains over HTTPS.',
          exploitation: [
            'An attacker needs only to be on the same network path — a cafe access point, a hotel LAN, a hostile ISP, or an ARP-spoofed position on the local subnet.',
            'Requests to the exempted hosts leave the device as plain HTTP, so everything in them is readable: session cookies, bearer tokens, request bodies, account identifiers.',
            'Responses are equally modifiable. A response that carries a balance, an entitlement flag, a feature toggle or an update URL can be rewritten in transit.',
            'No certificate, no warning and no user interaction is involved, which is what separates this from an interception attack that needs a trusted CA.',
          ],
          masvs: 'MASVS-NETWORK-1',
          cwe: 'CWE-319',
          locations: cleartextNodes.map((c) => ({
            file: `res/xml/${nscName}.xml`,
            line: c.line,
            excerpt: `${c.raw}   \u2190 cleartextTrafficPermitted="true"`,
          })),
          occurrences: cleartextNodes.length,
        });
      }

      const userCaNodes = findAll(nsc, 'certificates').filter((c) => attr(c, 'src') === 'user');
      if (userCaNodes.length > 0) {
        add({
          ruleId: 'manifest.nsc_user_ca',
          title: 'User-installed certificate authorities trusted',
          category: 'network',
          severity: 'medium',
          description: 'The network security config trusts the user CA store.',
          impact: 'Anyone who can install a certificate on the device — including every interception proxy — can read the app\'s TLS traffic.',
          remediation: 'Remove <certificates src="user"/>. If you need it for debugging, scope it to the debug build only.',
          exploitation: [
            'Since Android 7 apps ignore user-installed CAs by default. This config opts back in, which is precisely the configuration every interception proxy needs.',
            'An attacker — or anyone who talks the user through it in a support scam — installs a CA under Settings > Security > Encryption & credentials > Install a certificate.',
            'They point the device at Burp Suite, mitmproxy or Charles. Your TLS connections now terminate at the proxy, which presents a certificate signed by that CA and your app accepts it.',
            'Every request and response is readable and editable in clear text, with valid TLS shown to the user throughout.',
          ],
          masvs: 'MASVS-NETWORK-1',
          cwe: 'CWE-295',
          locations: userCaNodes.map((c) => ({
            file: `res/xml/${nscName}.xml`,
            line: c.line,
            excerpt: `${c.raw}   \u2190 trusts the user CA store`,
          })),
          occurrences: userCaNodes.length,
        });
      }

      const pins = findAll(nsc, 'pin');
      if (pins.length === 0) {
        add({
          ruleId: 'manifest.no_pinning',
          title: 'No certificate pinning configured',
          category: 'network',
          severity: 'low',
          description: 'A network security config is present but declares no <pin-set>.',
          impact: 'A certificate issued by any trusted public CA is accepted for your domain, so interception needs only a mis-issued or compelled certificate.',
          remediation: 'Add a <pin-set> with a backup pin and an expiry. Pin rotation must be planned before the expiry, or the app stops working.',
          masvs: 'MASVS-NETWORK-2',
          locations: [{ file: `res/xml/${nscName}.xml`, line: nsc?.line ?? 1, excerpt: 'no <pin-set> in this config' }],
          occurrences: 1,
        });
      }
    }
  }

  // Exported components, assessed one at a time.
  //
  // These used to collapse into a single "4 exported components" finding, which
  // told a reviewer the count and nothing else. What they need is which
  // component, on which line, reachable through which intent, and why that
  // particular one matters — a provider holding user data and a share-target
  // activity are both "exported" and carry entirely different risk.
  for (const tag of COMPONENT_TAGS) {
    for (const node of findAll(manifest, tag)) {
      if (!isExported(node) || hasPermission(node) || isSystemFacing(node)) continue;

      const name = attr(node, 'name') ?? '?';
      const explicit = attr(node, 'exported') === 'true';
      const actions = findAll(node, 'action').map((a) => attr(a, 'name') ?? '').filter(Boolean);
      const schemes = [...new Set(findAll(node, 'data').map((d) => attr(d, 'scheme')).filter(Boolean))];

      // Risk is per component type, because what an attacker gets differs.
      const perType: Record<string, { severity: SastFinding['severity']; reach: string }> = {
        provider: {
          severity: 'high',
          reach: 'Any app can query, insert, update or delete through this provider. If it fronts a database or the filesystem, that is direct read/write access to user data.',
        },
        service: {
          severity: 'medium',
          reach: 'Any app can bind to this service and call its exposed interface, or start it with a crafted Intent, running your code with your permissions.',
        },
        receiver: {
          severity: 'medium',
          reach: 'Any app can broadcast to this receiver and supply the Intent contents it acts on, which is a direct path to attacker-controlled input.',
        },
        activity: {
          severity: 'medium',
          reach: 'Any app can launch this screen directly with its own extras, bypassing whatever earlier screen normally guards it -- including a login screen.',
        },
      };
      const profile = perType[tag === 'activity-alias' ? 'activity' : tag] ?? perType.activity;

      add({
        ruleId: `manifest.exported_${tag.replace('-', '_')}:${name}`,
        title: `Exported ${tag} with no permission: ${name.split('.').pop()}`,
        category: 'manifest',
        severity: profile.severity,
        description:
          `<${tag} android:name="${name}"> is reachable by every other app on the device and declares no android:permission. ` +
          (explicit
            ? 'It is exported explicitly.'
            : 'It has no android:exported attribute but declares an intent-filter, which exports it on API levels below 31.') +
          (actions.length > 0 ? ` Reachable via: ${actions.join(', ')}.` : '') +
          (schemes.length > 0 ? ` URI schemes: ${schemes.join(', ')}.` : ''),
        impact: profile.reach,
        remediation:
          `Set android:exported="false" on ${name} if nothing outside the app needs it. ` +
          'If it must stay reachable, add android:permission with a signature-level permission you declare yourself, and treat every field of the incoming Intent as untrusted input.',
        exploitation: exploitFor(tag, name, actions, schemes),
        masvs: 'MASVS-PLATFORM-1',
        cwe: 'CWE-926',
        locations: [at(node, explicit ? 'android:exported="true"' : 'exported by its intent-filter')],
        occurrences: 1,
      });
    }
  }

  // A provider with grantUriPermissions and no path restriction is worth its
  // own finding: it is the usual shape of an arbitrary-file-read bug.
  const looseProviders = findAll(manifest, 'provider').filter(
    (p) => attr(p, 'grantUriPermissions') === 'true' && findAll(p, 'path-permission').length === 0,
  );
  if (looseProviders.length > 0) {
    add({
      ruleId: 'manifest.provider_grant_uri',
      title: 'ContentProvider grants URI permissions without path restrictions',
      category: 'manifest',
      severity: 'medium',
      description: 'grantUriPermissions="true" is set with no <path-permission> narrowing what may be granted.',
      impact: 'A crafted Intent can request a grant for a path you did not intend to share, reading files from the app sandbox.',
      remediation: 'Restrict the grant with <grant-uri-permission android:pathPrefix="..."/> and validate the requested URI server-side of the provider.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-926',
      locations: looseProviders.map((p) => ({
        file: 'AndroidManifest.xml',
        excerpt: `<provider android:name="${attr(p, 'name') ?? '?'}">`,
      })),
      occurrences: looseProviders.length,
    });
  }

  // A FileProvider whose paths file shares a whole storage area.
  //
  // A grant for any file under `<files-path path="."/>` is a grant for the whole files directory,
  // which holds the app's databases, preferences and keys. Only paths files a provider actually
  // names are read: a stray provider_paths.xml no provider uses exposes nothing.
  const overbroad: { provider: string; resource: string; element: string }[] = [];
  for (const provider of findAll(manifest, 'provider')) {
    for (const meta of findAll(provider, 'meta-data')) {
      const resource = attr(meta, 'resource');
      if (!resource?.startsWith('@xml/')) continue;
      const file = join(decodedRoot, 'res', 'xml', `${resource.slice(5)}.xml`);
      if (!existsSync(file)) continue;
      const paths = parseXml(readFileSync(file, 'utf8'));
      if (!paths) continue;
      for (const tag of ['files-path', 'cache-path', 'external-path', 'external-files-path', 'external-cache-path', 'root-path']) {
        for (const node of findAll(paths, tag)) {
          const path = attr(node, 'path') ?? '';
          if (path === '.' || path === '/' || path === '') {
            overbroad.push({ provider: attr(provider, 'name') ?? '?', resource: `res/xml/${resource.slice(5)}.xml`, element: `<${tag} name="${attr(node, 'name') ?? ''}" path="${path}"/>` });
          }
        }
      }
    }
  }
  if (overbroad.length > 0) {
    add({
      ruleId: 'storage.fileprovider_overbroad',
      title: 'FileProvider shares a whole directory',
      category: 'storage',
      severity: 'medium',
      description: 'A FileProvider paths file exposes the root of a storage area (path="." or "/").',
      impact:
        'A grant for any file in that area is a grant for the area. If another app can obtain a URI for this provider, it can read the app\'s databases, preferences and keys, not just the file that was meant to be shared.',
      remediation: 'Share a dedicated subdirectory (path="shared/") and keep everything else outside the provider\'s paths.',
      masvs: 'MASVS-STORAGE-2',
      cwe: 'CWE-552',
      locations: overbroad.map((o) => ({ file: o.resource, excerpt: `${o.element} (provider ${o.provider})` })),
      occurrences: overbroad.length,
    });
  }

  // Task hijacking: a launchMode that shares a task with other apps.
  const hijackable = findAll(manifest, 'activity').filter((a) => {
    const mode = attr(a, 'launchMode');
    return (mode === 'singleTask' || mode === 'singleInstance') && attr(a, 'taskAffinity') === undefined;
  });
  if (hijackable.length > 0) {
    add({
      ruleId: 'manifest.task_affinity',
      title: 'Activity vulnerable to task hijacking (StrandHogg)',
      category: 'manifest',
      severity: 'medium',
      description: 'An activity uses singleTask/singleInstance without an explicit taskAffinity.',
      impact: 'A malicious app declaring the same affinity can place its own activity in your task, so the user sees an attacker-controlled screen inside your app.',
      remediation: 'Set android:taskAffinity="" on the activity, and prefer launchMode="standard" unless you need otherwise.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-1021',
      locations: hijackable.map((a) => ({
        file: 'AndroidManifest.xml',
        excerpt: `<activity android:name="${attr(a, 'name') ?? '?'}">`,
      })),
      occurrences: hijackable.length,
    });
  }

  return findings;
}

function permissionFindings(permissions: string[]): SastFinding[] {
  const dangerous = permissions.filter((p) => DANGEROUS_PERMISSIONS.has(p));
  if (dangerous.length === 0) return [];
  return [
    {
      ruleId: 'manifest.dangerous_permissions',
      title: `${dangerous.length} high-impact permission${dangerous.length === 1 ? '' : 's'} requested`,
      category: 'manifest',
      // A hotspot, not a defect: needing the camera is not a bug. This exists
      // so a reviewer can ask whether each one is justified.
      severity: 'info',
      kind: 'hotspot',
      description: 'The app requests permissions that materially widen what a compromise can reach.',
      impact: 'Each one extends the blast radius if the app is compromised, and each is a prompt the user must be persuaded to accept.',
      remediation: 'Drop any that are not needed. For the rest, request at the point of use so the reason is obvious to the user.',
      masvs: 'MASVS-PLATFORM-1',
      locations: dangerous.map((p) => ({ file: 'AndroidManifest.xml', excerpt: p })),
      occurrences: dangerous.length,
    },
  ];
}


/**
 * The signing findings, from what the APK itself contains (`readApkSignatures`).
 *
 * The scheme verdict prefers a real verifier's answer when one ran, because
 * "verified" is a stronger statement than "present". Everything about the
 * certificates comes from the file, so it covers v2 and v3 signatures too.
 */
function signingAnalysis(
  apksigner: string | undefined,
  apkPath: string,
  sig: SignatureReport,
  signatureFile: string,
): {
  findings: SastFinding[];
  signers: string[];
  schemes: string[];
  limitations: string[];
} {
  const present = (['v1', 'v2', 'v3', 'v3.1'] as const).filter((k) => sig.schemes[k]);
  const limitations: string[] = [];
  let schemes: string[] = present;
  let verifierSigners: string[] = [];

  if (!apksigner) {
    limitations.push('Signature verification did not run on this server, so the signature schemes shown are those present in the file rather than verified ones.');
  } else {
    let output = '';
    try {
      output = run(apksigner, ['verify', '--verbose', '--print-certs', apkPath], 120_000);
    } catch (error) {
      output = `${(error as { stdout?: Buffer }).stdout?.toString() ?? ''}\n${(error as { stderr?: Buffer }).stderr?.toString() ?? ''}`;
    }
    const verified: string[] = [];
    for (const [label, needle] of [
      ['v1', 'Verified using v1 scheme'],
      ['v2', 'Verified using v2 scheme'],
      ['v3', 'Verified using v3 scheme'],
      ['v4', 'Verified using v4 scheme'],
    ] as const) {
      if (new RegExp(`${needle} \\(.*\\): true`).test(output)) verified.push(label);
    }
    if (verified.length > 0) schemes = verified;
    else limitations.push('Signature verification could not confirm this APK\u2019s signatures, so the schemes shown are those present in the file.');
    verifierSigners = [...output.matchAll(/Signer #\d+ certificate DN: (.+)/g)].map((m) => m[1].trim());
  }

  const findings: SastFinding[] = [];

  if (schemes.length > 0 && !schemes.includes('v2') && !schemes.includes('v3') && !schemes.includes('v3.1')) {
    findings.push({
      ruleId: 'signing.v1_only',
      title: 'APK signed with the v1 (JAR) scheme only',
      category: 'signing',
      severity: 'medium',
      description: 'No APK Signature Scheme v2 or v3 block is present.',
      impact: 'v1 signs individual entries, not the archive, which leaves the Janus class of repackaging attacks open on older devices.',
      remediation: 'Enable v2 and v3 signing in your signing config. Keep v1 only if you still ship to API < 24.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-347',
      // The v2 row, which says "absent": that absence is the finding.
      locations: [{ file: signatureFile, line: sig.lines.scheme.v2 }],
      occurrences: 1,
    });
  }

  const debugAt = sig.certificates.findIndex((c) => c.debug);
  if (debugAt >= 0) {
    findings.push({
      ruleId: 'signing.debug_certificate',
      title: 'Signed with the Android debug certificate',
      category: 'signing',
      severity: 'high',
      description: 'The signing certificate is the well-known debug key shipped with the Android SDK.',
      impact: 'The private key is on every developer machine in the world, so anyone can sign a modified build that the device accepts as an update to yours.',
      remediation: 'Sign release builds with a private key held in your own keystore or a hardware module, and never publish debug-signed artifacts.',
      exploitation: [
        'The debug key is not secret. It is generated at ~/.android/debug.keystore on every machine with the Android SDK, with the fixed password "android", alias "androiddebugkey" and key password "android".',
        'An attacker unpacks your APK: apktool d app.apk',
        'They change whatever they like — remove a licence check, add a screen that captures the PIN, repoint the API host — then rebuild: apktool b out -o evil.apk',
        'They re-sign with their own copy of the same debug key: apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android evil.apk',
        'The result carries a signature identical in origin to yours. Android compares signing certificates on update, so a device that already has your app will accept theirs as a legitimate update, inheriting its data directory and its granted permissions.',
        'Anything your app does with tamper.signature-style checks is also defeated, because the certificate genuinely matches the one you shipped with.',
      ],
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-321',
      locations: [{ file: signatureFile, line: sig.lines.certificates[debugAt].debug, excerpt: sig.certificates[debugAt].subject }],
      occurrences: 1,
    });
  }

  const subjects = sig.certificates.map((c) => c.subject);
  const digests = sig.certificates.map((c) => `SHA-256 ${c.sha256}`);
  return {
    findings,
    signers: verifierSigners.length > 0 ? verifierSigners : subjects.length > 0 ? subjects : digests,
    schemes,
    limitations,
  };
}

/**
 * Certificate algorithm and key strength, from the certificates in the file.
 *
 * The certificate's own signature algorithm and key size decide whether the
 * signature is forgeable. They are read from every scheme's certificates, not
 * only from `META-INF`, so a v2- or v3-only APK is checked too; a reader that
 * only understood the v1 signature never saw those at all.
 */
function certificateAlgorithmFindings(sig: SignatureReport, signatureFile: string): {
  findings: SastFinding[];
  detail: string[];
  limitations: string[];
} {
  const findings: SastFinding[] = [];
  const detail: string[] = [];
  const limitations: string[] = [];
  if (sig.certificates.length === 0) {
    limitations.push('No signing certificate could be read from this APK, so certificate algorithm and key size were not checked.');
  }

  sig.certificates.forEach((cert, i) => {
    const algorithm = cert.signatureAlgorithm;
    const keyInfo = `${cert.keyBits ? `${cert.keyBits}-bit ` : ''}${cert.keyAlgorithm} key`;
    detail.push(algorithm, keyInfo);
    const at = sig.lines.certificates[i];

    if (/\b(SHA1|MD5|MD2)with/i.test(algorithm)) {
      const broken = /MD5|MD2/i.test(algorithm);
      findings.push({
        ruleId: 'signing.weak_signature_algorithm',
        title: `Certificate signed with ${algorithm}`,
        category: 'signing',
        severity: broken ? 'high' : 'medium',
        description: `The signing certificate uses ${algorithm}, whose hash function is collision-broken.`,
        impact: 'A chosen-prefix collision allows a second certificate with the same signature to be constructed, which undermines the identity the signature is supposed to establish.',
        remediation: 'Re-issue the signing certificate with SHA-256 or stronger, and re-sign using the v2/v3 schemes.',
        masvs: 'MASVS-RESILIENCE-1',
        cwe: 'CWE-327',
        locations: [{ file: signatureFile, line: at.algorithm, excerpt: algorithm }],
        occurrences: 1,
      });
    }

    const bits = cert.keyBits ?? 0;
    if (bits > 0 && /RSA|DSA/i.test(cert.keyAlgorithm) && bits < 2048) {
      findings.push({
        ruleId: 'signing.weak_key_size',
        title: `Signing key is only ${bits} bits`,
        category: 'signing',
        severity: 'high',
        description: `The certificate carries a ${bits}-bit ${/DSA/i.test(cert.keyAlgorithm) ? 'DSA' : 'RSA'} key.`,
        impact: 'Keys below 2048 bits are within reach of a well-resourced attacker, who could forge updates that the device accepts as yours.',
        remediation: 'Generate a new 2048-bit (or larger) RSA key, or a P-256 EC key, and migrate signing with a key-rotation lineage.',
        masvs: 'MASVS-RESILIENCE-1',
        cwe: 'CWE-326',
        locations: [{ file: signatureFile, line: at.key, excerpt: keyInfo }],
        occurrences: 1,
      });
    }
  });

  return { findings, detail: [...new Set(detail)], limitations };
}

/**
 * The manifest rules, exposed for tests.
 *
 * `manifestFindings` needs a decoded directory for the network-security-config
 * lookups; passing a path that does not exist exercises the manifest rules
 * alone, which is what the coverage tests want.
 */
export function manifestFindingsForTest(manifest: XmlNode): SastFinding[] {
  return manifestFindings(manifest, '/nonexistent');
}

/**
 * Decompiles to readable Java with jadx.
 *
 * smali is what apktool produces and it is unreadable to anyone who does not
 * already read smali — `const-string v0, "AKIA…"` where the source said
 * `private final String aws_access_key_id = "AKIA…"`. jadx recovers something a
 * developer can actually judge, which is the whole point of showing a snippet.
 *
 * Optional. jadx fails on some obfuscated classes (it reports an error count
 * and still writes what it could), so a non-zero exit is not treated as fatal —
 * partial Java is better than none, and smali remains the fallback.
 *
 * `--no-imports` is deliberately NOT passed: it expands every type to its fully
 * qualified name, so a snippet reads `private final java.lang.String key` where
 * the point of decompiling was to get `private final String key`.
 */
/**
 * Decompile to Java, writing jadx's own progress where it can be read.
 *
 * jadx prints `INFO - progress: 3596 of 5245 (68%)` as it works, which is the
 * only genuine measure of the longest stage in the scan. `execFileSync` hands
 * stdout back only when the process exits, and this thread is blocked for the
 * duration anyway — so it is redirected to a file instead, and the main thread
 * tails it while this call blocks. `--quiet` is dropped for that reason: it
 * suppresses exactly the line worth reading.
 */
function decompileToJava(
  jadx: string,
  apkPath: string,
  workDir: string,
  logPath?: string,
): string | undefined {
  const out = join(workDir, 'java');
  const log = logPath ? openSync(logPath, 'w') : undefined;
  try {
    execFileSync(
      jadx,
      ['--no-res', '--no-debug-info', '-d', out, apkPath],
      {
        timeout: JADX_TIMEOUT_MS,
        maxBuffer: 256 * 1024 * 1024,
        // jadx writes its progress to stdout; send both streams to the log so
        // a failure explains itself there too.
        stdio: ['ignore', log ?? 'ignore', log ?? 'ignore'],
        env: {
          ...process.env,
          JAVA_HOME: resolveToolchain().javaHome ?? process.env.JAVA_HOME ?? '',
        },
      },
    );
  } catch {
    // Non-zero exit usually means "finished with errors, count: N" while still
    // having written most classes.
  } finally {
    if (log !== undefined) closeSync(log);
  }
  return existsSync(join(out, 'sources')) ? out : undefined;
}

/** jadx on a large APK is the slowest step in the scan; bound it. */
const JADX_TIMEOUT_MS = 300_000;

export function analyseApk(
  apkPath: string,
  tools: { apktool?: string; apksigner?: string; jadx?: string },
  workDir: string,
  progress: ProgressSink = () => {},
): AndroidAnalysis {
  const limitations: string[] = [];
  const groups: SastFinding[][] = [];
  const rules = rulesFor('android');

  // Files written for the Explorer that do not exist in the APK as text: the
  // signing report, a readable view of each native library, a description of a
  // binary a finding names. `views` maps what a finding says to where it opens.
  const syntheticDir = join(workDir, 'synthetic');
  const views = new Map<string, string>();
  const viewText = new Map<string, string[]>();
  const writeSynthetic = (rel: string, text: string): void => {
    const target = join(syntheticDir, rel);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, text);
    viewText.set(rel, text.split('\n'));
  };
  // Where in a native library's view each protection finding's evidence is.
  const nativeEvidence: Record<string, RegExp> = {
    'native.no_nx': /^NX stack/, 'native.no_pie': /^PIE /, 'native.no_stack_canary': /^stack canary/,
    'native.no_relro': /^RELRO/, 'native.partial_relro': /^RELRO/, 'native.runpath': /^RPATH/,
    'native.symbols_not_stripped': /^symbols /,
  };

  // Zip listing: cheap, always available, and enough for native libraries and
  // the third-party library inventory even when apktool is missing.
  let entries: string[] = [];
  try {
    entries = run('/usr/bin/unzip', ['-Z1', apkPath], 120_000).split('\n').filter(Boolean);
  } catch {
    limitations.push('The archive listing could not be read; native library and packaging checks were skipped.');
  }

  // What the archive holds, for the live map: it can start drawing as soon as the listing is read, long
  // before the decompiler has written anything.
  const listed = entries.filter((e) => !e.endsWith('/'));
  for (let i = 0; i < listed.length; i += 1500) {
    progress('unpacking', undefined, undefined, { t: 'files', paths: listed.slice(i, i + 1500) });
  }

  const nativeLibraries = [...new Set(
    entries.filter((e) => /^lib\/[^/]+\/.+\.so$/.test(e)).map((e) => e.split('/').pop()!),
  )].sort();

  // Which ABIs the APK ships. `nativeLibraries` keeps only base names, so the
  // directory is read from the archive listing instead.
  const nativeAbis = [...new Set(
    entries.map((e) => e.match(/^lib\/([^/]+)\/.+\.so$/)?.[1]).filter((abi): abi is string => Boolean(abi)),
  )].sort();

  const signatureFacts = readApkSignatures(apkPath);
  // The signing findings point at the APK's own v1 signature file (META-INF/CERT.RSA),
  // shown decoded. A v2/v3-only APK has no such file: its signatures are in a block of
  // the archive itself, so the original file is the APK, shown as its decoded signatures.
  const signatureFile = signatureFacts.v1Files[0] ?? basename(apkPath);
  const signing = signingAnalysis(tools.apksigner, apkPath, signatureFacts, signatureFile);
  groups.push(signing.findings);
  limitations.push(...signing.limitations);

  // Written even when nothing could be read, so a finding never points at nothing.
  writeSynthetic(signatureFile, signatureFacts.text);

  const certificate = certificateAlgorithmFindings(signatureFacts, signatureFile);
  groups.push(certificate.findings);
  limitations.push(...certificate.limitations);

  // Dependency versions, read from what the build wrote into the artifact.
  const deps = analyseDependencies(apkPath, entries);
  groups.push(deps.findings);

  const native = analyseNativeLibraries(apkPath, entries, (entry, buf) => {
    try {
      // At the library's own path: the Explorer shows the original file, decoded.
      writeSynthetic(entry, renderElfView(buf, entry));
      views.set(entry, entry);
    } catch {
      // A library the view cannot render keeps its finding and just has no button.
    }
  });
  groups.push(native.findings);
  const nativeInspected = native.inventory.length;

  let recon: ReconSection = { endpoints: [], hosts: [], emails: [], trackers: [], keyFiles: [] };
  let components: ComponentInventory = {
    activities: 0, services: 0, receivers: 0, providers: 0, exported: 0, browsable: [],
  };
  let parsedManifest: XmlNode | null = null;
  let androidFacts: AndroidFacts | undefined;
  let iconDataUrl: string | undefined;
  let decompiler: 'java' | 'smali' | 'none' = 'none';
  let sourceRoots: (string | undefined)[] = [];
  let javaFileCount = 0;
  let hasPinning = false;
  let usesSqlCipher = false;

  let packageName: string | undefined;
  let versionName: string | undefined;
  let versionCode: string | undefined;
  let minSdk: string | undefined;
  let targetSdk: string | undefined;
  let permissions: string[] = [];
  let detectedLibraries: string[] = [];

  if (!tools.apktool) {
    limitations.push(
      'apktool was not found. The manifest could not be decoded, so component, permission and configuration checks did not run; only the DEX string sweep was performed.',
    );
  } else {
    progress('decoding');
    const decoded = join(workDir, 'decoded');
    try {
      run(tools.apktool, ['d', '-f', '-o', decoded, apkPath]);
    } catch (error) {
      limitations.push('This APK could not be decoded, so structural checks were skipped.');
    }

    // apktool.yml is read FIRST.
    //
    // apktool lifts minSdkVersion, targetSdkVersion, versionName and
    // versionCode out of the manifest and records them here, so the manifest
    // frequently has no <uses-sdk> at all. Reading this afterwards left minSdk
    // undefined while the manifest rules ran, and the cleartext-by-default
    // check — which turns entirely on minSdk — would silently never fire.
    const ymlPath = join(decoded, 'apktool.yml');
    if (existsSync(ymlPath)) {
      const yml = readFileSync(ymlPath, 'utf8');
      minSdk = yml.match(/minSdkVersion:\s*'?(\d+)'?/)?.[1];
      targetSdk = yml.match(/targetSdkVersion:\s*'?(\d+)'?/)?.[1];
      versionName = yml.match(/versionName:\s*'?([^'\n]+?)'?\s*$/m)?.[1];
      versionCode = yml.match(/versionCode:\s*'?(\d+)'?/)?.[1];
    }

    const manifestPath = join(decoded, 'AndroidManifest.xml');
    if (existsSync(manifestPath)) {
      const manifest = parseXml(readFileSync(manifestPath, 'utf8'));
      if (manifest) {
        packageName = manifest.attrs.package;
        if (packageName) progress('decoding', undefined, undefined, { t: 'app', packageName });
        permissions = findAll(manifest, 'uses-permission')
          .map((p) => attr(p, 'name') ?? '')
          .filter(Boolean)
          .sort();

        // The manifest wins where it still carries them; apktool.yml is the
        // fallback already loaded above.
        const usesSdk = findFirst(manifest, 'uses-sdk');
        if (usesSdk) {
          minSdk = attr(usesSdk, 'minSdkVersion') ?? minSdk;
          targetSdk = attr(usesSdk, 'targetSdkVersion') ?? targetSdk;
        }
        versionName = attr(manifest, 'versionName') ?? versionName;
        versionCode = attr(manifest, 'versionCode') ?? versionCode;

        components = inventoryOf(manifest);
        groups.push(manifestFindings(manifest, decoded, minSdk, targetSdk));
        groups.push(permissionFindings(permissions));
        groups.push(extraManifestFindings(manifest, components));
        parsedManifest = manifest;
        androidFacts = androidFactsOf(manifest, decoded, nativeAbis);
        try {
          iconDataUrl = androidIcon(decoded, attr(findFirst(manifest, 'application') ?? manifest, 'icon'));
        } catch {
          // An icon is decoration; never a reason to lose the scan.
        }
        hasPinning = manifestDeclaresPinning(manifest, decoded);
      }
    }


    if (existsSync(decoded)) {
      const files = walk(decoded);
      let decompiledFiles: WalkedFile[] = [];

      // Code rules run against Java where jadx produced it, and against smali
      // otherwise. Scanning both would report every finding twice, and the
      // patterns recognise either notation.
      // Named so the main thread knows which file to tail for jadx's progress.
      const jadxLog = join(workDir, 'jadx-progress.log');
      progress('decompiling', 0, jadxLog);
      const javaRoot = tools.jadx
        ? decompileToJava(tools.jadx, apkPath, workDir, jadxLog)
        : undefined;
      progress('scanning', 0);
      // The rule pass tells the live map which file it is on and where a rule matched.
      const live: LiveSink = {
        visit: (paths) => progress('scanning', undefined, undefined, { t: 'visit', paths }),
        hit: (file, rule) =>
          progress('scanning', undefined, undefined, { t: 'hit', file, title: rule.title, severity: rule.severity, category: rule.category }),
      };
      sourceRoots = [javaRoot, decoded];
      // The app's own packages, so a rule with more hits than it can list keeps the ones in the app's code.
      const appPackages = appRoots({ packageName, declaredComponents: components.declared });
      const isFirstParty = (relative: string) => {
        const pkg = packageOf({ file: relative });
        return Boolean(pkg) && appPackages.some((root) => pkg === root || pkg!.startsWith(`${root}.`));
      };
      if (javaRoot) {
        // The rule pass reads every one of these next; start several readers on them now.
        warmCache(javaRoot, '*.java');
        const javaFiles = walk(javaRoot);
        decompiledFiles = javaFiles;
        // Four steps share the stage, each reporting into its own part of it, so the bar keeps moving through
        // the ones that cannot count their own progress.
        groups.push(scanFiles(javaRoot, javaFiles, rules, (f) => progress('scanning', f * 0.55), isFirstParty, live));
        // What reaches a call, not only which calls exist: constants used as keys, untrusted input reaching SQL.
        progress('scanning', 0.55);
        const flow = scanJavaFlow(javaRoot, javaFiles, isFirstParty, (f) => progress('scanning', 0.55 + f * 0.2));
        groups.push(flow);
        // The flow engine's findings light up the live map too, where the code they are in is.
        for (const f of flow) {
          for (const l of f.locations.slice(0, 3)) {
            progress('scanning', undefined, undefined, { t: 'hit', file: l.file, title: f.title, severity: f.severity, category: f.category });
          }
        }
        progress('scanning', 0.75);

        // Everything that is not code still lives only in the apktool decode:
        // res/, assets/, the manifest, raw files. jadx does not emit them, so
        // scanning the Java tree alone silently stopped covering them the day
        // jadx was introduced — and a Google API key sitting in
        // res/values/strings.xml went unreported because of it. The smali
        // trees are excluded here because the Java above already covers those
        // same classes.
        const nonCode = files.filter((f) => !/^smali(_classes\d+)?\//.test(f.relative));
        groups.push(
          scanFiles(decoded, nonCode, rules, (f) => progress('scanning', 0.75 + f * 0.1), undefined, live),
        );

        decompiler = 'java';
        javaFileCount = javaFiles.filter((f) => f.relative.endsWith('.java')).length;
      } else {
        groups.push(scanFiles(decoded, files, rules, (f) => progress('scanning', f), undefined, live));
        decompiler = 'smali';
        if (tools.jadx) {
          limitations.push('Decompilation to Java produced no sources for this APK, so code findings are shown as Dalvik assembly.');
        } else {
          limitations.push('Decompilation to Java is not available on this server, so code findings are shown as Dalvik assembly rather than readable Java.');
        }
      }

      // Method-body analysis stays on smali: the TrustManager and hardcoded-key
      // checks were tuned against it and their false positives fixed there. It reads only the classes whose
      // decompiled Java mentions what it looks for (or that the decompiler gave up on): a large app has tens of
      // thousands of smali files, and reading them all was most of the time the scan spent after the rules.
      progress('scanning', 0.88);
      const smali = javaRoot ? smaliToRead(files, decompiledFiles, (f) => readText(f.absolute)) : files;
      groups.push(analyseSmali(smali).findings);
      progress('scanning', 1);

      detectedLibraries = LIBRARY_SIGNATURES
        .filter((lib) => files.some((f) => lib.pattern.test(f.relative)))
        .map((lib) => lib.name);

      // Reconnaissance reads the decoded tree: resources and assets hold
      // endpoints that never appear in code.
      // The decompiled Java holds the same string constants the smali does, and is already in memory; the
      // smali is not read at all when Java exists. Resources and assets still come from the decode.
      recon = runRecon(decoded, javaRoot ? [...files.filter((f) => !/^smali(_classes\d+)?\//.test(f.relative)), ...decompiledFiles] : files);
      usesSqlCipher = files.some((f) => /sqlcipher/i.test(f.relative));
    }
  }

  progress('inspecting');

  // Native libraries are swept for secrets too.
  //
  // A key moved into C to "hide" it is a common pattern and was a blind spot:
  // the string sweep only ever looked at classes*.dex, so anything in a .so was
  // invisible to this scanner while remaining trivially readable with `strings`.
  // One copy of each library: the same source is built for every ABI, so sweeping all of them
  // reports one embedded string three times. arm64 is preferred, as for the hardening checks.
  const nativeCopies = new Map<string, string>();
  for (const entry of entries.filter((e) => /^lib\/[^/]+\/.+\.so$/.test(e))) {
    const name = entry.split('/').pop()!;
    const have = nativeCopies.get(name);
    if (!have || (entry.startsWith('lib/arm64-v8a/') && !have.startsWith('lib/arm64-v8a/'))) nativeCopies.set(name, entry);
  }
  for (const entry of [...nativeCopies.values()].slice(0, MAX_NATIVE_SWEEP)) {
    try {
      const so = execFileSync('/usr/bin/unzip', ['-p', apkPath, entry], {
        maxBuffer: 128 * 1024 * 1024,
        timeout: 60_000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      groups.push(scanBinaryStrings(entry, so, rules.filter((r) => r.category === 'secrets')));
    } catch {
      limitations.push(`${entry} could not be read for the native string sweep.`);
    }
  }

  // The DEX string sweep runs regardless: it is the fallback when apktool is
  // unavailable, and a useful second pass when it is not.
  for (const entry of entries.filter((e) => /^classes\d*\.dex$/.test(e))) {
    let dex: Buffer;
    try {
      dex = execFileSync('/usr/bin/unzip', ['-p', apkPath, entry], {
        maxBuffer: 256 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      limitations.push(`${entry} could not be extracted for the string sweep.`);
      continue;
    }
    // Reported separately from extraction: conflating the two produced a
    // "could not be extracted" message for a dex that had extracted fine and
    // then failed to scan, which sent the investigation in the wrong direction.
    try {
      groups.push(scanBinaryStrings(entry, dex, rules.filter((r) => r.category === 'secrets')));
    } catch (error) {
      limitations.push(`${entry} was extracted but could not be scanned: ${(error as Error).message}`);
    }
  }

  if (soEntriesPresent(entries) && nativeInspected === 0) {
    limitations.push('Native libraries are present but none could be read as ELF, so the binary-hardening checks did not run.');
  }

  if (minSdk && Number(minSdk) < 24) {
    groups.push([
      {
        ruleId: 'manifest.low_min_sdk',
        title: `minSdkVersion is ${minSdk}`,
        category: 'manifest',
        severity: 'medium',
        description: 'The app supports Android versions that no longer receive security patches.',
        impact: 'Devices below API 24 lack v2 signature enforcement, modern TLS defaults and scoped storage, so several protections in this report cannot apply there.',
        remediation: 'Raise minSdkVersion to 24 or above unless a measured share of your users is on older releases.',
        masvs: 'MASVS-PLATFORM-1',
        locations: [{ file: 'AndroidManifest.xml' }],
        occurrences: 1,
      },
    ]);
  }

  const merged = mergeFindings(groups);

  // Separate the three kinds. A hotspot is not a defect and a secure finding is
  // not a problem, so neither belongs in the same list as one.
  const defects = merged.filter((f) => (f.kind ?? 'defect') === 'defect');
  const hotspots = merged.filter((f) => f.kind === 'hotspot');
  // A rule may declare itself a secure observation — "this app does the right
  // thing here". Those belong in the secure list, not dropped on the floor.
  const secureFromRules = merged.filter((f) => f.kind === 'secure');

  // Bundled key material is a hotspot in its own right: a .pem in assets may be
  // a pinned public certificate (fine) or a private key (not), and only someone
  // who knows the app can say which.
  if (recon.keyFiles.length > 0) {
    hotspots.push({
      ruleId: 'recon.key_material',
      title: `${recon.keyFiles.length} certificate or key file${recon.keyFiles.length === 1 ? '' : 's'} bundled`,
      category: 'secrets',
      severity: 'low',
      kind: 'hotspot',
      description: 'Files with certificate or keystore extensions ship inside the artifact.',
      impact: 'A bundled public certificate is normal and is how pinning works. A bundled private key is not: it is readable by anyone who unzips the app.',
      remediation: 'Confirm each file holds only public key material. Anything private must be generated in the Keystore on-device and never shipped.',
      masvs: 'MASVS-CRYPTO-2',
      cwe: 'CWE-312',
      locations: recon.keyFiles.slice(0, 12).map((f) => ({ file: f })),
      occurrences: recon.keyFiles.length,
    });
  }

  if (recon.trackers.length > 0) {
    const categories = [...new Set(recon.trackers.map((t) => t.category))].sort();
    hotspots.push({
      ruleId: 'recon.trackers',
      title: `${recon.trackers.length} privacy tracker${recon.trackers.length === 1 ? '' : 's'} bundled`,
      category: 'dependencies',
      severity: recon.trackers.length > 4 ? 'medium' : 'low',
      kind: 'hotspot',
      description: `Signatures matched for: ${recon.trackers.map((t) => t.name).join(', ')}. Tracker signatures are from the Exodus Privacy database (ODbL 1.0, https://exodus-privacy.eu.org).`,
      impact: `These SDKs collect device or user data and send it to third parties (${categories.join(', ')}). Each one is a party to your users' data and a disclosure obligation under GDPR and similar regimes.`,
      remediation: 'Confirm each tracker is disclosed in your privacy policy and covered by user consent, and remove any that are not needed.',
      masvs: 'MASVS-PRIVACY-1',
      locations: recon.trackers.slice(0, 20).map((t) => ({ file: t.signature, excerpt: `${t.name} (${t.category})` })),
      occurrences: recon.trackers.length,
    });
  }

  const nativeAllHardened =
    native.inventory.length > 0 &&
    native.inventory.every((l) => l.facts.nx && l.facts.pie && l.facts.stackCanary && l.facts.relro === 'full');

  // Cleartext is blocked when nothing flagged it and the platform default (or an
  // explicit false) applies: targetSdk 28+ blocks it unless the app opts in.
  const cleartextFlag = parsedManifest
    ? attr(findFirst(parsedManifest, 'application') ?? parsedManifest, 'usesCleartextTraffic')
    : undefined;
  const cleartextBlocked =
    Boolean(parsedManifest) &&
    !defects.some((f) => f.ruleId === 'manifest.cleartext_traffic' || f.ruleId === 'manifest.nsc_cleartext') &&
    (cleartextFlag === 'false' || Number(targetSdk) >= 28);

  const secure = secureFindings({
    cleartextBlocked,
    manifest: parsedManifest,
    minSdk,
    signatureSchemes: signing.schemes,
    hasPinning,
    trackerCount: recon.trackers.length,
    usesSqlCipher,
    nativeAllHardened,
    nativeCount: native.inventory.length,
  });
  // Rules may also declare a secure observation of their own.
  secure.push(...secureFromRules);

  // A finding names what the rule saw; the Explorer holds what was retained.
  // Where those differ, point the finding at something that opens.
  const decodedDir = join(workDir, 'decoded');
  const firstFileUnder = (dir: string): string | undefined => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      return undefined;
    }
    for (const entry of entries) if (entry.isFile()) return join(dir, entry.name);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const found = firstFileUnder(join(dir, entry.name));
      if (found) return found;
    }
    return undefined;
  };
  const javaCache: JavaFiles = new Map();
  const retargetLocation = (ruleId: string, l: SastLocation): SastLocation => {
    // Method-body checks run on smali; show the decompiled class they came from instead.
    if (l.file.startsWith('smali')) {
      const mapped = mapSmaliToJava(l, ruleId, sourceRoots[0], javaCache);
      if (mapped.file !== l.file) return mapped;
    }
    // A native library or other binary that already has a view.
    const view = views.get(l.file);
    if (view) {
      const pattern = nativeEvidence[ruleId];
      const at = pattern ? (viewText.get(view) ?? []).findIndex((x) => pattern.test(x)) : -1;
      return { ...l, file: view, ...(at >= 0 ? { line: at + 1 } : {}) };
    }
    // A binary the APK carries (a keystore): described, never displayed.
    if (!l.file.endsWith('/') && !isReadable(l.file) && /[./]/.test(l.file)) {
      const real = join(decodedDir, l.file);
      try {
        if (statSync(real).isFile() && statSync(real).size <= 64 * 1024 * 1024) {
          writeSynthetic(l.file, binaryStub(readFileSync(real), l.file));
          views.set(l.file, l.file);
          return l;
        }
      } catch {
        // Not on disk under that name: leave the location as the rule spelled it.
      }
    }
    // A package prefix (`com.google.ads.`) names a namespace, not a file: open its first class.
    if (!l.file.includes('/') && /^[A-Za-z_][\w$]*(\.[A-Za-z_$][\w$]*)+\.?$/.test(l.file)) {
      const sub = l.file.replace(/\.$/, '').split('.').join('/');
      for (const root of sourceRoots) {
        if (!root) continue;
        const candidates = existsSync(join(root, 'sources', sub)) ? [join(root, 'sources', sub)] : [];
        if (candidates.length === 0 && existsSync(root)) {
          for (const dir of readdirSync(root)) if (/^smali(_classes\d+)?$/.test(dir) && existsSync(join(root, dir, sub))) candidates.push(join(root, dir, sub));
        }
        for (const dir of candidates) {
          const file = firstFileUnder(dir);
          if (file) return { ...l, file: relative(root, file), excerpt: l.excerpt ?? l.file };
        }
      }
    }
    return l;
  };
  const retarget = (list: SastFinding[]): SastFinding[] =>
    list.map((f) => ({
      ...f,
      locations: f.locations.flatMap((l) =>
        l.file.startsWith('smali')
          ? mapSmaliLocations(l, f.ruleId, sourceRoots[0], javaCache).map((m) => retargetLocation(f.ruleId, m))
          : [retargetLocation(f.ruleId, l)],
      ),
    }));

  // A hardcoded key can be found twice: by reading the method that builds the cipher key,
  // and by its declaration. They are one problem; keep the method-level finding (which also
  // shows the declaration) and drop the constant-rule locations in classes it already covers.
  const dedupeKeys = (list: SastFinding[]): SastFinding[] => {
    const keyFindings = list.filter((f) => f.ruleId === 'crypto.hardcoded_key');
    const coveredFiles = new Set(keyFindings.flatMap((f) => f.locations.map((l) => l.file)));
    const coveredLines = new Set(keyFindings.flatMap((f) => f.locations.map((l) => `${l.file}:${l.line}`)));
    return list.flatMap((f) => {
      // The constant rule is about the class; the credential-name rule is about one line.
      const covered = f.ruleId === 'crypto.hardcoded_key_constant'
        ? (l: SastLocation) => coveredFiles.has(l.file)
        : f.ruleId === 'secret.credential_literal'
          ? (l: SastLocation) => coveredLines.has(`${l.file}:${l.line}`)
          : undefined;
      if (!covered) return [f];
      const locations = f.locations.filter((l) => !covered(l));
      return locations.length > 0 ? [{ ...f, locations, occurrences: Math.min(f.occurrences, locations.length) }] : [];
    });
  };
  sourceRoots = [...sourceRoots, syntheticDir];

  return {
    findings: dedupeKeys(retarget(defects)),
    decompiler,
    javaFileCount,
    dependencies: deps.dependencies.map((d) => ({
      coordinate: d.coordinate,
      version: d.version,
      source: d.source,
      advisoryCount: d.advisories.length,
    })),
    secure: retarget(secure),
    hotspots: retarget(hotspots),
    recon,
    components,
    permissionDetail: describeAll(permissions),
    nativeLibraryDetail: native.inventory.map((l) => ({
      name: l.name,
      pie: l.facts.pie,
      nx: l.facts.nx,
      stackCanary: l.facts.stackCanary,
      relro: l.facts.relro,
      symbolsStripped: l.facts.symbolsStripped,
      fortified: l.facts.fortified,
    })),
    nativeInspected,
    android: androidFacts,
    iconDataUrl,
    fileCount: entries.length,
    packageName,
    versionName,
    versionCode,
    minSdk,
    targetSdk,
    permissions,
    signers: [...signing.signers, ...certificate.detail],
    signatureSchemes: signing.schemes,
    nativeLibraries,
    detectedLibraries,
    sourceRoots,
    syntheticRoot: syntheticDir,
    limitations,
  };
}
