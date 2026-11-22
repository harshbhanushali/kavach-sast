/**
 * The manifest rules, component inventory and positive findings that the first pass of this scanner did
 * not surface.
 *
 * Kept beside `android.ts` rather than inside it because that file was already
 * carrying the decode pipeline; this is pure analysis over an already-parsed
 * manifest and is much easier to test in isolation.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { attr, findAll, findFirst } from './xml.ts';
import type { XmlNode } from './xml.ts';
import type { AndroidFacts, ComponentInventory, SastFinding } from './types.ts';

const COMPONENT_TAGS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'] as const;

function isExported(node: XmlNode): boolean {
  const explicit = attr(node, 'exported');
  if (explicit !== undefined) return explicit === 'true';
  return findAll(node, 'intent-filter').length > 0;
}

function nameOf(node: XmlNode): string {
  return attr(node, 'name') ?? '?';
}

/**
 * Counts components and lists the browsable ones.
 *
 * A BROWSABLE activity is an entry point a web page can reach, which is a
 * materially different risk from an exported component another installed app
 * can reach — it needs no malicious app on the device at all, just a link.
 */
export function inventoryOf(manifest: XmlNode): ComponentInventory {
  const count = (tag: string) => findAll(manifest, tag).length;
  const all = COMPONENT_TAGS.flatMap((tag) => findAll(manifest, tag));

  // One entry per activity, with every scheme and host its filters declare: an activity with
  // two intent filters is one entry point, not two.
  const byComponent = new Map<string, { component: string; schemes: Set<string>; hosts: Set<string> }>();
  for (const activity of [...findAll(manifest, 'activity'), ...findAll(manifest, 'activity-alias')]) {
    for (const filter of findAll(activity, 'intent-filter')) {
      const categories = findAll(filter, 'category').map((c) => attr(c, 'name'));
      if (!categories.includes('android.intent.category.BROWSABLE')) continue;

      const data = findAll(filter, 'data');
      const schemes = data.map((d) => attr(d, 'scheme')).filter(Boolean) as string[];
      const hosts = data.map((d) => attr(d, 'host')).filter(Boolean) as string[];
      if (schemes.length === 0) continue;
      const entry = byComponent.get(nameOf(activity)) ?? { component: nameOf(activity), schemes: new Set<string>(), hosts: new Set<string>() };
      schemes.forEach((x) => entry.schemes.add(x));
      hosts.forEach((x) => entry.hosts.add(x));
      byComponent.set(nameOf(activity), entry);
    }
  }
  const browsable: ComponentInventory['browsable'] = [...byComponent.values()].map((b) => ({
    component: b.component,
    schemes: [...b.schemes],
    hosts: [...b.hosts],
  }));

  return {
    activities: count('activity') + count('activity-alias'),
    services: count('service'),
    receivers: count('receiver'),
    providers: count('provider'),
    exported: all.filter(isExported).length,
    declared: [...new Set(all.map((c) => nameOf(c)).filter((n) => n !== '?'))],
    browsable,
  };
}

/**
 * Additional manifest rules: decisions a developer makes in the manifest that other Android scanners also flag.
 *
 * Each one is a decision someone made in the manifest that has a security
 * consequence and cannot be seen from the code.
 */
export function extraManifestFindings(manifest: XmlNode, inventory: ComponentInventory): SastFinding[] {
  const findings: SastFinding[] = [];
  const application = findFirst(manifest, 'application');

  // --- android:testOnly ---
  if (application && attr(application, 'testOnly') === 'true') {
    findings.push({
      ruleId: 'manifest.test_only',
      title: 'Application is marked testOnly',
      category: 'manifest',
      severity: 'medium',
      description: 'android:testOnly="true" is set on <application>.',
      impact: 'A testOnly build can be installed with `adb install -t` and exposes internal test entry points. It also cannot be published, so its presence usually means a debug artifact escaped.',
      remediation: 'Remove the attribute from release builds. It is normally added by an IDE "run" configuration rather than written by hand.',
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-489',
      locations: [{ file: 'AndroidManifest.xml' }],
      occurrences: 1,
    });
  }

  // --- secret dialer codes ---
  const dialerCodes = findAll(manifest, 'data')
    .filter((d) => attr(d, 'scheme') === 'android_secret_code')
    .map((d) => attr(d, 'host') ?? '?');
  if (dialerCodes.length > 0) {
    findings.push({
      ruleId: 'manifest.dialer_secret_code',
      title: `${dialerCodes.length} hidden dialer code${dialerCodes.length === 1 ? '' : 's'}`,
      category: 'manifest',
      severity: 'medium',
      description: 'A receiver is registered for the android_secret_code scheme.',
      impact: 'Anyone who types the code into the dialer reaches a hidden entry point, which typically exposes diagnostics or test screens that were never meant for users.',
      remediation: 'Remove the receiver from release builds, or require a signature-level permission to reach it.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-489',
      locations: dialerCodes.map((code) => ({ file: 'AndroidManifest.xml', excerpt: `*#*#${code}#*#*` })),
      occurrences: dialerCodes.length,
    });
  }

  // --- intent-filter priority ---
  const highPriority = findAll(manifest, 'intent-filter')
    .filter((f) => Number(attr(f, 'priority') ?? 0) > 100);
  if (highPriority.length > 0) {
    findings.push({
      ruleId: 'manifest.high_intent_priority',
      title: `${highPriority.length} intent filter${highPriority.length === 1 ? '' : 's'} with very high priority`,
      category: 'manifest',
      severity: 'low',
      description: 'An intent-filter declares a priority above 100.',
      impact: 'The app positions itself ahead of others for these intents. For ordered broadcasts such as SMS that means it can read, and abort, the broadcast before anyone else.',
      remediation: 'Use the default priority unless there is a specific reason. Values above 100 are reserved by convention for system components.',
      masvs: 'MASVS-PLATFORM-1',
      locations: highPriority.slice(0, 8).map((f) => ({
        file: 'AndroidManifest.xml',
        excerpt: `priority=${attr(f, 'priority')}`,
      })),
      occurrences: highPriority.length,
    });
  }

  // --- browsable deeplinks ---
  if (inventory.browsable.length > 0) {
    const custom = inventory.browsable.filter((b) =>
      b.schemes.some((s) => s !== 'http' && s !== 'https'));
    findings.push({
      ruleId: 'manifest.browsable_deeplink',
      title: `${inventory.browsable.length} activit${inventory.browsable.length === 1 ? 'y is' : 'ies are'} reachable from a web link`,
      category: 'manifest',
      // A hotspot, not a defect: deep links are a feature. Whether each one
      // validates its input is the question, and only a human can answer it.
      severity: custom.length > 0 ? 'medium' : 'low',
      kind: 'hotspot',
      description: 'These activities declare BROWSABLE intent filters, so a link in a browser, an email or another app can launch them directly.',
      impact: 'Every parameter arriving this way is attacker-controlled and reaches the activity before any login screen. Custom schemes are worse than App Links: any app can register the same scheme, so the caller is not authenticated either.',
      remediation: 'Validate every extra and URI parameter as untrusted input, never perform a privileged action straight from a deep link, and prefer verified App Links (autoVerify with assetlinks.json) over custom schemes.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-939',
      locations: inventory.browsable.slice(0, 12).map((b) => ({
        file: 'AndroidManifest.xml',
        excerpt: `${b.component} — ${b.schemes.join(', ')}${b.hosts.length ? ` @ ${b.hosts.join(', ')}` : ''}`,
      })),
      occurrences: inventory.browsable.length,
    });
  }

  // --- App Links declared without autoVerify ---
  const appLinkFilters = [...findAll(manifest, 'activity'), ...findAll(manifest, 'activity-alias')]
    .flatMap((a) => findAll(a, 'intent-filter'))
    // autoVerify applies to a filter that names a host. A scheme with no host cannot be verified at all, and
    // the weakness there is that the filter claims every URL, which the deep-link finding already covers.
    .filter((f) => findAll(f, 'data').some((d) => {
      const scheme = attr(d, 'scheme');
      return (scheme === 'http' || scheme === 'https') && attr(d, 'host') !== undefined;
    }) && findAll(f, 'category').some((c) => attr(c, 'name') === 'android.intent.category.BROWSABLE'));
  const unverified = appLinkFilters.filter((f) => attr(f, 'autoVerify') !== 'true');
  if (unverified.length > 0) {
    findings.push({
      ruleId: 'manifest.applink_not_verified',
      title: `${unverified.length} http(s) link filter${unverified.length === 1 ? '' : 's'} without autoVerify`,
      category: 'manifest',
      severity: 'low',
      description: 'An intent filter claims http/https URLs but does not set android:autoVerify="true".',
      impact: 'Without verification against assetlinks.json on the domain, any other app can claim the same URLs and Android will show a chooser — or send your users to the other app.',
      remediation: 'Set autoVerify="true" and publish /.well-known/assetlinks.json containing your signing certificate fingerprint.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-939',
      locations: [{ file: 'AndroidManifest.xml' }],
      occurrences: unverified.length,
    });
  }

  // --- exported components guarded only by a normal-level permission ---
  const weaklyGuarded: string[] = [];
  const declared = new Map(
    findAll(manifest, 'permission').map((p) => [attr(p, 'name') ?? '', attr(p, 'protectionLevel') ?? 'normal']),
  );
  for (const tag of COMPONENT_TAGS) {
    for (const node of findAll(manifest, tag)) {
      const permission = attr(node, 'permission') ?? attr(node, 'readPermission');
      if (!permission || !isExported(node)) continue;
      const level = declared.get(permission);
      if (level && /^normal\b/.test(level)) weaklyGuarded.push(`${nameOf(node)} (${permission})`);
    }
  }
  if (weaklyGuarded.length > 0) {
    findings.push({
      ruleId: 'manifest.normal_permission_guard',
      title: `${weaklyGuarded.length} exported component${weaklyGuarded.length === 1 ? '' : 's'} guarded only by a normal permission`,
      category: 'manifest',
      severity: 'medium',
      description: 'The guarding permission is declared with protectionLevel="normal".',
      impact: 'Normal permissions are granted automatically at install with no user prompt, so the guard stops nothing — any app that requests it gets through.',
      remediation: 'Declare the permission with protectionLevel="signature" so only apps signed with your key can hold it.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-926',
      locations: weaklyGuarded.slice(0, 12).map((c) => ({ file: 'AndroidManifest.xml', excerpt: c })),
      occurrences: weaklyGuarded.length,
    });
  }

  return findings;
}

/**
 * Positive findings: what the app demonstrably does right.
 *
 * These never improve a grade past an outstanding critical (see `scoreOf`), and
 * they exist so a reader can tell a deliberately hardened app from one that
 * merely has a short finding list.
 */
export function secureFindings(input: {
  cleartextBlocked?: boolean;
  manifest: XmlNode | null;
  minSdk?: string;
  signatureSchemes: string[];
  hasPinning: boolean;
  trackerCount: number;
  usesSqlCipher: boolean;
  nativeAllHardened: boolean;
  nativeCount: number;
}): SastFinding[] {
  const out: SastFinding[] = [];
  const application = input.manifest ? findFirst(input.manifest, 'application') : null;
  const add = (
    ruleId: string,
    title: string,
    category: SastFinding['category'],
    description: string,
  ) => out.push({
    ruleId, title, category,
    severity: 'info',
    kind: 'secure',
    description,
    impact: '',
    remediation: '',
    locations: [],
    occurrences: 1,
  });

  if (application && attr(application, 'allowBackup') === 'false') {
    add('secure.backup_disabled', 'Application data is excluded from backup', 'manifest',
      'android:allowBackup="false" prevents `adb backup` from extracting the app\'s private data.');
  }
  if (application && attr(application, 'debuggable') !== 'true') {
    add('secure.not_debuggable', 'Release build is not debuggable', 'manifest',
      'No android:debuggable flag is set, so a debugger cannot attach on a production device.');
  }
  if (input.cleartextBlocked) {
    add('secure.cleartext_blocked', 'Cleartext HTTP traffic is blocked', 'network',
      'The manifest does not allow plain HTTP and the platform default for this target SDK refuses it, so traffic must use TLS.');
  }
  if (input.hasPinning) {
    add('secure.certificate_pinning', 'Certificate pinning is configured', 'network',
      'A <pin-set> is declared in the network security config, so a mis-issued CA certificate alone is not enough to intercept traffic.');
  }
  if (input.signatureSchemes.includes('v2') || input.signatureSchemes.includes('v3')) {
    add('secure.modern_signing', `Signed with the ${input.signatureSchemes.filter((s) => s !== 'v1').join(' and ')} scheme`, 'signing',
      'Whole-archive signing is in use, which closes the Janus class of repackaging attacks that v1-only signing leaves open.');
  }
  if (input.minSdk && Number(input.minSdk) >= 24) {
    add('secure.modern_min_sdk', `minSdkVersion is ${input.minSdk}`, 'manifest',
      'The app does not run on Android releases that predate v2 signature enforcement and modern TLS defaults.');
  }
  if (input.trackerCount === 0) {
    add('secure.no_trackers', 'No privacy trackers detected', 'dependencies',
      'No signature from the Exodus tracker database matched this artifact.');
  }
  if (input.usesSqlCipher) {
    add('secure.encrypted_database', 'Database encryption library present', 'storage',
      'SQLCipher is bundled, so local data can be stored encrypted rather than as plaintext SQLite.');
  }
  if (input.nativeCount > 0 && input.nativeAllHardened) {
    add('secure.hardened_native', `All ${input.nativeCount} native libraries are fully hardened`, 'binary',
      'Every shipped .so has NX, PIE, a stack protector and full RELRO.');
  }

  return out;
}

/** A `@string/name` reference resolved against the decoded strings.xml. */
function resolveString(value: string | undefined, decoded: string): string | undefined {
  if (!value) return undefined;
  const ref = value.match(/^@string\/(.+)$/);
  if (!ref) return value;
  try {
    const source = readFileSync(join(decoded, 'res', 'values', 'strings.xml'), 'utf8');
    return source.match(new RegExp(`<string[^>]*name="${ref[1]}"[^>]*>([^<]*)</string>`))?.[1];
  } catch {
    return undefined;
  }
}

/**
 * The manifest as structure, for the dashboard and the report.
 *
 * Every declared component is listed with whether another app can reach it and
 * what guards it, because the counts in `ComponentInventory` cannot answer
 * "which one?".
 */
export function androidFactsOf(
  manifest: XmlNode,
  decoded: string,
  nativeAbis: string[],
): AndroidFacts {
  const application = findFirst(manifest, 'application');
  const flag = (node: XmlNode | null, name: string): boolean | undefined => {
    const value = node ? attr(node, name) : undefined;
    return value === undefined ? undefined : value === 'true';
  };

  const components: AndroidFacts['components'] = [];
  const kinds: [string, AndroidFacts['components'][number]['kind']][] = [
    ['activity', 'activity'], ['activity-alias', 'activity'], ['service', 'service'],
    ['receiver', 'receiver'], ['provider', 'provider'],
  ];
  let launcher: string | undefined;
  for (const [tag, kind] of kinds) {
    for (const node of findAll(manifest, tag)) {
      const filters = findAll(node, 'intent-filter');
      const actions = [...new Set(filters.flatMap((f) => findAll(f, 'action').map((a) => attr(a, 'name') ?? '')).filter(Boolean))];
      const categories = filters.flatMap((f) => findAll(f, 'category').map((c) => attr(c, 'name')));
      const schemes = [...new Set(filters.flatMap((f) => findAll(f, 'data').map((d) => attr(d, 'scheme') ?? '')).filter(Boolean))];
      if (kind === 'activity' && !launcher && categories.includes('android.intent.category.LAUNCHER')) launcher = nameOf(node);
      components.push({
        name: nameOf(node),
        kind,
        exported: isExported(node),
        permission: attr(node, 'permission') ?? attr(node, 'readPermission'),
        actions,
        schemes,
        browsable: categories.includes('android.intent.category.BROWSABLE'),
      });
    }
  }

  return {
    label: resolveString(application ? attr(application, 'label') : undefined, decoded),
    applicationClass: application ? attr(application, 'name') : undefined,
    launcherActivity: launcher,
    debuggable: flag(application, 'debuggable') === true,
    // Android's default is to allow backups when the attribute is absent.
    allowBackup: flag(application, 'allowBackup') !== false,
    cleartextTraffic: flag(application, 'usesCleartextTraffic'),
    testOnly: flag(application, 'testOnly') === true,
    networkSecurityConfig: Boolean(application && attr(application, 'networkSecurityConfig')),
    usesFeatures: findAll(manifest, 'uses-feature').map((f) => ({
      name: attr(f, 'name') ?? attr(f, 'glEsVersion') ?? '?',
      required: attr(f, 'required') !== 'false',
    })),
    customPermissions: findAll(manifest, 'permission').map((p) => ({
      name: attr(p, 'name') ?? '?',
      protection: attr(p, 'protectionLevel') ?? 'normal',
    })),
    components: components.sort((a, b) => Number(b.exported) - Number(a.exported) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name)).slice(0, 400),
    nativeAbis: [...nativeAbis].sort(),
  };
}
