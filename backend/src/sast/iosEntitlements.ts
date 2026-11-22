/**
 * iOS entitlements: what the signature says the app is allowed to do.
 *
 * Entitlements are read from the plist signed into the binary where there is
 * one (ground truth: this is what the kernel enforces) and from the embedded
 * provisioning profile otherwise. Each key gets a risk rating and a sentence of
 * plain language, because a raw list of reverse-DNS strings tells a reader
 * nothing about whether to worry.
 */
import { dictGet } from './plist.ts';
import type { PlistValue } from './plist.ts';
import type { IosFacts, IosRisk, SastFinding } from './types.ts';

const RISK_ORDER: Record<IosRisk, number> = { high: 0, medium: 1, low: 2, info: 3 };

/** A plist value on one line, for a table cell. */
export function plistText(value: PlistValue): string {
  if (value === null) return '';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return `<data ${value.length} bytes>`;
  if (Array.isArray(value)) return value.map(plistText).join(', ');
  return JSON.stringify(value);
}

type Assessment = { risk: IosRisk; note: string };

/** Exact-key ratings. Anything not listed falls through to the prefix rules. */
const EXACT: Record<string, (value: PlistValue) => Assessment> = {
  'get-task-allow': (v) =>
    v === true
      ? { risk: 'high', note: 'Debuggable: any debugger can attach to the running app. Development signing only.' }
      : { risk: 'info', note: 'Not debuggable, as a release build should be.' },
  'application-identifier': () => ({ risk: 'info', note: 'Team id plus bundle id: the identity the signature vouches for.' }),
  'com.apple.developer.team-identifier': () => ({ risk: 'info', note: 'The developer team that signed this build.' }),
  'aps-environment': (v) =>
    v === 'development'
      ? { risk: 'medium', note: 'Push notifications use Apple’s sandbox service. A development build.' }
      : { risk: 'info', note: 'Push notifications enabled against the production service.' },
  'beta-reports-active': () => ({ risk: 'info', note: 'Distributed through TestFlight; crash reports go to the developer.' }),
  'keychain-access-groups': (v) => {
    const groups = Array.isArray(v) ? v.map(plistText) : [];
    return groups.some((g) => g.endsWith('*'))
      ? { risk: 'medium', note: 'A wildcard group lets every app from this team read the items stored under it.' }
      : { risk: 'low', note: 'Keychain items are shared with the listed groups; anything in a group is readable by every app in it.' };
  },
  'com.apple.developer.associated-domains': (v) => {
    const domains = Array.isArray(v) ? v.map(plistText) : [plistText(v)];
    return domains.some((d) => /\?mode=/.test(d))
      ? { risk: 'medium', note: 'A developer-mode suffix bypasses Apple’s CDN cache for association files, and is meant for development only.' }
      : { risk: 'info', note: 'Universal Links and shared web credentials are bound to these verified domains.' };
  },
  'com.apple.developer.devicecheck.appattest-environment': (v) =>
    v === 'development'
      ? { risk: 'medium', note: 'App Attest assertions come from the development environment, which the production server should reject.' }
      : { risk: 'info', note: 'App Attest is configured for production.' },
  'com.apple.developer.default-data-protection': (v) =>
    v === 'NSFileProtectionNone'
      ? { risk: 'high', note: 'Files are created with no encryption at rest by default.' }
      : v === 'NSFileProtectionComplete'
        ? { risk: 'info', note: 'Files are encrypted whenever the device is locked. The strongest default.' }
        : { risk: 'low', note: 'Files stay readable after first unlock; weaker than complete protection.' },
  'com.apple.developer.applesignin': () => ({ risk: 'info', note: 'Sign in with Apple.' }),
  'com.apple.developer.in-app-payments': () => ({ risk: 'low', note: 'Apple Pay merchant identifiers. The app handles payment flows.' }),
  'com.apple.developer.nfc.readersession.formats': () => ({ risk: 'low', note: 'Reads NFC tags; tag content is untrusted input.' }),
  'com.apple.developer.usernotifications.time-sensitive': () => ({ risk: 'low', note: 'Can break through Focus modes.' }),
  'com.apple.developer.usernotifications.critical-alerts': () => ({ risk: 'low', note: 'Critical alerts bypass silent mode.' }),
  'inter-app-audio': () => ({ risk: 'low', note: 'Exchanges audio with other apps.' }),
  'com.apple.developer.kernel.extended-virtual-addressing': () => ({ risk: 'low', note: 'Larger address space, used by memory-hungry apps.' }),
  'dynamic-codesigning': () => ({ risk: 'high', note: 'Permits JIT: writable memory may become executable, which removes a core exploit mitigation.' }),
  'com.apple.security.app-sandbox': (v) =>
    v === false
      ? { risk: 'high', note: 'The App Sandbox is switched off.' }
      : { risk: 'info', note: 'Runs inside the App Sandbox.' },
  'platform-application': () => ({ risk: 'high', note: 'Claims to be a platform binary; only Apple-signed system code may.' }),
};

/** Prefix rules, checked in order after the exact table. */
const PREFIX: [RegExp, Assessment][] = [
  [/^com\.apple\.private\./, { risk: 'high', note: 'A private Apple entitlement. The App Store rejects these; on any other build it signals a jailbreak-style or tampered package.' }],
  [/^com\.apple\.developer\.(healthkit|homekit|clinical)/, { risk: 'medium', note: 'Access to health or home data, which is sensitive personal information.' }],
  [/^com\.apple\.developer\.networking\.(vpn|networkextension|HotspotConfiguration|wifi-info|multicast)/, { risk: 'medium', note: 'Can shape, inspect or reconfigure device network traffic.' }],
  [/^com\.apple\.developer\.(icloud|ubiquity)/, { risk: 'low', note: 'Syncs data through iCloud; the data leaves the device.' }],
  [/^com\.apple\.security\.application-groups$/, { risk: 'low', note: 'Shares a container with other apps and extensions in the listed groups.' }],
  [/^com\.apple\.developer\.carplay/, { risk: 'low', note: 'Renders in CarPlay.' }],
  [/^com\.apple\.developer\.(siri|user-fonts|maps|weatherkit|shared-with-you)/, { risk: 'info', note: 'A platform capability, not a security exposure on its own.' }],
];

export function assessEntitlement(key: string, value: PlistValue): Assessment {
  const exact = EXACT[key];
  if (exact) return exact(value);
  for (const [pattern, assessment] of PREFIX) if (pattern.test(key)) return assessment;
  return { risk: 'info', note: 'No specific risk is attached to this entitlement.' };
}

/** The entitlement table, worst first then alphabetical. */
export function entitlementRows(entitlements: PlistValue): IosFacts['entitlements'] {
  if (!entitlements || typeof entitlements !== 'object' || Array.isArray(entitlements) || Buffer.isBuffer(entitlements)) {
    return [];
  }
  return Object.entries(entitlements as Record<string, PlistValue>)
    .map(([key, value]) => ({ key, value: plistText(value), ...assessEntitlement(key, value) }))
    .sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || a.key.localeCompare(b.key));
}

/**
 * Findings that come from the entitlements themselves.
 *
 * `file` names where the reader can open the source: the signed plist the
 * analyser wrote for the Explorer, or the provisioning profile.
 */
export function entitlementFindings(entitlements: PlistValue, file: string): SastFinding[] {
  const findings: SastFinding[] = [];
  const at = (excerpt: string) => [{ file, excerpt }];

  if (dictGet(entitlements, 'get-task-allow') === true) {
    findings.push({
      ruleId: 'ios.get_task_allow',
      title: 'Binary is debuggable (get-task-allow)',
      category: 'binary',
      severity: 'high',
      description: 'The signed entitlements grant get-task-allow, which is the development signing configuration.',
      impact: 'A debugger can attach to the running process on any provisioned device and read or rewrite its memory. This entitlement must never reach production.',
      exploitation: [
        'Install the build on a provisioned device, or a jailbroken one.',
        'Attach with `lldb -n <app>` or `frida -U -f <bundle id>` — get-task-allow lets the debugger obtain the task port without any exploit.',
        'Read secrets from memory, patch the login check or certificate validation, and dump the keychain items the app can see.',
      ],
      remediation: 'Sign release builds with a distribution certificate and profile. App Store and enterprise profiles do not carry this entitlement, and Xcode strips it on archive.',
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-489',
      locations: at('get-task-allow = true'),
      occurrences: 1,
    });
  }

  if (dictGet(entitlements, 'aps-environment') === 'development') {
    findings.push({
      ruleId: 'ios.aps_development',
      title: 'Push notifications configured for the development environment',
      category: 'manifest',
      severity: 'low',
      description: 'aps-environment is set to development.',
      impact: 'The build talks to Apple’s sandbox push service; production notifications will not be delivered.',
      remediation: 'Use a distribution profile so aps-environment becomes production.',
      locations: at('aps-environment = development'),
      occurrences: 1,
    });
  }

  if (dictGet(entitlements, 'com.apple.developer.devicecheck.appattest-environment') === 'development') {
    findings.push({
      ruleId: 'ios.appattest_development',
      title: 'App Attest is set to the development environment',
      category: 'binary',
      severity: 'medium',
      description: 'The App Attest entitlement selects the development environment.',
      impact: 'Attestations from this build are issued by Apple’s sandbox, so a server that trusts them is trusting a build anyone can produce.',
      remediation: 'Use production for release builds, and have the server reject development attestations.',
      masvs: 'MASVS-RESILIENCE-1',
      locations: at('com.apple.developer.devicecheck.appattest-environment = development'),
      occurrences: 1,
    });
  }

  const protection = dictGet(entitlements, 'com.apple.developer.default-data-protection');
  if (protection === 'NSFileProtectionNone') {
    findings.push({
      ruleId: 'ios.data_protection_none',
      title: 'Default file protection is switched off',
      category: 'storage',
      severity: 'medium',
      description: 'default-data-protection is NSFileProtectionNone.',
      impact: 'Files the app creates are not encrypted at rest, so they can be read from a device image or a locked, seized phone.',
      remediation: 'Use NSFileProtectionComplete, or at least CompleteUntilFirstUserAuthentication, and set stronger classes on sensitive files.',
      masvs: 'MASVS-STORAGE-1',
      cwe: 'CWE-311',
      locations: at('com.apple.developer.default-data-protection = NSFileProtectionNone'),
      occurrences: 1,
    });
  }

  const privateKeys = entitlementKeys(entitlements).filter((k) => k.startsWith('com.apple.private.') || k === 'platform-application');
  if (privateKeys.length > 0) {
    findings.push({
      ruleId: 'ios.private_entitlement',
      title: `${privateKeys.length} private Apple entitlement${privateKeys.length === 1 ? '' : 's'} claimed`,
      category: 'binary',
      severity: 'medium',
      description: 'The signature claims entitlements reserved for Apple’s own software.',
      impact: 'A build carrying these was not produced by the normal developer pipeline, and only runs where signature checks are bypassed — typically a jailbroken device or a repackaged copy.',
      remediation: 'Remove the private entitlements. If this is a repackaged or tool-signed copy of your app, obtain the original build for the assessment.',
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-269',
      locations: privateKeys.map((k) => ({ file, excerpt: k })),
      occurrences: privateKeys.length,
    });
  }

  if (dictGet(entitlements, 'dynamic-codesigning') === true) {
    findings.push({
      ruleId: 'ios.dynamic_codesigning',
      title: 'Just-in-time code generation permitted',
      category: 'binary',
      severity: 'medium',
      description: 'The dynamic-codesigning entitlement is granted.',
      impact: 'The app may turn writable memory into executable memory, which removes the code-signing guarantee that only reviewed code runs.',
      remediation: 'Remove it unless the app genuinely embeds a JIT compiler. Apple grants this only to browsers and a few system components.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-94',
      locations: at('dynamic-codesigning = true'),
      occurrences: 1,
    });
  }

  const domains = dictGet(entitlements, 'com.apple.developer.associated-domains');
  const developerMode = (Array.isArray(domains) ? domains.map(plistText) : []).filter((d) => /\?mode=/.test(d));
  if (developerMode.length > 0) {
    findings.push({
      ruleId: 'ios.associated_domains_dev',
      title: 'Associated domains use developer mode',
      category: 'manifest',
      severity: 'medium',
      description: 'One or more associated domains carry a ?mode= suffix.',
      impact: 'The device fetches the apple-app-site-association file straight from your server rather than through Apple’s CDN, which is a development convenience and means the link trust can be redirected on a hostile network.',
      remediation: 'Remove the ?mode=developer suffix from release builds.',
      masvs: 'MASVS-PLATFORM-1',
      locations: developerMode.map((d) => ({ file, excerpt: d })),
      occurrences: developerMode.length,
    });
  }

  const groups = dictGet(entitlements, 'keychain-access-groups');
  if (Array.isArray(groups) && groups.some((g) => typeof g === 'string' && g.endsWith('*'))) {
    findings.push({
      ruleId: 'ios.keychain_group_wildcard',
      title: 'Keychain access group is a wildcard',
      category: 'storage',
      severity: 'low',
      kind: 'hotspot',
      description: 'An entry in keychain-access-groups ends in a wildcard.',
      impact: 'Every app signed by the same team can read items the app stores in that group. That is intended for app suites and a mistake everywhere else.',
      remediation: 'Scope the group to the specific bundle identifiers that must share the item.',
      masvs: 'MASVS-STORAGE-1',
      cwe: 'CWE-732',
      locations: at('keychain-access-groups'),
      occurrences: 1,
    });
  }

  return findings;
}

function entitlementKeys(entitlements: PlistValue): string[] {
  if (!entitlements || typeof entitlements !== 'object' || Array.isArray(entitlements) || Buffer.isBuffer(entitlements)) {
    return [];
  }
  return Object.keys(entitlements as Record<string, PlistValue>);
}
