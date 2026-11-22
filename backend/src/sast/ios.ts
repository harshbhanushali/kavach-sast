/**
 * iOS static analysis.
 *
 * An IPA gives up less than an APK and the report should not pretend otherwise.
 * There is no apktool equivalent: the app binary is compiled machine code, so
 * the code-pattern rules run against its string table rather than against
 * anything resembling source. What *is* fully readable — Info.plist, the
 * entitlements, the code signature, the provisioning profile and the Mach-O load
 * commands of every image in the bundle — is parsed properly, and those carry
 * most of the configuration findings anyway.
 *
 * Every gap this creates is recorded in `limitations` and surfaced in the
 * report, so a clean iOS scorecard is never mistaken for the same depth of
 * assurance as a clean Android one.
 */
import type { LiveEvent, ProgressSink } from './progress.ts';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { iosIcon } from './appIcon.ts';
import { entitlementFindings, entitlementRows } from './iosEntitlements.ts';
import { inventoryBinaries } from './iosBinaries.ts';
import { describePermission } from './iosPermissions.ts';
import { readMachO } from './macho.ts';
import { renderBinaryView } from './machoView.ts';
import type { MachOFacts } from './macho.ts';
import { BINARY_PLIST_NOTE, dictGet, parsePlist, renderPlist } from './plist.ts';
import type { PlistValue } from './plist.ts';
import { PATTERN_RULES, rulesFor } from './rules.ts';
import { FUNCTION_LEVEL_RULES, analyseIosBinary } from './iosFlow.ts';
import type { IosAnalysis as IosFlowAnalysis } from './iosFlow.ts';
import { findingFrom, mergeFindings, scanBinaryStrings, scanFiles, snippetAround, walk } from './scanner.ts';
import type { WalkedFile } from './scanner.ts';
import { runRecon } from './recon.ts';
import type { ComponentInventory, IosFacts, ReconSection, SastCategory, SastFinding, SastLocation, SnippetLine } from './types.ts';

export type IosAnalysis = {
  findings: SastFinding[];
  decompiler: 'java' | 'smali' | 'none';
  javaFileCount: number;
  /** Always empty: an IPA carries no Maven-style version metadata. */
  dependencies: { coordinate: string; version: string; source: string; advisoryCount: number }[];
  secure: SastFinding[];
  hotspots: SastFinding[];
  recon: ReconSection;
  components: ComponentInventory;
  permissionDetail: { name: string; level: string; description: string }[];
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minimumOsVersion?: string;
  permissions: string[];
  signers: string[];
  signatureSchemes: string[];
  nativeLibraries: string[];
  detectedLibraries: string[];
  binaryProtections?: {
    pie: boolean; arc: boolean; stackCanary: boolean;
    encrypted: boolean; nonExecutableStack: boolean; archCount: number;
  };
  /** The structure behind the findings; see `IosFacts`. */
  ios?: IosFacts;
  iconDataUrl?: string;
  fileCount: number;
  /** Every file in the bundle (capped), so the replay draws the whole app and not only the files the Explorer keeps. */
  fileListing?: string[];
  /** Where a finding's path is relative to; see the Android analysis. */
  sourceRoots: (string | undefined)[];
  /** Readable renderings of binary files, written at those files' own paths; see `collectSources`. */
  syntheticRoot?: string;
  limitations: string[];
};

/**
 * Every structural iOS rule: id, title, category and what it reads.
 *
 * One list feeds the scorecard's rule counts and the report's coverage table, so
 * a rule cannot be implemented here and be missing from the audit — the two used
 * to be maintained by hand in scan.ts and had drifted apart.
 */
export const IOS_STRUCTURAL_RULES: [string, string, SastCategory, string][] = [
  ['ios.ats_arbitrary_loads', 'App Transport Security disabled globally', 'network', 'Info.plist'],
  ['ios.ats_webcontent', 'ATS disabled for web views', 'network', 'Info.plist'],
  ['ios.ats_media', 'ATS disabled for media loads', 'network', 'Info.plist'],
  ['ios.ats_insecure_domain', 'ATS exception domains allow cleartext', 'network', 'Info.plist'],
  ['ios.ats_weak_tls', 'ATS exception domains accept weak TLS', 'network', 'Info.plist'],
  ['ios.custom_url_scheme', 'Custom URL schemes registered', 'manifest', 'Info.plist'],
  ['ios.aps_development', 'Push configured for the development environment', 'manifest', 'entitlements'],
  ['ios.associated_domains_dev', 'Associated domains use developer mode', 'manifest', 'entitlements'],
  ['ios.no_privacy_manifest', 'No privacy manifest bundled', 'manifest', 'app bundle'],
  ['ios.low_min_os', 'Minimum iOS version is out of support', 'manifest', 'Info.plist'],
  ['ios.permissions_many', 'Many sensitive permissions requested', 'manifest', 'Info.plist'],
  ['ios.file_sharing', 'iTunes file sharing enabled', 'storage', 'Info.plist'],
  ['ios.data_protection_none', 'Default file protection is switched off', 'storage', 'entitlements'],
  ['ios.keychain_group_wildcard', 'Keychain access group is a wildcard', 'storage', 'entitlements'],
  ['ios.get_task_allow', 'Binary is debuggable (get-task-allow)', 'binary', 'entitlements'],
  ['ios.private_entitlement', 'Private Apple entitlements claimed', 'binary', 'entitlements'],
  ['ios.dynamic_codesigning', 'Just-in-time code generation permitted', 'binary', 'entitlements'],
  ['ios.appattest_development', 'App Attest set to the development environment', 'binary', 'entitlements'],
  ['ios.no_pie', 'Binary is not position-independent', 'binary', 'Mach-O headers'],
  ['ios.no_stack_canary', 'Stack protector not linked', 'binary', 'Mach-O symbol table'],
  ['ios.no_arc', 'Automatic Reference Counting not detected', 'binary', 'Mach-O symbol table'],
  ['ios.stack_execution', 'Stack is executable', 'binary', 'Mach-O headers'],
  ['ios.rwx_segment', 'Segment is writable and executable', 'binary', 'Mach-O segments'],
  ['ios.rpath_insecure', 'Run-path search entries outside the bundle', 'binary', 'Mach-O load commands'],
  ['ios.symbols_not_stripped', 'Local symbols left in the binary', 'binary', 'Mach-O symbol table'],
  ['ios.debug_dylib', 'Debug build artefacts shipped', 'binary', 'app bundle'],
  ['ios.simulator_build', 'Built for the iOS Simulator', 'binary', 'Info.plist'],
  ['ios.framework_hardening', 'Embedded frameworks missing a stack protector', 'binary', 'embedded Mach-O images'],
  ['ios.unsigned_binary', 'Binary carries no code signature', 'signing', 'Mach-O code signature'],
  ['ios.adhoc_signature', 'Binary is signed ad hoc, with no identity', 'signing', 'Mach-O code signature'],
  ['ios.profile_expired', 'Provisioning profile has expired', 'signing', 'embedded.mobileprovision'],
  ['ios.wildcard_app_id', 'Wildcard application identifier', 'signing', 'embedded.mobileprovision'],
  ['ios.embedded_unsigned', 'Embedded code is not signed', 'signing', 'embedded Mach-O images'],
  ['ios.firebase_config', 'Firebase configuration bundled', 'secrets', 'GoogleService-Info.plist'],
  ['recon.trackers', 'Privacy trackers bundled', 'dependencies', 'framework signatures'],
];

/** Info.plist keys that declare a privacy-sensitive capability. */
const USAGE_KEY = /^NS\w+UsageDescription$/;

function asString(value: PlistValue): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function isDict(value: PlistValue): value is Record<string, PlistValue> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value) && !(value instanceof Date);
}

function stringList(value: PlistValue): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (isDict(value)) return Object.keys(value);
  return [];
}

/** Parses a plist, returning null rather than throwing on a damaged file. */
function tryParse(buffer: Buffer): PlistValue {
  try {
    return parsePlist(buffer);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ ATS */

function readAts(info: PlistValue): IosFacts['ats'] {
  const ats = dictGet(info, 'NSAppTransportSecurity');
  const facts: IosFacts['ats'] = {
    configured: isDict(ats),
    arbitraryLoads: dictGet(ats, 'NSAllowsArbitraryLoads') === true,
    arbitraryLoadsInWebContent: dictGet(ats, 'NSAllowsArbitraryLoadsInWebContent') === true,
    arbitraryLoadsForMedia: dictGet(ats, 'NSAllowsArbitraryLoadsForMedia') === true,
    localNetworking: dictGet(ats, 'NSAllowsLocalNetworking') === true,
    domains: [],
  };
  const domains = dictGet(ats, 'NSExceptionDomains');
  if (isDict(domains)) {
    for (const [domain, config] of Object.entries(domains)) {
      const secrecy = dictGet(config, 'NSExceptionRequiresForwardSecrecy');
      facts.domains.push({
        domain,
        allowsHttp:
          dictGet(config, 'NSExceptionAllowsInsecureHTTPLoads') === true ||
          dictGet(config, 'NSThirdPartyExceptionAllowsInsecureHTTPLoads') === true,
        includesSubdomains: dictGet(config, 'NSIncludesSubdomains') === true,
        minTls: asString(dictGet(config, 'NSExceptionMinimumTLSVersion')) ?? asString(dictGet(config, 'NSThirdPartyExceptionMinimumTLSVersion')),
        forwardSecrecy: typeof secrecy === 'boolean' ? secrecy : undefined,
        thirdParty: isDict(config) && Object.keys(config).some((k) => k.startsWith('NSThirdPartyException')),
      });
    }
  }
  return facts;
}

/**
 * App Transport Security.
 *
 * ATS is secure by default; every finding here is an explicit opt-out someone
 * added. That makes these high-confidence: there is no ambiguity about whether
 * a default was merely left alone.
 */
function atsFindings(ats: IosFacts['ats']): SastFinding[] {
  if (!ats.configured) return [];
  const findings: SastFinding[] = [];

  if (ats.arbitraryLoads) {
    findings.push({
      ruleId: 'ios.ats_arbitrary_loads',
      title: 'App Transport Security disabled globally',
      category: 'network',
      severity: 'medium',
      description: 'NSAllowsArbitraryLoads is true, which switches ATS off for the whole app.',
      impact: 'The app may connect over plain HTTP and with weak TLS to any host, so its traffic can be read and modified on the network path.',
      exploitation: [
        'Join the same Wi-Fi as the victim, or run a rogue access point.',
        'Point the device at a proxy such as mitmproxy: with ATS off, the app accepts plain HTTP and legacy TLS, so downgrading the connection needs no certificate trick.',
        'Read or rewrite API traffic — session tokens, credentials, responses that drive app behaviour.',
      ],
      remediation: 'Remove the key. Where one legacy host genuinely needs an exception, scope it with NSExceptionDomains for that host alone.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: [{ file: 'Info.plist', excerpt: 'NSAppTransportSecurity.NSAllowsArbitraryLoads = true' }],
      occurrences: 1,
    });
  }

  if (ats.arbitraryLoadsInWebContent) {
    findings.push({
      ruleId: 'ios.ats_webcontent',
      title: 'ATS disabled for web views',
      category: 'network',
      severity: 'medium',
      description: 'NSAllowsArbitraryLoadsInWebContent permits insecure loads inside WKWebView.',
      impact: 'Content rendered in the app’s web views can be served and tampered with over cleartext.',
      remediation: 'Remove the key and serve web content over HTTPS.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: [{ file: 'Info.plist', excerpt: 'NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent = true' }],
      occurrences: 1,
    });
  }

  if (ats.arbitraryLoadsForMedia) {
    findings.push({
      ruleId: 'ios.ats_media',
      title: 'ATS disabled for media playback',
      category: 'network',
      severity: 'low',
      description: 'NSAllowsArbitraryLoadsForMedia lets AVFoundation load media over plain HTTP.',
      impact: 'Streams can be swapped or observed in transit. Content that carries tokens in its URL leaks them.',
      remediation: 'Serve media over HTTPS and remove the key.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: [{ file: 'Info.plist', excerpt: 'NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia = true' }],
      occurrences: 1,
    });
  }

  const cleartext = ats.domains.filter((d) => d.allowsHttp);
  if (cleartext.length > 0) {
    findings.push({
      ruleId: 'ios.ats_insecure_domain',
      title: `${cleartext.length} ATS exception domain${cleartext.length === 1 ? '' : 's'} allow cleartext`,
      category: 'network',
      severity: 'medium',
      description: 'Named domains are exempted from ATS and may be reached over HTTP.',
      impact: 'Traffic to those hosts is readable and modifiable in transit.',
      remediation: 'Move the hosts to HTTPS and delete the exceptions. Apple requires a justification for these at review.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-319',
      locations: cleartext.map((d) => ({ file: 'Info.plist', excerpt: `${d.domain}${d.includesSubdomains ? ' (and subdomains)' : ''}` })),
      occurrences: cleartext.length,
    });
  }

  const weakTls = ats.domains.filter((d) => d.minTls === 'TLSv1.0' || d.minTls === 'TLSv1.1' || d.forwardSecrecy === false);
  if (weakTls.length > 0) {
    findings.push({
      ruleId: 'ios.ats_weak_tls',
      title: `${weakTls.length} ATS exception domain${weakTls.length === 1 ? '' : 's'} accept weak TLS`,
      category: 'network',
      severity: 'medium',
      description: 'Exception domains lower the minimum TLS version or waive forward secrecy.',
      impact: 'A connection may negotiate TLS 1.0/1.1 or a cipher suite without forward secrecy, both of which are breakable with a recorded session and a later key compromise.',
      remediation: 'Require TLS 1.2 or later with forward secrecy for every host, and delete the exception once the server is upgraded.',
      masvs: 'MASVS-NETWORK-1',
      cwe: 'CWE-326',
      locations: weakTls.map((d) => ({
        file: 'Info.plist',
        excerpt: `${d.domain}: ${[d.minTls ? `NSExceptionMinimumTLSVersion = ${d.minTls}` : '', d.forwardSecrecy === false ? 'NSExceptionRequiresForwardSecrecy = false' : ''].filter(Boolean).join(', ')}`,
      })),
      occurrences: weakTls.length,
    });
  }

  return findings;
}

/* ---------------------------------------------------------- URL schemes */

function readUrlSchemes(info: PlistValue): IosFacts['urlSchemes'] {
  const types = dictGet(info, 'CFBundleURLTypes');
  if (!Array.isArray(types)) return [];
  const out: IosFacts['urlSchemes'] = [];
  for (const type of types) {
    const schemes = stringList(dictGet(type, 'CFBundleURLSchemes'));
    if (schemes.length === 0) continue;
    out.push({
      name: asString(dictGet(type, 'CFBundleURLName')),
      role: asString(dictGet(type, 'CFBundleTypeRole')),
      schemes,
    });
  }
  return out;
}

/** Custom URL schemes: an unauthenticated entry point into the app. */
function urlSchemeFindings(entries: IosFacts['urlSchemes']): SastFinding[] {
  const schemes = entries.flatMap((e) => e.schemes);
  if (schemes.length === 0) return [];

  return [
    {
      ruleId: 'ios.custom_url_scheme',
      title: `${schemes.length} custom URL scheme${schemes.length === 1 ? '' : 's'} registered`,
      category: 'manifest',
      severity: 'low',
      description: 'The app registers URL schemes that any other app, or any web page, can invoke.',
      impact: 'Schemes are not exclusive on iOS: another app can register the same one. Any action reachable through a scheme is reachable without authentication.',
      exploitation: [
        `Host a web page containing a link such as <a href="${schemes[0]}://…">; a victim who taps it launches the app with attacker-chosen parameters.`,
        'Or install a second app that registers the same scheme: iOS does not say which one wins, so it can intercept OAuth callbacks and deep links meant for this app.',
        'Any handler that acts on the URL without re-authenticating the user — transfer, reset, login — is reachable this way.',
      ],
      remediation: 'Validate every parameter arriving via a URL, never perform a privileged action directly from one, and prefer Universal Links, which are bound to your verified domain.',
      masvs: 'MASVS-PLATFORM-1',
      cwe: 'CWE-939',
      locations: schemes.slice(0, 12).map((s) => ({ file: 'Info.plist', excerpt: `CFBundleURLTypes → CFBundleURLSchemes: ${s}://` })),
      occurrences: schemes.length,
    },
  ];
}

/* ------------------------------------------------------ profile & signing */

type ProfileRead = {
  facts?: IosFacts['profile'];
  entitlements: PlistValue;
  plistXml?: string;
  provisionedDevices: boolean;
  provisionsAll: boolean;
  findings: SastFinding[];
  signers: string[];
};

/** The embedded profile: CMS-wrapped, with the plist readable inside it. */
function readProfile(appDir: string): ProfileRead {
  const none: ProfileRead = { entitlements: null, provisionedDevices: false, provisionsAll: false, findings: [], signers: [] };
  const profilePath = join(appDir, 'embedded.mobileprovision');
  if (!existsSync(profilePath)) return none;

  const text = readFileSync(profilePath).toString('latin1');
  const start = text.indexOf('<?xml');
  const end = text.indexOf('</plist>');
  if (start < 0 || end < 0) return none;

  const xml = text.slice(start, end + 8);
  const profile = tryParse(Buffer.from(xml, 'latin1'));
  if (!profile) return none;

  const name = asString(dictGet(profile, 'Name'));
  const teamName = asString(dictGet(profile, 'TeamName'));
  const entitlements = dictGet(profile, 'Entitlements');
  const devices = dictGet(profile, 'ProvisionedDevices');
  const created = dictGet(profile, 'CreationDate');
  const expires = dictGet(profile, 'ExpirationDate');
  const findings: SastFinding[] = [];

  // MASTG-APP-CODE-SIGNING: a profile that has expired, or one scoped to a
  // wildcard App ID, both say the build was not produced by the release
  // pipeline that ships to users.
  const expired = expires instanceof Date && expires.getTime() < Date.now();
  if (expired && expires instanceof Date) {
    findings.push({
      ruleId: 'ios.profile_expired',
      title: 'Provisioning profile has expired',
      category: 'signing',
      severity: 'medium',
      description: `The embedded profile expired on ${expires.toISOString().slice(0, 10)}.`,
      impact: 'The app will refuse to launch on a device once the profile lapses, and an expired profile means this artifact is not the one being shipped.',
      remediation: 'Re-sign with a current distribution profile before distributing the build.',
      masvs: 'MASVS-CODE-1',
      locations: [{ file: '_signature/embedded.mobileprovision.plist', excerpt: `ExpirationDate = ${expires.toISOString()}` }],
      occurrences: 1,
    });
  }

  const appIdName = asString(dictGet(entitlements, 'application-identifier'));
  if (appIdName && /\*$/.test(appIdName)) {
    findings.push({
      ruleId: 'ios.wildcard_app_id',
      title: 'Wildcard application identifier',
      category: 'signing',
      severity: 'medium',
      description: `The profile is issued for the wildcard identifier ${appIdName}.`,
      impact: 'A wildcard profile signs any bundle id in the team, so the signature says far less about which app this is. Keychain and app-group access are scoped by that identifier too.',
      remediation: 'Issue an explicit App ID for the bundle identifier and sign release builds with it.',
      masvs: 'MASVS-CODE-1',
      cwe: 'CWE-284',
      locations: [{ file: '_signature/embedded.mobileprovision.plist', excerpt: `application-identifier = ${appIdName}` }],
      occurrences: 1,
    });
  }

  return {
    facts: {
      name,
      uuid: asString(dictGet(profile, 'UUID')),
      teamName,
      teamId: stringList(dictGet(profile, 'TeamIdentifier'))[0],
      created: created instanceof Date ? created.toISOString() : undefined,
      expires: expires instanceof Date ? expires.toISOString() : undefined,
      expired,
      deviceCount: Array.isArray(devices) ? devices.length : undefined,
      platform: stringList(dictGet(profile, 'Platform'))[0],
    },
    entitlements,
    plistXml: xml,
    provisionedDevices: Array.isArray(devices),
    provisionsAll: dictGet(profile, 'ProvisionsAllDevices') === true,
    findings,
    signers: [teamName, name ? `Profile: ${name}` : undefined].filter((s): s is string => Boolean(s)),
  };
}

/* ------------------------------------------------------------- the binary */

const SAFE_RPATH = /^(@executable_path|@loader_path|@rpath)(\/|$)|^\/(usr\/lib|System)(\/|$)/;

/** Compiler and linker hardening, read from the Mach-O load commands. */
function binaryFindings(name: string, facts: MachOFacts): { findings: SastFinding[]; hotspots: SastFinding[]; limitations: string[] } {
  const findings: SastFinding[] = [];
  const hotspots: SastFinding[] = [];

  if (!facts.pie) {
    findings.push({
      ruleId: 'ios.no_pie',
      title: 'Binary is not position-independent',
      category: 'binary',
      severity: 'medium',
      description: 'The MH_PIE flag is not set on the Mach-O header.',
      impact: 'The image loads at a predictable address, so ASLR does not apply and memory-corruption bugs become far easier to exploit reliably.',
      exploitation: [
        'Find a memory-corruption bug (an unchecked `strcpy` or `memcpy` is enough).',
        'Because the image loads at a fixed address, gadget addresses are known in advance and can be hard-coded into a ROP chain.',
        'Without ASLR the exploit works on every device on the first attempt rather than needing an information leak.',
      ],
      remediation: 'Build with -fPIC and link with -pie. Xcode sets this by default; an explicit override usually removed it.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-121',
      locations: [{ file: name, excerpt: 'Mach-O header: MH_PIE not set' }],
      occurrences: 1,
    });
  }

  if (!facts.stackCanary) {
    findings.push({
      ruleId: 'ios.no_stack_canary',
      title: 'Stack protector not linked',
      category: 'binary',
      severity: 'medium',
      description: 'No reference to __stack_chk_fail or __stack_chk_guard is present in the symbol table.',
      impact: 'Stack buffer overflows are not detected at return, so a corrupted return address is simply used.',
      remediation: 'Compile with -fstack-protector-strong.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-121',
      locations: [{ file: name, excerpt: 'Mach-O symbol table: no __stack_chk_fail import' }],
      occurrences: 1,
    });
  }

  if (!facts.arc) {
    findings.push({
      ruleId: 'ios.no_arc',
      title: 'Automatic Reference Counting not detected',
      category: 'binary',
      severity: 'low',
      description: 'The ARC runtime symbols are absent, suggesting manual retain/release.',
      impact: 'Manual memory management is the usual source of use-after-free and double-free bugs in Objective-C.',
      remediation: 'Enable ARC (-fobjc-arc), or confirm this is a pure C binary where the finding does not apply.',
      masvs: 'MASVS-CODE-3',
      cwe: 'CWE-416',
      locations: [{ file: name, excerpt: 'Mach-O symbol table: no _objc_release import' }],
      occurrences: 1,
    });
  }

  if (facts.allowsStackExecution) {
    findings.push({
      ruleId: 'ios.stack_execution',
      title: 'Stack is executable',
      category: 'binary',
      severity: 'medium',
      description: 'MH_ALLOW_STACK_EXECUTION is set.',
      impact: 'Code placed on the stack can be executed, which removes one of the main barriers to exploiting a memory-corruption bug.',
      remediation: 'Remove -allow_stack_execute from the link flags.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-119',
      locations: [{ file: name, excerpt: 'Mach-O header: MH_ALLOW_STACK_EXECUTION set' }],
      occurrences: 1,
    });
  }

  if (facts.rwxSegments.length > 0) {
    findings.push({
      ruleId: 'ios.rwx_segment',
      title: 'Memory segment is writable and executable',
      category: 'binary',
      severity: 'medium',
      description: `Segment${facts.rwxSegments.length === 1 ? '' : 's'} ${facts.rwxSegments.join(', ')} ${facts.rwxSegments.length === 1 ? 'is' : 'are'} mapped read, write and execute at once.`,
      impact: 'Memory an attacker can write is also memory the CPU will run, so injected shellcode needs no code-reuse trick.',
      remediation: 'Split the segment so no region is both writable and executable, and remove the linker flag that produced it.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-123',
      locations: facts.rwxSegments.map((s) => ({ file: name, excerpt: `${s}: initprot rwx` })),
      occurrences: facts.rwxSegments.length,
    });
  }

  const unsafeRpaths = [...new Set(facts.rpaths)].filter((r) => !SAFE_RPATH.test(r));
  if (unsafeRpaths.length > 0) {
    findings.push({
      ruleId: 'ios.rpath_insecure',
      title: 'Run-path search entries point outside the bundle',
      category: 'binary',
      severity: 'low',
      description: `LC_RPATH names ${unsafeRpaths.length === 1 ? 'a location' : 'locations'} that ${unsafeRpaths.length === 1 ? 'is' : 'are'} neither inside the app bundle nor a system directory.`,
      impact: 'A library planted at one of these paths is loaded in place of the intended one on a device where that path is writable, and the path itself discloses the build machine’s layout.',
      remediation: 'Limit LC_RPATH to @executable_path/Frameworks and @loader_path/Frameworks.',
      masvs: 'MASVS-CODE-4',
      cwe: 'CWE-427',
      locations: unsafeRpaths.map((r) => ({ file: name, excerpt: `LC_RPATH ${r}` })),
      occurrences: unsafeRpaths.length,
    });
  }

  if (facts.localSymbols > 1000) {
    hotspots.push({
      ruleId: 'ios.symbols_not_stripped',
      title: 'Local symbols left in the binary',
      category: 'binary',
      severity: 'low',
      kind: 'hotspot',
      description: `The symbol table still holds ${facts.localSymbols.toLocaleString()} local symbols.`,
      impact: 'Function and class names make a disassembly far easier to read, which shortens the time to find the login check, the pinning routine or the key derivation.',
      remediation: 'Set Strip Style to All Symbols and Strip Linked Product to Yes for release, and keep the dSYM privately for crash symbolication.',
      masvs: 'MASVS-RESILIENCE-3',
      cwe: 'CWE-497',
      locations: [{ file: name, excerpt: `LC_DYSYMTAB nlocalsym = ${facts.localSymbols}` }],
      occurrences: 1,
    });
  }

  const limitations: string[] = [];
  if (!facts.encrypted) {
    limitations.push(
      'The binary is not FairPlay-encrypted, so its strings were readable in full. An App Store build would be encrypted, which reduces what this scan can see from a downloaded copy — but not from a jailbroken device, where the decrypted image is recoverable.',
    );
  }
  if (facts.archCount > 1) {
    limitations.push(`This is a universal binary with ${facts.archCount} slices; only the ${facts.arch ?? 'first'} slice was inspected.`);
  }
  return { findings, hotspots, limitations };
}

function signingFindings(name: string, facts: MachOFacts): SastFinding[] {
  const findings: SastFinding[] = [];
  if (!facts.signature.present) {
    findings.push({
      ruleId: 'ios.unsigned_binary',
      title: 'Binary carries no code signature',
      category: 'signing',
      severity: 'medium',
      description: 'The Mach-O image has no LC_CODE_SIGNATURE command.',
      impact: 'iOS refuses to run unsigned code on a stock device, so this build only runs where signature enforcement is off, and nothing guarantees it is the code that was built.',
      remediation: 'Sign the app with a distribution certificate as the last step of the build.',
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-347',
      locations: [{ file: name, excerpt: 'no LC_CODE_SIGNATURE load command' }],
      occurrences: 1,
    });
  } else if (facts.signature.adhoc) {
    findings.push({
      ruleId: 'ios.adhoc_signature',
      title: 'Binary is signed ad hoc, with no identity',
      category: 'signing',
      severity: 'medium',
      description: 'The code directory carries the ad-hoc flag and no team identifier.',
      impact: 'The signature proves the binary is unchanged since it was signed, but not who signed it, so any party can re-sign a modified copy.',
      remediation: 'Sign with a distribution certificate from your developer team.',
      masvs: 'MASVS-RESILIENCE-2',
      cwe: 'CWE-347',
      locations: [{ file: name, excerpt: 'CodeDirectory flags: CS_ADHOC' }],
      occurrences: 1,
    });
  }
  return findings;
}

/* ------------------------------------------------- binary plists for rules */

/**
 * Bundle property lists as text, so the pattern rules can read them.
 *
 * `scanFiles` reads files as UTF-8, and the plists Xcode writes are binary, so
 * every setting, URL and key in a `.plist` was invisible to the rules. Each is
 * decoded into `decodedDir` and keeps its original relative path, so a finding
 * still names the file the reader will open.
 */
function decodeBundleText(files: WalkedFile[], decodedDir: string): WalkedFile[] {
  return files.map((file) => {
    if (!/\.(plist|strings|xcprivacy)$/i.test(file.relative) || file.size > 2 * 1024 * 1024) return file;
    let raw: Buffer;
    try {
      raw = readFileSync(file.absolute);
    } catch {
      return file;
    }

    let text: string | undefined;
    if (raw.subarray(0, 6).equals(Buffer.from('bplist'))) {
      const parsed = tryParse(raw);
      if (parsed !== null) text = `${BINARY_PLIST_NOTE}${renderPlist(parsed, 0)}`;
    } else if ((raw[0] === 0xff && raw[1] === 0xfe) || (raw[0] === 0xfe && raw[1] === 0xff)) {
      // UTF-16 .strings, which the UTF-8 read turns into NUL-separated noise.
      const body = Buffer.from(raw.subarray(2, 2 + ((raw.length - 2) & ~1)));
      text = (raw[0] === 0xfe ? body.swap16() : body).toString('utf16le');
    }
    if (text === undefined) return file;

    const target = join(decodedDir, file.relative);
    try {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, text);
    } catch {
      return file;
    }
    return { absolute: target, relative: file.relative, size: Buffer.byteLength(text) };
  });
}

/** Firebase and Google service config: not a secret, but the most useful thing to find. */
function firebaseFinding(files: WalkedFile[], appName: string): SastFinding | undefined {
  const file = files.find((f) => f.relative === `${appName}/GoogleService-Info.plist`);
  if (!file) return undefined;
  const plist = tryParse(readFileSync(file.absolute));
  if (!isDict(plist)) return undefined;

  const project = asString(plist.PROJECT_ID);
  const rows = [
    ['PROJECT_ID', project],
    ['GOOGLE_APP_ID', asString(plist.GOOGLE_APP_ID)],
    ['STORAGE_BUCKET', asString(plist.STORAGE_BUCKET)],
    ['DATABASE_URL', asString(plist.DATABASE_URL)],
    ['BUNDLE_ID', asString(plist.BUNDLE_ID)],
  ].filter((r): r is [string, string] => Boolean(r[1]));

  return {
    ruleId: 'ios.firebase_config',
    title: project ? `Firebase project ${project} is configured in the app` : 'Firebase configuration is bundled with the app',
    category: 'secrets',
    severity: 'low',
    kind: 'hotspot',
    description: 'GoogleService-Info.plist ships in the bundle with the project identifiers and an API key.',
    impact: 'The key is not a secret — it identifies the project — but anyone can read it and call the project’s services with it. What it may reach depends entirely on the project’s security rules and the key’s restrictions.',
    remediation: 'Restrict the API key to this bundle id in the Google Cloud console, and confirm Firestore, Realtime Database and Storage rules deny unauthenticated access.',
    masvs: 'MASVS-STORAGE-2',
    cwe: 'CWE-200',
    locations: rows.map(([key, value]) => ({ file: 'GoogleService-Info.plist', excerpt: `${key} = ${value}` })),
    occurrences: rows.length || 1,
  };
}

/** A result shape for the paths where nothing could be read. */
function emptyIosAnalysis(): IosAnalysis {
  return {
    findings: [], decompiler: 'none', javaFileCount: 0, dependencies: [], secure: [], hotspots: [],
    recon: { endpoints: [], hosts: [], emails: [], trackers: [], keyFiles: [] },
    components: { activities: 0, services: 0, receivers: 0, providers: 0, exported: 0, browsable: [] },
    permissionDetail: [],
    permissions: [], signers: [], signatureSchemes: [],
    nativeLibraries: [], detectedLibraries: [], sourceRoots: [], limitations: [], fileCount: 0,
  };
}

/** "13.6" against "15": numeric, component-wise. */
function versionBelow(version: string | undefined, floor: number): boolean {
  const major = Number.parseInt(version ?? '', 10);
  return Number.isFinite(major) && major < floor;
}

export function analyseIpa(
  ipaPath: string,
  workDir: string,
  progress: ProgressSink = () => {},
): IosAnalysis {
  const limitations: string[] = [
    'iOS binaries ship as compiled machine code, so there is no source to read. Rules ran on the binary\'s string table and, for an unencrypted build, on what each function calls and which literals it uses. That finds a handler that never evaluates a certificate or a key passed to an API; it does not follow values the way the Android analysis does through decompiled Java.',
  ];
  const groups: SastFinding[][] = [];
  const extraHotspots: SastFinding[] = [];
  const rules = rulesFor('ios');

  progress('decoding');
  const extracted = join(workDir, 'extracted');
  try {
    execFileSync('/usr/bin/unzip', ['-qq', '-o', ipaPath, '-d', extracted], {
      timeout: 240_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
  } catch (error) {
    return { ...emptyIosAnalysis(), limitations: [`The IPA could not be unpacked: ${(error as Error).message.split('\n')[0]}`] };
  }
  // An IPA built by some tools stores files with no read permission (mode 000), which unzip faithfully applies.
  try {
    execFileSync('/bin/chmod', ['-R', 'u+rwX', extracted], { timeout: 60_000 });
  } catch {
    // Best effort: a file that is still unreadable is reported where it is read.
  }

  const payload = join(extracted, 'Payload');
  const files = existsSync(payload) ? walk(payload) : [];
  const appDirName = files
    .map((f) => f.relative.split('/')[0])
    .find((name) => name.endsWith('.app'));

  if (!appDirName) {
    return { ...emptyIosAnalysis(), limitations: ['No Payload/*.app bundle was found; this does not look like an IPA.'] };
  }

  const appDir = join(payload, appDirName);
  const appFiles = files.filter((f) => f.relative.startsWith(`${appDirName}/`));

  // What the console's live map is told: the bundle's files, then the ones read as the scan reads them.
  const tell = (stage: Parameters<ProgressSink>[0], event: LiveEvent, fraction?: number) => progress(stage, fraction, undefined, event);
  tell('unpacking', { t: 'app', packageName: appDirName, bundle: true });
  for (let i = 0; i < appFiles.length; i += 1500) tell('unpacking', { t: 'files', paths: appFiles.slice(i, i + 1500).map((f) => f.relative) });

  // Info.plist: the bundle's declared configuration.
  let packageName: string | undefined;
  let versionName: string | undefined;
  let versionCode: string | undefined;
  let minimumOsVersion: string | undefined;
  let permissions: string[] = [];
  let permissionDetail: IosAnalysis['permissionDetail'] = [];
  let executableName: string | undefined;

  let info: PlistValue = null;
  const infoPath = join(appDir, 'Info.plist');
  if (existsSync(infoPath)) {
    info = tryParse(readFileSync(infoPath));
    tell('decoding', { t: 'visit', paths: [`${appDirName}/Info.plist`] });
    if (info) {
      packageName = asString(dictGet(info, 'CFBundleIdentifier'));
      versionName = asString(dictGet(info, 'CFBundleShortVersionString'));
      versionCode = asString(dictGet(info, 'CFBundleVersion'));
      minimumOsVersion = asString(dictGet(info, 'MinimumOSVersion'));
      executableName = asString(dictGet(info, 'CFBundleExecutable'));

      if (isDict(info)) {
        permissions = Object.keys(info).filter((k) => USAGE_KEY.test(k)).sort();
        permissionDetail = permissions.map((key) => describePermission(key, info));
      }

      if (dictGet(info, 'UIFileSharingEnabled') === true) {
        groups.push([
          {
            ruleId: 'ios.file_sharing',
            title: 'iTunes file sharing enabled',
            category: 'storage',
            severity: 'medium',
            description: 'UIFileSharingEnabled exposes the app\'s Documents directory.',
            impact: 'Anyone with physical access and a cable — or the Files app — can read and replace everything in Documents.',
            exploitation: [
              'Connect the unlocked device to a computer, or open the Files app on it.',
              'Browse to the app’s folder and copy out everything in Documents — databases, caches, exported files.',
              'Replace a file in place: the app reads the substituted copy on next launch.',
            ],
            remediation: 'Disable it, or keep nothing sensitive in Documents. Credentials belong in the Keychain.',
            masvs: 'MASVS-STORAGE-2',
            cwe: 'CWE-200',
            locations: [{ file: 'Info.plist', excerpt: 'UIFileSharingEnabled = true' }],
            occurrences: 1,
          },
        ]);
      }

      if (dictGet(info, 'DTPlatformName') === 'iphonesimulator') {
        groups.push([
          {
            ruleId: 'ios.simulator_build',
            title: 'Built for the iOS Simulator',
            category: 'binary',
            severity: 'medium',
            description: 'DTPlatformName is iphonesimulator: this bundle targets the Simulator, not a device.',
            impact: 'A Simulator build is unsigned for devices and has none of the platform protections a device build gets, so it is not what ships and any assessment of it says little about the release.',
            remediation: 'Archive a device build (Any iOS Device) and scan the .ipa exported from that archive.',
            masvs: 'MASVS-CODE-1',
            locations: [{ file: 'Info.plist', excerpt: 'DTPlatformName = iphonesimulator' }],
            occurrences: 1,
          },
        ]);
      }

      if (versionBelow(minimumOsVersion, 15)) {
        extraHotspots.push({
          ruleId: 'ios.low_min_os',
          title: `Supports iOS ${minimumOsVersion}, which no longer receives security updates`,
          category: 'manifest',
          severity: 'low',
          kind: 'hotspot',
          description: `MinimumOSVersion is ${minimumOsVersion}.`,
          impact: 'The app installs on devices whose operating system has unpatched vulnerabilities, and cannot rely on newer platform protections.',
          remediation: 'Raise the deployment target to a release Apple still patches, unless a specific device population needs the older one.',
          masvs: 'MASVS-PLATFORM-1',
          locations: [{ file: 'Info.plist', excerpt: `MinimumOSVersion = ${minimumOsVersion}` }],
          occurrences: 1,
        });
      }

      const sensitive = permissionDetail.filter((p) => p.level === 'dangerous');
      if (sensitive.length >= 8) {
        extraHotspots.push({
          ruleId: 'ios.permissions_many',
          title: `${sensitive.length} sensitive permissions requested`,
          category: 'manifest',
          severity: 'low',
          kind: 'hotspot',
          description: 'The app declares purpose strings for a wide set of privacy-sensitive capabilities.',
          impact: 'Each permission widens what a compromise of the app can reach, and every one must be justified at review and in the privacy labels.',
          remediation: 'Remove the capabilities the app does not exercise; request the rest just in time, not at launch.',
          masvs: 'MASVS-PRIVACY-1',
          locations: sensitive.map((p) => ({ file: 'Info.plist', excerpt: p.name })),
          occurrences: sensitive.length,
        });
      }
    } else {
      limitations.push('Info.plist could not be parsed; configuration checks were skipped.');
    }
  } else {
    limitations.push('No Info.plist was found in the app bundle.');
  }

  const ats = readAts(info);
  const urlSchemes = readUrlSchemes(info);
  groups.push(atsFindings(ats));
  groups.push(urlSchemeFindings(urlSchemes));

  // The app binary: Mach-O facts, signature and the string sweep.
  const binaryName = executableName ?? appDirName.replace(/\.app$/, '');
  const binaryPath = join(appDir, binaryName);
  let binaryProtections: IosAnalysis['binaryProtections'];
  let main: MachOFacts | undefined;
  let binarySize = 0;
  let binaryBuffer: Buffer | undefined;
  if (existsSync(binaryPath)) {
    binaryBuffer = readFileSync(binaryPath);
    binarySize = binaryBuffer.length;
    main = readMachO(binaryBuffer);
  } else {
    limitations.push(`The app binary (${binaryName}) was not found, so binary protection checks did not run.`);
  }

  if (main && !main.parsed) {
    limitations.push('The app binary is not a readable Mach-O image; binary protection checks did not run.');
    main = undefined;
  }

  // Entitlements. The signed plist is authoritative; the profile is the
  // fallback for a binary whose signature carries none.
  const profile = readProfile(appDir);
  groups.push(profile.findings);

  const signedEntitlements = main?.signature.entitlementsXml ? tryParse(main.signature.entitlementsXml) : null;
  const entitlements = signedEntitlements ?? profile.entitlements;
  const entitlementsSource: IosFacts['signing']['entitlementsSource'] = signedEntitlements ? 'binary' : profile.entitlements ? 'profile' : 'none';

  // Written under `extracted` so the Explorer can open exactly what a finding
  // names: the entitlements as signed, and the profile's decoded plist.
  // Rendered at the path of the file they came from, in `viewRoot`: the profile's
  // decoded plist as `embedded.mobileprovision`, and the signed entitlements as a
  // section of the executable's own view. Nothing here is a file the IPA lacks.
  const viewRoot = join(workDir, 'synthetic');
  let entitlementsFile = 'embedded.mobileprovision';
  let signedEntitlementsText: string | undefined;
  try {
    if (main?.signature.entitlementsXml && signedEntitlements) {
      signedEntitlementsText = main.signature.entitlementsXml.toString('utf8');
      entitlementsFile = '_signature/entitlements.plist';
    }
    if (profile.plistXml) {
      const target = join(viewRoot, appDirName, 'embedded.mobileprovision');
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, `// Provisioning profile (a signed CMS container), decoded for display.\n${profile.plistXml}`);
      if (entitlementsSource === 'profile') entitlementsFile = '_signature/embedded.mobileprovision.plist';
    }
  } catch {
    // The Explorer copy is a convenience; the findings stand without it.
  }
  const entitlementGroup = entitlementFindings(entitlements, entitlementsFile);
  groups.push(entitlementGroup);

  let flow: IosFlowAnalysis | undefined;
  const functionsFile = `_functions/${binaryName}.functions.txt`;
  if (main && binaryBuffer) {
    const binary = binaryFindings(binaryName, main);
    groups.push(binary.findings, signingFindings(binaryName, main));
    extraHotspots.push(...binary.hotspots);
    limitations.push(...binary.limitations);
    binaryProtections = {
      pie: main.pie,
      arc: main.arc,
      stackCanary: main.stackCanary,
      encrypted: main.encrypted,
      nonExecutableStack: !main.allowsStackExecution,
      archCount: main.archCount,
    };
    // Written under `extracted` so `collectSources` (sourceRoots: [extracted])
    // picks it up: a binary-string finding otherwise names a synthetic file
    // like "DVIA-v2 (Binary)" that resolves to nothing browsable, and the
    // Explorer tab had nothing to show for the majority of iOS findings.
    tell('scanning', { t: 'visit', paths: [`${appDirName}/${binaryName}`] }, 0.1);
    const stringHits = scanBinaryStrings(binaryName, binaryBuffer, rules, 6, {
      writeTo: join(extracted, '_strings', `${binaryName}.strings.txt`),
      relativeFile: `_strings/${binaryName}.strings.txt`,
    });

    // What each function does, not only which strings the binary holds: the calls it makes and the
    // literals it uses, from its machine code. The findings point into a listing that becomes a
    // section of the binary's view, so the locations are provisional until the view is written.
    try {
      // Class names the storyboards and nibs refer to: classes that must be the app's own.
      const nibNames = new Set<string>();
      for (const f of appFiles) {
        if (!/\.nib(?:\/|$)/.test(f.relative) && !/\.storyboardc\//.test(f.relative)) continue;
        if (f.size > 2 * 1024 * 1024) continue;
        for (const m of readFileSync(f.absolute).toString('latin1').matchAll(/[A-Za-z_][A-Za-z0-9_.]{2,63}/g)) {
          nibNames.add(m[0]);
          const dot = m[0].lastIndexOf('.');
          if (dot > 0) nibNames.add(m[0].slice(dot + 1)); // "Module.ClassName"
        }
      }
      flow = analyseIosBinary(binaryBuffer, binaryName.replace(/[^A-Za-z0-9]/g, '_'), nibNames);
    } catch (error) {
      limitations.push(`Function-level analysis of the executable could not run: ${(error as Error).message.split('\n')[0]}`);
    }
    progress('scanning', 0.6);
    // Where the functions were read, an API's use is judged per function (below) instead of by its name
    // appearing anywhere in the string table, which also holds every statically linked library's.
    const functionLevel = Boolean(flow && !flow.encrypted && flow.functionCount > 0);
    groups.push(functionLevel ? stringHits.filter((f) => !FUNCTION_LEVEL_RULES.has(f.ruleId)) : stringHits);
    if (flow?.encrypted) {
      limitations.push('The executable is FairPlay-encrypted (an App Store build), so its code and strings could not be read. Scan a development, ad-hoc or enterprise build for the full analysis.');
    } else if (flow) {
      const byRule = new Map<string, { locations: SastLocation[]; occurrences: number }>();
      const seenKeys = new Set<string>();
      const seenPlaces = new Set<string>();
      for (const hit of flow.hits) {
        if (hit.key) {
          if (seenKeys.has(`${hit.rule}:${hit.key}`)) continue;
          seenKeys.add(`${hit.rule}:${hit.key}`);
        }
        const entry = byRule.get(hit.rule) ?? { locations: [], occurrences: 0 };
        entry.occurrences += 1;
        // Two hits of one rule in one function are one place to look at: the block already shows both.
        const place = `${hit.rule}:${hit.fn.address}`;
        if (entry.locations.length < 12 && !seenPlaces.has(place)) {
          seenPlaces.add(place);
          const start = flow.listing.headerLine.get(hit.fn.address);
          const size = flow.listing.blockSize.get(hit.fn.address) ?? 0;
          const marks = hit.marks ?? [];
          // The function's name, the finding's own line and the lines that show the evidence, each with a line of
          // context: the part of the block that matters, marked the way a Java finding marks its line.
          const keep = new Set<number>([0]);
          for (const m of marks) for (const i of [m - 1, m, m + 1]) if (i >= 0 && i < size) keep.add(i);
          if (marks.length === 0) for (let i = 1; i < Math.min(size, 12); i += 1) keep.add(i);
          const snippet: SnippetLine[] | undefined =
            start && size > 0
              ? [...keep].sort((a, b) => a - b).slice(0, 30).map((i) => ({ line: start + i, text: flow.listing.lines[start - 1 + i], vulnerable: marks.includes(i) }))
              : undefined;
          entry.locations.push({ file: functionsFile, line: start === undefined ? undefined : start + (marks[0] ?? 0), excerpt: hit.evidence, ...(snippet ? { snippet } : {}) });
        }
        byRule.set(hit.rule, entry);
      }
      const made: SastFinding[] = [];
      for (const [ruleId, entry] of byRule) {
        const rule = PATTERN_RULES.find((r) => r.id === ruleId);
        if (rule) made.push(findingFrom(rule, entry.locations, entry.occurrences));
      }
      groups.push(made);
      limitations.push(`Function-level analysis read ${flow.functionCount} functions (${flow.appFunctionCount} outside known libraries). It follows calls and string literals through the machine code; it is not a decompiler.`);
    }
  }

  // Debug-build artefacts: Xcode's debug dylibs and preview stubs never belong
  // in something that ships.
  const debugArtefacts = appFiles.filter((f) => /(\.debug\.dylib|__preview\.dylib)$/.test(f.relative));
  if (debugArtefacts.length > 0) {
    groups.push([
      {
        ruleId: 'ios.debug_dylib',
        title: 'Debug build artefacts are inside the bundle',
        category: 'binary',
        severity: 'medium',
        description: `${debugArtefacts.length} Xcode debug ${debugArtefacts.length === 1 ? 'library' : 'libraries'} (.debug.dylib / __preview.dylib) ${debugArtefacts.length === 1 ? 'is' : 'are'} bundled.`,
        impact: 'Xcode splits a debug build into a stub and a debug dylib to support previews and fast rebuilds. This is a debug configuration: symbols, assertions and development code paths are all still present.',
        remediation: 'Archive with the Release configuration, and make sure ENABLE_DEBUG_DYLIB is off for it.',
        masvs: 'MASVS-RESILIENCE-3',
        cwe: 'CWE-489',
        locations: debugArtefacts.map((f) => ({ file: f.relative.split('/').slice(1).join('/') })),
        occurrences: debugArtefacts.length,
      },
    ]);
  }

  // Bundled resources are readable text and worth the full rule set.
  const decodedDir = join(workDir, 'decoded');
  groups.push(
    scanFiles(appDir, decodeBundleText(appFiles, decodedDir), rules, (f) => progress('scanning', 0.6 + f * 0.35), undefined, {
      visit: (paths) => tell('scanning', { t: 'visit', paths }),
      // A match is announced with the finished report's findings, below, so each shows once and as it was merged.
      hit: () => {},
    }),
  );

  const firebase = firebaseFinding(appFiles, appDirName);
  if (firebase) extraHotspots.push(firebase);

  // Embedded frameworks, dylibs and extensions.
  const inventory = inventoryBinaries(appDir, appDirName, files);
  progress('inspecting', 0);
  for (let i = 0; i < inventory.binaries.length; i += 40) {
    tell('inspecting', { t: 'visit', paths: inventory.binaries.slice(i, i + 40).map((b) => `${appDirName}/${b.path}`) }, i / inventory.binaries.length);
  }

  // A readable view of every Mach-O, written under `extracted` like the strings
  // dump so the Explorer holds it, and recorded here so a finding that names a
  // binary opens the view instead of nothing. Keyed by the path the rules use:
  // the executable's bare name, or an embedded binary's path inside the app.
  const binaryViews = new Map<string, string>();
  const viewLines = new Map<string, string[]>();
  /** Where the sections of the main executable's view start, for findings that point into them. */
  let mainSections: { entitlements?: number; strings?: number; functions?: number; entitlementLines: string[] } | undefined;
  const writeView = (rulePath: string, absolute: string, extra?: (lines: string[]) => void): void => {
    try {
      // The original file's own path: the Explorer shows that file, decoded.
      const viewPath = `${appDirName}/${rulePath}`;
      const target = join(viewRoot, viewPath);
      mkdirSync(dirname(target), { recursive: true });
      const lines = renderBinaryView(readFileSync(absolute), viewPath).split('\n');
      extra?.(lines);
      writeFileSync(target, lines.join('\n'));
      binaryViews.set(rulePath, viewPath);
      viewLines.set(rulePath, lines);
    } catch {
      // A binary the view cannot render keeps its finding; it just has no button.
    }
  };
  if (main && binaryBuffer) {
    writeView(binaryName, binaryPath, (lines) => {
      mainSections = { entitlementLines: [] };
      if (signedEntitlementsText) {
        const entitlementLines = signedEntitlementsText.split('\n');
        lines.push('', `== Entitlements signed into the binary (${entitlementLines.length} lines) ==`);
        mainSections!.entitlements = lines.length + 1; // 1-based line of the first entitlement line
        mainSections!.entitlementLines = entitlementLines;
        lines.push(...entitlementLines);
      }
      // The functions the flow checks read, so a finding on a function opens the binary at that function.
      if (flow && flow.listing.lines.length > 0) {
        lines.push('', `== Functions analysed (${flow.listing.headerLine.size}) ==`);
        mainSections!.functions = lines.length; // header line n (1-based) is view line functions + n
        lines.push(...flow.listing.lines);
      }
      // The string table the rules read, so a finding on a string opens the binary at that string.
      try {
        const dumpPath = join(extracted, '_strings', `${binaryName}.strings.txt`);
        const dump = readFileSync(dumpPath, 'utf8').split('\n');
        lines.push('', `== Strings (${dump.length}) ==`);
        mainSections!.strings = lines.length; // string n (1-based) is view line strings + n
        lines.push(...dump);
        rmSync(dumpPath, { force: true }); // now a section of the view, not a file of its own
      } catch {
        // No dump was written (nothing to read): the view stands without that section.
      }
    });
  }
  for (const embedded of inventory.binaries) writeView(embedded.path, join(appDir, embedded.path));

  // The API rules (weak hash and PRNG, unbounded C strings, dlopen, system) look
  // at imported symbols, so they apply to every binary the app ships, not only
  // the executable. A vulnerable call inside a bundled framework is still in the
  // app. The string and secret rules stay on the main executable: running them
  // over third-party binaries is mostly noise (see the limitation recorded below).
  const API_RULES = new Set([
    'crypto.weak_hash', 'crypto.weak_prng_c', 'code.unsafe_c_string', 'ios.dynamic_loading', 'ios.command_execution',
  ]);
  const apiRules = rules.filter((r) => API_RULES.has(r.id));
  for (const embedded of inventory.binaries) {
    const viewPath = binaryViews.get(embedded.path);
    if (!viewPath) continue;
    try {
      const lines = viewLines.get(embedded.path) ?? [];
      const found = scanBinaryStrings(viewPath, readFileSync(join(appDir, embedded.path)), apiRules, 6).map((f) => ({
        ...f,
        // Point each hit at the line in the readable view that lists the symbol.
        locations: f.locations.map((l) => {
          const wanted = l.excerpt?.replace(/^@/, '');
          let at = l.excerpt ? lines.findIndex((x) => x === l.excerpt) : -1;
          if (at === -1 && wanted) at = lines.findIndex((x) => x.trim() === wanted || x.trim().endsWith(` ${wanted}`) || x.trim().endsWith(wanted));
          return at === -1 ? l : { ...l, line: at + 1, snippet: snippetAround(lines, at) };
        }),
      }));
      groups.push(found);
    } catch {
      // A binary that cannot be read keeps its inventory row and loses only this extra pass.
    }
  }
  const embeddedUnsigned = inventory.binaries.filter((b) => !b.signed);
  if (embeddedUnsigned.length > 0) {
    groups.push([
      {
        ruleId: 'ios.embedded_unsigned',
        title: `${embeddedUnsigned.length} embedded ${embeddedUnsigned.length === 1 ? 'library is' : 'libraries are'} not signed`,
        category: 'signing',
        severity: 'medium',
        description: 'Embedded Mach-O images carry no code signature.',
        impact: 'iOS validates every loaded image; an unsigned one either fails to load or, on a device without enforcement, can be swapped for a modified copy with nothing to detect it.',
        remediation: 'Sign every embedded framework and dylib with the same team identity as the app (Embed & Sign in Xcode).',
        masvs: 'MASVS-RESILIENCE-2',
        cwe: 'CWE-347',
        locations: embeddedUnsigned.slice(0, 20).map((b) => ({ file: b.path })),
        occurrences: embeddedUnsigned.length,
      },
    ]);
  }
  // Swift frameworks routinely omit the stack protector; only native
  // Objective-C or C code, where overflows are a real bug class, is worth naming.
  const noCanary = inventory.binaries.filter((b) => !b.stackCanary && !b.swift && b.kind !== 'extension' && (b.objc || b.kind === 'dylib') && !/^libswift/.test(b.name));
  if (noCanary.length > 0) {
    extraHotspots.push({
      ruleId: 'ios.framework_hardening',
      title: `${noCanary.length} native ${noCanary.length === 1 ? 'library lacks' : 'libraries lack'} a stack protector`,
      category: 'binary',
      severity: 'low',
      kind: 'hotspot',
      description: 'Embedded Objective-C or C images import no __stack_chk_fail.',
      impact: 'A stack overflow in those libraries is not caught at return. The main executable’s hardening does not extend to code it loads.',
      remediation: 'Rebuild the libraries with -fstack-protector-strong, or ask the vendor for a hardened build.',
      masvs: 'MASVS-RESILIENCE-1',
      cwe: 'CWE-121',
      locations: noCanary.slice(0, 20).map((b) => ({ file: b.path, excerpt: `${b.name}${b.version ? ` ${b.version}` : ''}` })),
      occurrences: noCanary.length,
    });
  }
  if (inventory.truncated) {
    limitations.push('More embedded images were present than the inventory cap; the list is not exhaustive.');
  }
  limitations.push('Embedded frameworks and extensions were inspected for hardening, signature and version. The string and secret rules ran on the main executable and bundle resources only, not on third-party binaries.');

  const frameworks = inventory.binaries.filter((b) => b.kind === 'framework').map((b) => b.name);
  const dylibs = inventory.binaries.filter((b) => b.kind === 'dylib').map((b) => b.name);

  const recon = runRecon(appDir, appFiles);

  // "Raw SQLite" means SQLite with no SQLCipher anywhere in the app. The rule can
  // only judge one string at a time, so the app-wide exception is applied here.
  const mergedAll = mergeFindings(groups);
  const usesSqlCipher = mergedAll.some((f) => f.ruleId === 'ios.sqlcipher');
  const merged = usesSqlCipher ? mergedAll.filter((f) => f.ruleId !== 'ios.sqlite_unencrypted') : mergedAll;
  const defects = merged.filter((f) => (f.kind ?? 'defect') === 'defect');
  const hotspots = [...merged.filter((f) => f.kind === 'hotspot'), ...extraHotspots];
  // A rule may declare itself a secure observation — "this app does the right
  // thing here". Those belong in the secure list, not dropped on the floor.
  const secureFromRules = merged.filter((f) => f.kind === 'secure');

  if (recon.trackers.length > 0) {
    hotspots.push({
      ruleId: 'recon.trackers',
      title: `${recon.trackers.length} privacy tracker${recon.trackers.length === 1 ? '' : 's'} bundled`,
      category: 'dependencies',
      severity: recon.trackers.length > 4 ? 'medium' : 'low',
      kind: 'hotspot',
      description: `Signatures matched for: ${recon.trackers.map((t) => t.name).join(', ')}. Tracker signatures are from the Exodus Privacy database (ODbL 1.0, https://exodus-privacy.eu.org).`,
      impact: 'These SDKs collect device or user data and send it to third parties, which is a disclosure obligation and a privacy consideration for your users.',
      remediation: 'Confirm each tracker is disclosed in your privacy policy and in the App Store privacy labels, and remove any that are not needed.',
      masvs: 'MASVS-PRIVACY-1',
      locations: recon.trackers.slice(0, 20).map((t) => ({ file: t.signature, excerpt: `${t.name} (${t.category})` })),
      occurrences: recon.trackers.length,
    });
  }

  // How the build was distributed. The profile says so when there is one; an
  // IPA without a profile came through the App Store or TestFlight, which strip it.
  const getTaskAllow = dictGet(entitlements, 'get-task-allow') === true;
  const distribution: IosFacts['distribution'] = profile.facts
    ? getTaskAllow ? 'development' : profile.provisionsAll ? 'enterprise' : profile.provisionedDevices ? 'ad-hoc' : 'app-store'
    : main?.signature.present ? (getTaskAllow ? 'development' : 'app-store') : 'unknown';

  // Positive findings. An App Store provisioning profile with no get-task-allow
  // and a PIE/ARC binary is a correctly built release, and the report says so.
  // Rule-declared secure observations first; the checks below add to them.
  const secure: SastFinding[] = [...secureFromRules];
  const addSecure = (ruleId: string, title: string, category: SastFinding['category'], description: string) =>
    secure.push({
      ruleId, title, category, severity: 'info', kind: 'secure',
      description, impact: '', remediation: '', locations: [], occurrences: 1,
    });

  if (!getTaskAllow && (distribution === 'app-store' || distribution === 'enterprise' || distribution === 'ad-hoc')) {
    addSecure('secure.distribution_profile', 'Signed for distribution, not for debugging', 'signing',
      'The signed entitlements do not grant get-task-allow, so a debugger cannot attach on a user device.');
  }
  if (main?.signature.present && !main.signature.adhoc && main.signature.teamId) {
    addSecure('secure.code_signature', 'Signed by a developer team', 'signing',
      `The code signature is bound to team ${main.signature.teamId} using ${main.signature.hashType ?? 'a strong hash'}.`);
  }
  if (main && main.pie && main.stackCanary && main.arc && !main.allowsStackExecution && main.rwxSegments.length === 0) {
    addSecure('secure.binary_hardening', 'Main binary is fully hardened', 'binary',
      'Position-independent, stack protector linked, ARC in use, non-executable stack and no writable-executable segments.');
  }
  if (main && main.localSymbols <= 50) {
    addSecure('secure.symbols_stripped', 'Symbols are stripped', 'binary',
      'The symbol table holds no local symbols, which makes the binary harder to reverse.');
  }
  if (!defects.some((f) => f.category === 'network' && f.ruleId.startsWith('ios.ats'))) {
    addSecure('secure.ats_enforced', 'App Transport Security is not weakened', 'network',
      'No ATS exception is declared, so the platform enforces HTTPS with modern TLS for every connection.');
  }
  const privacyManifest = appFiles.some((f) => f.relative === `${appDirName}/PrivacyInfo.xcprivacy`);
  if (privacyManifest) {
    addSecure('secure.privacy_manifest', 'Privacy manifest is bundled', 'manifest',
      'PrivacyInfo.xcprivacy declares the app’s data collection and required-reason API use, as App Store review requires.');
  } else {
    hotspots.push({
      ruleId: 'ios.no_privacy_manifest',
      title: 'No privacy manifest in the app bundle',
      category: 'manifest',
      severity: 'low',
      kind: 'hotspot',
      description: 'PrivacyInfo.xcprivacy is not present at the root of the app.',
      impact: 'Apple requires apps to declare data collection and use of required-reason APIs. A submission without a manifest is warned or rejected, and it leaves the app’s data practices undocumented.',
      remediation: 'Add a PrivacyInfo.xcprivacy to the app target and keep each SDK’s own manifest up to date.',
      masvs: 'MASVS-PRIVACY-1',
      locations: [{ file: `${appDirName}/PrivacyInfo.xcprivacy`, excerpt: 'missing' }],
      occurrences: 1,
    });
  }
  if (dictGet(entitlements, 'com.apple.developer.default-data-protection') === 'NSFileProtectionComplete') {
    addSecure('secure.data_protection', 'Files are encrypted whenever the device is locked', 'storage',
      'default-data-protection is NSFileProtectionComplete, the strongest default class.');
  }
  if (recon.trackers.length === 0) {
    addSecure('secure.no_trackers', 'No privacy trackers detected', 'dependencies',
      'No signature from the Exodus tracker database matched this bundle.');
  }

  const backgroundModes = stringList(dictGet(info, 'UIBackgroundModes'));
  const associatedDomains = stringList(dictGet(entitlements, 'com.apple.developer.associated-domains'));
  const deviceFamily = (Array.isArray(dictGet(info, 'UIDeviceFamily')) ? (dictGet(info, 'UIDeviceFamily') as PlistValue[]) : [])
    .map((n) => ({ 1: 'iPhone', 2: 'iPad', 3: 'Apple TV', 4: 'Apple Watch', 7: 'Apple Vision' } as Record<number, string>)[Number(n)])
    .filter((s): s is string => Boolean(s));

  const iosFacts: IosFacts = {
    displayName: asString(dictGet(info, 'CFBundleDisplayName')) ?? asString(dictGet(info, 'CFBundleName')),
    bundleId: packageName,
    executable: executableName,
    sdkName: asString(dictGet(info, 'DTSDKName')),
    platformVersion: asString(dictGet(info, 'DTPlatformVersion')),
    xcode: asString(dictGet(info, 'DTXcode')),
    buildOs: asString(dictGet(info, 'BuildMachineOSBuild')),
    supportedPlatforms: stringList(dictGet(info, 'CFBundleSupportedPlatforms')),
    deviceFamily,
    requiredCapabilities: stringList(dictGet(info, 'UIRequiredDeviceCapabilities')),
    distribution,
    profile: profile.facts,
    signing: {
      signed: Boolean(main?.signature.present),
      adhoc: Boolean(main?.signature.adhoc),
      teamId: main?.signature.teamId ?? profile.facts?.teamId,
      identifier: main?.signature.identifier,
      hashType: main?.signature.hashType,
      entitlementsSource,
    },
    entitlements: entitlementRows(entitlements),
    ats,
    urlSchemes,
    queriedSchemes: stringList(dictGet(info, 'LSApplicationQueriesSchemes')),
    associatedDomains,
    backgroundModes,
    privacyManifest,
    extensions: inventory.extensions,
    binaries: inventory.binaries,
    main: {
      arch: main?.arch,
      cpu: main?.cpu,
      fileType: main?.fileType,
      is64Bit: Boolean(main?.is64Bit),
      swift: Boolean(main?.swift),
      objc: Boolean(main?.objc),
      stripped: Boolean(main && main.localSymbols <= 50),
      localSymbols: main?.localSymbols ?? 0,
      uuid: main?.uuid,
      minOs: main?.minOs ?? minimumOsVersion,
      sdk: main?.sdk,
      sizeBytes: binarySize,
      linkedLibraries: [...new Set(main?.linkedLibraries ?? [])],
      weakLibraries: [...new Set(main?.weakLibraries ?? [])],
      rpaths: [...new Set(main?.rpaths ?? [])],
      hardenedRuntime: Boolean(main?.signature.hardenedRuntime),
      encrypted: Boolean(main?.encrypted),
    },
    plistKeys: isDict(info) ? Object.keys(info).length : 0,
    fileCount: appFiles.length,
  };

  // Rules name files the way a report reads (`Info.plist`, `GoogleService-Info.plist`),
  // but those names are shared with every storyboard's and framework's plist.
  // Anything that is a real file inside the bundle is qualified with it, so a
  // finding and the Explorer agree on which file is meant.
  const bundleFiles = new Set(appFiles.map((f) => f.relative.slice(appDirName.length + 1)));
  const mainView = binaryViews.get(binaryName);
  const stringsFile = `_strings/${binaryName}.strings.txt`;
  const mapLocation = (l: SastLocation): SastLocation => {
    const view = binaryViews.get(l.file);
    if (view) return { ...l, file: view };

    // A string-table finding: the table is a section of the executable's own view.
    if (l.file === stringsFile && mainView && mainSections?.strings !== undefined) {
      const base = mainSections.strings;
      return {
        ...l,
        file: mainView,
        ...(l.line ? { line: base + l.line } : {}),
        ...(l.snippet ? { snippet: l.snippet.map((s) => ({ ...s, line: base + s.line })) } : {}),
      };
    }

    // A function-level finding: the listing is a section of the executable's own view.
    if (l.file === functionsFile && mainView && mainSections?.functions !== undefined) {
      const base = mainSections.functions;
      return {
        ...l,
        file: mainView,
        ...(l.line ? { line: base + l.line } : {}),
        ...(l.snippet ? { snippet: l.snippet.map((s) => ({ ...s, line: base + s.line })) } : {}),
      };
    }

    // The signed entitlements are part of the executable's code signature.
    if (l.file === '_signature/entitlements.plist' && mainView && mainSections?.entitlements !== undefined) {
      const key = (l.excerpt ?? '').split(/\s|=/)[0];
      const at = Math.max(key ? mainSections.entitlementLines.findIndex((x) => x.includes(key)) : -1, 0);
      const base = mainSections.entitlements;
      return {
        ...l,
        file: mainView,
        line: base + at,
        snippet: snippetAround(mainSections.entitlementLines, at).map((s) => ({ ...s, line: base + s.line - 1 })),
      };
    }

    // The provisioning profile is the bundle's `embedded.mobileprovision`, shown decoded.
    if (l.file === '_signature/embedded.mobileprovision.plist') return quoted({ ...l, file: `${appDirName}/embedded.mobileprovision` });

    if (l.file === 'Info.plist' || bundleFiles.has(l.file)) return quoted({ ...l, file: `${appDirName}/${l.file}` });
    return l;
  };

  // A finding in a property list quotes the line it is about, the way a finding in Java does. The text is the
  // file the Explorer shows: decoded where the scan decoded it.
  const textCache = new Map<string, string[] | null>();
  const textOf = (file: string): string[] | null => {
    const known = textCache.get(file);
    if (known !== undefined) return known;
    let lines: string[] | null = null;
    for (const root of [decodedDir, viewRoot, payload]) {
      try {
        const path = join(root, file);
        if (statSync(path).size > 2 * 1024 * 1024) break;
        lines = readFileSync(path, 'utf8').split('\n');
        break;
      } catch {
        // Not at this root.
      }
    }
    textCache.set(file, lines);
    return lines;
  };
  const quoted = (l: SastLocation): SastLocation => {
    if (l.snippet || !l.excerpt || !/\.(?:plist|strings|xcprivacy|mobileprovision)$/i.test(l.file)) return l;
    const lines = textOf(l.file);
    if (!lines) return l;
    // The excerpt reads `Key.Sub = value`, `A → B: value` or `Key = value`: try the value, then each key, longest first.
    const parts = l.excerpt.split(/\s*(?:=|→|:(?=\s)|\.(?=[A-Za-z]))\s*/).map((x) => x.trim()).filter((x) => x.length >= 3);
    for (const token of parts.sort((a, b) => b.length - a.length)) {
      const at = lines.findIndex((x) => x.includes(token));
      if (at !== -1) return { ...l, line: at + 1, snippet: snippetAround(lines, at) };
    }
    return l;
  };
  const qualify = (list: SastFinding[]): SastFinding[] =>
    list.map((f) => ({ ...f, locations: f.locations.map(mapLocation) }));

  const reported = qualify(defects);
  // The report's findings, one flag each where they sit, file by file, as the last step of the scan.
  progress('reporting');
  const walked = new Set<string>();
  for (const f of reported) {
    for (const l of f.locations.slice(0, 3)) {
      if (!l.file) continue;
      if (!walked.has(l.file)) {
        walked.add(l.file);
        tell('reporting', { t: 'visit', paths: [l.file] });
      }
      tell('reporting', { t: 'hit', file: l.file, title: f.title, severity: f.severity, category: f.category });
    }
  }

  return {
    findings: reported,
    decompiler: 'none',
    javaFileCount: 0,
    dependencies: [],
    secure: qualify(secure),
    hotspots: qualify(hotspots),
    recon,
    components: {
      activities: 0, services: 0, receivers: 0, providers: 0,
      exported: 0,
      // iOS has no manifest components; URL schemes are the analogous surface.
      browsable: urlSchemes.flatMap((e) => e.schemes).map((scheme) => ({
        component: 'CFBundleURLTypes', schemes: [scheme], hosts: [],
      })),
    },
    permissionDetail,
    packageName,
    versionName,
    versionCode,
    minimumOsVersion,
    permissions,
    signers: [...new Set([...profile.signers, ...(main?.signature.teamId ? [`Team ID: ${main.signature.teamId}`] : [])])],
    signatureSchemes: [distribution],
    nativeLibraries: [...new Set(dylibs)].sort(),
    detectedLibraries: [...new Set(frameworks)].sort(),
    binaryProtections,
    ios: iosFacts,
    iconDataUrl: iosIcon(appDir, info),
    fileCount: appFiles.length,
    fileListing: appFiles.slice(0, 8000).map((f) => f.relative),
    sourceRoots: [extracted, viewRoot],
    syntheticRoot: viewRoot,
    limitations,
  };
}
