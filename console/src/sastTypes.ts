/**
 * The SAST shapes the console consumes.
 *
 * Mirrors `backend/src/sast/types.ts`. Duplicated rather than imported because
 * the console builds standalone and must not pull the backend's Node-only
 * modules into the browser bundle.
 */

export type SastSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SnippetLine = { line: number; text: string; vulnerable: boolean };

/**
 * Whose code a finding sits in — an axis independent of severity.
 *
 * Most findings on a real app land in a bundled library, where the remedy is a
 * dependency upgrade or nothing at all. Separating those from the app's own
 * code is the difference between a list to triage and a list to act on.
 */
export type Origin = 'first-party' | 'third-party' | 'unknown';
export type FindingOrigin = Origin | 'mixed';

export type Provenance = {
  origin: Origin;
  library?: string;
  /** Why it was classified this way; shown on hover. */
  because: string;
};

export type SastLocation = {
  file: string;
  line?: number;
  excerpt?: string;
  provenance?: Provenance;
  /** Surrounding source, with the matched line marked. */
  snippet?: SnippetLine[];
  /** Where this sits in the compiled artifact. */
  dex?: string;
  className?: string;
  method?: string;
};

/** `classes2.dex › Lcom/example/Foo;->bar()V` */
export function describeDexContext(l: SastLocation): string | undefined {
  if (!l.dex) return undefined;
  const target = l.className ? `${l.className}${l.method ? `->${l.method}` : ''}` : undefined;
  return target ? `${l.dex} \u203a ${target}` : l.dex;
}

export type FindingKind = 'defect' | 'hotspot' | 'secure';

export type SastFinding = {
  ruleId: string;
  title: string;
  category: string;
  severity: SastSeverity;
  kind?: FindingKind;
  description: string;
  impact: string;
  /** Concrete steps from this finding to harm. */
  exploitation?: string[];
  remediation: string;
  masvs?: string;
  cwe?: string;
  /** OWASP Mobile Top 10 (2024) category, e.g. "M5". Derived from the MASVS control and the weakness class. */
  owasp?: string;
  locations: SastLocation[];
  occurrences: number;
  /** Rolled up over `locations`. */
  origin?: FindingOrigin;
  /** Libraries this finding touches, when identifiable. */
  libraries?: string[];
  /** Set by the console on a review item a person confirmed, which then counts and is listed as a defect. */
  fromReview?: boolean;
};

/** The label and tone each origin gets, in one place so nothing drifts. */
export const ORIGIN_LABEL: Record<FindingOrigin, string> = {
  'first-party': 'Your code',
  'third-party': 'Library',
  mixed: 'Both',
  unknown: 'Unattributed',
};

/**
 * A one-line explanation of what the tag means for the reader.
 *
 * Deliberately about what to *do*: a tag that only names a category leaves the
 * reader to work out the consequence themselves.
 */
export const ORIGIN_MEANING: Record<FindingOrigin, string> = {
  'first-party': 'In a package the app itself owns — fix this in your source.',
  'third-party': 'In a bundled library. Usually fixed by upgrading the dependency, not by editing your code.',
  mixed: 'Matches in both your code and a bundled library. The hits in your own packages are the actionable ones.',
  unknown:
    'Could not be attributed to the app or to a known library. Shown under "Your code" so an unattributed finding is never hidden from the person who might own it.',
};

/** Which origins a finding list is filtered to. */
export type OriginFilter = 'all' | 'first-party' | 'third-party';

export function matchesOrigin(finding: SastFinding, filter: OriginFilter): boolean {
  if (filter === 'all') return true;
  // `mixed` belongs in both views: it has something actionable for each reader.
  if (finding.origin === 'mixed') return true;
  // An unattributed finding stays visible under "your code": the scanner could
  // not rule out that it is yours, and hiding it would be the wrong default
  // when the whole point of the filter is to find what you must fix.
  if (filter === 'first-party') return finding.origin !== 'third-party';
  return finding.origin === 'third-party';
}

export type DomainRow = {
  host: string;
  schemes: string[];
  cleartext: boolean;
  environment: 'production' | 'non-production' | 'local' | 'unknown';
  urls: string[];
  urlCount: number;
  files: string[];
  fileCount: number;
};


/**
 * Mirror of backend/src/sast/types.ts SecurityControl. A protection the app implements (or conspicuously does not), with the usual
 * ways an attacker defeats it.
 *
 * This is the "how strong is it really?" half of a security review. A pinning
 * check or a jailbreak check being *present* is good; it is also a client-side
 * check that runs on a device the attacker controls, so every one has a known
 * bypass. Listing them lets a team judge whether a control buys time or only
 * looks like it does, and what would make it harder to remove.
 *
 * Detection is by reference in the binary or decompiled code. It shows the
 * check exists, not that it is reachable or that its result is acted on.
 */
export type ControlGroup =
  | 'network' | 'device-integrity' | 'tamper' | 'storage' | 'authentication' | 'platform' | 'build';

export type SecurityControl = {
  id: string;
  title: string;
  group: ControlGroup;
  /**
   * `detected`: a reference was found. `not-detected`: the scanner looks for
   * this and found none. `not-assessed`: the scanner cannot tell either way, so
   * it must not be read as a gap.
   */
  status: 'detected' | 'not-detected' | 'not-assessed';
  /** Whose code the reference sits in; only meaningful when detected. */
  origin?: FindingOrigin;
  libraries?: string[];
  /** Where it was found, capped. */
  evidence: { file: string; line?: number; excerpt?: string }[];
  occurrences: number;
  /** What the control protects against. */
  what: string;
  /** How much effort it typically takes an attacker with device control to defeat. */
  bypassEffort: 'trivial' | 'low' | 'moderate' | 'high';
  /** Technique-level ways the control is commonly defeated. */
  bypass: string[];
  /** What raises the bar. */
  harden: string[];
  /** Specific to this scan, e.g. "only in a bundled library". */
  note?: string;
  /** `warning` when the note says something undermines the control; otherwise informational. */
  noteTone?: 'warning' | 'info';
  masvs?: string;
};

/**
 * Mirror of backend/src/sast/types.ts AndroidFacts. What the Android analyser read out of the manifest, as structure.
 *
 * The counterpart of `IosFacts`: the findings say what is wrong, this says what
 * the app is — its identity, its configuration flags and every declared
 * component, so a clean scan still shows the whole shape of the app.
 */
export type AndroidFacts = {
  /** The launcher label, resolved from strings.xml where it is a reference. */
  label?: string;
  applicationClass?: string;
  launcherActivity?: string;
  debuggable: boolean;
  allowBackup: boolean;
  /** android:usesCleartextTraffic; undefined when the manifest is silent. */
  cleartextTraffic?: boolean;
  testOnly: boolean;
  networkSecurityConfig: boolean;
  usesFeatures: { name: string; required: boolean }[];
  /** Permissions this app declares for others to request. */
  customPermissions: { name: string; protection: string }[];
  components: {
    name: string;
    kind: 'activity' | 'service' | 'receiver' | 'provider';
    exported: boolean;
    permission?: string;
    actions: string[];
    schemes: string[];
    browsable: boolean;
  }[];
  nativeAbis: string[];
};

/**
 * Mirror of backend/src/sast/types.ts IosFacts. Everything the iOS analyser read out of the IPA, as structure.
 *
 * Findings say what is wrong; this says what the app *is*: how it is signed,
 * what it is entitled to, how it talks to the network, what it bundles and how
 * hardened each bundled binary is. The dashboard and the PDF both render it, so
 * a clean scan still shows a reader the whole shape of the app.
 */
export type IosRisk = 'high' | 'medium' | 'low' | 'info';

export type IosFacts = {
  displayName?: string;
  bundleId?: string;
  executable?: string;
  /** Info.plist DTSDKName / DTPlatformVersion / DTXcode / DTPlatformBuild. */
  sdkName?: string;
  platformVersion?: string;
  xcode?: string;
  buildOs?: string;
  supportedPlatforms: string[];
  /** 1 = iPhone, 2 = iPad. */
  deviceFamily: string[];
  requiredCapabilities: string[];
  /** development | ad-hoc | enterprise | app-store | unknown */
  distribution: 'development' | 'ad-hoc' | 'enterprise' | 'app-store' | 'unknown';
  profile?: {
    name?: string; uuid?: string; teamName?: string; teamId?: string;
    created?: string; expires?: string; expired: boolean; deviceCount?: number;
    platform?: string;
  };
  signing: {
    /** LC_CODE_SIGNATURE is present on the main binary. */
    signed: boolean;
    adhoc: boolean;
    teamId?: string;
    identifier?: string;
    hashType?: string;
    entitlementsSource: 'binary' | 'profile' | 'none';
  };
  entitlements: { key: string; value: string; risk: IosRisk; note: string }[];
  ats: {
    arbitraryLoads: boolean;
    arbitraryLoadsInWebContent: boolean;
    arbitraryLoadsForMedia: boolean;
    localNetworking: boolean;
    configured: boolean;
    domains: {
      domain: string; allowsHttp: boolean; includesSubdomains: boolean;
      minTls?: string; forwardSecrecy?: boolean; thirdParty: boolean;
    }[];
  };
  urlSchemes: { name?: string; role?: string; schemes: string[] }[];
  queriedSchemes: string[];
  associatedDomains: string[];
  backgroundModes: string[];
  privacyManifest: boolean;
  extensions: { name: string; bundleId?: string; point?: string }[];
  /** Embedded frameworks, dylibs and app extensions, one row per Mach-O. */
  binaries: {
    name: string;
    kind: 'framework' | 'dylib' | 'extension' | 'watch';
    path: string;
    version?: string;
    bundleId?: string;
    sizeBytes: number;
    swift: boolean;
    objc: boolean;
    arc: boolean;
    stackCanary: boolean;
    stripped: boolean;
    signed: boolean;
  }[];
  main: {
    arch?: string;
    cpu?: string;
    fileType?: string;
    is64Bit: boolean;
    swift: boolean;
    objc: boolean;
    stripped: boolean;
    localSymbols: number;
    uuid?: string;
    minOs?: string;
    sdk?: string;
    sizeBytes: number;
    linkedLibraries: string[];
    weakLibraries: string[];
    rpaths: string[];
    hardenedRuntime: boolean;
    encrypted: boolean;
  };
  /** Info.plist key counts, for a "what is declared" overview. */
  plistKeys: number;
  fileCount: number;
};

export type CategoryScore = {
  category: string;
  title: string;
  blurb: string;
  /** False when no rule for this category applies to the scanned platform. */
  applicable: boolean;
  pass: boolean;
  findings: number;
  worst: SastSeverity | null;
  rulesEvaluated: number;
};

/**
 * How the scan was produced, for the report's scope and methodology page.
 */
export type ScanMethod = {
  decompiler: 'java' | 'smali' | 'none';
  javaFileCount: number;
  /** What ran, in plain words. */
  tools: string[];
};

/** OWASP Mobile Top 10 (2024) names, keyed by the code a finding carries in `owasp`. */
export const OWASP_MOBILE_2024: Record<string, string> = {
  M1: 'Improper Credential Usage',
  M2: 'Inadequate Supply Chain Security',
  M3: 'Insecure Authentication/Authorization',
  M4: 'Insufficient Input/Output Validation',
  M5: 'Insecure Communication',
  M6: 'Inadequate Privacy Controls',
  M7: 'Insufficient Binary Protections',
  M8: 'Security Misconfiguration',
  M9: 'Insecure Data Storage',
  M10: 'Insufficient Cryptography',
};

/**
 * A reviewer's decision about one finding. `open` is the absence of a decision
 * and is never stored; the rest carry who decided, when and why. See
 * `triage.ts` for what each status does to the numbers.
 */
export type TriageStatus = 'open' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'fixed';

export type TriageEntry = {
  status: Exclude<TriageStatus, 'open'>;
  reason: string;
  /** Accepted risks only: the date (YYYY-MM-DD) the acceptance lapses. */
  expiresAt?: string;
  updatedBy: string;
  updatedAt: string;
  /** Set when copied forward from an earlier scan of the same app: that scan's id. */
  carriedFrom?: string;
};

export type SastScan = {
  /** Which scoring model produced the score (see the backend's `SCORE_MODEL`). */
  scoreModel?: number;
  /** How many decompiled files this scan retained for the Explorer. */
  retainedFiles?: number;
  /** True while the server is still collecting the sources for the Explorer; they are served once ready. */
  filesPending?: boolean;
  /** How many readable files the decode held, before any cap. */
  filesFound?: number;
  /** True when a cap stopped retention short of the whole tree. */
  filesTruncated?: boolean;
  scanId: string;
  createdAt: string;
  durationMs: number;
  artifact: {
    platform: 'android' | 'ios';
    fileName: string;
    sizeBytes: number;
    sha256: string;
    packageName?: string;
    versionName?: string;
    versionCode?: string;
    minSdk?: string;
    targetSdk?: string;
    minimumOsVersion?: string;
    permissions: string[];
    signers: string[];
    signatureSchemes: string[];
    nativeLibraries: string[];
    nativeLibraryDetail: {
      name: string; pie: boolean; nx: boolean; stackCanary: boolean;
      relro: 'full' | 'partial' | 'none'; symbolsStripped: boolean; fortified: boolean;
    }[];
    detectedLibraries: string[];
  binaryProtections?: {
    pie: boolean; arc: boolean; stackCanary: boolean;
    encrypted: boolean; nonExecutableStack: boolean; archCount: number;
  };
    ios?: IosFacts;
    android?: AndroidFacts;
    iconDataUrl?: string;
    fileCount: number;
    /** An iOS bundle's files (capped), so a replay can draw the whole app. */
    fileListing?: string[];
    components: ComponentInventory;
    permissionDetail: { name: string; level: string; description: string }[];
    dependencies: { coordinate: string; version: string; source: string; advisoryCount: number }[];
  };
  findings: SastFinding[];
  secure: SastFinding[];
  hotspots: SastFinding[];
  recon: ReconSection;
  domains?: DomainRow[];
  categories: CategoryScore[];
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<SastSeverity, number>;
  limitations: string[];
  /** SHA-256 over the artifact digest, score and findings. */
  reportHash: string;
  /** How many rules were evaluated and how they came out. Counts only: the list is never served. */
  coverageSummary?: CoverageSummary;
  /** Protections the app implements or lacks, with how each is typically bypassed. Absent on older scans. */
  controls?: SecurityControl[];
  /** Findings read as attack paths. Absent when the server could not derive them. */
  chains?: AttackChain[];
  /** What produced the scan; absent on older scans. */
  method?: ScanMethod;
  /** Decisions recorded against this scan's findings and hotspots, keyed by rule id. */
  triage?: Record<string, TriageEntry>;
};

export type CoverageSummary = { total: number; flagged: number; clear: number };

/** What a link of an attack chain rests on: a finding, a hotspot, or a fact read from the artifact. `ruleId` is the triage key. */
export type ChainItem = {
  ruleId?: string;
  title: string;
  severity?: SastSeverity;
  kind: 'defect' | 'hotspot' | 'fact';
  location?: { file: string; line?: number };
};

/** One step of a chain. `absence` marks a protection the scan looked for and did not find; it has no items. */
export type ChainLink = {
  role: 'entry' | 'weakness' | 'amplifier' | 'impact';
  label: string;
  required: boolean;
  items: ChainItem[];
  /** How many matched; `items` is capped. */
  total: number;
  absence?: boolean;
};

/**
 * Findings joined into the path an attacker would take. Derived from the findings, so it never changes the
 * score. `likely` only when the entry point and the flaw are in the same class; static analysis cannot prove
 * more than that.
 */
export type AttackChain = {
  id: string;
  title: string;
  severity: SastSeverity;
  confidence: 'likely' | 'possible';
  summary: string;
  steps: string[];
  links: ChainLink[];
  breakpoint: string;
  masvs?: string;
  cwe?: string[];
};

export type ScanSummary = {
  scanId: string;
  appId: string | null;
  createdAt: string;
  platform: string;
  fileName: string;
  packageName: string | null;
  versionName?: string;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<SastSeverity, number>;
  findings: number;
  durationMs: number;
};


export type ComponentInventory = {
  activities: number;
  services: number;
  receivers: number;
  providers: number;
  exported: number;
  browsable: { component: string; schemes: string[]; hosts: string[] }[];
};

export type ReconSection = {
  endpoints: { url: string; host: string; cleartext: boolean; files: string[] }[];
  hosts: string[];
  emails: { address: string; files: string[] }[];
  trackers: { name: string; category: string; signature: string }[];
  keyFiles: string[];
};
