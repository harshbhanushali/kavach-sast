/**
 * Static analysis: the vocabulary.
 *
 * This is a *static* scanner and it is kept strictly separate from the runtime
 * catalog. The distinction matters and is worth stating once, because conflating
 * them is the easiest way to mislead someone reading a report:
 *
 *   - A **catalog check** runs on the end user's device and reports what it saw
 *     there. It answers "is this device hostile right now?"
 *   - A **SAST rule** runs here, on an artifact, and reports what is in the
 *     binary. It answers "did we ship a mistake?"
 *
 * A SAST finding therefore never produces a detection event, never has a
 * `ThreatResponse`, and never reaches a device. It is advice to the developer.
 */

/** Ordered weakest to strongest; the report sorts on this. */
export const SAST_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type SastSeverity = (typeof SAST_SEVERITIES)[number];

export const SAST_SEVERITY_RANK: Record<SastSeverity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/**
 * Scorecard categories. Every rule belongs to exactly one, and the scorecard
 * shows pass/fail per category — which is what the spec asks for and what makes
 * a long finding list actionable rather than merely long.
 */
export const SAST_CATEGORIES = [
  'manifest',
  'secrets',
  'crypto',
  'network',
  'storage',
  'code',
  'binary',
  'signing',
  'dependencies',
] as const;
export type SastCategory = (typeof SAST_CATEGORIES)[number];

export const CATEGORY_TITLES: Record<SastCategory, string> = {
  manifest: 'Manifest & components',
  secrets: 'Hardcoded secrets',
  crypto: 'Cryptography',
  network: 'Network security',
  storage: 'Data storage',
  code: 'Code quality & injection',
  binary: 'Binary protections',
  signing: 'Code signing',
  dependencies: 'Dependencies',
};

export const CATEGORY_BLURBS: Record<SastCategory, string> = {
  manifest: 'What the app declares to the OS: exported components, permissions, and debug flags.',
  secrets: 'Credentials compiled into the artifact, where anyone who downloads it can read them.',
  crypto: 'Algorithms, modes and key material — the places weak crypto usually hides.',
  network: 'Transport security: cleartext, certificate validation, and pinning.',
  storage: 'Where data lands on disk and who else on the device can read it.',
  code: 'Patterns that turn attacker-controlled input into attacker-controlled behaviour.',
  binary: 'Compiler and linker hardening applied to the shipped native code.',
  signing: 'How the artifact is signed and whether that signature means anything.',
  dependencies: 'Third-party libraries carried into the build, and their known problems.',
};

/**
 * One finding.
 *
 * `evidence` is capped and redacted at construction — a report that quotes a
 * live secret in full has published it a second time, this time into a PDF that
 * gets emailed around.
 */
/**
 * What kind of statement a finding makes.
 *
 * Severity says how bad something is; this says what sort of thing it is, and
 * the two are independent. Making that split is the difference between a list of 30 problems and a report someone can act
 * on:
 *
 *   defect  — something is wrong and should be fixed.
 *   hotspot — nothing is provably wrong, but a human should look. A dangerous
 *             permission or a bundled key file is not a bug; shipping one
 *             without having considered it is the risk.
 *   secure  — the app does this correctly. Reporting these is not flattery: it
 *             is how a reader tells "we checked and it is fine" apart from "we
 *             never checked", which is the same distinction `applicable` draws
 *             at the category level.
 */
export const FINDING_KINDS = ['defect', 'hotspot', 'secure'] as const;
export type FindingKind = (typeof FINDING_KINDS)[number];

export type SastFinding = {
  ruleId: string;
  title: string;
  category: SastCategory;
  severity: SastSeverity;
  /** Defaults to 'defect' when a rule does not say otherwise. */
  kind?: FindingKind;
  /** One sentence: what is wrong. */
  description: string;
  /** One sentence: what an attacker does with it. */
  impact: string;
  /**
   * The concrete path from this finding to harm.
   *
   * Written as the steps someone would actually take, with the real commands
   * and file paths where they exist. "Signed with a debug certificate" tells a
   * reader nothing they can act on; "the key lives at ~/.android/debug.keystore
   * with the password `android` on every machine with the SDK installed, so
   * anyone can sign a modified build the device accepts as an update" tells
   * them why it is a critical.
   */
  exploitation?: string[];
  /** What to actually change. */
  remediation: string;
  /** OWASP MASVS control id, e.g. "MASVS-CRYPTO-1". */
  masvs?: string;
  /** CWE identifier, e.g. "CWE-798". */
  cwe?: string;
  /** OWASP Mobile Top 10 (2024) category, e.g. "M5". Derived from the MASVS control and the weakness class. */
  owasp?: string;
  /** Where it was found, artifact-relative. */
  locations: SastLocation[];
  /** How many places matched in total (locations is truncated). */
  occurrences: number;
  /** Rolled up over `locations`: yours, a library's, or both. */
  origin?: FindingOrigin;
  /** The libraries this finding touches, when any are identifiable. */
  libraries?: string[];
};

/**
 * Whose code a finding sits in.
 *
 * Severity says how bad it is, `kind` says what sort of statement it is, and
 * this says who has to fix it — three independent axes. Most findings on a real
 * app land in a bundled library, where the remedy is a dependency upgrade or
 * nothing at all; separating those from the app's own code is the difference
 * between a list to triage and a list to act on.
 */
export type Origin = 'first-party' | 'third-party' | 'unknown';

/** A finding may span both, in which case it is `mixed`. */
export type FindingOrigin = Origin | 'mixed';

export type Provenance = {
  origin: Origin;
  /** The library, when third-party and identifiable. */
  library?: string;
  /** Why it was classified this way. */
  because: string;
};

export type SastLocation = {
  file: string;
  line?: number;
  /** Redacted excerpt. Never the raw secret. */
  excerpt?: string;
  /**
   * The surrounding source, so the finding can be read in context.
   *
   * One redacted line is enough to prove a match and not enough to judge it.
   * A reviewer looking at `invoke-virtual ... setAllowFileAccessFromFileURLs`
   * wants to see the method it sits in and what runs either side of it before
   * deciding whether it matters. Every line is redacted the same way the
   * excerpt is, so widening the window cannot leak a secret the narrow view
   * was protecting.
   */
  snippet?: SnippetLine[];
  /**
   * Where this sits in the *compiled* artifact.
   *
   * A smali path is a decompiler artefact that exists only on the machine that
   * ran apktool. The DEX, the class descriptor and the method signature are
   * properties of the shipped APK, and are what a stack trace, a decompiler and
   * `dexdump` all speak in. Carrying both means the finding can be followed
   * either way round.
   */
  dex?: string;
  className?: string;
  method?: string;
  /** Whose code this line is. Set by a pass in `provenance.ts`. */
  provenance?: Provenance;
};

export type SnippetLine = {
  line: number;
  text: string;
  /** True for the line that actually matched; the rest are context. */
  vulnerable: boolean;
};


/**
 * A protection the app implements (or conspicuously does not), with the usual
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
 * What the Android analyser read out of the manifest, as structure.
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
 * Everything the iOS analyser read out of the IPA, as structure.
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

/** Facts about the artifact itself, shown in the report header. */
export type ArtifactFacts = {
  platform: 'android' | 'ios';
  fileName: string;
  sizeBytes: number;
  sha256: string;
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  /** iOS: minimum OS version. */
  minimumOsVersion?: string;
  permissions: string[];
  /** Signing certificate subjects / digests. */
  signers: string[];
  /** e.g. ["v1", "v2", "v3"] for Android; ["adhoc"] etc for iOS. */
  signatureSchemes: string[];
  nativeLibraries: string[];
  /** Per-library ELF hardening, for the report's inventory table. */
  nativeLibraryDetail: {
    name: string;
    pie: boolean; nx: boolean; stackCanary: boolean;
    relro: 'full' | 'partial' | 'none'; symbolsStripped: boolean; fortified: boolean;
  }[];
  /**
   * iOS binary protections as state, not only as findings.
   *
   * A finding is raised when one is missing; this says what is *present*, so a
   * reader can tell "we checked and PIE is on" from "we never looked".
   */
  binaryProtections?: {
    pie: boolean;
    arc: boolean;
    stackCanary: boolean;
    encrypted: boolean;
    nonExecutableStack: boolean;
    archCount: number;
  };
  /** Detected third-party SDKs, by package/framework prefix. */
  detectedLibraries: string[];
  /** iOS only: the structure behind the findings. */
  ios?: IosFacts;
  /** Android only: the manifest, as structure. */
  android?: AndroidFacts;
  /** The app icon as a small data URL, when one could be read. */
  iconDataUrl?: string;
  fileCount: number;
  /** An iOS bundle's files (capped), so a replay can draw the whole app. */
  fileListing?: string[];
  /** Declared components, which is what another app can reach. */
  components: ComponentInventory;
  /** Permissions with protection level and a plain description. */
  permissionDetail: { name: string; level: string; description: string; exported?: boolean }[];
  /** Resolved dependency coordinates and versions, with advisory counts. */
  dependencies: { coordinate: string; version: string; source: string; advisoryCount: number }[];
};

export type ComponentInventory = {
  activities: number;
  services: number;
  receivers: number;
  providers: number;
  exported: number;
  /** Class names of every declared component, as written in the manifest. */
  declared?: string[];
  /** Activities reachable from a browser via an http(s) or custom scheme. */
  browsable: { component: string; schemes: string[]; hosts: string[] }[];
};

/** The Reconnaissance section: endpoints, trackers, and bundled key material. */
export type ReconSection = {
  endpoints: { url: string; host: string; cleartext: boolean; files: string[] }[];
  hosts: string[];
  emails: { address: string; files: string[] }[];
  trackers: { name: string; category: string; signature: string }[];
  keyFiles: string[];
};

/** One row per host the artifact mentions; see `domains.ts`. */
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

export type CategoryScore = {
  category: SastCategory;
  title: string;
  blurb: string;
  /**
   * False when no rule for this category applies to this platform at all.
   *
   * Without it, `binary` and `dependencies` rendered as a green PASS on an
   * Android scan purely because nothing had looked — the exact confusion
   * `rulesEvaluated` exists to prevent. The console shows these as "not
   * assessed", never as a pass.
   */
  applicable: boolean;
  /** false when any finding at `medium` or above landed in this category. */
  pass: boolean;
  findings: number;
  worst: SastSeverity | null;
  /** Rules that ran and found nothing — evidence the category was examined. */
  rulesEvaluated: number;
};

/**
 * How the scan was produced, for the report's scope and methodology page.
 *
 * A reader judging a result needs to know what looked at the artifact: a scan
 * that decompiled to Java and one that fell back to smali, or ran without
 * apktool, are different assurances, and the report should not leave that to be
 * inferred from the limitations list.
 */
export type ScanMethod = {
  decompiler: 'java' | 'smali' | 'none';
  javaFileCount: number;
  /** What ran, in plain words. */
  tools: string[];
};

export type SastScan = {
  /** Which scoring model produced `score` and `grade`; scans stored under an older one are rescored when the database opens. */
  scoreModel?: number;
  /**
   * Retained decompiled sources, present only on the value `runScan` returns.
   *
   * Deliberately not part of the stored report: the contents run to megabytes
   * and every history listing would carry them. The route moves these to their
   * own table and strips the field before the document is persisted or sent.
   */
  sources?: {
    files: { path: string; bytes: number; content: string }[];
    found: number;
    truncated: boolean;
  };
  scanId: string;
  createdAt: string;
  durationMs: number;
  artifact: ArtifactFacts;
  findings: SastFinding[];
  /** Things the app does correctly. Never counted against the score. */
  secure: SastFinding[];
  /** Things a reviewer should look at. Weighted far below a defect. */
  hotspots: SastFinding[];
  recon: ReconSection;
  /** Every host the artifact mentions, grouped and classified. */
  domains: DomainRow[];
  categories: CategoryScore[];
  /** 0-100. See `scoreOf` for the weighting. */
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<SastSeverity, number>;
  /** Analysis steps that could not run, and why. Never silently skipped. */
  limitations: string[];
  /**
   * SHA-256 over the findings and the artifact digest.
   *
   * Two jobs. It lets a reader confirm the PDF in front of them matches the scan
   * it claims to be — a security report that travels by email is exactly the
   * kind of document someone edits before forwarding. And because the artifact's
   * own SHA-256 is part of the input, two reports with the same hash are the
   * same verdict on the same binary, which makes "has this actually changed
   * since the last release?" answerable by comparing one line.
   *
   * Deliberately not a signature: it proves integrity against accident and
   * casual edit, not against someone who recomputes it. Saying otherwise would
   * be the kind of overclaim this codebase avoids elsewhere.
   */
  reportHash: string;
  /** Protections the app implements or lacks, with how each is typically bypassed. */
  controls: SecurityControl[];
  /** What produced the scan. */
  method: ScanMethod;
  /**
   * How many rules were evaluated, and how they came out.
   *
   * Counts only. The per-rule list is the scanner's detection logic written out,
   * so it is never serialised, stored or served. The counts keep the useful half
   * of the claim: a scan that evaluated 94 rules and flagged 22 says it looked,
   * without publishing what it looks for.
   */
  coverageSummary: CoverageSummary;
  /** Findings joined into attack paths. Absent on scans stored before chains existed; derived on read. */
  chains?: AttackChain[];
};

export type CoverageSummary = { total: number; flagged: number; clear: number };

/**
 * One thing a link of an attack chain rests on: a finding, a hotspot, or a fact the scan read out of the
 * artifact (a host it talks to). `ruleId` is the triage key, so the console can tell when a decision has
 * taken a link away; a fact has none.
 */
export type ChainItem = {
  ruleId?: string;
  title: string;
  severity?: SastSeverity;
  kind: 'defect' | 'hotspot' | 'fact';
  /** The place most worth opening: in the same class as the entry point when there is one. */
  location?: { file: string; line?: number };
};

/**
 * One step of a chain, with whatever the scan found for it.
 *
 * `entry` is how an attacker gets in, `weakness` is the flaw they use, `amplifier` makes the outcome worse
 * and is never needed for the chain to exist, `impact` is what the app gives away. A link with no items and
 * `absence` set stands for a protection the scan looked for and did not find.
 */
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
 * Findings joined into the path an attacker would take.
 *
 * A finding says one thing is wrong. A chain says which things are wrong *together*, so that fixing one of
 * them ends the story. It is derived from the findings already in the scan and never adds to the score: it
 * is a way of reading them. Static analysis cannot prove a path is reachable, so `confidence` is `likely`
 * only when the entry point and the flaw sit in the same class, and `possible` otherwise.
 */
export type AttackChain = {
  id: string;
  title: string;
  severity: SastSeverity;
  confidence: 'likely' | 'possible';
  /** One sentence: what the attacker ends up with. */
  summary: string;
  /** The path, in order, in the app's own names. */
  steps: string[];
  links: ChainLink[];
  /** The one change that ends the chain. */
  breakpoint: string;
  masvs?: string;
  cwe?: string[];
};


/** One rule's outcome, used inside the scanner to derive `coverageSummary`. Never serialised. */
export type RuleOutcome = {
  ruleId: string;
  title: string;
  category: SastCategory;
  /** 'flagged' when it produced a finding, 'clear' when it ran and did not. */
  status: 'flagged' | 'clear';
  severity?: SastSeverity;
  /** Where it looked, in one short phrase. */
  scope: string;
};

/**
 * How the score is worked out (model 2).
 *
 * The first model took a fixed number of points per finding with no limit, so three criticals or six highs
 * reached zero. Nearly every app, including a real one with two criticals of its own, scored 0, which tells
 * nobody anything. This one keeps the same ordering (a critical is worth far more than a medium) and fixes
 * what made it saturate:
 *
 * - **Diminishing returns inside a severity.** Each severity has a ceiling on what it can cost, and every
 *   finding after the first costs a little less than the one before. The tenth medium is not as bad as the
 *   first, and a score keeps separating "one critical" from "five".
 * - **Whose code it is.** A finding in a bundled library counts a quarter as much as one in the app's own
 *   code: it is usually fixed by upgrading a dependency, not by editing the app. Unattributed findings
 *   count in full, so nothing is discounted on a guess.
 * - **The ceilings add up to less than 100.** Even an app with everything wrong keeps a few points, so the
 *   bottom of the scale means "as bad as it gets", not "this is where the arithmetic ran out".
 * - **A grade gate.** A critical defect in the app's own code cannot grade better than C (a score of 74 at
 *   most), and a high one cannot grade better than B (89), whatever else is clean.
 *
 * Hotspots cost a little and good practice earns a little back, both capped; good practice is not counted
 * while a critical defect in the app's own code is open.
 */
export const SCORE_MODEL = 2;

export const SCORE_LOSS: Record<SastSeverity, { weight: number; cap: number }> = {
  critical: { weight: 25, cap: 50 },
  high: { weight: 5, cap: 25 },
  medium: { weight: 1.2, cap: 12 },
  low: { weight: 0.4, cap: 3 },
  info: { weight: 0, cap: 0 },
};
export const LIBRARY_SHARE = 0.25;
export const SCORE_CEILING = { critical: 74, high: 89 };
const HOTSPOT_PENALTY = 1;
const HOTSPOT_CAP = 4;
const SECURE_CREDIT = 2;
const SECURE_CAP = 6;

export function gradeFor(score: number): SastScan['grade'] {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

export function scoreOf(
  findings: SastFinding[],
  secure: SastFinding[] = [],
  hotspots: SastFinding[] = [],
): { score: number; grade: SastScan['grade'] } {
  // A finding counts in full unless it is known to be in a bundled library.
  const weighted: Record<SastSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) weighted[f.severity] += f.origin === 'third-party' ? LIBRARY_SHARE : 1;

  let loss = 0;
  for (const severity of Object.keys(weighted) as SastSeverity[]) {
    const { weight, cap } = SCORE_LOSS[severity];
    if (cap > 0 && weighted[severity] > 0) loss += cap * (1 - Math.exp((-weight * weighted[severity]) / cap));
  }

  const ownCritical = findings.some((f) => f.severity === 'critical' && f.origin !== 'third-party');
  const ownHigh = findings.some((f) => f.severity === 'high' && f.origin !== 'third-party');
  const hotspotPenalty = Math.min(HOTSPOT_CAP, hotspots.length * HOTSPOT_PENALTY);
  // An app with a live AWS key in it does not get points for using SQLCipher.
  const credit = ownCritical ? 0 : Math.min(SECURE_CAP, secure.length * SECURE_CREDIT);

  let score = 100 - loss - hotspotPenalty + credit;
  if (ownCritical) score = Math.min(score, SCORE_CEILING.critical);
  else if (ownHigh) score = Math.min(score, SCORE_CEILING.high);
  score = Math.round(Math.max(0, Math.min(100, score)));
  return { score, grade: gradeFor(score) };
}

export function countsOf(findings: SastFinding[]): Record<SastSeverity, number> {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/**
 * Builds the per-category scorecard.
 *
 * `rulesEvaluated` is carried through so a green category can be read as "18
 * rules looked and found nothing" rather than the much weaker "nothing was
 * reported", which is also what an unimplemented category looks like.
 */
export function scorecardOf(
  findings: SastFinding[],
  rulesPerCategory: Record<SastCategory, number>,
): CategoryScore[] {
  return SAST_CATEGORIES.map((category) => {
    const own = findings.filter((f) => f.category === category);
    const worst = own.reduce<SastSeverity | null>(
      (acc, f) => (acc === null || SAST_SEVERITY_RANK[f.severity] > SAST_SEVERITY_RANK[acc] ? f.severity : acc),
      null,
    );
    const rulesEvaluated = rulesPerCategory[category] ?? 0;
    return {
      category,
      title: CATEGORY_TITLES[category],
      blurb: CATEGORY_BLURBS[category],
      applicable: rulesEvaluated > 0,
      pass: worst === null || SAST_SEVERITY_RANK[worst] < SAST_SEVERITY_RANK.medium,
      findings: own.length,
      worst,
      rulesEvaluated,
    };
  });
}

/**
 * Trims an excerpt to a printable length.
 *
 * Values are shown in full, on purpose. This scanner is self-hosted and the
 * operator is scanning their own artifact; masking the one thing they need was
 * getting in the way of the job. You cannot revoke a key you cannot read, and
 * you cannot tell a live credential from a placeholder without seeing it — a
 * masked `AKIA••••••••7ABC` forces the reviewer to go and extract it by hand,
 * which is strictly worse than printing what every person who downloads the APK
 * can already read.
 *
 * The consequence is that a report containing a secrets finding contains the
 * secret. The report says so where it matters, so it can be handled like the
 * sensitive document it is.
 */
export function redact(text: string): string {
  // Name kept so every call site does not change; what it does now is bound the
  // length, not hide the content.
  return text.replace(/\s+$/, '').slice(0, 300);
}
