/**
 * Scan orchestration.
 *
 * Picks the analyser from the file type, assembles the scorecard, and cleans up
 * after itself. The uploaded artifact is a customer's application binary: it is
 * decoded into a temporary directory, analysed, and both the upload and the
 * decode are removed before this returns. Only the findings are kept.
 */
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyseApk } from './android.ts';
import { IOS_STRUCTURAL_RULES, analyseIpa } from './ios.ts';
import { rulesFor } from './rules.ts';
import {
  SAST_CATEGORIES,
  SAST_SEVERITY_RANK,
  countsOf,
  scorecardOf,
  scoreOf,
  SCORE_MODEL,
} from './types.ts';
import { coveredCoordinates } from './advisories.ts';
import { PATTERN_RULES } from './rules.ts';
import { attribute } from './provenance.ts';
import { collectSources } from './sources.ts';
import { beginFileCache, clearFileCache } from './fileCache.ts';
import { hashReport } from './reportHash.ts';
import { scrubDecompilerNotes } from './redact.ts';
import { chainsOf } from './chains.ts';
import { controlsOf } from './controls.ts';
import { owaspMobileFor } from './owasp.ts';
import { inventoryDomains } from './domains.ts';
import type { ProgressSink } from './progress.ts';
import type { ArtifactFacts, CoverageSummary, RuleOutcome, SastCategory, SastFinding, SastScan } from './types.ts';

export type ScanOptions = {
  /** Called as the scan moves between stages, for the console's progress bar. */
  onProgress?: ProgressSink;
  /**
   * Called with the finished report before the sources the Explorer shows are collected. Collecting them
   * means reading every file again and then deleting the decode, which is much of the time between "the
   * findings are known" and "the scan returned"; whoever is waiting on the findings should not wait for it.
   */
  onDocument?: (document: Omit<SastScan, 'sources'>) => void;
  filePath: string;
  fileName: string;
  tools: { apktool?: string; apksigner?: string; jadx?: string };
};

export class ScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanError';
  }
}

/**
 * How many rules examined each category.
 *
 * Structural rules have no entry in `PATTERN_RULES`, so their counts are added
 * here. The number exists so the report can say "18 rules looked and found
 * nothing" — a green category with a zero here would be indistinguishable from
 * one that was never implemented.
 */
function ruleCoverage(
  platform: 'android' | 'ios',
  /** Android: native libraries actually read. Zero means nothing to harden. */
  nativeInspected = 1,
): Record<SastCategory, number> {
  const coverage = Object.fromEntries(SAST_CATEGORIES.map((c) => [c, 0])) as Record<SastCategory, number>;
  for (const rule of rulesFor(platform)) coverage[rule.category] += 1;

  const structural: Record<'android' | 'ios', Partial<Record<SastCategory, number>>> = {
    // manifest: debuggable, allowBackup, cleartext, nsc cleartext, nsc user CA,
    // no pinning, exported components, provider grants, task affinity,
    // dangerous permissions, low minSdk.
    // manifest (8) + network (3) + signing (2) + the seven ELF hardening
    // checks in nativeLibs.ts, which is what moved `binary` off "not assessed".
    // dependencies: the advisory match plus the tracker inventory. Without
    // this the category reported "not assessed" while carrying a finding,
    // which is the exact contradiction `applicable` exists to prevent.
    android: { manifest: 8, network: 3, signing: 4, binary: 7, dependencies: 2 },
    // Derived from the rule list itself, so the count cannot drift from what runs.
    ios: IOS_STRUCTURAL_RULES.reduce<Partial<Record<SastCategory, number>>>(
      (counts, [, , category]) => ({ ...counts, [category]: (counts[category] ?? 0) + 1 }),
      {},
    ),
  };
  for (const [category, count] of Object.entries(structural[platform])) {
    coverage[category as SastCategory] += count ?? 0;
  }

  // An app with no native code has nothing for the ELF rules to examine. Zero
  // here makes the category render as "not assessed" rather than as a green
  // pass earned by an empty lib/ directory.
  if (platform === 'android' && nativeInspected === 0) coverage.binary = 0;

  return coverage;
}

function summaryOf(rows: RuleOutcome[]): CoverageSummary {
  const flagged = rows.filter((r) => r.status === 'flagged').length;
  return { total: rows.length, flagged, clear: rows.length - flagged };
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * The full rule inventory for a scan: what ran, and what it concluded.
 *
 * Built from the rule table plus the structural rules, so a rule cannot appear
 * in the report's coverage list without existing in the code. The alternative —
 * a hand-maintained list — drifts the first time someone adds a rule and
 * forgets, and then the report lies about what it checked.
 */
function coverageOf(
  platform: 'android' | 'ios',
  findings: SastFinding[],
  hotspots: SastFinding[],
  nativeInspected: number,
): RuleOutcome[] {
  const flagged = new Map<string, SastFinding>();
  for (const f of [...findings, ...hotspots]) {
    // Per-component rule ids carry the component after a colon; the coverage
    // list reports the rule, not each instance of it.
    const base = f.ruleId.split(':')[0];
    flagged.set(base, f);
    // Advisory ids are per-CVE (`dependency.cve-2021-0341`); the coverage row
    // is the generic one, so map any of them onto it.
    if (base.startsWith('dependency.')) flagged.set('dependency.known_vulnerable', f);
  }

  const rows: RuleOutcome[] = [];
  const push = (ruleId: string, title: string, category: SastCategory, scope: string) => {
    const hit = flagged.get(ruleId);
    rows.push({
      ruleId,
      title,
      category,
      status: hit ? 'flagged' : 'clear',
      severity: hit?.severity,
      scope,
    });
  };

  for (const rule of PATTERN_RULES.filter((r) => r.platforms.includes(platform))) {
    push(rule.id, rule.title, rule.category, rule.allOf || rule.anyOf ? 'decompiled sources (multi-pattern)' : 'decompiled sources');
  }

  if (platform === 'android') {
    const manifest: [string, string][] = [
      ['manifest.debuggable', 'Application is debuggable'],
      ['manifest.allow_backup', 'Application data is backed up'],
      ['manifest.cleartext_traffic', 'Cleartext HTTP traffic permitted'],
      ['manifest.nsc_cleartext', 'Network security config permits cleartext'],
      ['manifest.nsc_user_ca', 'User-installed certificate authorities trusted'],
      ['manifest.no_pinning', 'No certificate pinning configured'],
      ['manifest.exported_activity', 'Exported activity with no permission'],
      ['manifest.exported_service', 'Exported service with no permission'],
      ['manifest.exported_receiver', 'Exported receiver with no permission'],
      ['manifest.exported_provider', 'Exported provider with no permission'],
      ['manifest.provider_grant_uri', 'ContentProvider grants URI permissions'],
      ['manifest.task_affinity', 'Activity vulnerable to task hijacking'],
      ['manifest.low_min_sdk', 'minSdkVersion below the supported floor'],
      ['manifest.dangerous_permissions', 'High-impact permissions requested'],
      ['manifest.test_only', 'Application is marked testOnly'],
      ['manifest.dialer_secret_code', 'Hidden dialer codes'],
      ['manifest.high_intent_priority', 'Intent filters with very high priority'],
      ['manifest.browsable_deeplink', 'Activities reachable from a web link'],
      ['manifest.applink_not_verified', 'http(s) link filters without autoVerify'],
      ['manifest.normal_permission_guard', 'Exported components guarded by a normal permission'],
    ];
    for (const [id, title] of manifest) push(id, title, 'manifest', 'AndroidManifest.xml');

    push('net.trust_all_certs', 'TrustManager accepts every certificate', 'network', 'smali method bodies');
    push('net.allow_all_hostnames', 'HostnameVerifier accepts every hostname', 'network', 'smali method bodies');
    push('signing.v1_only', 'APK signed with the v1 scheme only', 'signing', 'signing block');
    push('signing.debug_certificate', 'Signed with the Android debug certificate', 'signing', 'signing certificate');
    push('signing.weak_signature_algorithm', 'Certificate signed with a broken hash', 'signing', 'signing certificate');
    push('signing.weak_key_size', 'Signing key below 2048 bits', 'signing', 'signing certificate');
      push('recon.trackers', 'Privacy trackers bundled', 'dependencies', 'package signatures');
    push('dependency.known_vulnerable', 'Dependency with a known advisory', 'dependencies',
      `${coveredCoordinates().length} coordinates in the advisory set`);
    push('recon.key_material', 'Certificate or key files bundled', 'secrets', 'artifact contents');

    if (nativeInspected > 0) {
      const native: [string, string][] = [
        ['native.no_nx', 'Native library with an executable stack'],
        ['native.no_pie', 'Native library not position-independent'],
        ['native.no_stack_canary', 'Native library without a stack protector'],
        ['native.no_relro', 'Native library without RELRO'],
        ['native.partial_relro', 'Native library with partial RELRO only'],
        ['native.runpath', 'Native library setting RPATH or RUNPATH'],
        ['native.symbols_not_stripped', 'Native library retaining debug symbols'],
      ];
      for (const [id, title] of native) push(id, title, 'binary', `lib/**.so (${nativeInspected} inspected)`);
    }
  } else {
    for (const [id, title, category, scope] of IOS_STRUCTURAL_RULES) push(id, title, category, scope);
  }

  return rows.sort(
    (a, b) =>
      Number(b.status === 'flagged') - Number(a.status === 'flagged') ||
      a.category.localeCompare(b.category) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

/** Worst first, then by how much of the artifact each one touches. */
function rank(findings: SastFinding[]): SastFinding[] {
  return [...findings].sort(
    (a, b) =>
      SAST_SEVERITY_RANK[b.severity] - SAST_SEVERITY_RANK[a.severity] ||
      b.occurrences - a.occurrences ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function runScan(options: ScanOptions): SastScan {
  const started = Date.now();
  const lower = options.fileName.toLowerCase();
  const platform: 'android' | 'ios' = lower.endsWith('.ipa')
    ? 'ios'
    : lower.endsWith('.apk')
      ? 'android'
      : (() => {
          throw new ScanError('expected a .apk or .ipa file');
        })();

  const workDir = join(tmpdir(), `kavach-sast-${randomUUID()}`);
  mkdirSync(workDir, { recursive: true });

  try {
    beginFileCache();
    const progress: ProgressSink = options.onProgress ?? (() => {});
    progress('unpacking');

    const analysis =
      platform === 'android'
        ? analyseApk(options.filePath, options.tools, workDir, progress)
        : analyseIpa(options.filePath, workDir, progress);

    progress('reporting');

    // Attribution runs here rather than inside each scanner: it needs the
    // manifest's package name and the resolved dependency list, which only
    // exist once the artifact has been parsed.
    const attribution = {
      packageName: analysis.packageName,
      dependencies: 'dependencies' in analysis ? analysis.dependencies : [],
      declaredComponents: analysis.components.declared,
      // A browsable activity's class name is direct evidence of a package the
      // app team owns, and it catches the case where the application id has a
      // flavour suffix the code packages do not.
      extraAppRoots: analysis.components.browsable
        .map((b) => b.component.split('.').slice(0, -1).join('.'))
        .filter((p) => p.includes('.')),
    };

    // Snippets are copied out of decompiled files, so they carry the decompiler's own notes.
    const scrubLocations = (list: SastFinding[]): SastFinding[] =>
      list.map((f) => ({
        ...f,
        locations: f.locations.map((l) => ({
          ...l,
          ...(l.excerpt ? { excerpt: scrubDecompilerNotes(l.excerpt) } : {}),
          ...(l.snippet ? { snippet: l.snippet.map((line) => ({ ...line, text: scrubDecompilerNotes(line.text) })) } : {}),
        })),
      }));

    const withOwasp = (list: SastFinding[]) => list.map((f) => ({ ...f, owasp: owaspMobileFor(f) }));
    const findings = scrubLocations(withOwasp(attribute(rank(analysis.findings), attribution)));
    // Attributed like the rest so a control can say whose code the check lives in.
    const secure = scrubLocations(attribute(analysis.secure, attribution));
    const hotspots = scrubLocations(withOwasp(attribute(rank(analysis.hotspots), attribution)));
    const { score, grade } = scoreOf(findings, secure, hotspots);

    const artifact: ArtifactFacts = {
      platform,
      fileName: options.fileName,
      sizeBytes: statSync(options.filePath).size,
      sha256: sha256(options.filePath),
      packageName: analysis.packageName,
      versionName: analysis.versionName,
      versionCode: analysis.versionCode,
      minSdk: 'minSdk' in analysis ? analysis.minSdk : undefined,
      targetSdk: 'targetSdk' in analysis ? analysis.targetSdk : undefined,
      minimumOsVersion: 'minimumOsVersion' in analysis ? analysis.minimumOsVersion : undefined,
      permissions: analysis.permissions,
      signers: analysis.signers,
      signatureSchemes: analysis.signatureSchemes,
      nativeLibraries: analysis.nativeLibraries,
      nativeLibraryDetail: 'nativeLibraryDetail' in analysis ? analysis.nativeLibraryDetail : [],
      detectedLibraries: analysis.detectedLibraries,
      binaryProtections: 'binaryProtections' in analysis ? analysis.binaryProtections : undefined,
      ios: 'ios' in analysis ? analysis.ios : undefined,
      android: 'android' in analysis ? analysis.android : undefined,
      iconDataUrl: analysis.iconDataUrl,
      fileCount: 'fileCount' in analysis ? analysis.fileCount : 0,
      fileListing: 'fileListing' in analysis ? analysis.fileListing : undefined,
      components: analysis.components,
      permissionDetail: analysis.permissionDetail,
      dependencies: 'dependencies' in analysis ? analysis.dependencies : [],
    };

    const controls = controlsOf({ platform, secure, findings, hotspots, artifact });
    const domains = inventoryDomains(analysis.recon.endpoints);
    const chains = chainsOf({ findings, hotspots, secure, domains, artifact });
    // Evaluated here, reduced to counts, and discarded: the list itself is never kept.
    const coverage = coverageOf(platform, findings, hotspots, 'nativeInspected' in analysis ? analysis.nativeInspected : 0);

    const document: Omit<SastScan, 'sources'> = {
      scoreModel: SCORE_MODEL,
      scanId: randomUUID(),
      createdAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      artifact,
      findings,
      secure,
      hotspots,
      controls,
      chains,
      method: {
        decompiler: analysis.decompiler,
        javaFileCount: analysis.javaFileCount,
        tools:
          platform === 'android'
            ? [
                options.tools.apktool ? 'manifest and resource decoding' : '',
                analysis.decompiler === 'java' ? 'decompilation to Java' : 'code read as Dalvik assembly (no Java decompiler)',
                'signature parsing' + (options.tools.apksigner ? ' and verification' : ''),
                'built-in ELF reader \u2014 native library hardening',
                'built-in pattern rules, entropy and advisory matching',
              ].filter(Boolean)
            : [
                'built-in Mach-O reader \u2014 headers, load commands, symbols',
                'built-in code-signature and entitlement parser',
                'built-in Info.plist and provisioning-profile parser',
                'built-in pattern rules over binary strings and bundle resources',
              ],
      },
      recon: analysis.recon,
      domains,
      categories: scorecardOf(
        findings,
        ruleCoverage(platform, 'nativeInspected' in analysis ? analysis.nativeInspected : 1),
      ),
      score,
      grade,
      counts: countsOf(findings),
      coverageSummary: summaryOf(coverage),
      reportHash: hashReport(sha256(options.filePath), findings, hotspots, score),
      limitations: [
        ...analysis.limitations,
        // Stated rather than silently left blank: the dependencies category
        // renders as "not assessed", and a reader deserves to know that is a
        // missing feature and not a clean result.
        ...(platform === 'android'
          ? [`Dependency advisories are matched against a curated set covering ${coveredCoordinates().length} coordinates, not a live CVE feed. Versions are read from META-INF/*.version and pom.properties, so a library that embeds neither is inventoried by name only and not version-checked.`]
          : ['Embedded frameworks are inventoried with the version each one declares in its Info.plist, but no advisory database is applied to them, so a vulnerable third-party framework will not be flagged by version.']),
        ...(platform === 'android'
          ? ['Native libraries are inspected for one ABI only (arm64-v8a where present). The same sources are compiled with the same flags for every ABI, so scanning the rest would repeat each finding rather than add coverage.']
          : []),
      ],
    };

    // The report is complete. Hand it over, then read the files the Explorer serves; everything else in
    // the working directory goes.
    options.onDocument?.(document);
    const sources = collectSources(analysis.sourceRoots, [findings, hotspots], {
      stripPrefix: platform === 'ios' ? 'Payload/' : undefined,
      trustedRoots: analysis.syntheticRoot ? [analysis.syntheticRoot] : [],
    });
    return { ...document, sources };
  } finally {
    clearFileCache();
    // The decode holds a full copy of someone's application. It goes away even
    // when the scan throws. Deleting tens of thousands of files is slow where the file system is, so it
    // happens in a separate process while the scan returns.
    removeInBackground(workDir);
  }
}

function removeInBackground(dir: string): void {
  if (process.platform !== 'win32') {
    try {
      const child = spawn('rm', ['-rf', dir], { stdio: 'ignore', detached: true });
      child.on('error', () => rmSync(dir, { recursive: true, force: true }));
      child.unref();
      return;
    } catch {
      // Fall through to the plain delete.
    }
  }
  rmSync(dir, { recursive: true, force: true });
}
