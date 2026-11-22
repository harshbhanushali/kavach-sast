/**
 * Comparing two scans.
 *
 * The question this answers is "what changed", and the useful framing is not a
 * list of two reports side by side but a verdict on the difference: what did we
 * fix, what did we break, and what has been sitting there through both.
 *
 * Two scans of the same app across releases is the case this exists for. The
 * route in routes/sast.ts refuses to compare different apps or platforms, since
 * "did it get better" means nothing across them. This function stays permissive
 * and notes a mismatch rather than throwing, so it remains usable on stored
 * scans directly.
 *
 * Findings match on `ruleId`. Per-component rules carry the component in the id
 * (`manifest.exported_provider:com.foo.Bar`), which means a component that is
 * newly exported shows as introduced rather than being lost inside an unchanged
 * count — that precision is the reason those ids were split up in the first place.
 */
import { SAST_SEVERITY_RANK } from './types.ts';
import type { SastFinding, SastLocation, SastScan, SastSeverity } from './types.ts';

export type FindingChange = {
  ruleId: string;
  title: string;
  category: string;
  status: 'introduced' | 'resolved' | 'worsened' | 'improved' | 'unchanged';
  before?: { severity: SastSeverity; occurrences: number };
  after?: { severity: SastSeverity; occurrences: number };
  /** The finding itself, from whichever side has it, for rendering detail. */
  finding: SastFinding;
  /**
   * Locations present in the candidate but not the baseline, and vice versa.
   *
   * A count that moved from 728 to 731 says nothing actionable on its own; the
   * three new call sites are the entire content of that change. Identity is
   * file plus line, which is stable for a rule that did not move.
   */
  locationsAdded: SastLocation[];
  locationsRemoved: SastLocation[];
};

export type DependencyChange = {
  coordinate: string;
  status: 'added' | 'removed' | 'upgraded' | 'downgraded' | 'unchanged';
  before?: string;
  after?: string;
  advisoriesBefore: number;
  advisoriesAfter: number;
};

export type ListChange = { value: string; status: 'added' | 'removed' };

export type ScanComparison = {
  baseline: ScanRef;
  candidate: ScanRef;
  /** One sentence on whether this got better or worse. */
  headline: string;
  scoreDelta: number;
  counts: {
    introduced: number;
    resolved: number;
    worsened: number;
    improved: number;
    unchanged: number;
  };
  findings: FindingChange[];
  dependencies: DependencyChange[];
  permissions: ListChange[];
  trackers: ListChange[];
  hosts: ListChange[];
  /** Things a reader should know before trusting the comparison. */
  notes: string[];
};

export type ScanRef = {
  scanId: string;
  fileName: string;
  packageName?: string;
  versionName?: string;
  createdAt: string;
  score: number;
  grade: string;
  sha256: string;
};

function refOf(scan: SastScan): ScanRef {
  return {
    scanId: scan.scanId,
    fileName: scan.artifact.fileName,
    packageName: scan.artifact.packageName,
    versionName: scan.artifact.versionName,
    createdAt: scan.createdAt,
    score: scan.score,
    grade: scan.grade,
    sha256: scan.artifact.sha256,
  };
}

/** Defects and hotspots together: both are things the diff should track. */
function allFindings(scan: SastScan): SastFinding[] {
  return [...scan.findings, ...scan.hotspots];
}

/** `file:line`, the identity of a location for diffing purposes. */
function locationKey(l: SastLocation): string {
  return `${l.file}:${l.line ?? ''}`;
}

function diffLocations(
  before: SastLocation[] = [],
  after: SastLocation[] = [],
): { added: SastLocation[]; removed: SastLocation[] } {
  const beforeKeys = new Set(before.map(locationKey));
  const afterKeys = new Set(after.map(locationKey));
  return {
    added: after.filter((l) => !beforeKeys.has(locationKey(l))),
    removed: before.filter((l) => !afterKeys.has(locationKey(l))),
  };
}

function diffLists(before: string[], after: string[]): ListChange[] {
  const a = new Set(before);
  const b = new Set(after);
  return [
    ...after.filter((v) => !a.has(v)).map((value) => ({ value, status: 'added' as const })),
    ...before.filter((v) => !b.has(v)).map((value) => ({ value, status: 'removed' as const })),
  ].sort((x, y) => x.status.localeCompare(y.status) || x.value.localeCompare(y.value));
}

export function compareScans(baseline: SastScan, candidate: SastScan): ScanComparison {
  const before = new Map(allFindings(baseline).map((f) => [f.ruleId, f]));
  const after = new Map(allFindings(candidate).map((f) => [f.ruleId, f]));

  const findings: FindingChange[] = [];

  for (const [ruleId, f] of after) {
    const old = before.get(ruleId);
    if (!old) {
      findings.push({
        ruleId, title: f.title, category: f.category, status: 'introduced',
        after: { severity: f.severity, occurrences: f.occurrences },
        finding: f,
        // Everything is new when the finding itself is.
        locationsAdded: f.locations,
        locationsRemoved: [],
      });
      continue;
    }
    const rankDelta = SAST_SEVERITY_RANK[f.severity] - SAST_SEVERITY_RANK[old.severity];
    const status =
      rankDelta > 0 ? 'worsened'
      : rankDelta < 0 ? 'improved'
      // Same severity but more places: still worse, and worth surfacing.
      : f.occurrences > old.occurrences ? 'worsened'
      : f.occurrences < old.occurrences ? 'improved'
      : 'unchanged';

    const moved = diffLocations(old.locations, f.locations);
    findings.push({
      ruleId, title: f.title, category: f.category, status,
      before: { severity: old.severity, occurrences: old.occurrences },
      after: { severity: f.severity, occurrences: f.occurrences },
      finding: f,
      locationsAdded: moved.added,
      locationsRemoved: moved.removed,
    });
  }

  for (const [ruleId, old] of before) {
    if (after.has(ruleId)) continue;
    findings.push({
      ruleId, title: old.title, category: old.category, status: 'resolved',
      before: { severity: old.severity, occurrences: old.occurrences },
      finding: old,
      locationsAdded: [],
      locationsRemoved: old.locations,
    });
  }

  // --- dependencies ---
  const depsBefore = new Map(baseline.artifact.dependencies.map((d) => [d.coordinate, d]));
  const depsAfter = new Map(candidate.artifact.dependencies.map((d) => [d.coordinate, d]));
  const dependencies: DependencyChange[] = [];

  for (const [coordinate, now] of depsAfter) {
    const then = depsBefore.get(coordinate);
    if (!then) {
      dependencies.push({
        coordinate, status: 'added', after: now.version,
        advisoriesBefore: 0, advisoriesAfter: now.advisoryCount,
      });
      continue;
    }
    const cmp = compareVersionStrings(now.version, then.version);
    dependencies.push({
      coordinate,
      status: cmp > 0 ? 'upgraded' : cmp < 0 ? 'downgraded' : 'unchanged',
      before: then.version,
      after: now.version,
      advisoriesBefore: then.advisoryCount,
      advisoriesAfter: now.advisoryCount,
    });
  }
  for (const [coordinate, then] of depsBefore) {
    if (depsAfter.has(coordinate)) continue;
    dependencies.push({
      coordinate, status: 'removed', before: then.version,
      advisoriesBefore: then.advisoryCount, advisoriesAfter: 0,
    });
  }

  const counts = {
    introduced: findings.filter((f) => f.status === 'introduced').length,
    resolved: findings.filter((f) => f.status === 'resolved').length,
    worsened: findings.filter((f) => f.status === 'worsened').length,
    improved: findings.filter((f) => f.status === 'improved').length,
    unchanged: findings.filter((f) => f.status === 'unchanged').length,
  };

  const notes: string[] = [];
  if (
    baseline.artifact.packageName &&
    candidate.artifact.packageName &&
    baseline.artifact.packageName !== candidate.artifact.packageName
  ) {
    notes.push(
      `These are different applications (${baseline.artifact.packageName} and ${candidate.artifact.packageName}). ` +
        'The comparison is still meaningful for posture, but a rule that fires on one and not the other may reflect a difference in what the apps do rather than a regression.',
    );
  }
  if (baseline.artifact.platform !== candidate.artifact.platform) {
    notes.push(
      `The platforms differ (${baseline.artifact.platform} and ${candidate.artifact.platform}), so most rules apply to only one side and nearly everything will read as introduced or resolved.`,
    );
  }
  if (baseline.artifact.sha256 === candidate.artifact.sha256) {
    notes.push('Both scans are of the same binary, so any difference comes from a change to the scanner, not to the app.');
  }
  const ruleDelta = (candidate.coverageSummary?.total ?? 0) - (baseline.coverageSummary?.total ?? 0);
  if (ruleDelta !== 0) {
    // Two quite different causes, and the note has to allow for both: the
    // scanner may have gained or lost rules between the runs, or the rules may
    // simply not apply to one artifact: the ELF rules do not run on an APK with
    // no native libraries. Saying "did not run against the baseline" implied
    // scanner drift in a case that was really a property of the app.
    const n = Math.abs(ruleDelta);
    notes.push(
      `The candidate evaluated ${n} ${ruleDelta > 0 ? 'more' : 'fewer'} rule${n === 1 ? '' : 's'} than the baseline \u2014 ` +
        'either because the scanner changed between the two runs, or because some rules do not apply to one of the artifacts. ' +
        'Findings from those rules read as introduced or resolved without the underlying code having changed.',
    );
  }

  const scoreDelta = candidate.score - baseline.score;
  const regressions = counts.introduced + counts.worsened;
  const fixes = counts.resolved + counts.improved;

  const headline =
    regressions === 0 && fixes === 0
      ? 'No change: the same findings, at the same severities, in both scans.'
      : regressions === 0
        ? `${fixes} finding${fixes === 1 ? '' : 's'} fixed and nothing new introduced.`
        : fixes === 0
          ? `${regressions} finding${regressions === 1 ? '' : 's'} introduced or made worse, with nothing fixed.`
          : `${fixes} fixed, ${regressions} introduced or made worse.`;

  return {
    baseline: refOf(baseline),
    candidate: refOf(candidate),
    headline,
    scoreDelta,
    counts,
    // Regressions first: the reason to open a comparison is usually to find them.
    findings: findings.sort(
      (a, b) => statusWeight(a.status) - statusWeight(b.status) ||
        SAST_SEVERITY_RANK[(b.after ?? b.before)!.severity] - SAST_SEVERITY_RANK[(a.after ?? a.before)!.severity] ||
        a.ruleId.localeCompare(b.ruleId),
    ),
    dependencies: dependencies.sort(
      (a, b) => depWeight(b) - depWeight(a) || a.coordinate.localeCompare(b.coordinate),
    ),
    permissions: diffLists(
      baseline.artifact.permissionDetail.map((p) => p.name),
      candidate.artifact.permissionDetail.map((p) => p.name),
    ),
    trackers: diffLists(
      baseline.recon.trackers.map((t) => t.name),
      candidate.recon.trackers.map((t) => t.name),
    ),
    hosts: diffLists(baseline.recon.hosts, candidate.recon.hosts),
    notes,
  };
}

const STATUS_ORDER = ['introduced', 'worsened', 'improved', 'resolved', 'unchanged'];
function statusWeight(status: FindingChange['status']): number {
  return STATUS_ORDER.indexOf(status);
}

/** A dependency whose advisory count moved is the most interesting row. */
function depWeight(d: DependencyChange): number {
  if (d.advisoriesAfter > d.advisoriesBefore) return 4;
  if (d.advisoriesBefore > d.advisoriesAfter) return 3;
  if (d.status === 'added' || d.status === 'removed') return 2;
  if (d.status !== 'unchanged') return 1;
  return 0;
}

/**
 * Numeric version comparison.
 *
 * Same rule as the advisory matcher: segments compare numerically so
 * `1.10.0 > 1.9.0`, which a string compare gets backwards.
 */
function compareVersionStrings(a: string, b: string): number {
  const left = a.replace(/^v/i, '').split(/[.\-+_]/);
  const right = b.replace(/^v/i, '').split(/[.\-+_]/);
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
