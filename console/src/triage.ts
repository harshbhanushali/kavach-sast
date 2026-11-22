/**
 * What a triage decision does to a scan's numbers, in one place.
 *
 * The dashboard and the report both need the same answers: is this finding
 * still active, how many are excluded and why, and what would the score be
 * without them. Keeping the rules here means the two cannot drift, which is the
 * failure mode that makes a report disagree with the screen it was exported from.
 *
 * - `open` and `confirmed` findings are **active**: they count.
 * - `false_positive`, `fixed` and a current `accepted_risk` are **excluded**:
 *   they stay listed, marked as triaged, but stop counting.
 * - An `accepted_risk` whose expiry date has passed is **active again**. An
 *   acceptance is a decision for a period, and a report must not keep honouring
 *   it after that period without anyone noticing.
 *
 * The score uses the scanner's own formula (see `scoreOf` in the backend), over
 * the active findings, so "54 as scanned, 62 after triage" is a like-for-like
 * comparison.
 */
import type { SastFinding, SastScan, SastSeverity, TriageEntry, TriageStatus } from './sastTypes';
import { HOTSPOT_PENALTY_CAP, LIBRARY_SHARE, SCORE_CEILING, SCORE_LOSS, SECURE_CREDIT_CAP } from './report/policy.ts';

export const TRIAGE_STATUSES: TriageStatus[] = ['open', 'confirmed', 'false_positive', 'accepted_risk', 'fixed'];

export const TRIAGE_META: Record<
  TriageStatus,
  { label: string; short: string; needsReason: boolean; blurb: string }
> = {
  open: { label: 'Open', short: 'Open', needsReason: false, blurb: 'Not reviewed yet.' },
  confirmed: { label: 'Confirmed', short: 'Confirmed', needsReason: false, blurb: 'A person checked it and it is a real issue.' },
  false_positive: { label: 'False positive', short: 'False +', needsReason: true, blurb: 'The scanner matched something that is not a problem. Excluded from the counts and the score.' },
  accepted_risk: { label: 'Accepted risk', short: 'Accepted', needsReason: true, blurb: 'A real issue the team has chosen to live with, for now. Excluded until the expiry date, if there is one.' },
  fixed: { label: 'Fixed', short: 'Fixed', needsReason: false, blurb: 'Resolved in the code. Excluded from the counts; a rescan confirms it.' },
};

/** Reasons shorter than this are refused by the server; the UI uses the same floor. */
export const MIN_REASON = 10;

/** The date an acceptance lapses has passed (compared by day, UTC). */
export function isExpired(entry: TriageEntry | undefined, now: Date = new Date()): boolean {
  return Boolean(entry?.status === 'accepted_risk' && entry.expiresAt && entry.expiresAt < now.toISOString().slice(0, 10));
}

/** The status shown for a finding: no decision is `open`. */
export function statusOf(scan: Pick<SastScan, 'triage'>, ruleId: string): TriageStatus {
  return scan.triage?.[ruleId]?.status ?? 'open';
}

/** Whether a finding still counts: open, confirmed, or an acceptance that has expired. */
export function isActive(scan: Pick<SastScan, 'triage'>, ruleId: string, now: Date = new Date()): boolean {
  const entry = scan.triage?.[ruleId];
  if (!entry) return true;
  if (entry.status === 'confirmed') return true;
  return isExpired(entry, now);
}

const SEVERITY_RANK: Record<SastSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * The scanner keeps two lists: defects, and "review" items it cannot call
 * wrong on its own. A person reading the report should not have to work out
 * which list a thing is in, so the console and the report show one list, and
 * the person decides on each item (confirmed, false positive, ...). The score
 * still tells them apart, so nothing here changes what a scan scored: an item
 * from the review list weighs as a small capped penalty until it is confirmed,
 * and as a defect at its severity once it is. `fromReview` records where it came from.
 * Safe to apply twice.
 */
export function mergeReview(scan: SastScan): SastScan {
  if (scan.hotspots.length === 0) return scan;
  const findings = [...scan.findings, ...scan.hotspots.map((f) => ({ ...f, fromReview: true }))]
    .map((f, i) => ({ f, i }))
    .sort((a, b) => SEVERITY_RANK[b.f.severity] - SEVERITY_RANK[a.f.severity] || a.i - b.i)
    .map(({ f }) => f);
  return { ...scan, findings, hotspots: [] };
}

export function activeFindings(scan: SastScan, now?: Date): SastFinding[] {
  return scan.findings.filter((f) => isActive(scan, f.ruleId, now));
}

export function activeHotspots(scan: SastScan, now?: Date): SastFinding[] {
  return scan.hotspots.filter((f) => isActive(scan, f.ruleId, now));
}

export type TriageSummary = {
  /** Findings and hotspots with any decision recorded. */
  decided: number;
  confirmed: number;
  falsePositive: number;
  acceptedRisk: number;
  /** Accepted risks whose expiry date has passed; they count as active again. */
  expiredAcceptances: number;
  fixed: number;
};

export function triageSummary(scan: SastScan): TriageSummary {
  const known = new Set([...scan.findings, ...scan.hotspots].map((f) => f.ruleId));
  const out: TriageSummary = { decided: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, expiredAcceptances: 0, fixed: 0 };
  for (const [ruleId, entry] of Object.entries(scan.triage ?? {})) {
    if (!known.has(ruleId)) continue;
    out.decided += 1;
    if (entry.status === 'confirmed') out.confirmed += 1;
    else if (entry.status === 'false_positive') out.falsePositive += 1;
    else if (entry.status === 'fixed') out.fixed += 1;
    else if (isExpired(entry)) out.expiredAcceptances += 1;
    else out.acceptedRisk += 1;
  }
  return out;
}

/** The scanner's formula (model 2, see backend/src/sast/types.ts), over any set of findings. */
export function scoreOf(findings: Pick<SastFinding, 'severity' | 'origin'>[], hotspots: number, secure: number): number {
  const weighted: Record<SastSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) weighted[f.severity] += f.origin === 'third-party' ? LIBRARY_SHARE : 1;

  let loss = 0;
  for (const severity of Object.keys(weighted) as SastSeverity[]) {
    const { weight, cap } = SCORE_LOSS[severity];
    if (cap > 0 && weighted[severity] > 0) loss += cap * (1 - Math.exp((-weight * weighted[severity]) / cap));
  }
  const ownCritical = findings.some((f) => f.severity === 'critical' && f.origin !== 'third-party');
  const ownHigh = findings.some((f) => f.severity === 'high' && f.origin !== 'third-party');
  const credit = ownCritical ? 0 : Math.min(SECURE_CREDIT_CAP, secure * 2);

  let score = 100 - loss - Math.min(HOTSPOT_PENALTY_CAP, hotspots) + credit;
  if (ownCritical) score = Math.min(score, SCORE_CEILING.critical);
  else if (ownHigh) score = Math.min(score, SCORE_CEILING.high);
  return Math.round(Math.max(0, Math.min(100, score)));
}

export function gradeOf(score: number): SastScan['grade'] {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

/**
 * The scan's score over the active findings only.
 *
 * Same formula as the scanner: severity penalties, a small capped cost for
 * hotspots, and credit for good practice that is withheld while a critical is
 * outstanding. With no decisions recorded it equals the scan's own score.
 */
export function adjustedScore(scan: SastScan, now?: Date): {
  score: number;
  grade: SastScan['grade'];
  counts: Record<SastSeverity, number>;
  changed: boolean;
} {
  const total = scan;
  scan = mergeReview(scan);
  const active = activeFindings(scan, now);
  const counts: Record<SastSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of active) counts[f.severity] += 1;

  // An item from the review list is a defect once confirmed; until then it is a capped, light penalty.
  const defects = active.filter((f) => !f.fromReview || scan.triage?.[f.ruleId]?.status === 'confirmed');
  const score = scoreOf(defects, active.length - defects.length, scan.secure.length);
  return { score, grade: gradeOf(score), counts, changed: score !== total.score };
}

/** What stops a category passing: nothing at medium or above, the scanner's own rule. */
const REPORT_FAILING: SastSeverity[] = ['critical', 'high', 'medium'];

/**
 * The scan as the report tells it.
 *
 * One list, as on screen: the scanner's review items sit with the defects. And
 * a finding a person called a false positive is left out altogether, as if the
 * scanner had never raised it: no row, no count, no mention of the decision. The
 * "as scanned" figures are re-based on what is left, so the report never
 * accounts for something it does not show.
 */
export function reportScan(raw: SastScan): SastScan {
  const merged = mergeReview(raw);
  const decisions = Object.entries(merged.triage ?? {});
  const dropped = new Set(decisions.filter(([, e]) => e.status === 'false_positive').map(([id]) => id));
  if (dropped.size === 0) return merged;
  const stripped: SastScan = {
    ...merged,
    findings: merged.findings.filter((f) => !dropped.has(f.ruleId)),
    triage: Object.fromEntries(decisions.filter(([id]) => !dropped.has(id))),
  };
  const base = adjustedScore({ ...stripped, triage: {} });
  return {
    ...stripped,
    score: base.score,
    grade: base.grade,
    counts: base.counts,
    categories: stripped.categories.map((c) => {
      const own = stripped.findings.filter((f) => f.category === c.category && !f.fromReview);
      return { ...c, findings: own.length, pass: !own.some((f) => REPORT_FAILING.includes(f.severity)) };
    }),
  };
}
