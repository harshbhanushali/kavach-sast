/**
 * Triage: a reviewer's decision about a finding, with the reason.
 *
 * A scanner reports what it matched; a person decides what it means. Without
 * somewhere to record that decision, every report re-litigates the same
 * findings and the people reading it cannot tell a false positive from one
 * nobody has looked at. The decision is stored with who made it, when and why,
 * and never deletes the finding: a report shows triaged findings as triaged,
 * not as missing.
 *
 * `open` is the absence of a decision, so it is never stored.
 */
import type { Db } from '../db.ts';
import { SAST_SEVERITY_RANK } from './types.ts';
import type { SastFinding, SastScan } from './types.ts';

export const TRIAGE_STATUSES = ['confirmed', 'false_positive', 'accepted_risk', 'fixed'] as const;
export type StoredTriageStatus = (typeof TRIAGE_STATUSES)[number];

export type TriageEntry = {
  status: StoredTriageStatus;
  reason: string;
  /** Accepted risks only: the date the acceptance lapses (YYYY-MM-DD). */
  expiresAt?: string;
  updatedBy: string;
  updatedAt: string;
  /**
   * Set when this decision was copied from an earlier scan of the same app
   * rather than made on this one: the id of that scan. `updatedBy` and
   * `updatedAt` still name the person and moment of the original decision.
   */
  carriedFrom?: string;
};

export const MIN_REASON = 10;
export const MAX_REASON = 1000;

/** Decisions that exclude a finding from the active list must say why. */
const REASON_REQUIRED: ReadonlySet<string> = new Set(['false_positive', 'accepted_risk']);

export type TriageInput = { status?: unknown; reason?: unknown; expiresAt?: unknown };

export type TriageDecision =
  | { ok: true; clear: true }
  | { ok: true; clear: false; status: StoredTriageStatus; reason: string; expiresAt?: string }
  | { ok: false; error: string };

/** Today as YYYY-MM-DD in UTC, which is how expiry dates are compared. */
const today = (now: Date) => now.toISOString().slice(0, 10);

export function validateTriage(input: TriageInput, now = new Date()): TriageDecision {
  const status = input.status;
  if (status === 'open') return { ok: true, clear: true };
  if (typeof status !== 'string' || !(TRIAGE_STATUSES as readonly string[]).includes(status)) {
    return { ok: false, error: `status must be one of open, ${TRIAGE_STATUSES.join(', ')}` };
  }

  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  if (reason.length > MAX_REASON) return { ok: false, error: `reason is limited to ${MAX_REASON} characters` };
  if (REASON_REQUIRED.has(status) && reason.length < MIN_REASON) {
    return {
      ok: false,
      error: `a reason of at least ${MIN_REASON} characters is required to mark a finding ${status.replace('_', ' ')}`,
    };
  }

  let expiresAt: string | undefined;
  if (input.expiresAt !== undefined && input.expiresAt !== null && input.expiresAt !== '') {
    if (status !== 'accepted_risk') return { ok: false, error: 'only an accepted risk can have an expiry date' };
    if (typeof input.expiresAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(input.expiresAt) ||
        Number.isNaN(Date.parse(`${input.expiresAt}T00:00:00Z`))) {
      return { ok: false, error: 'expiresAt must be a date in the form YYYY-MM-DD' };
    }
    if (input.expiresAt < today(now)) return { ok: false, error: 'expiresAt cannot be in the past' };
    expiresAt = input.expiresAt;
  }

  return { ok: true, clear: false, status: status as StoredTriageStatus, reason, expiresAt };
}

type Row = {
  rule_id: string;
  status: StoredTriageStatus;
  reason: string;
  expires_at: string | null;
  updated_by: string;
  updated_at: string;
  carried_from: string | null;
};

/** Every decision recorded against a scan, keyed by rule id. */
export function loadTriage(db: Db, scanId: string): Record<string, TriageEntry> {
  const rows = db
    .prepare('SELECT rule_id, status, reason, expires_at, updated_by, updated_at, carried_from FROM sast_triage WHERE scan_id = ?')
    .all(scanId) as Row[];
  const out: Record<string, TriageEntry> = {};
  for (const r of rows) {
    out[r.rule_id] = {
      status: r.status,
      reason: r.reason,
      ...(r.expires_at ? { expiresAt: r.expires_at } : {}),
      updatedBy: r.updated_by,
      updatedAt: r.updated_at,
      ...(r.carried_from ? { carriedFrom: r.carried_from } : {}),
    };
  }
  return out;
}

export function saveTriage(
  db: Db,
  scanId: string,
  ruleId: string,
  decision: TriageDecision & { ok: true },
  actor: string,
  now = new Date(),
): TriageEntry | null {
  if (decision.clear) {
    db.prepare('DELETE FROM sast_triage WHERE scan_id = ? AND rule_id = ?').run(scanId, ruleId);
    return null;
  }
  const entry: TriageEntry = {
    status: decision.status,
    reason: decision.reason,
    ...(decision.expiresAt ? { expiresAt: decision.expiresAt } : {}),
    updatedBy: actor,
    updatedAt: now.toISOString(),
  };
  db.prepare(
    `INSERT INTO sast_triage (scan_id, rule_id, status, reason, expires_at, updated_by, updated_at, carried_from)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
     ON CONFLICT (scan_id, rule_id) DO UPDATE SET
       status = excluded.status, reason = excluded.reason, expires_at = excluded.expires_at,
       updated_by = excluded.updated_by, updated_at = excluded.updated_at, carried_from = NULL`,
  ).run(scanId, ruleId, entry.status, entry.reason, entry.expiresAt ?? null, entry.updatedBy, entry.updatedAt);
  return entry;
}

/** The rule ids a decision can be recorded against: defects and hotspots, never the "done right" list. */
export function triageableRuleIds(scan: Pick<SastScan, 'findings' | 'hotspots'>): Set<string> {
  return new Set([...scan.findings, ...scan.hotspots].map((f) => f.ruleId));
}

const findingsOf = (scan: Pick<SastScan, 'findings' | 'hotspots'>): Map<string, SastFinding> =>
  new Map([...scan.findings, ...scan.hotspots].map((f) => [f.ruleId, f]));

/**
 * Whether a finding is the same one a reviewer already judged.
 *
 * A decision is about a specific thing, so it only follows the finding while
 * that thing has not got worse: same rule (per-component rules carry the
 * component in the id), no higher severity, no more occurrences, and no
 * location in a file the earlier scan did not have. Anything else goes back
 * to open, because "false positive" said of three call sites does not cover a
 * fourth in a file nobody has looked at. Line numbers are deliberately not
 * compared: they shift on every build.
 */
function unchanged(before: SastFinding, after: SastFinding): boolean {
  if (SAST_SEVERITY_RANK[after.severity] > SAST_SEVERITY_RANK[before.severity]) return false;
  if (after.occurrences > before.occurrences) return false;
  const knownFiles = new Set(before.locations.map((l) => l.file));
  return after.locations.every((l) => knownFiles.has(l.file));
}

export type CarriedDecision = { ruleId: string; entry: TriageEntry };

/**
 * The decisions on `prior` that still hold on `next`.
 *
 * Not carried: `fixed` (the earlier scan said it was gone and it is back, so
 * that claim was wrong), an accepted risk whose date has passed, and anything
 * that changed (see `unchanged`).
 */
export function carriedDecisions(
  prior: Pick<SastScan, 'scanId' | 'findings' | 'hotspots'>,
  priorTriage: Record<string, TriageEntry>,
  next: Pick<SastScan, 'findings' | 'hotspots'>,
  now = new Date(),
): CarriedDecision[] {
  const before = findingsOf(prior);
  const after = findingsOf(next);
  const out: CarriedDecision[] = [];
  for (const [ruleId, entry] of Object.entries(priorTriage)) {
    if (entry.status === 'fixed') continue;
    if (entry.expiresAt && entry.expiresAt < today(now)) continue;
    const was = before.get(ruleId);
    const is = after.get(ruleId);
    if (!was || !is || !unchanged(was, is)) continue;
    out.push({ ruleId, entry: { ...entry, carriedFrom: prior.scanId } });
  }
  return out;
}

/** Writes carried decisions onto `scanId`. Never overwrites a decision already there. */
export function saveCarried(db: Db, scanId: string, carried: CarriedDecision[]): void {
  const insert = db.prepare(
    `INSERT OR IGNORE INTO sast_triage (scan_id, rule_id, status, reason, expires_at, updated_by, updated_at, carried_from)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const { ruleId, entry } of carried) {
    insert.run(scanId, ruleId, entry.status, entry.reason, entry.expiresAt ?? null, entry.updatedBy, entry.updatedAt, entry.carriedFrom ?? null);
  }
}
