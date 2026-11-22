/**
 * Tidying that a long-running instance needs and a one-off run does not.
 *
 * - Scan and upload working directories hold a full decompile of someone's app.
 *   A scan removes its own, but a crash or a kill leaves it behind, and on a
 *   server that is a slow disk leak of exactly the material that should not linger.
 * - Sessions are only deleted when someone presents an expired token, so tokens
 *   nobody uses again would stay for ever.
 * - Scans can be set to expire (KAVACH_SAST_RETENTION_DAYS), because the
 *   decompiled sources kept with each one are a copy of the application.
 */
import { readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AppContext } from './context.ts';
import { purgeExpiredSessions } from './users.ts';

/** Working directories this server creates: scan, upload and PDF. */
const OURS = /^kavach-(sast-upload-|sast-|pdf-)/;

/** Older than any scan can legitimately run (the timeout is at most a day; the default is 15 minutes). */
const STALE_AFTER_MS = 2 * 3_600_000;

export type HousekeepingResult = {
  staleDirectories: number;
  expiredSessions: number;
  expiredScans: number;
};

/** Removes working directories this server left behind. Returns how many. */
export function removeStaleWorkDirs(now = Date.now(), dir = tmpdir(), maxAgeMs = STALE_AFTER_MS): number {
  let removed = 0;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return 0;
  }
  for (const name of names) {
    if (!OURS.test(name)) continue;
    const path = join(dir, name);
    try {
      if (now - statSync(path).mtimeMs < maxAgeMs) continue;
      rmSync(path, { recursive: true, force: true });
      removed += 1;
    } catch {
      // Gone already, or not ours to remove: either way, nothing to do.
    }
  }
  return removed;
}

/** Deletes scans older than the retention period, with their retained sources and triage decisions. */
export function expireScans(ctx: AppContext, now = Date.now()): number {
  const days = ctx.config.retentionDays;
  if (days <= 0) return 0;
  const cutoff = new Date(now - days * 86_400_000).toISOString();
  const old = ctx.db.prepare('SELECT scan_id FROM sast_scans WHERE created_at < ?').all(cutoff) as { scan_id: string }[];
  if (old.length === 0) return 0;

  const deleteFiles = ctx.db.prepare('DELETE FROM sast_files WHERE scan_id = ?');
  const deleteTriage = ctx.db.prepare('DELETE FROM sast_triage WHERE scan_id = ?');
  const deleteScan = ctx.db.prepare('DELETE FROM sast_scans WHERE scan_id = ?');
  for (const { scan_id } of old) {
    deleteFiles.run(scan_id);
    deleteTriage.run(scan_id);
    deleteScan.run(scan_id);
  }
  ctx.db
    .prepare('INSERT INTO audit_log (at, actor, role, action, app_id, subject, detail) VALUES (?, ?, ?, ?, NULL, ?, ?)')
    .run(new Date(now).toISOString(), 'system', 'user', 'sast.retention', 'retention', `deleted ${old.length} scan${old.length === 1 ? '' : 's'} older than ${days} days`);
  return old.length;
}

export function runHousekeeping(ctx: AppContext): HousekeepingResult {
  ctx.limits.requests.sweep();
  ctx.limits.loginFailures.sweep();
  const result = {
    staleDirectories: removeStaleWorkDirs(),
    expiredSessions: purgeExpiredSessions(ctx.db),
    expiredScans: expireScans(ctx),
  };
  // Cheap, and keeps the query planner's statistics from going stale on a long-lived database.
  try {
    ctx.db.exec('PRAGMA optimize');
  } catch {
    // Not worth failing housekeeping over.
  }
  return result;
}

/** Runs once now and then hourly. Returns a function that stops it. */
export function startHousekeeping(ctx: AppContext, log: (message: string) => void): () => void {
  const tick = () => {
    try {
      const r = runHousekeeping(ctx);
      const parts = [
        r.staleDirectories && `${r.staleDirectories} stale working director${r.staleDirectories === 1 ? 'y' : 'ies'}`,
        r.expiredSessions && `${r.expiredSessions} expired session${r.expiredSessions === 1 ? '' : 's'}`,
        r.expiredScans && `${r.expiredScans} scan${r.expiredScans === 1 ? '' : 's'} past retention`,
      ].filter(Boolean);
      if (parts.length > 0) log(`housekeeping removed ${parts.join(', ')}`);
    } catch (error) {
      log(`housekeeping failed: ${(error as Error).message}`);
    }
  };
  tick();
  const timer = setInterval(tick, 3_600_000);
  timer.unref();
  return () => clearInterval(timer);
}
