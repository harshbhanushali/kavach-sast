/**
 * An app is its package name.
 *
 * A scan taken with no app selected would otherwise be filed under nothing, and
 * "scan the next build of the same app" (carry-over, progress, compare) only
 * works for scans that share an app. So the artifact's own package name (or iOS
 * bundle id) names the app: it is attached if it exists and registered if not.
 *
 * An app the person picked is honoured only when it really is this artifact's
 * app (same package, same platform). The console keeps the last app selected, so
 * without that check an Android scan of a different app would be filed under
 * whichever app happened to be selected, and no new app would ever be registered.
 */
import type { Actor } from '../auth.ts';
import type { AppContext } from '../context.ts';
import { audit } from '../routes/common.ts';
import type { SastScan } from './types.ts';

export type ResolvedApp = {
  appId?: string;
  created: boolean;
  /** The picked app was not this artifact's, so the scan was filed under its own app instead. */
  redirectedFrom?: string;
};

/** The longest app id the registration route accepts. */
const MAX_APP_ID = 200;

type Identity = { platform: string; packageName?: string; label?: string; fileName: string };

/** The app for a package on a platform: an existing one, or a new one named after the package. */
function appForPackage(ctx: AppContext, actor: Actor, who: Identity & { packageName: string }): { appId: string; created: boolean } {
  const existing = ctx.db
    .prepare(`SELECT app_id FROM apps WHERE bundle_id = ? AND platform IN (?, 'universal') ORDER BY (app_id = ?) DESC, created_at LIMIT 1`)
    .get(who.packageName, who.platform, who.packageName) as { app_id: string } | undefined;
  if (existing) return { appId: existing.app_id, created: false };

  // The same package can exist on both platforms; the id must still be unique.
  const taken = ctx.db.prepare('SELECT 1 FROM apps WHERE app_id = ?').get(who.packageName);
  const appId = taken ? `${who.packageName}:${who.platform}` : who.packageName;
  const displayName = (who.label || who.packageName).slice(0, MAX_APP_ID);
  ctx.db
    .prepare(
      `INSERT INTO apps (app_id, display_name, platform, bundle_id, signing_cert_sha256, owner, created_at)
       VALUES (?, ?, ?, ?, NULL, ?, ?)`,
    )
    .run(appId, displayName, who.platform, who.packageName, actor.subject, new Date().toISOString());

  audit(ctx, actor, {
    action: 'app.register',
    appId,
    subject: appId,
    detail: `auto-registered ${displayName} (${who.platform}) from the scan of ${who.fileName}`,
  });
  return { appId, created: true };
}

export function resolveApp(ctx: AppContext, actor: Actor, scan: SastScan, requested?: string): ResolvedApp {
  const packageName = scan.artifact.packageName?.trim();
  const usable = packageName && packageName.length <= MAX_APP_ID ? packageName : undefined;

  if (requested) {
    const picked = ctx.db.prepare('SELECT platform, bundle_id FROM apps WHERE app_id = ?').get(requested) as
      | { platform: string; bundle_id: string }
      | undefined;
    // Nothing to compare against (no such app, or an artifact with no package): the person's choice stands.
    if (!picked || !usable) return { appId: requested, created: false };
    const same = picked.bundle_id === usable && (picked.platform === scan.artifact.platform || picked.platform === 'universal');
    if (same) return { appId: requested, created: false };
  }

  if (!usable) return { created: false };
  const found = appForPackage(ctx, actor, {
    platform: scan.artifact.platform,
    packageName: usable,
    label: scan.artifact.android?.label || scan.artifact.ios?.displayName,
    fileName: scan.artifact.fileName,
  });
  return { ...found, ...(requested ? { redirectedFrom: requested } : {}) };
}

/**
 * Files scans that sit under the wrong app, or none, under the app for their own
 * package. Scans taken while the console sent a stale selection (an Android app
 * filed under an iOS one) are the target. Safe to run on every start: a scan whose
 * app already matches is left alone, and a scan with no package cannot be placed.
 */
export function refileMisfiledScans(ctx: AppContext): number {
  const actor: Actor = { subject: 'system', role: 'user' };
  const rows = ctx.db
    .prepare(
      `SELECT s.scan_id, s.platform, s.package_name, s.file_name,
              COALESCE(json_extract(s.document, '$.artifact.android.label'), json_extract(s.document, '$.artifact.ios.displayName')) AS label
         FROM sast_scans s LEFT JOIN apps a ON a.app_id = s.app_id
        WHERE s.package_name IS NOT NULL AND s.package_name != ''
          AND (s.app_id IS NULL OR a.app_id IS NULL
               OR a.bundle_id != s.package_name
               OR (a.platform != s.platform AND a.platform != 'universal'))
        ORDER BY s.created_at`,
    )
    .all() as { scan_id: string; platform: string; package_name: string; file_name: string; label: string | null }[];
  if (rows.length === 0) return 0;

  const move = ctx.db.prepare('UPDATE sast_scans SET app_id = ? WHERE scan_id = ?');
  let moved = 0;
  for (const row of rows) {
    if (row.package_name.length > MAX_APP_ID) continue;
    const { appId } = appForPackage(ctx, actor, {
      platform: row.platform,
      packageName: row.package_name,
      label: row.label ?? undefined,
      fileName: row.file_name,
    });
    move.run(appId, row.scan_id);
    moved += 1;
  }
  audit(ctx, actor, {
    action: 'app.refile',
    subject: 'scans',
    detail: `filed ${moved} scan${moved === 1 ? '' : 's'} under the app for their own package`,
  });
  return moved;
}
