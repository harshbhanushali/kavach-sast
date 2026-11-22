/**
 * The audit trail, read back.
 *
 * Adapted from the author's earlier Kavach project (a runtime-protection platform), where `GET /v1/audit`
 * lived in the policy routes file only because that file registered it alongside the others — the route itself is generic and touches only `audit_log`.
 */
import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import { actorFor } from './common.ts';

export function registerAuditRoutes(server: FastifyInstance, ctx: AppContext): void {
  server.get('/v1/audit', async (request) => {
    actorFor(request, ctx);
    const query = request.query as { appId?: string; limit?: string };
    const limit = Math.min(Number(query.limit ?? 200), 1000);
    const rows = query.appId
      ? (ctx.db
          .prepare('SELECT * FROM audit_log WHERE app_id = ? ORDER BY id DESC LIMIT ?')
          .all(query.appId, limit) as Record<string, unknown>[])
      : (ctx.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as Record<
          string,
          unknown
        >[]);
    return {
      entries: rows.map((r) => ({
        id: r.id,
        at: r.at,
        actor: r.actor,
        role: r.role,
        action: r.action,
        appId: r.app_id,
        subject: r.subject,
        detail: r.detail,
      })),
    };
  });
}
