/** Shared route helpers: actor resolution and the audit trail. */
import type { FastifyRequest } from 'fastify';
import { AuthError, resolveActor } from '../auth.ts';
import type { Actor } from '../auth.ts';
import type { AppContext } from '../context.ts';
import { actorForSession } from '../users.ts';

export function actorFor(request: FastifyRequest, ctx: AppContext): Actor {
  // Session tokens first, then the static development tokens.
  return resolveActor(request.headers.authorization, ctx.tokens, (token) =>
    actorForSession(ctx.db, token),
  );
}

export type AuditEntry = {
  action: string;
  appId?: string;
  subject?: string;
  detail: string;
};

/**
 * Writes the audit trail. Every mutation goes through here, so "who changed
 * what, when" is answerable without reconstructing it from application logs.
 */
export function audit(ctx: AppContext, actor: Actor, entry: AuditEntry): void {
  ctx.db
    .prepare(
      'INSERT INTO audit_log (at, actor, role, action, app_id, subject, detail) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
    .run(
      new Date().toISOString(),
      actor.subject,
      actor.role,
      entry.action,
      entry.appId ?? null,
      entry.subject ?? null,
      entry.detail,
    );
}

export { AuthError };
