/** App registration: an optional grouping a scan can hang off. Authenticated. */
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import { requireRole } from '../auth.ts';
import type { AppContext } from '../context.ts';
import { actorFor, audit } from './common.ts';

const RegisterApp = z
  .object({
    appId: z.string().min(1).max(200),
    displayName: z.string().min(1).max(200),
    platform: z.enum(['android', 'ios', 'universal']),
    bundleId: z.string().min(1).max(200),
    signingCertSha256: z
      .string()
      .regex(/^[A-Fa-f0-9]{64}$/, 'expected a hex SHA-256 digest')
      .optional(),
    owner: z.string().min(1).max(320),
  })
  .strict();

export function registerAppRoutes(server: FastifyInstance, ctx: AppContext): void {
  server.get('/v1/apps', async (request) => {
    actorFor(request, ctx);
    const rows = ctx.db
      .prepare('SELECT * FROM apps ORDER BY created_at DESC')
      .all() as Record<string, unknown>[];
    return { apps: rows.map(toApp) };
  });

  server.get('/v1/apps/:appId', async (request, reply) => {
    actorFor(request, ctx);
    const { appId } = request.params as { appId: string };
    const row = ctx.db.prepare('SELECT * FROM apps WHERE app_id = ?').get(appId) as
      | Record<string, unknown>
      | undefined;
    if (!row) return reply.code(404).send({ error: 'no such app' });
    return { app: toApp(row) };
  });

  server.post('/v1/apps', async (request, reply) => {
    const actor = actorFor(request, ctx);
    requireRole(actor, 'user');

    const parsed = RegisterApp.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: 'invalid app', issues: parsed.error.issues });
    }
    const app = parsed.data;

    const existing = ctx.db.prepare('SELECT app_id FROM apps WHERE app_id = ?').get(app.appId);
    if (existing) return reply.code(409).send({ error: `app ${app.appId} is already registered` });

    const now = new Date().toISOString();
    ctx.db
      .prepare(
        `INSERT INTO apps (app_id, display_name, platform, bundle_id, signing_cert_sha256, owner, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        app.appId,
        app.displayName,
        app.platform,
        app.bundleId,
        app.signingCertSha256 ?? null,
        app.owner,
        now,
      );

    audit(ctx, actor, {
      action: 'app.register',
      appId: app.appId,
      subject: app.appId,
      detail: `registered ${app.displayName} (${app.platform})`,
    });

    return reply.code(201).send({ app: { ...app, createdAt: now } });
  });
}

function toApp(row: Record<string, unknown>) {
  return {
    appId: row.app_id,
    displayName: row.display_name,
    platform: row.platform,
    bundleId: row.bundle_id,
    signingCertSha256: row.signing_cert_sha256,
    owner: row.owner,
    createdAt: row.created_at,
  };
}

export { RegisterApp };
