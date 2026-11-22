/**
 * The backend, assembled.
 *
 * Adapted from the server of the author's earlier Kavach project (a runtime-protection platform), trimmed to the
 * routes this standalone product has: app registration, static analysis, auth,
 * and the console itself. Every RASP route (policy, build, protect, events,
 * devices, dashboard, detections, attest) is gone along with the code it
 * served.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import { findChrome, findQpdf } from './sast/pdf.ts';
import multipart from '@fastify/multipart';
import type { FastifyInstance } from 'fastify';
import { AuthError } from './auth.ts';
import { ConfigError } from './config.ts';
import { accountsOnDefaults } from './users.ts';
import { createContext } from './context.ts';
import { startHousekeeping } from './housekeeping.ts';
import { refileMisfiledScans } from './sast/appFromScan.ts';
import { registerSecurity } from './security.ts';
import type { AppContext } from './context.ts';
import { registerAppRoutes } from './routes/apps.ts';
import { registerAuditRoutes } from './routes/audit.ts';
import { registerSastRoutes, MAX_ARTIFACT_BYTES } from './routes/sast.ts';
import { registerAuthRoutes } from './routes/auth.ts';
import { resolveToolchain } from './toolchain.ts';

export async function buildServer(ctx: AppContext = createContext()): Promise<FastifyInstance> {
  const server = Fastify({
    logger: ctx.config.isProduction
      ? { level: process.env.KAVACH_SAST_LOG_LEVEL ?? 'info', redact: ['req.headers.authorization', 'req.headers.cookie'] }
      : { transport: undefined, level: 'warn' },
    bodyLimit: 1024 * 1024,
    // Only trust X-Forwarded-For when told how many proxies set it (see `trustProxy` in config).
    trustProxy: ctx.config.trustProxy,
    // Honour a request id set by the proxy, so a request can be followed across both logs.
    requestIdHeader: 'x-request-id',
    // A slow client must not hold a connection for ever; an upload may legitimately take a while.
    requestTimeout: 30 * 60_000,
    // Longer than a typical load balancer's idle timeout, so the balancer closes first rather than racing a reset.
    keepAliveTimeout: 65_000,
  });

  registerSecurity(server, ctx);

  // The console runs on a different port in development. Artifact uploads are
  // large and streamed straight to disk rather than buffered.
  await server.register(multipart, {
    limits: { fileSize: MAX_ARTIFACT_BYTES, files: 2, fields: 10 },
  });

  await server.register(cors, {
    origin: ctx.config.isProduction ? false : true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  });

  server.setErrorHandler((error, _request, reply) => {
    if (error instanceof AuthError) {
      return reply.code(error.statusCode).send({ error: error.message });
    }
    const status = error.statusCode ?? 500;
    if (status >= 400 && status < 500) {
      return reply.code(status).send({ error: error.message, code: error.code });
    }
    server.log.error(error);
    return reply.code(500).send({ error: 'internal error' });
  });

  server.get('/healthz', async (_request, reply) => {
    // Verifies what matters for serving: that the database answers.
    try {
      ctx.db.prepare('SELECT 1').get();
    } catch {
      return reply.code(503).send({ ok: false, service: 'kavach-sast' });
    }
    const toolchain = resolveToolchain();
    return {
      ok: true,
      service: 'kavach-sast',
      // Booleans only. It answers anyone who can reach the port, and which
      // components are installed is for the operator (see the startup log).
      scanning: { ready: true, readableJava: Boolean(toolchain.jadx) },
      android: { full: Boolean(toolchain.apktool) },
    };
  });

  registerAuthRoutes(server, ctx);
  registerAppRoutes(server, ctx);
  registerAuditRoutes(server, ctx);
  registerSastRoutes(server, ctx);

  // Serving the built console from the backend is what lets the container be a
  // single image on a single port, with no reverse proxy and no CORS. It is
  // registered last so it can never shadow an API route.
  //
  // In development the directory does not exist — the console runs on Vite's
  // own server and proxies here — so this switches itself off rather than
  // needing a mode flag.
  if (existsSync(join(ctx.config.consoleDir, 'index.html'))) {
    await server.register(fastifyStatic, { root: ctx.config.consoleDir });

    server.setNotFoundHandler((request, reply) => {
      const url = request.raw.url ?? '';
      if (url.startsWith('/v1') || url.startsWith('/healthz')) {
        return reply.code(404).send({ error: 'not found' });
      }
      return reply.sendFile('index.html');
    });
  }

  return server;
}

async function main(): Promise<void> {
  let ctx;
  try {
    ctx = createContext();
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(`\nconfiguration error: ${error.message}\n`);
      process.exit(2);
    }
    throw error;
  }

  // A damaged database is better refused now, with a way out, than served until it corrupts further.
  const check = ctx.db.prepare('PRAGMA quick_check').get() as { quick_check?: string } | undefined;
  if (check?.quick_check !== 'ok') {
    console.error(`\nthe database failed its integrity check (${check?.quick_check ?? 'no answer'}). Restore it from a backup (see DEPLOYMENT.md).\n`);
    process.exit(3);
  }

  const server = await buildServer(ctx);
  await server.listen({ port: ctx.config.port, host: ctx.config.host });

  console.log(`\nKavach SAST backend on http://${ctx.config.host}:${ctx.config.port}`);
  // For the operator running this process; never sent to a client.
  const toolchain = resolveToolchain();
  const absent = [
    ...toolchain.missing,
    ...(toolchain.jadx ? [] : ['jadx (optional: readable Java)']),
    ...(findChrome() ? [] : ['chrome/chromium (PDF export)']),
    ...(findQpdf() ? [] : ['qpdf (password-protected PDFs)']),
  ];
  if (absent.length > 0) console.log(`\n  not found on this machine: ${absent.join(', ')}`);
  const onDefault = accountsOnDefaults(ctx.db);
  if (onDefault.length > 0) {
    console.log(`\n  ${onDefault.join(', ')} is still on the published default password (admin / kavach).\n  Change it from the account menu before anyone else can reach this server, or set KAVACH_SAST_ADMIN_PASSWORD before the first start.`);
  }
  if (Object.keys(ctx.tokens).length > 0) {
    console.log('\n  development token:');
    for (const [token, actor] of Object.entries(ctx.tokens)) {
      console.log(`    ${actor.role.padEnd(6)} ${token}`);
    }
  }
  console.log('');

  try {
    const refiled = refileMisfiledScans(ctx);
    if (refiled > 0) server.log.info(`filed ${refiled} scan${refiled === 1 ? '' : 's'} under the app for their own package`);
  } catch (error) {
    server.log.warn(`could not re-file scans by package: ${(error as Error).message}`);
  }

  const stopHousekeeping = startHousekeeping(ctx, (message) => server.log.info(message));

  // Stop taking new requests, let scans that are running finish (up to the grace
  // period), then close the database cleanly. A container orchestrator sends
  // SIGTERM and kills the process if it has not exited when its own grace ends,
  // so this must be shorter than that: see `stop_grace_period` in docker-compose.yml.
  let closing = false;
  const shutdown = async (signal: string) => {
    if (closing) return;
    closing = true;
    console.log(`\n${signal} received: no new requests; waiting up to ${Math.round(ctx.config.shutdownGraceMs / 1000)}s for ${ctx.limits.scans.active} running scan(s)`);
    const force = setTimeout(() => {
      console.error('the grace period ended with work still running; exiting');
      process.exit(1);
    }, ctx.config.shutdownGraceMs);
    force.unref();
    stopHousekeeping();
    try {
      await server.close();
      ctx.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      ctx.db.close();
    } catch (error) {
      console.error('error while shutting down:', error);
      process.exit(1);
    }
    console.log('shut down cleanly');
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // Log, then exit: a process in an unknown state should be restarted by whatever supervises it, not limp on.
  process.on('unhandledRejection', (reason) => {
    console.error('unhandled rejection:', reason);
    process.exit(1);
  });
  process.on('uncaughtException', (error) => {
    console.error('uncaught exception:', error);
    process.exit(1);
  });
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
