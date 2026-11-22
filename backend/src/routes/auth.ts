/**
 * Login, logout, and changing a password.
 *
 * `/v1/auth/login` is the only unauthenticated route in the system that accepts
 * a credential, so the rate limiting lives here rather than in a global hook:
 * every other route rejects an unknown token outright and has nothing to
 * brute-force.
 */
import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import {
  DEFAULT_ACCOUNTS,
  SESSION_TTL_HOURS,
  accountsOnDefaults,
  changePassword,
  login,
  logout,
  userByName,
} from '../users.ts';
import { actorFor, audit } from './common.ts';

/**
 * Failed attempts per username, in memory.
 *
 * Deliberately modest and deliberately not persisted: this is a self-hosted
 * tool on a trusted network, and the threat is a careless script or someone
 * guessing at the published default, not a determined distributed attacker.
 * A lockout that survives restarts would mostly lock out the operator.
 */
const MAX_ATTEMPTS = 10;
const ATTEMPT_WINDOW_MS = 5 * 60_000;
const attempts = new Map<string, { count: number; first: number }>();

function tooManyAttempts(username: string): boolean {
  const record = attempts.get(username);
  if (!record) return false;
  if (Date.now() - record.first > ATTEMPT_WINDOW_MS) {
    attempts.delete(username);
    return false;
  }
  return record.count >= MAX_ATTEMPTS;
}

function noteFailure(username: string): void {
  const record = attempts.get(username);
  if (!record || Date.now() - record.first > ATTEMPT_WINDOW_MS) {
    attempts.set(username, { count: 1, first: Date.now() });
    return;
  }
  record.count += 1;
}

export function registerAuthRoutes(server: FastifyInstance, ctx: AppContext): void {
  /**
   * What the login screen needs before anyone has logged in.
   *
   * Unauthenticated by necessity. While an account is still on its default it names that account and the
   * shared default password, which are already in the README and in this repository — stating them here does
   * not widen exposure, and withholding them only locks out the person who just installed the tool. It also
   * reports which accounts are still on the default, so the console can say so.
   */
  server.get('/v1/auth/info', async () => {
    // The published account is listed only while it is still on its published password: once it is changed
    // there is nothing to publish, and an operator who set a password never had one.
    const onDefault = accountsOnDefaults(ctx.db);
    return {
      defaultAccounts: DEFAULT_ACCOUNTS.filter((a) => onDefault.includes(a.username)).map((a) => ({ username: a.username, role: a.role, password: a.password })),
      accountsOnDefaults: onDefault,
      sessionHours: SESSION_TTL_HOURS,
    };
  });

  server.post('/v1/auth/login', async (request, reply) => {
    const body = request.body as { username?: unknown; password?: unknown } | undefined;
    const username = typeof body?.username === 'string' ? body.username.trim() : '';
    const password = typeof body?.password === 'string' ? body.password : '';

    if (!username || !password) {
      return reply.code(400).send({ error: 'username and password are required' });
    }
    // Per address as well as per name: counting only names lets one client try a
    // different username each time, and lets anyone lock a known account out.
    const fromAddress = ctx.limits.loginFailures.blocked(request.ip);
    if (fromAddress.blocked) {
      reply.header('retry-after', String(fromAddress.retryAfterSec));
      return reply.code(429).send({ error: 'too many failed sign-ins from this address; wait a few minutes and try again' });
    }
    if (tooManyAttempts(username)) {
      return reply.code(429).send({
        error: `too many failed attempts for ${username}; wait a few minutes and try again`,
      });
    }

    const result = login(ctx.db, username, password);
    if (!result.ok) {
      noteFailure(username);
      ctx.limits.loginFailures.hit(request.ip);
      audit(ctx, { subject: (username || 'unknown').slice(0, 64), role: 'user' }, {
        action: 'auth.login_failed',
        subject: username.slice(0, 64),
        detail: `failed sign-in from ${request.ip}`,
      });
      // One message for both causes. Saying "no such user" would turn this
      // endpoint into a username oracle.
      return reply.code(401).send({ error: 'incorrect username or password' });
    }

    attempts.delete(username);
    ctx.limits.loginFailures.reset(request.ip);
    audit(ctx, { subject: username, role: result.user.role }, {
      action: 'auth.login',
      subject: username,
      detail: `signed in as ${result.user.role}`,
    });

    return { token: result.token, expiresAt: result.expiresAt, user: result.user };
  });

  server.post('/v1/auth/logout', async (request) => {
    const header = request.headers.authorization;
    if (header?.startsWith('Bearer ')) logout(ctx.db, header.slice('Bearer '.length));
    return { ok: true };
  });

  /** The signed-in user, used by the console to restore a session on reload. */
  server.get('/v1/auth/me', async (request, reply) => {
    const actor = actorFor(request, ctx);
    const user = userByName(ctx.db, actor.subject);
    if (!user) {
      // A static development token resolves to an actor with no user row.
      return {
        username: actor.subject,
        role: actor.role,
        usingDefaultPassword: false,
        createdAt: null,
        lastLoginAt: null,
        staticToken: true,
      };
    }
    return { ...user, staticToken: false, accountsOnDefaults: accountsOnDefaults(ctx.db) };
  });

  server.post('/v1/auth/password', async (request, reply) => {
    const actor = actorFor(request, ctx);
    const body = request.body as { currentPassword?: unknown; newPassword?: unknown } | undefined;
    const current = typeof body?.currentPassword === 'string' ? body.currentPassword : '';
    const next = typeof body?.newPassword === 'string' ? body.newPassword : '';

    const result = changePassword(ctx.db, actor.subject, current, next);
    if (!result.ok) return reply.code(400).send({ error: result.reason });

    audit(ctx, actor, {
      action: 'auth.password_changed',
      subject: actor.subject,
      detail: 'password changed; existing sessions revoked',
    });
    // Every session was dropped, including this one.
    return { ok: true, message: 'Password changed. Sign in again with the new password.' };
  });
}
