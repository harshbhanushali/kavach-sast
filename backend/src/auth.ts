/**
 * Access control.
 *
 * Adapted from the RBAC module (viewer/editor/publisher) of the author's earlier Kavach project (a runtime-protection platform),
 * simplified to one role: this product has no policy to publish, which was the
 * entire reason that split existed (publishing reaches a signing key; SAST
 * signs nothing). `requireRole` is kept, unused as a real gate today, so a
 * route written against it reads the same way it would in the full product and
 * a second role can be reintroduced later without rewriting every call site.
 *
 * Local development uses bearer tokens from a file so the console can run with
 * no identity provider. In a real deployment this module is the seam where you
 * plug in OIDC — route handlers only ever see the resolved `Actor`.
 */
import { timingSafeEqual } from 'node:crypto';

export const ROLES = ['user'] as const;
export type Role = (typeof ROLES)[number];

const RANK: Record<Role, number> = { user: 0 };

export type Actor = { subject: string; role: Role };

export class AuthError extends Error {
  statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

export type TokenTable = Record<string, Actor>;

/**
 * Resolves the caller.
 *
 * Two credential kinds are accepted. A session token issued by the login route
 * is checked first via `sessionLookup`; the static development tokens remain so
 * that scripts and tests keep working without a login round-trip.
 */
export function resolveActor(
  authorization: string | undefined,
  tokens: TokenTable,
  sessionLookup?: (token: string) => Actor | undefined,
): Actor {
  if (!authorization?.startsWith('Bearer ')) {
    throw new AuthError(401, 'missing bearer token');
  }
  const presented = authorization.slice('Bearer '.length);

  const session = sessionLookup?.(presented);
  if (session) return session;
  // Constant-time comparison against every known token, so response timing does
  // not leak which prefix was right.
  let match: Actor | undefined;
  for (const [token, actor] of Object.entries(tokens)) {
    const a = Buffer.from(token);
    const b = Buffer.from(presented);
    if (a.length === b.length && timingSafeEqual(a, b)) match = actor;
  }
  if (!match) throw new AuthError(401, 'unknown token');
  return match;
}

export function requireRole(actor: Actor, minimum: Role): void {
  if (RANK[actor.role] < RANK[minimum]) {
    throw new AuthError(403, `this action requires the ${minimum} role; you have ${actor.role}`);
  }
}
