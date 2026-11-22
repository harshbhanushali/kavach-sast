/**
 * Username/password accounts and their sessions.
 *
 * Adapted from the accounts module of the author's earlier Kavach project (a runtime-protection platform), with one change: a
 * single seeded account rather than three roles, since this standalone product
 * has nothing a second role would distinguish (see auth.ts). The scrypt/session
 * mechanics are otherwise identical.
 *
 * Passwords are stored as scrypt hashes with a per-password salt, including the
 * seeded default. That is not ceremony: a self-hosted tool's database ends up
 * in backups, in `docker cp`, and occasionally in a bug report, and a plaintext
 * password column means every one of those is a credential leak. Verification
 * is constant-time, so response timing does not narrow down a password.
 *
 * Sessions are opaque random tokens with an expiry, stored server-side, so a
 * shared instance can revoke one without key management.
 */
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Db } from './db.ts';
import { ROLES } from './auth.ts';
import type { Actor, Role } from './auth.ts';

/** scrypt parameters. N=16384 is the usual interactive-login setting. */
const SCRYPT = { N: 16_384, r: 8, p: 1, keylen: 64 } as const;

/** How long a login lasts before it must be repeated. */
export const SESSION_TTL_HOURS = 12;

export type User = {
  username: string;
  role: Role;
  /** True until the account's seeded default password is changed. */
  usingDefaultPassword: boolean;
  createdAt: string;
  lastLoginAt: string | null;
};

/**
 * The account created on an empty database.
 *
 * Published in the README and shown on the login screen, because an access-
 * control system nobody can get into is not access control. Seeded only when
 * the table is empty, so changing the password is permanent.
 */
export const DEFAULT_ACCOUNTS: { username: string; password: string; role: Role }[] = [
  { username: 'admin', password: 'kavach', role: 'user' },
];

function hash(password: string, salt: string): string {
  return scryptSync(password, salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    // scrypt needs memory proportional to N*r*128; the default cap rejects
    // these parameters outright.
    maxmem: 64 * 1024 * 1024,
  }).toString('hex');
}

function verify(password: string, salt: string, expected: string): boolean {
  const actual = Buffer.from(hash(password, salt), 'hex');
  const wanted = Buffer.from(expected, 'hex');
  if (actual.length !== wanted.length) return false;
  return timingSafeEqual(actual, wanted);
}

export type Bootstrap = { seeded: string[] };

/**
 * Creates the first account if, and only if, there are none.
 *
 * It is the published default (`admin` / `kavach`), so a tool anyone can install signs in on first run with
 * nothing to look up. The console says so, loudly, until the password is changed. An operator who sets
 * `KAVACH_SAST_ADMIN_PASSWORD` gets that password instead and never has a published one.
 */
export function seedDefaultUsers(db: Db, options: { adminPassword?: string } = {}): Bootstrap {
  const existing = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
  if (existing.n > 0) return { seeded: [] };

  const now = new Date().toISOString();
  const insert = db.prepare(
    `INSERT INTO users (username, salt, password_hash, role, using_default_password, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  for (const account of DEFAULT_ACCOUNTS) {
    const salt = randomBytes(16).toString('hex');
    const custom = options.adminPassword;
    insert.run(account.username, salt, hash(custom ?? account.password, salt), account.role, custom ? 0 : 1, now);
  }
  return { seeded: DEFAULT_ACCOUNTS.map((a) => a.username) };
}

/**
 * An operator who sets a password owns it, even on a database an earlier run left on the default.
 *
 * Each account still on the published default is moved to the operator's password and its sessions are
 * dropped. Without a configured password nothing changes: the default stays until someone changes it.
 */
export function rotateDefaultPasswords(db: Db, adminPassword: string): string[] {
  const rows = db.prepare('SELECT username FROM users WHERE using_default_password = 1').all() as { username: string }[];
  for (const { username } of rows) {
    const salt = randomBytes(16).toString('hex');
    db.prepare('UPDATE users SET salt = ?, password_hash = ?, using_default_password = 0 WHERE username = ?').run(salt, hash(adminPassword, salt), username);
    db.prepare('DELETE FROM sessions WHERE username = ?').run(username);
  }
  return rows.map((r) => r.username);
}

/** Removes sessions that have expired. Run on a timer; expiry is also enforced when a token is used. */
export function purgeExpiredSessions(db: Db): number {
  const result = db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
  return Number(result.changes);
}

type UserRow = {
  username: string;
  salt: string;
  password_hash: string;
  role: string;
  using_default_password: number;
  created_at: string;
  last_login_at: string | null;
};

function toUser(row: UserRow): User {
  return {
    username: row.username,
    role: (ROLES as readonly string[]).includes(row.role) ? (row.role as Role) : 'user',
    usingDefaultPassword: row.using_default_password === 1,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

export type LoginResult =
  | { ok: true; token: string; expiresAt: string; user: User }
  | { ok: false };

export function login(db: Db, username: string, password: string): LoginResult {
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;

  // Hash even when the user does not exist, so a missing account and a wrong
  // password take the same time. Without this, response latency enumerates
  // valid usernames.
  const salt = row?.salt ?? randomBytes(16).toString('hex');
  const expected = row?.password_hash ?? hash('no-such-user', salt);
  const matched = verify(password, salt, expected);

  if (!row || !matched) return { ok: false };

  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3_600_000).toISOString();
  const now = new Date().toISOString();

  db.prepare('INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, row.username, now, expiresAt);
  db.prepare('UPDATE users SET last_login_at = ? WHERE username = ?').run(now, row.username);

  return { ok: true, token, expiresAt, user: { ...toUser(row), lastLoginAt: now } };
}

export function logout(db: Db, token: string): void {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

/** The actor behind a session token, or undefined when it is unknown or expired. */
export function actorForSession(db: Db, token: string): Actor | undefined {
  const row = db
    .prepare(
      `SELECT u.username, u.role, s.expires_at
         FROM sessions s JOIN users u ON u.username = s.username
        WHERE s.token = ?`,
    )
    .get(token) as { username: string; role: string; expires_at: string } | undefined;

  if (!row) return undefined;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    // Expired sessions are removed on encounter rather than by a sweep, which
    // keeps the table from growing without adding a scheduled job.
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return undefined;
  }
  return {
    subject: row.username,
    role: (ROLES as readonly string[]).includes(row.role) ? (row.role as Role) : 'user',
  };
}

export function userByName(db: Db, username: string): User | undefined {
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
  return row ? toUser(row) : undefined;
}

export type PasswordChange = { ok: true } | { ok: false; reason: string };

/**
 * Changes a password, requiring the current one.
 *
 * Every existing session for the account is dropped. A password change is
 * usually a response to "someone else may have this", and leaving old sessions
 * alive would make the change cosmetic.
 */
export function changePassword(
  db: Db,
  username: string,
  currentPassword: string,
  newPassword: string,
): PasswordChange {
  if (newPassword.length < 10) {
    return { ok: false, reason: 'the new password must be at least 10 characters' };
  }
  if (DEFAULT_ACCOUNTS.some((a) => a.password === newPassword)) {
    return { ok: false, reason: 'that is one of the published default passwords; choose another' };
  }

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
  if (!row || !verify(currentPassword, row.salt, row.password_hash)) {
    return { ok: false, reason: 'the current password is not correct' };
  }

  const salt = randomBytes(16).toString('hex');
  db.prepare(
    'UPDATE users SET salt = ?, password_hash = ?, using_default_password = 0 WHERE username = ?',
  ).run(salt, hash(newPassword, salt), username);
  db.prepare('DELETE FROM sessions WHERE username = ?').run(username);

  return { ok: true };
}

/** Accounts still on their seeded password, for the banner in the console. */
export function accountsOnDefaults(db: Db): string[] {
  const rows = db
    .prepare('SELECT username FROM users WHERE using_default_password = 1 ORDER BY username')
    .all() as { username: string }[];
  return rows.map((r) => r.username);
}

export { randomUUID };
