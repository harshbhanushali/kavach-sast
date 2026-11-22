/** Everything a route handler needs, assembled once at startup. */
import { openDb } from './db.ts';
import { rotateDefaultPasswords, seedDefaultUsers } from './users.ts';
import { FixedWindowLimiter, ScanGate } from './limits.ts';
import type { Db } from './db.ts';
import { loadConfig } from './config.ts';
import type { Config } from './config.ts';
import type { TokenTable } from './auth.ts';

export type AppContext = {
  config: Config;
  db: Db;
  tokens: TokenTable;
  limits: {
    /** Every API request, per client address. */
    requests: FixedWindowLimiter;
    /** Failed sign-ins, per client address. */
    loginFailures: FixedWindowLimiter;
    /** Scans running at once, and waiting. */
    scans: ScanGate;
  };
};

/**
 * Local-development bearer token.
 *
 * A development credential, printed at startup so the console can use it. In
 * production this table is replaced by an OIDC lookup; route handlers only
 * ever see the resolved Actor, so nothing else changes.
 */
export function developmentTokens(): TokenTable {
  return {
    'dev-user-token': { subject: 'user@localhost', role: 'user' },
  };
}

export function createContext(overrides: Partial<AppContext> = {}): AppContext {
  const config = overrides.config ?? loadConfig();
  const db = overrides.db ?? openDb(config.dbPath);
  // First start: create the administrator, on the published default unless the operator set a password. Later
  // starts: nothing, so a changed password is never resurrected.
  seedDefaultUsers(db, { adminPassword: config.adminPassword });
  if (config.adminPassword) rotateDefaultPasswords(db, config.adminPassword);

  return {
    config,
    db,
    // The static token is a hardcoded credential that outlives any password
    // change, so it exists only outside production. A deployment (the Docker
    // image sets NODE_ENV=production) signs in with a real account instead.
    tokens: overrides.tokens ?? (config.isProduction ? {} : developmentTokens()),
    limits: overrides.limits ?? {
      requests: new FixedWindowLimiter(config.requestsPerMinute, 60_000),
      loginFailures: new FixedWindowLimiter(config.loginFailuresPerAddress, 5 * 60_000),
      scans: new ScanGate(config.maxConcurrentScans, config.maxQueuedScans),
    },
  };
}
