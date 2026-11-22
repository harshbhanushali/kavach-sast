/**
 * Runtime configuration, from the environment.
 *
 * Everything has a default that works on a developer's machine. A deployment
 * overrides only what it needs, and anything it gets wrong is refused at startup
 * with a message that names the variable, rather than surfacing later as a
 * server that starts and then misbehaves.
 */
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export type Config = {
  port: number;
  host: string;
  dbPath: string;
  /**
   * The built console, served from this origin when it exists.
   *
   * In development the console runs on Vite's own server and proxies here, so
   * this directory is absent and static serving stays switched off.
   */
  consoleDir: string;
  isProduction: boolean;

  /**
   * How many reverse proxies sit in front of this server, or `true` to trust the
   * whole X-Forwarded-For chain. 0 (the default) trusts none, which is correct
   * when clients connect directly: a client-supplied header must not be able to
   * pick its own address for rate limiting.
   */
  trustProxy: number | boolean;
  /** Password for the first administrator, set at the first start. Unset means the account starts on the published default (admin / kavach). */
  adminPassword?: string;
  /** Scans running at once. Each one holds a decompile in memory and on disk, so this is the capacity knob. */
  maxConcurrentScans: number;
  /** Scans allowed to wait for a free slot before new ones are refused as busy. */
  maxQueuedScans: number;
  /** A scan that has not finished by then is abandoned. */
  scanTimeoutMs: number;
  /** Delete scans older than this many days. 0 keeps them for ever. */
  retentionDays: number;
  /** Send Strict-Transport-Security. For deployments served over HTTPS (directly or by a proxy). */
  hsts: boolean;
  /** Requests per minute per client address, across the API. */
  requestsPerMinute: number;
  /** Failed sign-ins per client address in five minutes before further attempts are refused. */
  loginFailuresPerAddress: number;
  /** How long in-flight work gets to finish after a shutdown signal. */
  shutdownGraceMs: number;
};

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** A whole number within bounds, or the default when the variable is unset. */
function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`${name} must be a whole number from ${min} to ${max}; got "${raw}"`);
  }
  return value;
}

function flag(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name]?.trim().toLowerCase();
  if (raw === undefined || raw === '') return fallback;
  if (['1', 'true', 'yes', 'on'].includes(raw)) return true;
  if (['0', 'false', 'no', 'off'].includes(raw)) return false;
  throw new ConfigError(`${name} must be true or false; got "${env[name]}"`);
}

function proxy(env: NodeJS.ProcessEnv): number | boolean {
  const raw = env.KAVACH_SAST_TRUST_PROXY?.trim().toLowerCase();
  if (raw === undefined || raw === '' || raw === '0' || raw === 'false') return 0;
  if (raw === 'true') return true;
  const hops = Number(raw);
  if (!Number.isInteger(hops) || hops < 1 || hops > 10) {
    throw new ConfigError(`KAVACH_SAST_TRUST_PROXY must be true, or the number of proxies (1-10) in front of this server; got "${env.KAVACH_SAST_TRUST_PROXY}"`);
  }
  return hops;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const adminPassword = env.KAVACH_SAST_ADMIN_PASSWORD;
  if (adminPassword !== undefined && adminPassword !== '' && adminPassword.length < 10) {
    throw new ConfigError('KAVACH_SAST_ADMIN_PASSWORD must be at least 10 characters');
  }

  return {
    port: integer(env, 'PORT', 8788, 1, 65535),
    host: env.HOST ?? '127.0.0.1',
    dbPath: env.KAVACH_SAST_DB_PATH ?? join(ROOT, 'data', 'kavach-sast.db'),
    consoleDir: env.KAVACH_SAST_CONSOLE_DIR ?? join(ROOT, '..', 'console', 'dist'),
    isProduction: env.NODE_ENV === 'production',
    trustProxy: proxy(env),
    adminPassword: adminPassword || undefined,
    maxConcurrentScans: integer(env, 'KAVACH_SAST_MAX_SCANS', 2, 1, 32),
    maxQueuedScans: integer(env, 'KAVACH_SAST_MAX_QUEUE', 4, 0, 256),
    scanTimeoutMs: integer(env, 'KAVACH_SAST_SCAN_TIMEOUT_SEC', 900, 30, 86_400) * 1000,
    retentionDays: integer(env, 'KAVACH_SAST_RETENTION_DAYS', 0, 0, 36_500),
    hsts: flag(env, 'KAVACH_SAST_HSTS', false),
    requestsPerMinute: integer(env, 'KAVACH_SAST_REQUESTS_PER_MINUTE', 600, 10, 100_000),
    loginFailuresPerAddress: integer(env, 'KAVACH_SAST_LOGIN_FAILURES', 20, 3, 1000),
    shutdownGraceMs: integer(env, 'KAVACH_SAST_SHUTDOWN_GRACE_SEC', 60, 1, 3600) * 1000,
  };
}
