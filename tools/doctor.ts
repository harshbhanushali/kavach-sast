/**
 * `npm run doctor`: is this machine ready to run Kavach SAST?
 *
 * Checks what a deployment depends on and says, for each, whether it is fine, a
 * limitation, or a blocker. Exits non-zero only for blockers, so it can gate a
 * deploy. It prints component names because it is for the operator on the
 * machine; none of this is ever sent to a client.
 */
import { accessSync, constants, existsSync, mkdirSync, statfsSync, writeFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { ConfigError, loadConfig } from '../backend/src/config.ts';
import { findChrome, findQpdf } from '../backend/src/sast/pdf.ts';
import { resolveToolchain } from '../backend/src/toolchain.ts';

type Level = 'ok' | 'warn' | 'fail';
const results: { level: Level; name: string; detail: string }[] = [];
const report = (level: Level, name: string, detail: string) => results.push({ level, name, detail });

// ---- runtime
const [major, minor] = process.versions.node.split('.').map(Number);
if (major > 22 || (major === 22 && minor >= 6)) report('ok', 'Node.js', process.versions.node);
else report('fail', 'Node.js', `${process.versions.node}: version 22.6 or newer is required (TypeScript is run directly)`);

try {
  await import('node:sqlite');
  report('ok', 'SQLite (node:sqlite)', 'available');
} catch {
  report('fail', 'SQLite (node:sqlite)', 'not available in this Node.js build');
}

// ---- configuration
let config: ReturnType<typeof loadConfig> | undefined;
try {
  config = loadConfig();
  report('ok', 'Configuration', `${config.isProduction ? 'production' : 'development'} mode, port ${config.port}, ${config.maxConcurrentScans} concurrent scan(s)`);
} catch (error) {
  report('fail', 'Configuration', error instanceof ConfigError ? error.message : String(error));
}

if (config) {
  if (config.isProduction) {
    if (config.host === '0.0.0.0' && !config.hsts && config.trustProxy === 0) {
      report('warn', 'Transport security', 'listening on all interfaces with no TLS in front. Put it behind a TLS proxy and set KAVACH_SAST_HSTS=true and KAVACH_SAST_TRUST_PROXY (see DEPLOYMENT.md)');
    } else {
      report('ok', 'Transport security', config.hsts ? 'HSTS enabled' : 'not exposed beyond this host');
    }
    report(config.adminPassword ? 'ok' : 'warn', 'Administrator password', config.adminPassword ? 'set from KAVACH_SAST_ADMIN_PASSWORD' : 'not set: the account is on the published default (admin / kavach) until it is changed from the console');
  } else {
    report('warn', 'Mode', 'NODE_ENV is not production: the published default account and a development token are active. Not for a shared network');
  }

  // ---- storage
  const dataDir = dirname(config.dbPath);
  try {
    mkdirSync(dataDir, { recursive: true });
    const probe = join(dataDir, `.doctor-${process.pid}`);
    writeFileSync(probe, 'x');
    rmSync(probe);
    report('ok', 'Data directory', `${dataDir} is writable`);
  } catch (error) {
    report('fail', 'Data directory', `${dataDir} is not writable: ${(error as Error).message}`);
  }
  try {
    const stats = statfsSync(existsSync(dataDir) ? dataDir : dirname(dataDir));
    const freeGb = (Number(stats.bavail) * Number(stats.bsize)) / 1024 ** 3;
    report(freeGb < 5 ? (freeGb < 1 ? 'fail' : 'warn') : 'ok', 'Free disk', `${freeGb.toFixed(1)} GB where the database lives (scans of large apps use several GB of working space)`);
  } catch {
    report('warn', 'Free disk', 'could not be read');
  }

  // ---- port
  await new Promise<void>((resolve) => {
    const probe = createServer();
    probe.once('error', (error: NodeJS.ErrnoException) => {
      report(error.code === 'EADDRINUSE' ? 'warn' : 'fail', 'Port', error.code === 'EADDRINUSE' ? `${config!.port} is already in use (fine if this is the running instance)` : error.message);
      resolve();
    });
    probe.listen(config!.port, config!.host, () => {
      probe.close(() => {
        report('ok', 'Port', `${config!.port} is free`);
        resolve();
      });
    });
  });

  report(existsSync(join(config.consoleDir, 'index.html')) ? 'ok' : 'warn', 'Console', existsSync(join(config.consoleDir, 'index.html')) ? `built, served from ${config.consoleDir}` : `not built at ${config.consoleDir}: run "npm run build" (a development setup runs it separately)`);
}

// ---- scanning toolchain
const tc = resolveToolchain();
report(tc.apktool ? 'ok' : 'warn', 'Android decoding (apktool)', tc.apktool ?? 'not found: Android scans are limited to a string sweep');
report(tc.apksigner ? 'ok' : 'warn', 'Signature verification (apksigner)', tc.apksigner ?? 'not found: signing schemes are reported as present rather than verified');
report(tc.jadx ? 'ok' : 'warn', 'Decompilation (jadx)', tc.jadx ?? 'not found: code findings are shown as Dalvik assembly, not Java');
report(tc.javaHome ? 'ok' : 'warn', 'Java runtime', tc.javaHome ?? 'not found: the Android tools need a JDK (21 is expected)');
report(findChrome() ? 'ok' : 'warn', 'PDF export (Chrome/Chromium)', findChrome() ?? 'not found: reports can still be printed from the browser');
report(findQpdf() ? 'ok' : 'warn', 'PDF passwords (qpdf)', findQpdf() ?? 'not found: PDFs cannot be password-protected');
try {
  accessSync('/usr/bin/unzip', constants.X_OK);
  report('ok', 'unzip', '/usr/bin/unzip');
} catch {
  report('fail', 'unzip', 'not found at /usr/bin/unzip: needed to read every artifact');
}

// ---- report
const mark: Record<Level, string> = { ok: '  ok  ', warn: ' warn ', fail: ' FAIL ' };
console.log('\nKavach SAST: environment check\n');
for (const r of results) console.log(`[${mark[r.level]}] ${r.name.padEnd(36)} ${r.detail}`);
const fails = results.filter((r) => r.level === 'fail').length;
const warns = results.filter((r) => r.level === 'warn').length;
console.log(`\n${fails} blocker${fails === 1 ? '' : 's'}, ${warns} warning${warns === 1 ? '' : 's'}.\n`);
process.exit(fails > 0 ? 1 : 0);
