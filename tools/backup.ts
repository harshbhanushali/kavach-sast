/**
 * `npm run backup -- <directory>`: a consistent copy of the database.
 *
 * Uses SQLite's own `VACUUM INTO`, which produces a complete, defragmented copy
 * from a live database without stopping the server or copying a half-written
 * WAL file. (Copying the .db file while the server runs can give a corrupt
 * backup, which is the usual way backups of a SQLite app go wrong.)
 *
 * The backup contains scans, the decompiled sources kept with them, triage
 * decisions, accounts (as password hashes) and the audit log. Treat it like the
 * applications it describes.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { loadConfig } from '../backend/src/config.ts';

const target = process.argv[2];
if (!target) {
  console.error('usage: npm run backup -- <directory>');
  process.exit(2);
}

const config = loadConfig();
if (!existsSync(config.dbPath)) {
  console.error(`no database at ${config.dbPath}`);
  process.exit(1);
}

const dir = resolve(target);
mkdirSync(dir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const file = join(dir, `kavach-sast-${stamp}.db`);

const db = new DatabaseSync(config.dbPath, { readOnly: true });
try {
  db.exec('PRAGMA busy_timeout = 10000');
  db.prepare('VACUUM INTO ?').run(file);
} finally {
  db.close();
}

// Prove the copy is usable before telling anyone it is a backup.
const copy = new DatabaseSync(file, { readOnly: true });
const check = copy.prepare('PRAGMA integrity_check').get() as { integrity_check: string };
const scans = (copy.prepare('SELECT COUNT(*) AS n FROM sast_scans').get() as { n: number }).n;
copy.close();
if (check.integrity_check !== 'ok') {
  console.error(`the backup at ${file} failed its integrity check: ${check.integrity_check}`);
  process.exit(1);
}
console.log(`backup written: ${file} (${(statSync(file).size / 1024 / 1024).toFixed(1)} MB, ${scans} scan${scans === 1 ? '' : 's'}, integrity ok)`);
