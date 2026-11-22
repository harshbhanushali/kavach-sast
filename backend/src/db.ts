/**
 * Storage. SQLite via node:sqlite — no native dependency, so the whole backend
 * runs locally with `npm start` and nothing else installed.
 *
 * Adapted from the shared database module of the author's earlier Kavach project (a runtime-protection platform), trimmed to the
 * tables this standalone SAST product actually uses: apps (optional grouping for
 * a scan), users/sessions (login), audit_log, and the three sast_* tables. Every
 * RASP-only table (policies, builds, instances, events, attestations, ...) is
 * gone — this product never had them to begin with.
 */
import { DatabaseSync } from 'node:sqlite';
import { neutraliseScan } from './sast/redact.ts';
import { hashReport } from './sast/reportHash.ts';
import { SCORE_MODEL, scoreOf } from './sast/types.ts';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type Db = DatabaseSync;

export function openDb(path: string): Db {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  // Wait for a lock instead of failing a request with SQLITE_BUSY; with WAL, NORMAL is
  // durable across an application crash and much faster than FULL.
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA synchronous = NORMAL');
  migrate(db);
  return db;
}

function migrate(db: Db): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS apps (
      app_id              TEXT PRIMARY KEY,
      display_name        TEXT NOT NULL,
      platform            TEXT NOT NULL CHECK (platform IN ('android','ios','universal')),
      bundle_id           TEXT NOT NULL,
      signing_cert_sha256 TEXT,
      owner               TEXT NOT NULL,
      created_at          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      at          TEXT NOT NULL,
      actor       TEXT NOT NULL,
      role        TEXT NOT NULL,
      action      TEXT NOT NULL,
      app_id      TEXT,
      subject     TEXT,
      detail      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_log(app_id, at DESC);

    -- Static analysis results. app_id is nullable on purpose: a scan is a
    -- review of an artifact and is useful before the app is registered, so the
    -- scanner is not gated behind creating a project first.
    --
    -- The document column holds the whole SastScan. The scanned binary itself
    -- is never stored: it is deleted when the request ends, and the excerpts
    -- inside the document are redacted at construction.
    CREATE TABLE IF NOT EXISTS sast_scans (
      scan_id      TEXT PRIMARY KEY,
      app_id       TEXT REFERENCES apps(app_id) ON DELETE SET NULL,
      created_at   TEXT NOT NULL,
      platform     TEXT NOT NULL CHECK (platform IN ('android','ios')),
      file_name    TEXT NOT NULL,
      package_name TEXT,
      score        INTEGER NOT NULL,
      grade        TEXT NOT NULL,
      document     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sast_scans_by_app ON sast_scans (app_id, created_at DESC);

    -- The decompiled files a scan's findings point at, so a reviewer can open
    -- the code rather than re-run a two-minute scan to see one line. content is
    -- gzipped; bytes is the uncompressed size, which is what the explorer shows.
    CREATE TABLE IF NOT EXISTS sast_files (
      scan_id TEXT NOT NULL,
      path    TEXT NOT NULL,
      bytes   INTEGER NOT NULL,
      content BLOB NOT NULL,
      PRIMARY KEY (scan_id, path)
    );

    -- A reviewer's decision about one finding in one scan: confirmed, a false
    -- positive, an accepted risk or fixed. "Open" is the absence of a row, so a
    -- finding nobody has looked at costs nothing to store.
    CREATE TABLE IF NOT EXISTS sast_triage (
      scan_id    TEXT NOT NULL,
      rule_id    TEXT NOT NULL,
      status     TEXT NOT NULL CHECK (status IN ('confirmed','false_positive','accepted_risk','fixed')),
      reason     TEXT NOT NULL,
      expires_at TEXT,
      updated_by TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      carried_from TEXT,
      PRIMARY KEY (scan_id, rule_id)
    );

    -- Console accounts. Passwords are scrypt hashes with a per-password salt;
    -- no column here ever holds a password. A single simplified role ('user')
    -- replaces the original product's viewer/editor/publisher split, since that
    -- distinction existed for policy publishing, which this product does not have.
    CREATE TABLE IF NOT EXISTS users (
      username               TEXT PRIMARY KEY,
      salt                   TEXT NOT NULL,
      password_hash          TEXT NOT NULL,
      role                   TEXT NOT NULL CHECK (role IN ('user')),
      using_default_password INTEGER NOT NULL DEFAULT 0,
      created_at             TEXT NOT NULL,
      last_login_at          TEXT
    );

    -- Opaque session tokens. Server-side so they can be revoked.
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_by_user ON sessions (username);
  `);

  // A decision copied forward from an earlier scan of the same app names that
  // scan. Databases created before carry-over existed lack the column.
  const triageColumns = db.prepare('PRAGMA table_info(sast_triage)').all() as { name: string }[];
  if (!triageColumns.some((c) => c.name === 'carried_from')) {
    db.exec('ALTER TABLE sast_triage ADD COLUMN carried_from TEXT');
  }

  // Scans stored before the scanner stopped naming its own toolchain carry those
  // names in their limitations and method. Clean each once; the query matches
  // nothing afterwards, so this is a no-op on every later start.
  const named = db
    .prepare(
      `SELECT scan_id, document FROM sast_scans
        WHERE json_extract(document, '$.method.decompiler') = 'jadx'
           OR json_extract(document, '$.limitations') LIKE '%apktool%'
           OR json_extract(document, '$.limitations') LIKE '%jadx%'
           OR json_extract(document, '$.limitations') LIKE '%apksigner%'
           OR json_extract(document, '$.limitations') LIKE '%keytool%'
           OR json_extract(document, '$.method.tools') LIKE '%apktool%'
           OR json_extract(document, '$.method.tools') LIKE '%jadx%'
           OR json_extract(document, '$.method.tools') LIKE '%apksigner%'`,
    )
    .all() as { scan_id: string; document: string }[];
  const rewrite = db.prepare('UPDATE sast_scans SET document = ? WHERE scan_id = ?');
  for (const row of named) {
    const doc = JSON.parse(row.document);
    if (neutraliseScan(doc)) rewrite.run(JSON.stringify(doc), row.scan_id);
  }
  // The decode tool's own bookkeeping file was listed in the Explorer as if it were part of the app.
  db.prepare("DELETE FROM sast_files WHERE path = 'apktool.yml'").run();

  // The first scoring model took a fixed number of points per finding with no limit, so almost every scan
  // stored under it scored 0. Rescore each once with the current model, from the findings it already holds,
  // so history, comparisons and the progress chart are all on one scale. Idempotent: a scan carrying the
  // current model number is left alone. The report hash includes the score, so it is recomputed with it.
  const unscored = db
    .prepare("SELECT scan_id, document FROM sast_scans WHERE COALESCE(json_extract(document, '$.scoreModel'), 1) < ?")
    .all(SCORE_MODEL) as { scan_id: string; document: string }[];
  if (unscored.length > 0) {
    const update = db.prepare('UPDATE sast_scans SET score = ?, grade = ?, document = ? WHERE scan_id = ?');
    db.exec('BEGIN');
    try {
      for (const row of unscored) {
        const doc = JSON.parse(row.document);
        const { score, grade } = scoreOf(doc.findings ?? [], doc.secure ?? [], doc.hotspots ?? []);
        doc.score = score;
        doc.grade = grade;
        doc.scoreModel = SCORE_MODEL;
        if (doc.artifact?.sha256) doc.reportHash = hashReport(doc.artifact.sha256, doc.findings ?? [], doc.hotspots ?? [], score);
        update.run(score, grade, JSON.stringify(doc), row.scan_id);
      }
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  // The per-rule coverage list is the scanner's detection logic written out, so it
  // is not kept or served. Scans stored before that decision still carry it: reduce
  // each to the three counts that remain, once, and drop the list. Idempotent: it
  // only touches documents that still have one.
  const scrubbed = db.prepare(`
    UPDATE sast_scans
       SET document = json_remove(
             json_set(
               document,
               '$.coverageSummary',
               json_object(
                 'total',   json_array_length(json_extract(document, '$.coverage')),
                 'flagged', (SELECT COUNT(*) FROM json_each(json_extract(document, '$.coverage'))
                              WHERE json_extract(value, '$.status') = 'flagged'),
                 'clear',   (SELECT COUNT(*) FROM json_each(json_extract(document, '$.coverage'))
                              WHERE json_extract(value, '$.status') = 'clear')
               )
             ),
             '$.coverage'
           )
     WHERE json_type(document, '$.coverage') = 'array'
  `).run();
  // SQLite does not erase deleted data: the old lists would stay readable in the
  // file's unused pages. Rewriting the file is what actually removes them.
  if (Number(scrubbed.changes) > 0) {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.exec('VACUUM');
  }
}
