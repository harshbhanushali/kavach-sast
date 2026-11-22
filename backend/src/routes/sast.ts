/**
 * Static analysis: upload an APK or IPA, get a scorecard back.
 *
 * This is a *review* surface, not a protection surface, and the separation is
 * deliberate. Nothing here signs a policy, alters a build, or reaches a device.
 * The scan reads an artifact and reports what is in it; acting on that is the
 * developer's job.
 *
 * The uploaded binary is deleted as soon as the scan finishes — see `runScan`,
 * which also removes its decode directory. What is persisted is the finding
 * list, and that DOES include secret values in full: masking them made it
 * impossible to tell a live credential from a placeholder, or to search a
 * secret store for the one that leaked. Treat the scan store accordingly.
 */
import { gunzipSync } from 'node:zlib';
import { emit, eventsSince, forget, progressOf, report } from '../sast/progress.ts';
import { ExpectedScanError, runScanInWorker } from '../sast/runInWorker.ts';
import { randomUUID } from 'node:crypto';
import { createWriteStream, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { FastifyInstance } from 'fastify';
import { requireRole } from '../auth.ts';
import type { Actor } from '../auth.ts';
import type { AppContext } from '../context.ts';
import { resolveToolchain } from '../toolchain.ts';
import { chainsOf } from '../sast/chains.ts';
import { compareScans } from '../sast/compare.ts';
import { BadQuery, byPriority, searchFiles, validateQuery } from '../sast/codeSearch.ts';
import { ScanError, runScan } from '../sast/scan.ts';
import type { SastScan } from '../sast/types.ts';
import { actorFor, audit } from './common.ts';
import { BusyError } from '../limits.ts';
import { carriedDecisions, loadTriage, saveCarried, saveTriage, triageableRuleIds, validateTriage } from '../sast/triage.ts';
import { toSarif } from '../sast/sarif.ts';
import { resolveApp } from '../sast/appFromScan.ts';
import { MAX_REPORT_HTML_BYTES, findChrome, findQpdf, passwordProblem, protectPdf, renderPdf } from '../sast/pdf.ts';

/** Anything larger is not an app a person meant to scan. */
export const MAX_ARTIFACT_BYTES = 600 * 1024 * 1024;

/** Scans whose retained sources are still being stored after their findings were sent, by scan id. */
const pendingFiles = new Map<string, Promise<void>>();

type ScanRow = {
  scan_id: string;
  app_id: string | null;
  created_at: string;
  platform: string;
  file_name: string;
  package_name: string | null;
  score: number;
  grade: string;
  document: string;
};

function summarise(row: ScanRow): Record<string, unknown> {
  const scan = JSON.parse(row.document) as SastScan;
  return {
    scanId: row.scan_id,
    appId: row.app_id,
    createdAt: row.created_at,
    platform: row.platform,
    fileName: row.file_name,
    packageName: row.package_name,
    versionName: scan.artifact.versionName,
    score: row.score,
    grade: row.grade,
    counts: scan.counts,
    findings: scan.findings.length,
    durationMs: scan.durationMs,
  };
}

/**
 * Copies still-valid decisions from the app's previous scan onto a new one.
 * Returns how many were carried. Matching is by app, platform and package, so
 * a different app registered under the same id never inherits judgements about
 * code it does not share.
 */
function carryTriageForward(ctx: AppContext, actor: Actor, scan: SastScan, appId: string): number {
  const prior = ctx.db
    .prepare(
      `SELECT scan_id, file_name, document FROM sast_scans
        WHERE app_id = ? AND platform = ? AND scan_id != ? AND created_at <= ?
          AND (package_name IS NULL OR ? IS NULL OR package_name = ?)
        ORDER BY created_at DESC LIMIT 1`,
    )
    .get(
      appId, scan.artifact.platform, scan.scanId, scan.createdAt,
      scan.artifact.packageName ?? null, scan.artifact.packageName ?? null,
    ) as { scan_id: string; file_name: string; document: string } | undefined;
  if (!prior) return 0;

  const before = JSON.parse(prior.document) as SastScan;
  const carried = carriedDecisions(before, loadTriage(ctx.db, prior.scan_id), scan);
  if (carried.length === 0) return 0;

  saveCarried(ctx.db, scan.scanId, carried);
  audit(ctx, actor, {
    action: 'sast.triage_carry',
    appId,
    subject: scan.scanId,
    detail: `carried ${carried.length} decision${carried.length === 1 ? '' : 's'} forward from ${prior.file_name} (${prior.scan_id})`,
  });
  return carried.length;
}

export function registerSastRoutes(server: FastifyInstance, ctx: AppContext): void {
  /** Whether this deployment can scan, and how deeply. */
  server.get('/v1/sast/capability', async (request) => {
    actorFor(request, ctx);
    const toolchain = resolveToolchain();
    return {
      android: {
        // A scan still runs without the full decoder, but only the string sweep,
        // so the console can warn rather than silently returning a thin report.
        available: true,
        full: Boolean(toolchain.apktool),
        signing: Boolean(toolchain.apksigner),
        note: toolchain.apktool
          ? `Full scan: manifest, resources, decompiled code and signing. Code findings are shown as ${
              toolchain.jadx ? 'readable Java' : 'Dalvik assembly rather than Java'
            }.`
          : 'Limited scan: full Android decoding is not available on this server, so only the string sweep runs.',
      },
      ios: {
        available: true,
        full: true,
        note: 'Info.plist, entitlements, provisioning profile and Mach-O headers are parsed in-process; code rules run against the binary string table.',
      },
      maxBytes: MAX_ARTIFACT_BYTES,
      // Whether the server can turn a report into a PDF file itself. Without a
      // browser installed the console falls back to the print dialog.
      pdf: findChrome()
        ? { available: true }
        : { available: false, note: 'PDF export is not available on this server. Use the print option to save the report instead.' },
      // Whether a finished PDF can be locked with a password. Needs qpdf as well as Chrome.
      pdfPassword: findChrome() && findQpdf()
        ? { available: true }
        : { available: false, note: 'Password-protected PDFs are not available on this server.' },
    };
  });

  /**
   * Render a report to a PDF file.
   *
   * The console builds the report HTML (it owns the template) and posts it here;
   * the server prints it with Chrome and returns the file. Any signed-in user may
   * call it: it changes nothing and the HTML is already on their screen.
   */
  server.post('/v1/sast/report/pdf', { bodyLimit: MAX_REPORT_HTML_BYTES + 1024 }, async (request, reply) => {
    actorFor(request, ctx);
    const body = (request.body ?? {}) as { html?: unknown; fileName?: unknown; password?: unknown };
    if (typeof body.html !== 'string' || body.html.length < 200 || !/<html[\s>]/i.test(body.html)) {
      return reply.code(400).send({ error: 'html must be a complete report document' });
    }
    if (Buffer.byteLength(body.html) > MAX_REPORT_HTML_BYTES) {
      return reply.code(413).send({ error: 'report is too large to render' });
    }
    // A password is optional. When one is sent it is checked and its tool found before the
    // (slow) render, so a bad password fails in milliseconds rather than after a minute.
    const wantsPassword = body.password !== undefined && body.password !== null && body.password !== '';
    const qpdf = wantsPassword ? findQpdf() : undefined;
    if (wantsPassword) {
      const problem = passwordProblem(body.password);
      if (problem) return reply.code(400).send({ error: problem });
      if (!qpdf) return reply.code(503).send({ error: 'Password-protected PDFs are not available on this server.' });
    }
    const chrome = findChrome();
    if (!chrome) {
      return reply.code(503).send({ error: 'PDF export is not available on this server. Use the print option instead.' });
    }
    try {
      let pdf = await renderPdf(body.html, chrome);
      if (qpdf) pdf = await protectPdf(pdf, body.password as string, qpdf);
      const name = String(body.fileName ?? 'report').replace(/[^\w.\- ]+/g, '_').slice(0, 120) || 'report';
      return reply
        .header('content-type', 'application/pdf')
        .header('content-disposition', `attachment; filename="${name.replace(/\.pdf$/i, '')}.pdf"`)
        .header('cache-control', 'no-store')
        .send(pdf);
    } catch (error) {
      request.log.error({ err: error }, 'pdf render failed');
      // The detail (which can include command lines and paths) stays in the server log.
      return reply.code(502).send({ error: 'The PDF could not be rendered. Use the print option instead.' });
    }
  });

  /** Upload and scan. Synchronous: a scan is seconds, not minutes. */
  server.post('/v1/sast/scan', async (request, reply) => {
    const actor = actorFor(request, ctx);
    requireRole(actor, 'user');

    // Refuse before reading the body: a busy server should not first receive a large upload.
    if (ctx.limits.scans.full) {
      reply.header('retry-after', '30');
      return reply.code(503).send({ error: new BusyError().message });
    }

    const uploadDir = join(tmpdir(), `kavach-sast-upload-${randomUUID()}`);
    mkdirSync(uploadDir, { recursive: true });
    let artifactPath: string | undefined;
    let fileName: string | undefined;
    let appId: string | undefined;
    let progressId: string | undefined;
    let releaseSlot: (() => void) | undefined;

    try {
      for await (const part of request.parts()) {
        if (part.type === 'file') {
          fileName = part.filename || 'upload.bin';
          artifactPath = join(uploadDir, fileName.replace(/[^\w.-]/g, '_'));
          await pipeline(part.file, createWriteStream(artifactPath));
          if (part.file.truncated) {
            return reply.code(413).send({ error: `file exceeds ${MAX_ARTIFACT_BYTES} bytes` });
          }
        } else if (part.fieldname === 'appId') {
          appId = String(part.value) || undefined;
        } else if (part.fieldname === 'progressId') {
          // Generated by the client so it can poll for progress while this
          // request is still open. It names a scan that is running, nothing
          // more: it grants no access and is forgotten when the scan ends.
          progressId = String(part.value).slice(0, 64) || undefined;
        }
      }

      if (!artifactPath || !fileName) {
        return reply.code(400).send({ error: 'no file was uploaded' });
      }
      if (!/\.(apk|ipa)$/i.test(fileName)) {
        return reply.code(400).send({ error: 'expected a .apk or .ipa file' });
      }

      report(progressId, 'received');

      const toolchain = resolveToolchain();
      // A slot in the scan gate, so a few large uploads cannot take the machine down.
      const release = await ctx.limits.scans.acquire();
      let released = false;
      releaseSlot = () => {
        if (!released) {
          released = true;
          release();
        }
      };
      let result;
      try {
        // Off the main thread: the scan is synchronous end to end, and running it
        // here would stop this process answering anything — including the
        // progress poll the console makes while this request is still open.
        result = await runScanInWorker(
          {
            filePath: artifactPath,
            fileName,
            tools: { apktool: toolchain.apktool, apksigner: toolchain.apksigner, jadx: toolchain.jadx },
          },
          (stage, fraction) => report(progressId, stage, fraction),
          ctx.config.scanTimeoutMs,
          (event) => emit(progressId, event),
        );
      } catch (error) {
        releaseSlot();
        throw error;
      }
      const scan = result.document;

      // Name the app after the artifact when none was picked, so every scan of
      // the same app lands together. Must precede the insert: scans reference it.
      const resolved = resolveApp(ctx, actor, scan, appId);
      appId = resolved.appId;

      ctx.db
        .prepare(
          `INSERT INTO sast_scans
             (scan_id, app_id, created_at, platform, file_name, package_name, score, grade, document)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          scan.scanId,
          appId ?? null,
          scan.createdAt,
          scan.artifact.platform,
          scan.artifact.fileName,
          scan.artifact.packageName ?? null,
          scan.score,
          scan.grade,
          JSON.stringify(scan),
        );

      audit(ctx, actor, {
        action: 'sast.scan',
        appId,
        subject: scan.scanId,
        detail: `scanned ${scan.artifact.fileName} (${scan.artifact.platform}): ${scan.findings.length} findings, score ${scan.score} (${scan.grade})`,
      });

      // The retained sources go to their own table and come off the document: they are megabytes, and every
      // history listing reads that column. They are collected and stored after the findings have been sent,
      // because the person who ran the scan is waiting on the findings and the Explorer is the only thing that
      // needs the sources. A request for them in the meantime waits for this to finish (`pendingFiles`), and the
      // scan keeps its slot in the gate until then, since the work is still running.
      const scanId = scan.scanId;
      const stored = result.files
        .then(async ({ files: retained }) => {
          const insertFile = ctx.db.prepare(
            'INSERT OR REPLACE INTO sast_files (scan_id, path, bytes, content) VALUES (?, ?, ?, ?)',
          );
          // In slices, so a scan with twenty thousand files does not hold the server for the whole insert.
          for (let i = 0; i < retained.length; i += 1000) {
            ctx.db.exec('BEGIN');
            try {
              for (const file of retained.slice(i, i + 1000)) insertFile.run(scanId, file.path, file.bytes, file.gz);
              ctx.db.exec('COMMIT');
            } catch (error) {
              ctx.db.exec('ROLLBACK');
              throw error;
            }
            await new Promise((resolve) => setImmediate(resolve));
          }
        })
        .catch((error: unknown) => server.log.error({ err: error, scanId }, 'could not store the retained sources'))
        .finally(() => {
          pendingFiles.delete(scanId);
          releaseSlot?.();
        });
      pendingFiles.set(scanId, stored);

      // Decisions already made on the previous scan of this app follow any
      // finding that has not changed, so a new build starts from where the last
      // review ended rather than from a wall of findings someone already judged.
      const carried = appId ? carryTriageForward(ctx, actor, scan, appId) : 0;

      // The contents are fetched per file by the Explorer; returning them here
      // would add megabytes to a response the console does not read them from.
      return {
        ...scan,
        appId: appId ?? null,
        appCreated: resolved.created,
        appRedirectedFrom: resolved.redirectedFrom ?? null,
        triage: loadTriage(ctx.db, scan.scanId),
        triageCarried: carried,
        // The Explorer's sources are still being collected; ask for them and the server waits.
        filesPending: true,
      };
    } catch (error) {
      releaseSlot?.();
      if (error instanceof BusyError) {
        reply.header('retry-after', String(error.retryAfterSec));
        return reply.code(503).send({ error: error.message });
      }
      if (error instanceof ExpectedScanError || error instanceof ScanError) {
        return reply.code(400).send({ error: error.message });
      }
      request.log.error({ err: error }, 'sast scan failed');
      return reply.code(500).send({ error: 'The scan failed unexpectedly. See the server log for details.' });
    } finally {
      // A short scan is over before the console has asked what happened in it, so the feed outlives the
      // request by a little: the console reads the last of it, and the map plays it out.
      if (progressId) setTimeout(() => forget(progressId), 30_000).unref();
      // The upload is someone's application binary. It does not outlive the request.
      rmSync(uploadDir, { recursive: true, force: true });
    }
  });

  /**
   * How far a running scan has got.
   *
   * Polled while the upload POST is still open, which is why it is a separate
   * route rather than something the POST could return. Unknown ids answer with
   * a placeholder rather than a 404: a poll that arrives a moment before the
   * server registers the scan, or a moment after it finishes, is normal and
   * should not look like an error in the console.
   */
  server.get('/v1/sast/progress/:progressId', async (request) => {
    actorFor(request, ctx);
    const { progressId } = request.params as { progressId: string };
    const { after } = request.query as { after?: string };
    const progress = progressOf(progressId) ?? { stage: 'received', percent: 0, label: 'Starting', at: Date.now() };
    // The live map's feed rides on the same poll: what happened since the cursor the console last held.
    return after === undefined ? progress : { ...progress, ...eventsSince(progressId, Number(after) || 0) };
  });

  /** Scan history, newest first. */
  server.get('/v1/sast/scans', async (request) => {
    actorFor(request, ctx);
    const { appId } = request.query as { appId?: string };
    const rows = (
      appId
        ? ctx.db
            .prepare('SELECT * FROM sast_scans WHERE app_id = ? ORDER BY created_at DESC LIMIT 100')
            .all(appId)
        : ctx.db.prepare('SELECT * FROM sast_scans ORDER BY created_at DESC LIMIT 100').all()
    ) as ScanRow[];
    return { scans: rows.map(summarise) };
  });

  /** One scan, in full. */
  server.get('/v1/sast/scans/:scanId', async (request, reply) => {
    actorFor(request, ctx);
    const { scanId } = request.params as { scanId: string };
    const row = ctx.db.prepare('SELECT document FROM sast_scans WHERE scan_id = ?').get(scanId) as
      | { document: string }
      | undefined;
    if (!row) return reply.code(404).send({ error: 'no such scan' });

    // Scans taken before sources were retained have none, and the console needs
    // to know that so it can say so instead of showing an empty tree.
    const files = ctx.db
      .prepare('SELECT COUNT(*) AS n FROM sast_files WHERE scan_id = ?')
      .get(scanId) as { n: number };

    // Chains are derived from the findings, so a scan stored before they existed gets them here. They are a
    // reading of the report and never a reason to refuse it: a document that cannot be read that way is
    // served without them.
    const document = JSON.parse(row.document) as SastScan;
    let chains = document.chains;
    if (!chains) {
      try {
        chains = chainsOf(document);
      } catch (error) {
        server.log.warn({ err: error, scanId }, 'could not derive attack chains for this scan');
      }
    }
    return { ...document, ...(chains ? { chains } : {}), retainedFiles: files.n, triage: loadTriage(ctx.db, scanId) };
  });

  /**
   * The retained file tree for a scan.
   *
   * Paths only — contents are fetched one at a time, because the whole set can
   * run to megabytes and a reviewer opens a handful.
   */
  server.get('/v1/sast/scans/:scanId/files', async (request, reply) => {
    actorFor(request, ctx);
    const { scanId } = request.params as { scanId: string };
    await pendingFiles.get(scanId);
    const { path } = request.query as { path?: string };

    if (path) {
      const file = ctx.db
        .prepare('SELECT path, bytes, content FROM sast_files WHERE scan_id = ? AND path = ?')
        .get(scanId, path) as { path: string; bytes: number; content: Uint8Array } | undefined;
      if (!file) return reply.code(404).send({ error: 'that file was not retained with this scan' });
      return { path: file.path, bytes: file.bytes, content: gunzipSync(file.content).toString('utf8') };
    }

    const files = ctx.db
      .prepare('SELECT path, bytes FROM sast_files WHERE scan_id = ? ORDER BY path')
      .all(scanId) as { path: string; bytes: number }[];
    return { files };
  });

  /**
   * Full-text search over the retained decompiled sources of one scan.
   *
   * Contents are gunzipped one file at a time and the work is capped in files,
   * matches and time (see sast/codeSearch.ts), because it runs on the thread
   * that serves everyone else. `regex=1` runs under a timeout so a pattern that
   * backtracks badly ends the search instead of the server.
   */
  server.get('/v1/sast/scans/:scanId/search', async (request, reply) => {
    actorFor(request, ctx);
    const { scanId } = request.params as { scanId: string };
    await pendingFiles.get(scanId);
    const query = request.query as { q?: string; regex?: string; case?: string };
    const opts = { regex: query.regex === '1', caseSensitive: query.case === '1' };
    let q: string;
    try {
      q = validateQuery(query.q, opts);
    } catch (error) {
      if (error instanceof BadQuery) return reply.code(400).send({ error: error.message });
      throw error;
    }

    const paths = ctx.db
      .prepare('SELECT path FROM sast_files WHERE scan_id = ?')
      .all(scanId) as { path: string }[];
    paths.sort((a, b) => byPriority(a.path, b.path));
    const body = ctx.db.prepare('SELECT content FROM sast_files WHERE scan_id = ? AND path = ?');
    function* rows() {
      for (const { path } of paths) {
        const row = body.get(scanId, path) as { content: Uint8Array } | undefined;
        if (row) yield { path, gz: row.content };
      }
    }
    const { result, files } = searchFiles(rows(), q, opts);
    return { ...result, files };
  });

  /**
   * Compare two scans.
   *
   * `baseline` is what you had, `candidate` is what you are about to ship, and
   * the diff is expressed in that direction — a finding present only in the
   * candidate is "introduced", not merely "different".
   */
  server.get('/v1/sast/compare', async (request, reply) => {
    actorFor(request, ctx);
    const { baseline, candidate } = request.query as { baseline?: string; candidate?: string };
    if (!baseline || !candidate) {
      return reply.code(400).send({ error: 'baseline and candidate scan ids are both required' });
    }
    if (baseline === candidate) {
      return reply.code(400).send({ error: 'baseline and candidate are the same scan' });
    }

    const load = (scanId: string): SastScan | undefined => {
      const row = ctx.db.prepare('SELECT document FROM sast_scans WHERE scan_id = ?').get(scanId) as
        | { document: string }
        | undefined;
      return row ? (JSON.parse(row.document) as SastScan) : undefined;
    };

    const a = load(baseline);
    const b = load(candidate);
    if (!a) return reply.code(404).send({ error: `no such scan: ${baseline}` });
    if (!b) return reply.code(404).send({ error: `no such scan: ${candidate}` });

    // A comparison answers "did this app get better", which only means something
    // between builds of the same app. A scan with no recorded package (an old
    // one) cannot be told apart, so it is not refused.
    const pa = a.artifact.packageName;
    const pb = b.artifact.packageName;
    if (a.artifact.platform !== b.artifact.platform) {
      return reply.code(400).send({
        error: `these scans are for different platforms (${a.artifact.platform} and ${b.artifact.platform}); only scans of the same app can be compared`,
      });
    }
    if (pa && pb && pa !== pb) {
      return reply.code(400).send({
        error: `these scans are of different apps (${pa} and ${pb}); only scans of the same app can be compared`,
      });
    }

    return compareScans(a, b);
  });

  /**
   * The scan as SARIF 2.1.0, for code-scanning dashboards and CI. Triage
   * decisions are included as suppressions.
   */
  server.get('/v1/sast/scans/:scanId/sarif', async (request, reply) => {
    actorFor(request, ctx);
    const { scanId } = request.params as { scanId: string };
    const row = ctx.db.prepare('SELECT document FROM sast_scans WHERE scan_id = ?').get(scanId) as
      | { document: string }
      | undefined;
    if (!row) return reply.code(404).send({ error: 'no such scan' });
    const scan = JSON.parse(row.document) as SastScan;
    return reply
      .header('content-type', 'application/sarif+json')
      .header('content-disposition', `attachment; filename="${scan.artifact.fileName.replace(/[^\w.-]/g, '_')}.sarif"`)
      .send(JSON.stringify(toSarif(scan, loadTriage(ctx.db, scanId)), null, 2));
  });

  /**
   * Record a decision about one finding: confirmed, false positive, accepted
   * risk or fixed, with the reason. `open` clears it. Editors and above only,
   * and every change lands in the audit log with the reason, because a quiet
   * "false positive" is the easiest way to make a report say what someone
   * wants it to.
   */
  server.put('/v1/sast/scans/:scanId/triage/:ruleId', async (request, reply) => {
    const actor = actorFor(request, ctx);
    requireRole(actor, 'user');
    const { scanId, ruleId } = request.params as { scanId: string; ruleId: string };

    const row = ctx.db.prepare('SELECT document FROM sast_scans WHERE scan_id = ?').get(scanId) as
      | { document: string }
      | undefined;
    if (!row) return reply.code(404).send({ error: 'no such scan' });
    if (!triageableRuleIds(JSON.parse(row.document) as SastScan).has(ruleId)) {
      return reply.code(404).send({ error: 'this scan has no finding with that rule id' });
    }

    const decision = validateTriage((request.body ?? {}) as Record<string, unknown>);
    if (!decision.ok) return reply.code(400).send({ error: decision.error });

    const entry = saveTriage(ctx.db, scanId, ruleId, decision, actor.subject);
    audit(ctx, actor, {
      action: 'sast.triage',
      subject: scanId,
      detail: entry
        ? `${ruleId}: ${entry.status}${entry.expiresAt ? ` until ${entry.expiresAt}` : ''}${entry.reason ? ` \u2014 ${entry.reason.slice(0, 160)}` : ''}`
        : `${ruleId}: reopened`,
    });
    return { ruleId, entry };
  });

  server.delete('/v1/sast/scans/:scanId', async (request, reply) => {
    const actor = actorFor(request, ctx);
    requireRole(actor, 'user');
    const { scanId } = request.params as { scanId: string };
    const result = ctx.db.prepare('DELETE FROM sast_scans WHERE scan_id = ?').run(scanId);
    if (result.changes === 0) return reply.code(404).send({ error: 'no such scan' });
    // The retained sources are a copy of someone's application. Deleting the
    // scan and leaving them behind would be the worst of both.
    ctx.db.prepare('DELETE FROM sast_files WHERE scan_id = ?').run(scanId);
    ctx.db.prepare('DELETE FROM sast_triage WHERE scan_id = ?').run(scanId);
    audit(ctx, actor, { action: 'sast.delete', subject: scanId, detail: 'scan deleted' });
    return { deleted: true };
  });
}
