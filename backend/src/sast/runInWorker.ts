/** Starting a scan worker and turning its messages back into a promise. */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Worker } from 'node:worker_threads';
import type { SastScan } from './types.ts';
import type { ScanOptions } from './scan.ts';
import type { LiveEvent, ScanStage } from './progress.ts';

export type RetainedFile = { path: string; bytes: number; gz: Uint8Array };

/**
 * What a scan hands back, in two parts. The report (`document`) arrives as soon as the analysis is done;
 * the retained sources, which take a few seconds more to compress, arrive through `files`.
 */
export type WorkerScanResult = {
  document: Omit<SastScan, 'sources'>;
  /** Settles when the sources are collected and compressed; rejects if the worker fails or is stopped first. */
  files: Promise<{ files: RetainedFile[]; found: number; truncated: boolean }>;
};

/** Thrown for the "your upload was wrong" case, so the route can answer 400. */
export class ExpectedScanError extends Error {}

/** `INFO  - progress: 3596 of 5245 (68%)` — jadx counting classes as it works. */
const JADX_PROGRESS = /progress:\s*(\d+)\s+of\s+(\d+)/g;

/**
 * The last progress figure jadx wrote.
 *
 * The log is a single line that jadx rewrites with carriage returns, so the
 * whole file is read and the final match taken rather than trying to seek.
 * It stays small — a few kilobytes — for exactly that reason.
 */
function tailJadxProgress(path: string): number | undefined {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return undefined; // Not created yet; jadx is still starting.
  }
  let done: number | undefined;
  let total: number | undefined;
  for (const match of text.matchAll(JADX_PROGRESS)) {
    done = Number(match[1]);
    total = Number(match[2]);
  }
  return done !== undefined && total ? done / total : undefined;
}

/**
 * Files jadx has written so far that this watcher has not yet reported.
 *
 * Read from the main thread while the worker is blocked inside jadx, which is the only way to learn
 * what is being produced: jadx itself reports a count, not names. Only `.java` and `.kt` under
 * `sources/` are reported, the same files the rule pass will go on to read.
 */
function newSources(root: string, seen: Set<string>): string[] {
  let entries;
  try {
    entries = readdirSync(root, { recursive: true, withFileTypes: true });
  } catch {
    return []; // Not created yet.
  }
  const fresh: string[] = [];
  for (const entry of entries) {
    if (!entry.isFile() || !/\.(?:java|kt)$/.test(entry.name)) continue;
    const parent = (entry as { parentPath?: string; path?: string }).parentPath ?? (entry as { path?: string }).path ?? root;
    const relative = join('sources', parent.slice(root.length).replace(/^[\\/]/, ''), entry.name).replace(/\\/g, '/');
    if (seen.has(relative)) continue;
    seen.add(relative);
    fresh.push(relative);
  }
  return fresh;
}

export function runScanInWorker(
  options: Omit<ScanOptions, 'onProgress'>,
  onProgress: (stage: ScanStage, fraction?: number) => void,
  /** Abandon the scan after this long. Each step has its own limit; this bounds the whole. */
  timeoutMs?: number,
  /** The live map's feed: files appearing, files read, rule matches. Optional; a scan runs the same without it. */
  onEvent?: (event: LiveEvent) => void,
): Promise<WorkerScanResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./scanWorker.ts', import.meta.url), {
      workerData: { options },
    });

    // Tailing happens here, on the main thread, because the worker is blocked
    // inside the very process writing the log.
    let tail: ReturnType<typeof setInterval> | undefined;
    let tree: ReturnType<typeof setInterval> | undefined;
    const stopTail = () => {
      if (tail) clearInterval(tail);
      if (tree) clearInterval(tree);
      tail = undefined;
      tree = undefined;
    };

    // The scan has two outcomes: the document, and then the files. Failing before the document rejects the
    // promise the caller is waiting on; failing after it rejects the files.
    let documentSent = false;
    let settled = false;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    let sources: { resolve: (r: { files: RetainedFile[]; found: number; truncated: boolean }) => void; reject: (error: Error) => void } | undefined;
    const filesPromise = new Promise<{ files: RetainedFile[]; found: number; truncated: boolean }>((res, rej) => {
      sources = { resolve: res, reject: rej };
    });
    // The caller may never look at the files (a scan that failed has none); a rejection must not become unhandled.
    filesPromise.catch(() => undefined);

    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      stopTail();
      if (deadline) clearTimeout(deadline);
      fn();
      void worker.terminate();
    };
    const fail = (error: Error) => {
      if (documentSent) finish(() => sources?.reject(error));
      else finish(() => reject(error));
    };
    if (timeoutMs) {
      deadline = setTimeout(
        () => fail(new ExpectedScanError('The scan took too long and was stopped. Try a smaller artifact, or ask the operator to raise the scan time limit.')),
        timeoutMs,
      );
      deadline.unref();
    }

    worker.on('message', (message) => {
      if (message.type === 'event') {
        onEvent?.(message.event as LiveEvent);
      } else if (message.type === 'progress') {
        stopTail();
        onProgress(message.stage as ScanStage, message.fraction);
        if (message.watch) {
          const stage = message.stage as ScanStage;
          const watched = message.watch as string;
          tail = setInterval(() => {
            const fraction = tailJadxProgress(watched);
            if (fraction !== undefined) onProgress(stage, fraction);
          }, 1000);
          tail.unref();
          // The log sits beside jadx's output folder; what jadx has written there is the live file list.
          if (onEvent) {
            const seen = new Set<string>();
            const sourcesDir = join(dirname(watched), 'java', 'sources');
            tree = setInterval(() => {
              const paths = newSources(sourcesDir, seen);
              for (let i = 0; i < paths.length; i += 1500) onEvent({ t: 'files', paths: paths.slice(i, i + 1500) });
            }, 1200);
            tree.unref();
          }
        }
      } else if (message.type === 'document') {
        documentSent = true;
        stopTail();
        resolve({ document: message.document, files: filesPromise });
      } else if (message.type === 'done') {
        finish(() => sources?.resolve({ files: message.files as RetainedFile[], found: message.found, truncated: message.truncated }));
      } else if (message.type === 'error') {
        fail(message.expected ? new ExpectedScanError(message.message) : new Error(message.message));
      }
    });

    worker.on('error', (error) => fail(error));
    worker.on('exit', (code) => {
      // A worker that dies without a message is usually the OOM killer on a
      // very large artifact; saying so beats an unexplained hang.
      if (code !== 0) fail(new Error(`the scan worker exited with code ${code}`));
    });
  });
}
