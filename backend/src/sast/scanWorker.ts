/**
 * Runs a scan off the main thread.
 *
 * `runScan` is synchronous from top to bottom — apktool, jadx, unzip and
 * dexdump are all `execFileSync` — so calling it on the server's own thread
 * blocks the event loop for as long as the scan takes. On a large APK that is
 * two and a half minutes during which the process answers nothing: not
 * /healthz, not the console, and not the progress poll the console needs in
 * order to draw a progress bar for this very scan.
 *
 * Measured before this existed: /healthz took 0.7s during a half-second IPA
 * scan against 0.0014s idle. Scaled to an APK it is the whole console frozen.
 *
 * So the work happens in a worker and the main thread stays free. Progress
 * arrives as messages; the finished report arrives as one more.
 *
 * The retained sources are gzipped *here* rather than in the route, because
 * they are the largest thing crossing the thread boundary: about 96 MB of Java
 * as text, or 18 MB compressed. Compressing before the hand-off is what makes
 * the copy affordable.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { gzipSync } from 'node:zlib';
import { ScanError, runScan } from './scan.ts';
import type { ScanOptions } from './scan.ts';

type Incoming = { options: Omit<ScanOptions, 'onProgress'> };

const { options } = workerData as Incoming;

try {
  const scan = runScan({
    ...options,
    onProgress: (stage, fraction, watch, event) =>
      parentPort?.postMessage(event ? { type: 'event', event } : { type: 'progress', stage, fraction, watch }),
    // The findings go first. Reading the sources again, deleting the decode and compressing them is the slow
    // part of finishing, and nobody reviewing findings is waiting on it: the Explorer needs the sources,
    // the report does not.
    onDocument: (document) => parentPort?.postMessage({ type: 'document', document }),
  });

  const { sources } = scan;
  const files = (sources?.files ?? []).map((file) => ({
    path: file.path,
    bytes: file.bytes,
    gz: gzipSync(file.content),
  }));

  // Deliberately no transfer list. `gzipSync` returns Buffers carved out of
  // Node's shared allocation pool, so their `.buffer` is that pool rather than
  // a standalone ArrayBuffer: transferring it is rejected outright, and were it
  // accepted it would detach every other Buffer sharing the same pool. A
  // structured clone of 18 MB is the cheaper mistake to avoid.
  parentPort?.postMessage({
    type: 'done',
    files,
    found: sources?.found ?? 0,
    truncated: sources?.truncated ?? false,
  });
} catch (error) {
  parentPort?.postMessage({
    type: 'error',
    message: (error as Error).message,
    // ScanError means "your file was wrong", which is a 400. Anything else is
    // a fault here, which is a 500. The distinction does not survive the
    // thread boundary on its own.
    expected: error instanceof ScanError,
  });
}
