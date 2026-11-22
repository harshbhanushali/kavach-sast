/**
 * Reading a directory of freshly written files ahead of the pass that needs them.
 *
 * Where a security agent or the file system scans new files on first read, a scan that reads thousands of
 * them one after another spends most of its time waiting, not working: the decompiled Java of a large app
 * took close to a minute to read one file at a time. Several readers at once overlap those waits.
 *
 * Only for a tree the next pass will read in full, and only that tree: warming files nothing reads soon
 * queues them ahead of the ones that matter (it made a scan slower when it was pointed at the smali too).
 *
 * Best effort and invisible: if it cannot start, the scan reads the files itself exactly as before.
 */
import { spawn } from 'node:child_process';

export function warmCache(dir: string, namePattern = '*'): void {
  if (process.platform === 'win32' || process.env.KAVACH_NO_WARM) return;
  try {
    const child = spawn(
      'sh',
      ['-c', 'find "$1" -type f -name "$2" -print0 | xargs -0 -n 100 -P 8 cat > /dev/null 2>&1', 'sh', dir, namePattern],
      { stdio: 'ignore' },
    );
    child.on('error', () => undefined);
    child.unref();
  } catch {
    // No shell, no head start; the scan is just not sped up.
  }
}
