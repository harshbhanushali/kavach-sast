/**
 * One read per file, however many passes want it.
 *
 * A scan looks at the same decompiled sources several times: the rule pass, the entropy sweep, the data-flow
 * checks, reconnaissance, and finally the copy kept for the Explorer. Where reading a freshly written file
 * is slow (a security agent or the file system scans new files on first use: twenty thousand of them took
 * thirty-five seconds to read back), every extra pass costs a full re-read. Holding the text the first pass
 * read removes the later ones.
 *
 * Bounded, and empty past the bound: a file that does not fit is simply read from disk as before, so a very
 * large app costs time, never memory it does not have. Cleared when the scan ends.
 */
import { readFileSync } from 'node:fs';

const MAX_CHARS = 320 * 1024 * 1024;
const cache = new Map<string, string>();
let held = 0;
// Only inside a scan. Outside one (a test, a script) a file can change between two reads of the same path.
let active = false;

/** Start caching; the scan calls this once and `clearFileCache` when it ends. */
export function beginFileCache(): void {
  active = true;
}

/** The file's text, from the cache when an earlier pass already read it. Throws like `readFileSync`. */
export function readText(absolute: string): string {
  if (!active) return readFileSync(absolute, 'utf8');
  const hit = cache.get(absolute);
  if (hit !== undefined) return hit;
  const text = readFileSync(absolute, 'utf8');
  if (held + text.length <= MAX_CHARS) {
    cache.set(absolute, text);
    held += text.length;
  }
  return text;
}

/** The cached text if some pass has read the file, otherwise undefined. Never touches the disk. */
export function peekText(absolute: string): string | undefined {
  return cache.get(absolute);
}

export function clearFileCache(): void {
  cache.clear();
  held = 0;
  active = false;
}
