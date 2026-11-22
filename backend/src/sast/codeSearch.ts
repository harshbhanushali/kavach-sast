/**
 * Searching the decompiled source a scan kept.
 *
 * The retained files are gzipped blobs, so a search has to gunzip each one. That
 * is fast for thousands of files but not free, so the work is bounded three
 * ways: a cap on files and matches returned, a time budget for the whole search,
 * and, for regular expressions, a per-file timeout.
 *
 * The timeout is the important one. A pattern the reader types runs against
 * minified source on the same thread that serves everyone else, and a pattern
 * with nested quantifiers can take minutes on a long line. Regex matching
 * therefore runs inside `vm.Script.runInContext` with a timeout, the one way to
 * interrupt a synchronous regex in Node, and a pattern that trips it ends the
 * search with `timedOut` rather than hanging the server.
 */
import { createContext, Script } from 'node:vm';
import { gunzipSync } from 'node:zlib';

export const SEARCH_LIMITS = {
  minQueryLength: 2,
  maxQueryLength: 200,
  /** Files returned; the rest are counted in `filesMatched` but not listed. */
  maxFiles: 300,
  /** Lines previewed per file; `count` still reports every match in it. */
  previewPerFile: 5,
  /** Stop once this many matching lines have been found, in all files. */
  maxTotalMatches: 5000,
  /** Whole-search budget. */
  budgetMs: 8000,
  /** One file's regex run. */
  regexTimeoutMs: 1000,
  /** A preview shows this many characters around the match. */
  snippetBefore: 70,
  snippetAfter: 150,
} as const;

export type SearchOptions = { regex: boolean; caseSensitive: boolean };

export type LineMatch = {
  line: number;
  /** The line, trimmed around the match when it is very long. */
  text: string;
  /** Offsets of the match within `text`. */
  from: number;
  to: number;
};

export type FileMatches = { path: string; count: number; matches: LineMatch[] };

export type SearchResult = {
  query: string;
  regex: boolean;
  caseSensitive: boolean;
  filesScanned: number;
  filesMatched: number;
  totalMatches: number;
  /** Results were cut at a cap, so there are more than are listed. */
  truncated: boolean;
  /** The time budget or a regex timeout stopped the search early. */
  timedOut: boolean;
};

export class BadQuery extends Error {}

/**
 * Where to look first. Readable Java and the manifest are what a reviewer is
 * after; drawable XML, smali and the untouched originals would otherwise bury
 * them, since results are listed in scan order.
 */
export function searchPriority(path: string): number {
  if (path.startsWith('sources/')) return 0;
  if (path === 'AndroidManifest.xml') return 1;
  if (path.startsWith('res/')) return 2;
  if (path.startsWith('smali')) return 3;
  return 4;
}

export function byPriority(a: string, b: string): number {
  return searchPriority(a) - searchPriority(b) || (a < b ? -1 : a > b ? 1 : 0);
}

export function validateQuery(query: unknown, opts: SearchOptions): string {
  if (typeof query !== 'string') throw new BadQuery('q is required');
  if (query.length < SEARCH_LIMITS.minQueryLength) {
    throw new BadQuery(`Type at least ${SEARCH_LIMITS.minQueryLength} characters.`);
  }
  if (query.length > SEARCH_LIMITS.maxQueryLength) {
    throw new BadQuery(`That search is longer than ${SEARCH_LIMITS.maxQueryLength} characters.`);
  }
  if (opts.regex) {
    try {
      new RegExp(query, opts.caseSensitive ? '' : 'i');
    } catch (error) {
      throw new BadQuery(`Not a valid regular expression: ${(error as Error).message}`);
    }
  }
  return query;
}

type Hit = { index: number; length: number };

/** [lineIndex, offset, length] for each matching line, plus the full count. */
function literalHits(lines: string[], query: string, caseSensitive: boolean): { hits: [number, Hit][]; total: number } {
  const needle = caseSensitive ? query : query.toLowerCase();
  const hits: [number, Hit][] = [];
  for (let i = 0; i < lines.length; i++) {
    const hay = caseSensitive ? lines[i] : lines[i].toLowerCase();
    const at = hay.indexOf(needle);
    if (at >= 0) hits.push([i, { index: at, length: needle.length }]);
  }
  return { hits, total: hits.length };
}

const REGEX_SCRIPT = new Script(`
  (() => {
    const re = new RegExp(__src, __flags);
    const out = [];
    for (let i = 0; i < __lines.length; i++) {
      const m = re.exec(__lines[i]);
      if (m && m[0].length > 0) out.push([i, m.index, m[0].length]);
    }
    return out;
  })()
`);

/**
 * One context for every file: creating a context per file made a regex search
 * four times slower than a literal one. Safe to share because a search runs to
 * completion synchronously and the properties are reset on every call.
 */
const SANDBOX: { __src: string; __flags: string; __lines: string[] } = { __src: '', __flags: '', __lines: [] };
createContext(SANDBOX);

/** Runs the pattern over the lines inside a vm so a runaway regex can be interrupted. */
function regexHits(lines: string[], query: string, caseSensitive: boolean, timeoutMs: number): { hits: [number, Hit][]; total: number } {
  SANDBOX.__src = query;
  SANDBOX.__flags = caseSensitive ? '' : 'i';
  SANDBOX.__lines = lines;
  try {
    const raw = REGEX_SCRIPT.runInContext(SANDBOX, { timeout: timeoutMs }) as [number, number, number][];
    const hits = raw.map(([line, index, length]): [number, Hit] => [line, { index, length }]);
    return { hits, total: hits.length };
  } finally {
    SANDBOX.__lines = [];
  }
}

function snippet(line: string, hit: Hit): { text: string; from: number; to: number } {
  const { snippetBefore, snippetAfter } = SEARCH_LIMITS;
  let start = Math.max(0, hit.index - snippetBefore);
  let end = Math.min(line.length, hit.index + hit.length + snippetAfter);
  // Whole line when it is short enough that trimming would only hide context.
  if (line.length <= snippetBefore + snippetAfter + hit.length) {
    start = 0;
    end = line.length;
  }
  const lead = start > 0 ? '…' : '';
  const tail = end < line.length ? '…' : '';
  const text = `${lead}${line.slice(start, end)}${tail}`;
  const from = lead.length + (hit.index - start);
  return { text, from, to: from + hit.length };
}

/**
 * Searches the file bodies. `files` yields (path, gzipped content) lazily so the
 * caller never holds every body in memory. Pure apart from the clock, so tests
 * can feed it rows built in memory.
 */
export function searchFiles(
  files: Iterable<{ path: string; gz: Uint8Array }>,
  query: string,
  opts: SearchOptions,
  now: () => number = Date.now,
): { result: SearchResult; files: FileMatches[] } {
  const started = now();
  const out: FileMatches[] = [];
  const result: SearchResult = {
    query,
    regex: opts.regex,
    caseSensitive: opts.caseSensitive,
    filesScanned: 0,
    filesMatched: 0,
    totalMatches: 0,
    truncated: false,
    timedOut: false,
  };

  for (const file of files) {
    if (now() - started > SEARCH_LIMITS.budgetMs) {
      result.timedOut = true;
      break;
    }
    if (result.totalMatches >= SEARCH_LIMITS.maxTotalMatches) {
      result.truncated = true;
      break;
    }
    result.filesScanned += 1;

    let content: string;
    try {
      content = gunzipSync(file.gz).toString('utf8');
    } catch {
      continue; // A corrupt blob is not a reason to fail the whole search.
    }
    const lines = content.split('\n');

    let found: { hits: [number, Hit][]; total: number };
    try {
      found = opts.regex
        ? regexHits(lines, query, opts.caseSensitive, SEARCH_LIMITS.regexTimeoutMs)
        : literalHits(lines, query, opts.caseSensitive);
    } catch {
      // The regex timeout. Stop rather than burn the budget on every remaining file.
      result.timedOut = true;
      break;
    }
    if (found.total === 0) continue;

    result.filesMatched += 1;
    result.totalMatches += found.total;
    if (out.length >= SEARCH_LIMITS.maxFiles) {
      result.truncated = true;
      continue;
    }
    out.push({
      path: file.path,
      count: found.total,
      matches: found.hits.slice(0, SEARCH_LIMITS.previewPerFile).map(([i, hit]) => ({ line: i + 1, ...snippet(lines[i], hit) })),
    });
  }
  return { result, files: out };
}
