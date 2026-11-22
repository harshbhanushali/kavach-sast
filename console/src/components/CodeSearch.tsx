/**
 * Searching inside the code, not just file names.
 *
 * The server does the search (it holds the gzipped sources); this file owns the
 * query box, the request lifecycle and the grouped result list. The explorer
 * uses the same query to mark matches in the file that is open.
 */
import { useEffect, useRef, useState } from 'react';
import { ApiError, request } from '../api';
import { FileGlyph } from './explorer/FileIcons';

export type CodeHit = { line: number; text: string; from: number; to: number };
export type CodeFileHits = { path: string; count: number; matches: CodeHit[] };
export type CodeSearchResult = {
  query: string;
  regex: boolean;
  caseSensitive: boolean;
  filesScanned: number;
  filesMatched: number;
  totalMatches: number;
  truncated: boolean;
  timedOut: boolean;
  files: CodeFileHits[];
};

export type CodeQuery = { q: string; regex: boolean; caseSensitive: boolean };

export const MIN_QUERY = 2;

export type SearchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'done'; result: CodeSearchResult };

/** Debounced search. A newer query supersedes an older one, whatever order they answer in. */
export function useCodeSearch(scanId: string, query: CodeQuery, enabled: boolean): SearchState {
  const [state, setState] = useState<SearchState>({ status: 'idle' });
  const latest = useRef(0);

  useEffect(() => {
    const q = query.q.trim() === '' ? '' : query.q;
    if (!enabled || q.length < MIN_QUERY) {
      latest.current += 1;
      setState({ status: 'idle' });
      return;
    }
    const mine = ++latest.current;
    setState({ status: 'loading' });
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ q, regex: query.regex ? '1' : '0', case: query.caseSensitive ? '1' : '0' });
      request<CodeSearchResult>(`/v1/sast/scans/${scanId}/search?${params}`)
        .then((result) => mine === latest.current && setState({ status: 'done', result }))
        .catch((e) => {
          if (mine !== latest.current) return;
          setState({ status: 'error', message: e instanceof ApiError ? e.message : 'The search could not be run.' });
        });
    }, 350);
    return () => clearTimeout(timer);
  }, [scanId, query.q, query.regex, query.caseSensitive, enabled]);

  return state;
}

function Toggle({ on, onClick, title, children }: { on: boolean; onClick: () => void; title: string; children: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      title={title}
      className={`rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold transition ${
        on ? 'border-ember-400 bg-ember-500/20 text-ember-100' : 'border-slate-700 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
      }`}
    >
      {children}
    </button>
  );
}

/** `onChange` takes a patch, merged by the parent against its latest state, so two quick edits cannot overwrite each other. */
export function CodeSearchBox({ query, onChange }: { query: CodeQuery; onChange: (patch: Partial<CodeQuery>) => void }) {
  return (
    <div className="mt-2.5 flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-950 pr-1.5 focus-within:border-ember-500">
      <input
        value={query.q}
        onChange={(e) => onChange({ q: e.target.value })}
        onKeyDown={(e) => e.key === 'Escape' && onChange({ q: '' })}
        placeholder="Search inside the code…"
        aria-label="Search inside the code"
        spellCheck={false}
        className="min-w-0 flex-1 bg-transparent px-3 py-2 font-mono text-[13px] text-slate-100 outline-none placeholder:font-sans placeholder:text-slate-500"
      />
      <Toggle on={query.caseSensitive} title="Match case" onClick={() => onChange({ caseSensitive: !query.caseSensitive })}>Aa</Toggle>
      <Toggle on={query.regex} title="Regular expression" onClick={() => onChange({ regex: !query.regex })}>.*</Toggle>
    </div>
  );
}

/** One matching line, with the match marked. */
function HitLine({ hit, onOpen }: { hit: CodeHit; onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="flex w-full items-baseline gap-2 py-1 pl-6 pr-3 text-left transition-colors hover:bg-ember-500/10"
    >
      <span className="w-9 shrink-0 text-right font-mono text-[11px] tabular-nums text-slate-500">{hit.line}</span>
      <span className="min-w-0 break-all font-mono text-[12px] leading-snug text-slate-300">
        {hit.text.slice(0, hit.from)}
        <mark className="rounded-sm bg-amber-400/30 px-px text-amber-50">{hit.text.slice(hit.from, hit.to)}</mark>
        {hit.text.slice(hit.to)}
      </span>
    </button>
  );
}

export function CodeResults({ state, query, selected, onOpen }: {
  state: SearchState;
  query: CodeQuery;
  selected: string | null;
  onOpen: (path: string, line: number) => void;
}) {
  if (state.status === 'idle') {
    return (
      <p className="px-3 py-3 text-[13px] leading-relaxed text-slate-400">
        {query.q.length > 0 && query.q.length < MIN_QUERY
          ? `Type at least ${MIN_QUERY} characters.`
          : 'Finds text in every kept source file: a method, a URL, a key, a string. Use .* for a regular expression.'}
      </p>
    );
  }
  if (state.status === 'loading') return <p className="px-3 py-3 text-[13px] text-slate-400">Searching…</p>;
  if (state.status === 'error') return <p className="px-3 py-3 text-[13px] text-rose-300">{state.message}</p>;

  const { result } = state;
  if (result.totalMatches === 0) {
    return (
      <div className="px-3 py-3 text-[13px] leading-relaxed text-slate-400">
        <p>Nothing in {result.filesScanned.toLocaleString()} files matches “{result.query}”.</p>
        {result.timedOut && <p className="mt-1 text-amber-200/80">The search was stopped early, so this may not be complete.</p>}
      </div>
    );
  }
  return (
    <div>
      <p className="px-3 pb-1 pt-2 text-[12px] text-slate-400">
        <span className="font-semibold text-slate-200">{result.totalMatches.toLocaleString()}</span>{' '}
        {result.totalMatches === 1 ? 'line' : 'lines'} in{' '}
        <span className="font-semibold text-slate-200">{result.filesMatched.toLocaleString()}</span>{' '}
        {result.filesMatched === 1 ? 'file' : 'files'}
      </p>
      {(result.truncated || result.timedOut) && (
        <p className="px-3 pb-1 text-[11px] text-amber-200/80">
          {result.timedOut
            ? 'The search ran out of time or the pattern was too slow, so these are not all the matches. Make it more specific.'
            : 'Too many matches to list. Make the search more specific to see the rest.'}
        </p>
      )}
      <ul>
        {result.files.map((f) => {
          const slash = f.path.lastIndexOf('/');
          return (
            <li key={f.path} className="border-t border-slate-800/70 first:border-t-0">
              <button
                type="button"
                onClick={() => onOpen(f.path, f.matches[0]?.line ?? 1)}
                className={`flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-ember-500/10 ${selected === f.path ? 'bg-ember-500/15' : ''}`}
              >
                <FileGlyph name={f.path.slice(slash + 1)} />
                <span className="min-w-0 truncate font-mono text-[12.5px]" title={f.path}>
                  <span className="text-slate-500">{slash >= 0 ? f.path.slice(0, slash + 1) : ''}</span>
                  <span className="font-medium text-slate-100">{f.path.slice(slash + 1)}</span>
                </span>
                <span className="ml-auto shrink-0 rounded-full bg-slate-800 px-1.5 text-[10px] font-semibold tabular-nums text-slate-300">
                  {f.count}
                </span>
              </button>
              {f.matches.map((m) => (
                <HitLine key={m.line} hit={m} onOpen={() => onOpen(f.path, m.line)} />
              ))}
              {f.count > f.matches.length && (
                <button
                  type="button"
                  onClick={() => onOpen(f.path, f.matches[0]?.line ?? 1)}
                  className="w-full py-1 pl-16 pr-2.5 text-left text-[11px] text-ember-300 hover:underline"
                >
                  {f.count - f.matches.length} more in this file
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
