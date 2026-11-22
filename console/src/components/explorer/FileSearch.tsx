/**
 * "Search in file": find text in the file that is open, with a match counter,
 * previous and next, and the same Aa / .* options as the search across files.
 *
 * The matching itself is plain functions so the explorer can render the marks
 * and scroll to the current one; the box only edits the query and steps.
 */
import { forwardRef } from 'react';
import type { ReactNode } from 'react';
import type { CodeQuery } from '../CodeSearch';

export type Occurrence = { line: number; start: number; len: number };

export type Found = {
  occurrences: Occurrence[];
  /** The pattern is not a valid regular expression. */
  invalid: boolean;
  /** Matching was abandoned because it was taking too long. */
  slow: boolean;
  /** More matches exist than were collected. */
  capped: boolean;
};

const MAX_OCCURRENCES = 5000;
const BUDGET_MS = 400;
export const MIN_FILE_QUERY = 1;

/** Every match in `content`, line by line, within a time and count budget. */
export function findOccurrences(content: string, query: CodeQuery): Found {
  const none: Found = { occurrences: [], invalid: false, slow: false, capped: false };
  if (query.q.length < MIN_FILE_QUERY) return none;
  let re: RegExp;
  try {
    const source = query.regex ? query.q : query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    re = new RegExp(source, query.caseSensitive ? 'g' : 'gi');
  } catch {
    return { ...none, invalid: true };
  }
  const out: Occurrence[] = [];
  const started = performance.now();
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (performance.now() - started > BUDGET_MS) return { occurrences: out, invalid: false, slow: true, capped: false };
    re.lastIndex = 0;
    for (let m = re.exec(lines[i]); m; m = re.exec(lines[i])) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      if (out.length >= MAX_OCCURRENCES) return { occurrences: out, invalid: false, slow: false, capped: true };
      out.push({ line: i + 1, start: m.index, len: m[0].length });
    }
  }
  return { occurrences: out, invalid: false, slow: false, capped: false };
}

/** A line split into text and marked matches. `items` are that line's occurrences, with their index overall. */
export function markLine(line: string, items: { occ: Occurrence; index: number }[], current: number): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const { occ, index } of items) {
    if (occ.start > last) out.push(line.slice(last, occ.start));
    const isCurrent = index === current;
    out.push(
      <mark
        key={index}
        data-occ={index}
        className={`rounded-[3px] px-px ${
          isCurrent ? 'bg-orange-400 text-slate-950 shadow-[0_0_0_2px_rgba(251,146,60,0.45)]' : 'bg-amber-400/30 text-amber-50'
        }`}
      >
        {line.slice(occ.start, occ.start + occ.len)}
      </mark>,
    );
    last = occ.start + occ.len;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function Toggle({ on, onClick, title, children }: { on: boolean; onClick: () => void; title: string; children: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      title={title}
      className={`rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold transition ${
        on ? 'border-ember-400 bg-ember-500/20 text-ember-100' : 'border-transparent text-slate-400 hover:bg-slate-800 hover:text-slate-200'
      }`}
    >
      {children}
    </button>
  );
}

const Chevron = ({ up }: { up?: boolean }) => (
  <svg viewBox="0 0 12 12" className={`size-3 ${up ? '' : 'rotate-180'}`} aria-hidden>
    <path d="m2.5 7.5 3.5-3.5 3.5 3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const FileSearchBox = forwardRef<HTMLInputElement, {
  query: CodeQuery;
  onChange: (patch: Partial<CodeQuery>) => void;
  found: Found;
  /** Index of the current match, or -1. */
  cursor: number;
  onStep: (delta: 1 | -1) => void;
}>(function FileSearchBox({ query, onChange, found, cursor, onStep }, ref) {
  const total = found.occurrences.length;
  const has = query.q.length >= MIN_FILE_QUERY;
  const status = !has
    ? ''
    : found.invalid
      ? 'invalid pattern'
      : total === 0
        ? 'no matches'
        : `${cursor + 1} / ${total.toLocaleString()}${found.capped ? '+' : ''}`;
  return (
    <div
      role="search"
      className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-950 py-1 pl-2.5 pr-1.5 transition focus-within:border-ember-500 focus-within:ring-1 focus-within:ring-ember-500/40"
    >
      <svg viewBox="0 0 20 20" className="size-4 shrink-0 text-slate-500" aria-hidden>
        <circle cx="8.5" cy="8.5" r="5.2" fill="none" stroke="currentColor" strokeWidth="1.7" />
        <path d="m12.6 12.6 4 4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
      <input
        ref={ref}
        value={query.q}
        onChange={(e) => onChange({ q: e.target.value })}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            onStep(e.shiftKey ? -1 : 1);
          } else if (e.key === 'Escape') {
            onChange({ q: '' });
            e.currentTarget.blur();
          }
        }}
        placeholder="Search in file…"
        aria-label="Search in this file"
        spellCheck={false}
        className="w-40 min-w-0 bg-transparent px-1 font-mono text-[13px] text-slate-100 outline-none placeholder:font-sans placeholder:text-slate-500 focus:w-56"
      />
      <span
        aria-live="polite"
        className={`min-w-[4.2rem] text-right text-[11px] tabular-nums ${
          found.invalid ? 'text-rose-300' : has && total === 0 ? 'text-slate-500' : 'text-amber-200'
        }`}
      >
        {status}
      </span>
      <div className="flex items-center">
        <button type="button" title="Previous match (Shift+Enter)" aria-label="Previous match" disabled={total === 0} onClick={() => onStep(-1)} className="grid size-6 place-items-center rounded text-slate-300 transition hover:bg-slate-800 disabled:opacity-30 disabled:hover:bg-transparent">
          <Chevron up />
        </button>
        <button type="button" title="Next match (Enter)" aria-label="Next match" disabled={total === 0} onClick={() => onStep(1)} className="grid size-6 place-items-center rounded text-slate-300 transition hover:bg-slate-800 disabled:opacity-30 disabled:hover:bg-transparent">
          <Chevron />
        </button>
      </div>
      <Toggle on={query.caseSensitive} title="Match case" onClick={() => onChange({ caseSensitive: !query.caseSensitive })}>Aa</Toggle>
      <Toggle on={query.regex} title="Regular expression" onClick={() => onChange({ regex: !query.regex })}>.*</Toggle>
    </div>
  );
});
