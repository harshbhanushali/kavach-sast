/**
 * The hardening matrix, shared by both platforms: one row per binary, one
 * column per protection, each cell a glyph and a word rather than a colour.
 *
 * An app is only as hardened as its weakest binary, so this leads with a
 * coverage bar per protection and the weakest rows, then lists everything with
 * search, filters and sortable columns. What a "binary" is differs (a bundled
 * Mach-O on iOS, a `.so` on Android) and so do the protections; the caller maps
 * its data into rows and this does the rest.
 */
import { useMemo, useState } from 'react';
import { Panel } from '../ui';
import { formatBytes } from './model';
import { CoverageBar, FilterChip, Mark, NotPresent, Pips, Tag } from './ui';

export type MatrixProtection = { key: string; label: string; hint: string };
export type CellState = 'yes' | 'partial' | 'no';

export type MatrixRow = {
  id: string;
  name: string;
  /** A filterable group (framework, dylib...). Omit when rows have no kinds. */
  kind?: string;
  /** Small trailing text on the name line (Swift). */
  note?: string;
  /** Muted second line under the name. */
  sub: string;
  subTitle?: string;
  /** Second line on a "weakest link" card, after what it misses. */
  weakSub: string;
  sizeBytes?: number;
  checks: Record<string, CellState>;
  /** Extra text the search box matches. */
  searchText?: string;
};

type SortKey = 'weakest' | 'name' | 'size' | string;

export type MatrixCopy = {
  title: string;
  emptySubtitle: string;
  empty: string;
  /** Sentence when every row has every protection. */
  allGood: string;
  columnLabel: string;
  tableTitle: string;
  searchLabel: string;
  searchPlaceholder: string;
  nounPlural: string;
  noMatch: string;
};

const score = (r: MatrixRow, ps: MatrixProtection[]) => ps.reduce((n, p) => n + (r.checks[p.key] === 'yes' ? 1 : 0), 0);
const missing = (r: MatrixRow, ps: MatrixProtection[]) => ps.filter((p) => r.checks[p.key] !== 'yes').map((p) => p.label);

function Weakest({ list, ps, onPick }: { list: MatrixRow[]; ps: MatrixProtection[]; onPick: (name: string) => void }) {
  if (list.length === 0) return null;
  return (
    <ul className="grid gap-2.5 @2xl:grid-cols-2 @5xl:grid-cols-3">
      {list.map((b) => (
        <li key={b.id}>
          <button
            type="button"
            onClick={() => onPick(b.name)}
            className="w-full rounded-lg border border-rose-500/30 bg-rose-500/[0.05] px-3.5 py-3 text-left transition hover:border-rose-400/60 hover:bg-rose-500/10"
          >
            <span className="flex items-center justify-between gap-2">
              <span className="truncate text-sm font-semibold text-slate-50">{b.name}</span>
              <Pips filled={score(b, ps)} total={ps.length} label="Protections present" />
            </span>
            <span className="mt-1.5 block text-xs text-slate-400">
              Missing <span className="font-medium text-rose-200">{missing(b, ps).join(', ')}</span>
            </span>
            <span className="mt-0.5 block text-xs text-slate-500">{b.weakSub}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

export function BinaryMatrix({
  copy, protections, rows: all, kindLabels,
}: {
  copy: MatrixCopy;
  protections: MatrixProtection[];
  rows: MatrixRow[];
  kindLabels?: Record<string, string>;
}) {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<string>('all');
  const [weakOnly, setWeakOnly] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'weakest', dir: 1 });
  const [limit, setLimit] = useState(40);

  const total = all.length;
  const hasSize = all.some((r) => r.sizeBytes !== undefined);
  const kinds = useMemo(() => [...new Set(all.map((r) => r.kind).filter((k): k is string => !!k))], [all]);
  const perfect = all.filter((r) => score(r, protections) === protections.length).length;
  const weakest = useMemo(
    () => all.filter((r) => score(r, protections) < protections.length)
      .sort((a, b) => score(a, protections) - score(b, protections) || (b.sizeBytes ?? 0) - (a.sizeBytes ?? 0)).slice(0, 6),
    [all, protections],
  );

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const cmp = (a: MatrixRow, b: MatrixRow): number => {
      switch (sort.key) {
        case 'name': return a.name.localeCompare(b.name);
        case 'size': return (a.sizeBytes ?? 0) - (b.sizeBytes ?? 0);
        case 'weakest': return score(a, protections) - score(b, protections) || (b.sizeBytes ?? 0) - (a.sizeBytes ?? 0);
        default: return Number(a.checks[sort.key] === 'yes') - Number(b.checks[sort.key] === 'yes');
      }
    };
    return all
      .filter((r) => (kind === 'all' || r.kind === kind)
        && (!weakOnly || score(r, protections) < protections.length)
        && (!q || `${r.name} ${r.searchText ?? ''}`.toLowerCase().includes(q)))
      .sort((a, b) => cmp(a, b) * sort.dir);
  }, [all, protections, query, kind, weakOnly, sort]);

  const setSortKey = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: (s.dir * -1) as 1 | -1 } : { key, dir: key === 'size' ? -1 : 1 }));

  const head = (key: SortKey, label: string, hint?: string, align = 'text-left') => (
    <th
      key={key}
      scope="col"
      aria-sort={sort.key === key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}
      className={`px-3 py-2 ${align}`}
    >
      <button
        type="button"
        onClick={() => setSortKey(key)}
        title={hint ?? `Sort by ${label}`}
        className={`eyebrow inline-flex items-center gap-1 hover:text-slate-200 ${sort.key === key ? '!text-ember-300' : ''}`}
      >
        {label}
        <span aria-hidden className="text-[0.6rem]">{sort.key === key ? (sort.dir === 1 ? '▲' : '▼') : ''}</span>
      </button>
    </th>
  );

  return (
    <div className="space-y-5">
      <Panel
        title={`${copy.title} (${total})`}
        subtitle={
          total === 0
            ? copy.emptySubtitle
            : `${perfect} of ${total} carry every protection. The rest are ranked by how much they lack${hasSize ? ', then by size' : ''}.`
        }
      >
        {total === 0 ? (
          <NotPresent>{copy.empty}</NotPresent>
        ) : (
          <div className="space-y-5">
            <div className="grid gap-x-8 gap-y-4 @2xl:grid-cols-2 @5xl:grid-cols-4">
              {protections.map((p) => (
                <CoverageBar key={p.key} label={p.label} hint={p.hint} have={all.filter((r) => r.checks[p.key] === 'yes').length} total={total} />
              ))}
            </div>

            {total <= 6 ? null : weakest.length > 0 ? (
              <div>
                <p className="eyebrow mb-2">Weakest links</p>
                <Weakest list={weakest} ps={protections} onPick={(name) => { setQuery(name); setWeakOnly(false); setKind('all'); }} />
              </div>
            ) : (
              <p className="flex items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.05] px-3.5 py-2.5 text-sm text-emerald-200">
                <span aria-hidden>{'✓'}</span> {copy.allGood}
              </p>
            )}
          </div>
        )}
      </Panel>

      {total > 0 && (
        <Panel title={copy.tableTitle}>
          <div className="mb-3.5 flex flex-wrap items-center gap-2">
            <label className="min-w-[12rem] flex-1 @2xl:max-w-xs">
              <span className="sr-only">{copy.searchLabel}</span>
              <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={copy.searchPlaceholder} className="w-full" />
            </label>
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={`Filter ${copy.nounPlural}`}>
              {kinds.length > 1 && (
                <>
                  <FilterChip active={kind === 'all'} onClick={() => setKind('all')}>All kinds</FilterChip>
                  {kinds.map((k) => (
                    <FilterChip key={k} active={kind === k} onClick={() => setKind(kind === k ? 'all' : k)}>
                      {kindLabels?.[k] ?? k} <span className="tabular-nums text-slate-500">{all.filter((r) => r.kind === k).length}</span>
                    </FilterChip>
                  ))}
                </>
              )}
              <FilterChip active={weakOnly} onClick={() => setWeakOnly((v) => !v)}>
                <span aria-hidden className="text-[0.65rem] text-rose-300">{'✕'}</span> Missing a protection
              </FilterChip>
            </div>
            <span className="ml-auto text-xs tabular-nums text-slate-500">{rows.length} shown</span>
          </div>

          {rows.length === 0 ? (
            <NotPresent>{copy.noMatch}</NotPresent>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[46rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60">
                    {head('name', copy.columnLabel)}
                    {protections.map((p) => head(p.key, p.label, p.hint, 'text-center'))}
                    {head('weakest', 'Hardening', 'Sort by protections present')}
                    {hasSize && head('size', 'Size', undefined, 'text-right')}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {rows.slice(0, limit).map((r) => (
                    <tr key={r.id} className="check-row">
                      <td className="max-w-[18rem] px-3 py-2">
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                          <span className="truncate text-sm font-medium text-slate-100">{r.name}</span>
                          {r.kind && <Tag mono={false}>{kindLabels?.[r.kind] ?? r.kind}</Tag>}
                          {r.note && <span className="text-[11px] text-slate-500">{r.note}</span>}
                        </span>
                        <span className="block truncate font-mono text-[11px] text-slate-500" title={r.subTitle}>{r.sub}</span>
                      </td>
                      {protections.map((p) => {
                        const st = r.checks[p.key] ?? 'no';
                        return (
                          <td key={p.key} className="px-3 py-2 text-center">
                            <Mark ok={st === 'yes'} partial={st === 'partial'} yes={`${p.label}: yes`} no={`${p.label}: no`} partialLabel={`${p.label}: partial`} />
                          </td>
                        );
                      })}
                      <td className="px-3 py-2"><Pips filled={score(r, protections)} total={protections.length} label="Protections present" /></td>
                      {hasSize && <td className="px-3 py-2 text-right text-xs tabular-nums text-slate-400">{formatBytes(r.sizeBytes)}</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {rows.length > limit && (
            <div className="mt-3 text-center">
              <FilterChip active={false} onClick={() => setLimit((n) => n + 60)}>Show {Math.min(60, rows.length - limit)} more</FilterChip>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
