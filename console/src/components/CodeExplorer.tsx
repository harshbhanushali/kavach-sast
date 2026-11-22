/**
 * Browsing the decompiled source a scan kept.
 *
 * A finding says "KeychainModule.java line 84". The snippet shows seven lines
 * around it, which is enough to judge a match and not enough to judge the
 * method it sits in. This is the rest of the file.
 *
 * Only the files the findings reference are retained when a decompile is too
 * large to keep whole, and the panel says so rather than presenting a partial
 * tree as the whole artifact: an explorer that silently omits things is worse
 * than one that admits what it has.
 *
 * Three ways to find things: filter the tree by name (and by kind), search the
 * text of every file (CodeSearch), and search inside the open file (FileSearch).
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { request } from '../api';
import { highlight } from './highlight';
import { CodeResults, CodeSearchBox, useCodeSearch } from './CodeSearch';
import type { CodeQuery } from './CodeSearch';
import { FileGlyph, FolderGlyph, KIND_LABEL, kindOf } from './explorer/FileIcons';
import type { FileKind } from './explorer/FileIcons';
import { FileSearchBox, findOccurrences, markLine } from './explorer/FileSearch';

type FileRef = { path: string; bytes: number };
type FileBody = { path: string; bytes: number; content: string };

/** A directory tree assembled from flat paths. */
type Node = {
  name: string;
  path: string;
  children: Map<string, Node>;
  file?: FileRef;
  /** Files at or below this node, for the folder's count. */
  count: number;
};

function buildTree(files: FileRef[]): Node {
  const root: Node = { name: '', path: '', children: new Map(), count: 0 };
  for (const file of files) {
    let node = root;
    const parts = file.path.split('/');
    node.count += 1;
    parts.forEach((part, i) => {
      const path = parts.slice(0, i + 1).join('/');
      if (!node.children.has(part)) {
        node.children.set(part, { name: part, path, children: new Map(), count: 0 });
      }
      node = node.children.get(part)!;
      node.count += 1;
      if (i === parts.length - 1) node.file = file;
    });
  }
  return root;
}

function bytes(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

const INDENT = 16;

function Branch({
  node, depth, selected, onSelect, expanded, onToggle, expandAll, flaggedPaths,
}: {
  node: Node;
  depth: number;
  selected: string | null;
  onSelect: (path: string) => void;
  expanded: Set<string>;
  onToggle: (path: string) => void;
  /** While a search is active every branch is open, or the result is a
      collapsed folder and the reader has to drill to what they just found. */
  expandAll: boolean;
  /** Files a finding landed in, marked so the tree is worth scanning. */
  flaggedPaths: Set<string>;
}) {
  const children = [...node.children.values()].sort((a, b) => {
    // Directories first, then alphabetical: the order every file browser uses,
    // and its absence is immediately disorienting.
    const aDir = a.children.size > 0;
    const bDir = b.children.size > 0;
    if (aDir !== bDir) return aDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <>
      {children.map((child) => {
        const isDir = child.children.size > 0;
        const open = expandAll || expanded.has(child.path);
        const isSelected = selected === child.path;
        const flagged = flaggedPaths.has(child.path);
        return (
          <div key={child.path}>
            <button
              type="button"
              onClick={() => (isDir ? onToggle(child.path) : onSelect(child.path))}
              style={{ paddingLeft: `${depth * INDENT + 10}px` }}
              aria-expanded={isDir ? open : undefined}
              className={`group relative flex w-full items-center gap-2.5 py-[7px] pr-3 text-left text-[14px] transition-colors duration-150 ${
                isSelected
                  ? 'bg-gradient-to-r from-ember-600/35 via-ember-600/15 to-transparent text-slate-50'
                  : 'text-slate-300 hover:bg-ember-500/[0.09] hover:text-slate-50'
              }`}
            >
              {/* Accent bar: solid when selected, a hint on hover. */}
              <span
                aria-hidden
                className={`absolute inset-y-1 left-0 w-[3px] rounded-r bg-ember-400 transition-opacity ${
                  isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-60'
                }`}
              />
              <span className="grid w-3 shrink-0 place-items-center text-slate-500 group-hover:text-ember-300">
                {isDir && (
                  <svg viewBox="0 0 12 12" className={`size-3 transition-transform duration-150 ${open ? 'rotate-90' : ''}`} aria-hidden>
                    <path d="m4 2.5 4 3.5-4 3.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                )}
              </span>
              {isDir ? <FolderGlyph name={child.name} open={open} depth={depth} /> : <FileGlyph name={child.name} />}
              <span
                className={`min-w-0 truncate ${
                  isDir
                    ? 'font-semibold text-slate-100'
                    : `font-mono text-[13.5px] ${flagged ? 'text-rose-200' : ''}`
                }`}
                title={child.path}
              >
                {child.name}
              </span>
              {flagged && (
                <span
                  title="a finding landed in this file"
                  className="shrink-0 rounded-full bg-rose-500/25 px-1.5 text-[10px] font-bold text-rose-200 ring-1 ring-rose-400/40"
                >
                  !
                </span>
              )}
              {isDir ? (
                <span className="ml-auto shrink-0 rounded-full bg-slate-800/80 px-2 py-px text-[11px] font-medium tabular-nums text-slate-400 group-hover:bg-ember-500/20 group-hover:text-ember-100">
                  {child.count.toLocaleString()}
                </span>
              ) : (
                child.file && (
                  <span className="ml-auto shrink-0 pl-2 font-mono text-[11px] tabular-nums text-slate-500 group-hover:text-slate-300">
                    {bytes(child.file.bytes)}
                  </span>
                )
              )}
            </button>
            {isDir && open && (
              <div className="relative">
                {/* Indent guide, so the depth of a long list stays readable. */}
                <span aria-hidden className="absolute inset-y-0 w-px bg-slate-800" style={{ left: `${depth * INDENT + 10 + 5.5}px` }} />
                <Branch
                  node={child}
                  depth={depth + 1}
                  selected={selected}
                  onSelect={onSelect}
                  expanded={expanded}
                  onToggle={onToggle}
                  expandAll={expandAll}
                  flaggedPaths={flaggedPaths}
                />
              </div>
            )}
          </div>
        );
      })}
    </>
  );
}

const KIND_DOT: Record<FileKind, string> = {
  source: 'bg-amber-400',
  resource: 'bg-sky-400',
  smali: 'bg-fuchsia-400',
  native: 'bg-rose-400',
  other: 'bg-slate-400',
};

type KindFilter = 'all' | 'flagged' | FileKind;

export function CodeExplorer({
  scanId,
  retainedFiles,
  filesFound,
  filesTruncated,
  jumpTo: jumpProp,
  /** Lines to mark, by path: the places findings landed in this file. */
  flagged,
}: {
  scanId: string;
  retainedFiles?: number;
  filesFound?: number;
  filesTruncated?: boolean;
  /** Set when a finding asked to be opened here; bumped per request. */
  jumpTo?: { path: string; line?: number; nonce: number };
  flagged: Map<string, Set<number>>;
}) {
  const [files, setFiles] = useState<FileRef[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [body, setBody] = useState<FileBody | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState('');
  const [kind, setKind] = useState<KindFilter>('all');
  // Decompiled resource lines run past 200 characters, which puts the value a
  // finding is about off the right edge. Wrapping is the default for that
  // reason; the toggle is there because wrapping ruins aligned code.
  const [wrap, setWrap] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Two ways to ask for a line: a finding elsewhere on the page (the prop) and a
  // search result here. Both end up in one value the scroll effect watches.
  const [jumpTo, setJumpTo] = useState(jumpProp);
  useEffect(() => setJumpTo(jumpProp), [jumpProp?.nonce, jumpProp?.path, jumpProp?.line]);
  const openAt = (path: string, line: number) => setJumpTo((prev) => ({ path, line, nonce: (prev?.nonce ?? 0) + 1 }));

  // Search across files.
  const [mode, setMode] = useState<'files' | 'code'>('files');
  const [query, setQuery] = useState<CodeQuery>({ q: '', regex: false, caseSensitive: false });
  const search = useCodeSearch(scanId, query, mode === 'code');

  // Search inside the open file.
  const [fileQuery, setFileQuery] = useState<CodeQuery>({ q: '', regex: false, caseSensitive: false });
  const [debouncedFileQuery, setDebouncedFileQuery] = useState(fileQuery);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedFileQuery(fileQuery), 140);
    return () => clearTimeout(t);
  }, [fileQuery]);
  const [cursor, setCursor] = useState(0);
  const [pendingLine, setPendingLine] = useState<number | null>(null);
  const fileSearchInput = useRef<HTMLInputElement>(null);

  /** A result of the search across files: open the file with that search carried into it. */
  const openResult = (path: string, line: number) => {
    setFileQuery(query);
    setDebouncedFileQuery(query);
    setPendingLine(line);
    openAt(path, line);
  };

  useEffect(() => {
    setFiles(null);
    setSelected(null);
    setBody(null);
    setFileQuery((q) => ({ ...q, q: '' }));
    request<{ files: FileRef[] }>(`/v1/sast/scans/${scanId}/files`)
      .then((r) => {
        setFiles(r.files);
        // Open the path to the first flagged file, so the tree lands on
        // something worth reading instead of a row of collapsed folders.
        const first = r.files.find((f) => flagged.has(f.path)) ?? r.files[0];
        if (first) {
          const parts = first.path.split('/').slice(0, -1);
          setExpanded(new Set(parts.map((_, i) => parts.slice(0, i + 1).join('/'))));
        }
      })
      .catch((e) => setError(String(e)));
  }, [scanId, flagged]);

  // A finding asked for a file: select it and open the tree to it. The scroll
  // is handled separately below, once the contents are on screen.
  useEffect(() => {
    if (!jumpTo) return;
    setSelected(jumpTo.path);
    const parts = jumpTo.path.split('/').slice(0, -1);
    setExpanded((prev) => {
      const next = new Set(prev);
      parts.forEach((_, i) => next.add(parts.slice(0, i + 1).join('/')));
      return next;
    });
  }, [jumpTo?.nonce, jumpTo?.path, jumpTo?.line]);

  useEffect(() => {
    if (!selected) return;
    setBody(null);
    request<FileBody>(`/v1/sast/scans/${scanId}/files?path=${encodeURIComponent(selected)}`)
      .then(setBody)
      .catch((e) => setError(String(e)));
  }, [scanId, selected]);

  const flaggedPaths = useMemo(() => new Set(flagged.keys()), [flagged]);

  // How many files of each kind, so the filter chips say what they will show.
  const kindCounts = useMemo(() => {
    const counts: Record<FileKind, number> = { source: 0, resource: 0, smali: 0, native: 0, other: 0 };
    let flaggedCount = 0;
    for (const f of files ?? []) {
      counts[kindOf(f.path)] += 1;
      if (flaggedPaths.has(f.path)) flaggedCount += 1;
    }
    return { counts, flagged: flaggedCount };
  }, [files, flaggedPaths]);

  // A full decompile is thirteen thousand files. Rendering every match of a
  // two-letter search would build a DOM node for most of them and stall the
  // tab, so the result list is capped and the cap is stated rather than
  // silently truncating.
  const MAX_RENDERED = 600;
  const matched = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return (files ?? []).filter(
      (f) =>
        (kind === 'all' || (kind === 'flagged' ? flaggedPaths.has(f.path) : kindOf(f.path) === kind)) &&
        (!needle || f.path.toLowerCase().includes(needle)),
    );
  }, [files, filter, kind, flaggedPaths]);
  const narrowed = filter.trim().length > 0 || kind !== 'all';
  const shown = useMemo(() => (narrowed ? matched.slice(0, MAX_RENDERED) : matched), [matched, narrowed]);
  const tree = useMemo(() => buildTree(shown), [shown]);
  const marks = selected ? flagged.get(selected) : undefined;

  // Matches of the in-file search, with their order across the whole file.
  const found = useMemo(
    () => (body && body.path === selected ? findOccurrences(body.content, debouncedFileQuery) : { occurrences: [], invalid: false, slow: false, capped: false }),
    [body, selected, debouncedFileQuery],
  );
  const byLine = useMemo(() => {
    const map = new Map<number, { occ: (typeof found.occurrences)[number]; index: number }[]>();
    found.occurrences.forEach((occ, index) => {
      const list = map.get(occ.line);
      if (list) list.push({ occ, index });
      else map.set(occ.line, [{ occ, index }]);
    });
    return map;
  }, [found]);

  useEffect(() => setCursor(0), [debouncedFileQuery.q, debouncedFileQuery.regex, debouncedFileQuery.caseSensitive, selected]);
  // A result of the search across files starts at the match that was clicked.
  useEffect(() => {
    if (pendingLine === null || !body || body.path !== selected) return;
    const at = found.occurrences.findIndex((o) => o.line >= pendingLine);
    setCursor(Math.max(0, at));
    setPendingLine(null);
  }, [pendingLine, body, selected, found]);

  // Bring the current match into view, inside the file pane only.
  useEffect(() => {
    if (found.occurrences.length === 0) return;
    const id = requestAnimationFrame(() => {
      const pane = document.querySelector<HTMLPreElement>('pre[data-explorer-path]');
      const el = pane?.querySelector<HTMLElement>(`[data-occ="${cursor}"]`);
      if (!pane || !el) return;
      const p = pane.getBoundingClientRect();
      const r = el.getBoundingClientRect();
      pane.scrollTop += r.top - p.top - pane.clientHeight / 2;
      pane.scrollLeft += r.left - p.left - pane.clientWidth / 2;
    });
    return () => cancelAnimationFrame(id);
  }, [cursor, found]);

  const step = (delta: 1 | -1) => {
    const n = found.occurrences.length;
    if (n > 0) setCursor((c) => (c + delta + n) % n);
  };

  /**
   * Scroll to the requested line once its row exists.
   *
   * Keyed on the jump itself rather than on the loaded file. The earlier
   * version waited for `body` to change, which meant jumping to the file
   * already open scrolled nowhere: nothing in its dependencies had moved. It
   * also raced the fetch on a first jump.
   *
   * The pane carries the path it is showing, so a row left over from the
   * previous file cannot be mistaken for the one being waited on.
   */
  useEffect(() => {
    if (!jumpTo?.line) return;
    let tries = 0;
    const timer = setInterval(() => {
      const pane = document.querySelector<HTMLPreElement>('pre[data-explorer-path]');
      const row = document.getElementById(`line-${jumpTo.line}`);
      if (pane?.dataset.explorerPath === jumpTo.path && row && pane.contains(row)) {
        const delta = row.getBoundingClientRect().top - pane.getBoundingClientRect().top;
        pane.scrollTop += delta - pane.clientHeight / 2;
        clearInterval(timer);
      } else if (++tries > 60) {
        clearInterval(timer); // The file never arrived; leave the pane alone.
      }
    }, 50);
    return () => clearInterval(timer);
  }, [jumpTo?.nonce, jumpTo?.path, jumpTo?.line]);

  if (retainedFiles === 0) {
    return (
      <p className="text-sm leading-relaxed text-slate-400">
        This scan kept no source files. Scans taken before the Explorer existed did not retain
        them. Re-run the scan to browse the code.
      </p>
    );
  }

  if (error) return <p className="text-sm text-rose-300">{error}</p>;
  if (!files) return <p className="text-sm text-slate-400">Loading the file tree…</p>;

  const slash = selected ? selected.lastIndexOf('/') : -1;
  const lineCount = body ? body.content.split('\n').length : 0;
  const chips: { id: KindFilter; label: string; count: number; dot?: string }[] = [
    { id: 'all', label: 'All', count: files.length },
    ...(kindCounts.flagged > 0 ? [{ id: 'flagged' as const, label: 'Flagged', count: kindCounts.flagged, dot: 'bg-rose-400' }] : []),
    ...(['source', 'resource', 'smali', 'native', 'other'] as const)
      .filter((k) => kindCounts.counts[k] > 0)
      .map((k) => ({ id: k as KindFilter, label: KIND_LABEL[k], count: kindCounts.counts[k], dot: KIND_DOT[k] })),
  ];

  return (
    <div className="grid gap-4 lg:grid-cols-[27rem_minmax(0,1fr)]">
      {/* --- tree --- */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/50">
        <div className="border-b border-slate-800 bg-gradient-to-b from-slate-900/70 to-transparent p-3.5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-[15px] font-semibold text-slate-100">
              Files{' '}
              <span className="font-normal text-slate-400">
                {mode === 'files' && narrowed ? `${matched.length.toLocaleString()} of ${files.length.toLocaleString()}` : files.length.toLocaleString()}
              </span>
            </p>
            <div role="tablist" aria-label="Search by" className="inline-flex rounded-lg border border-slate-700 bg-slate-950 p-0.5">
              {(['files', 'code'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  role="tab"
                  aria-selected={mode === m}
                  onClick={() => setMode(m)}
                  className={`rounded-md px-3 py-1 text-xs font-semibold transition ${
                    mode === m ? 'bg-ember-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {m === 'files' ? 'Names' : 'Code'}
                </button>
              ))}
            </div>
          </div>
          {filesTruncated && filesFound ? (
            <p className="mt-0.5 text-[11px] text-amber-200/70">
              {filesFound.toLocaleString()} files were decompiled; the largest were left out to keep
              the report a sane size.
            </p>
          ) : null}
          {mode === 'files' ? (
            <>
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Search files and packages…"
                aria-label="Search files and packages"
                className="mt-3 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-[14px] text-slate-100 outline-none placeholder:text-slate-500 focus:border-ember-500 focus:ring-1 focus:ring-ember-500/40"
              />
              <div className="mt-2.5 flex flex-wrap gap-1.5" role="group" aria-label="Show">
                {chips.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    aria-pressed={kind === c.id}
                    onClick={() => setKind(c.id)}
                    className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition ${
                      kind === c.id
                        ? 'border-ember-400 bg-ember-500/20 text-ember-50'
                        : 'border-slate-700 text-slate-300 hover:border-ember-500/60 hover:bg-ember-500/10'
                    }`}
                  >
                    {c.dot && <span aria-hidden className={`size-1.5 rounded-full ${c.dot}`} />}
                    {c.label}
                    <span className="tabular-nums text-slate-400">{c.count.toLocaleString()}</span>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <CodeSearchBox query={query} onChange={(patch) => setQuery((prev) => ({ ...prev, ...patch }))} />
          )}
        </div>
        <div className="max-h-[46rem] overflow-y-auto py-1.5">
          {mode === 'code' ? (
            <CodeResults state={search} query={query} selected={selected} onOpen={openResult} />
          ) : shown.length === 0 ? (
            <p className="px-4 py-3 text-[14px] text-slate-400">Nothing matches{filter ? ` “${filter}”` : ' that filter'}.</p>
          ) : (
            <Branch
              node={tree}
              depth={0}
              selected={selected}
              onSelect={setSelected}
              expandAll={narrowed}
              flaggedPaths={flaggedPaths}
              expanded={expanded}
              onToggle={(path) =>
                setExpanded((prev) => {
                  const next = new Set(prev);
                  if (next.has(path)) next.delete(path);
                  else next.add(path);
                  return next;
                })
              }
            />
          )}
          {mode === 'files' && matched.length > shown.length && (
            <p className="px-4 py-2 text-[11px] text-slate-500">
              Showing the first {shown.length} of {matched.length.toLocaleString()} matches. Narrow
              the search to see the rest.
            </p>
          )}
        </div>
      </div>

      {/* --- viewer --- */}
      <div className="min-w-0 overflow-hidden rounded-xl border border-slate-800 bg-slate-950/50">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5 border-b border-slate-800 bg-gradient-to-b from-slate-900/70 to-transparent px-4 py-3">
          <div className="flex min-w-0 flex-1 basis-60 items-center gap-3">
            {selected && <FileGlyph name={selected.slice(slash + 1)} />}
            <div className="min-w-0">
              <p className="truncate font-mono text-[14px]" title={selected ?? undefined}>
                {selected ? (
                  <>
                    <span className="text-slate-500">{selected.slice(0, slash + 1)}</span>
                    <span className="font-semibold text-slate-50">{selected.slice(slash + 1)}</span>
                  </>
                ) : (
                  <span className="text-slate-400">No file selected</span>
                )}
              </p>
              {body && (
                <p className="mt-0.5 text-xs text-slate-400">
                  {lineCount.toLocaleString()} lines · {bytes(body.bytes)}
                  {marks && marks.size > 0 && (
                    <span className="ml-2 font-medium text-rose-300">
                      {marks.size} flagged line{marks.size === 1 ? '' : 's'}
                    </span>
                  )}
                </p>
              )}
            </div>
          </div>
          {body && (
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <FileSearchBox
                ref={fileSearchInput}
                query={fileQuery}
                onChange={(patch) => setFileQuery((prev) => ({ ...prev, ...patch }))}
                found={found}
                cursor={found.occurrences.length === 0 ? -1 : cursor}
                onStep={step}
              />
              <button
                type="button"
                onClick={() => setWrap(!wrap)}
                title={wrap ? 'Long lines are wrapped' : 'Long lines run off to the right'}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  wrap
                    ? 'border-ember-500/50 bg-ember-500/15 text-ember-200'
                    : 'border-slate-700 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                Wrap
              </button>
              <button
                type="button"
                onClick={() => navigator.clipboard?.writeText(body.content).catch(() => undefined)}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-ember-500/60 hover:bg-ember-500/10 hover:text-slate-50"
              >
                Copy
              </button>
            </div>
          )}
        </div>

        {found.slow && (
          <p className="border-b border-slate-800 bg-amber-500/10 px-4 py-1.5 text-xs text-amber-200">
            That pattern was slow to match, so only part of the file was searched.
          </p>
        )}

        {!selected ? (
          <p className="px-4 py-20 text-center text-sm text-slate-500">
            Select a file from the tree to read it.
          </p>
        ) : !body ? (
          <p className="px-4 py-20 text-center text-sm text-slate-500">Loading…</p>
        ) : (
          <pre
            data-explorer-path={selected}
            className="max-h-[46rem] overflow-auto py-2 text-[14px] leading-[1.7]"
          >
            {body.content.split('\n').map((line, i) => {
              const n = i + 1;
              const hit = marks?.has(n);
              const inLine = byLine.get(n);
              return (
                <div
                  key={n}
                  id={`line-${n}`}
                  className={`group/line flex ${wrap ? '' : 'w-max min-w-full'} ${
                    hit
                      ? 'border-l-2 border-rose-500 bg-rose-500/10'
                      : inLine
                        ? 'border-l-2 border-amber-400/70 bg-amber-400/[0.06]'
                        : 'border-l-2 border-transparent hover:bg-ember-500/[0.06]'
                  }`}
                >
                  <span
                    className={`w-14 shrink-0 select-none pr-3 text-right font-mono tabular-nums ${
                      hit ? 'font-bold text-rose-300' : inLine ? 'text-amber-200' : 'text-slate-500 group-hover/line:text-slate-300'
                    }`}
                  >
                    {n}
                  </span>
                  <code
                    className={`pr-4 font-mono ${
                      wrap ? 'min-w-0 whitespace-pre-wrap break-all' : 'whitespace-pre'
                    } ${hit ? 'text-rose-50' : 'text-slate-200'}`}
                  >
                    {inLine ? markLine(line, inLine, cursor) : highlight(line, selected)}
                  </code>
                </div>
              );
            })}
          </pre>
        )}
      </div>
    </div>
  );
}
