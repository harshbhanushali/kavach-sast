/**
 * Where a finding sits: a few code windows, then the rest as one line each.
 *
 * Evidence is there to be checked, not to be exhaustive: three windows prove a
 * pattern as well as thirty, and thirty bury the finding. So the windows are
 * capped, the app's own code comes first, and every other location is still
 * named, one line each, so nothing is hidden, only shortened. The full list is
 * always in the console and the JSON export.
 */
import { describeDexContext } from '../sastTypes';
import type { SastLocation } from '../sastTypes';
import { esc, plural } from './kit';

type Loc = SastLocation;

/** A code window, possibly the union of several overlapping ones. */
type Window = Loc & { hits?: number[] };

/** `your code` / library name, from a location's own provenance. */
function provenanceLabel(l: Loc): string {
  const p = l.provenance;
  if (!p || p.origin === 'unknown') return '';
  // A library coordinate (group:artifact) is too long for the narrow origin column; the artifact name says enough.
  return p.origin === 'first-party' ? 'your code' : (p.library?.split(':').pop() ?? 'library');
}

function provenanceTag(l: Loc): string {
  const label = provenanceLabel(l);
  if (!label) return '';
  const mine = l.provenance?.origin === 'first-party';
  return `<span class="prov${mine ? ' mine' : ''}" title="${esc(l.provenance?.because ?? '')}">${esc(label)}</span>`;
}

/**
 * Folds windows that overlap or touch in the same file into one.
 *
 * A rule that fires on consecutive lines used to print a near-identical window
 * per hit, each repeating the same six surrounding lines. The union shows every
 * line once, marks every hit, and lists the hit lines in the header.
 */
export function mergeWindows(locations: Loc[]): Window[] {
  const out: Window[] = [];
  for (const l of locations) {
    const snippet = l.snippet ?? [];
    if (snippet.length === 0) {
      out.push(l);
      continue;
    }
    const first = snippet[0].line;
    const last = snippet[snippet.length - 1].line;
    const target = out.find((w) => {
      const s = w.snippet;
      return w.file === l.file && s && s.length > 0 && first <= s[s.length - 1].line + 1 && last >= s[0].line - 1;
    });
    if (!target || !target.snippet) {
      out.push({ ...l, snippet: [...snippet], hits: l.line ? [l.line] : [] });
      continue;
    }
    const byLine = new Map(target.snippet.map((x) => [x.line, x]));
    for (const line of snippet) {
      const seen = byLine.get(line.line);
      byLine.set(line.line, seen ? { ...seen, vulnerable: seen.vulnerable || line.vulnerable } : line);
    }
    target.snippet = [...byLine.values()].sort((a, b) => a.line - b.line);
    if (l.line) target.hits = [...(target.hits ?? []), l.line].sort((a, b) => a - b);
  }
  return out;
}

export function codeWindow(l: Window): string {
  const ctx = describeDexContext(l);
  const where = l.hits && l.hits.length > 1 ? `:${l.hits.join(', ')}` : l.line ? `:${l.line}` : '';
  return `<div class="code">
    <div class="code-head"><div class="ch-l">${ctx ? `<span class="dexref">${esc(ctx)}</span><br>` : ''}<span class="srcref">${
      ctx ? 'decompiled to ' : ''
    }${esc(l.file)}${where}</span></div>${provenanceTag(l)}</div>
    <table class="code-body">${(l.snippet ?? [])
      .map(
        (line) => `<tr class="${line.vulnerable ? 'vuln' : ''}"><td class="gut">${line.vulnerable ? '›' : ''}</td>
        <td class="num">${line.line}</td><td class="src">${esc(line.text) || '&nbsp;'}</td></tr>`,
      )
      .join('')}</table></div>`;
}

function compactRows(rows: Loc[]): string {
  return rows
    .map((l) => {
      const ctx = describeDexContext(l);
      return `<tr><td class="lc"><code>${esc(l.file)}${l.line ? `:${l.line}` : ''}</code>${
        ctx ? `<span class="dx">${esc(ctx)}</span>` : ''
      }</td><td><code class="snip">${esc((l.excerpt ?? '').slice(0, 130))}</code></td><td class="pv">${provenanceTag(l)}</td></tr>`;
    })
    .join('');
}

/**
 * Every recorded location as consecutive runs: a run of code windows is one
 * table (a row per window, so a window is never split), a run of compact
 * locations is another. `ctx` is the repeating context line.
 */
export type EvidenceCaps = {
  /** Code windows shown in full. */
  windows: number;
  /** Further locations listed as one line each, before "and N more". */
  rows: number;
};

const mine = (l: Loc) => l.provenance?.origin === 'first-party';

export function locationsBlock(locations: Loc[], ctx: string, occurrences: number, caps: EvidenceCaps = { windows: 3, rows: 6 }): string {
  if (locations.length === 0) {
    return '<p class="small muted">No file location: this is a property of the artifact as a whole.</p>';
  }
  // The app's own code first: it is the part the reader can change.
  const ordered = mergeWindows(locations).sort((a, b) => Number(mine(b)) - Number(mine(a)));
  const wanted = ordered.filter((l) => l.snippet && l.snippet.length > 0).slice(0, caps.windows);
  const shown = new Set<Window>(wanted);
  const rest = ordered.filter((l) => !shown.has(l));
  const lines: Window[] = rest.slice(0, caps.rows);
  const omitted = rest.length - lines.length;

  const runs: { window: boolean; items: Window[] }[] = [];
  for (const l of [...wanted, ...lines.map((x) => ({ ...x, snippet: undefined }))]) {
    const window = !!l.snippet && l.snippet.length > 0;
    const last = runs[runs.length - 1];
    if (last && last.window === window) last.items.push(l);
    else runs.push({ window, items: [l] });
  }

  const html = runs
    .map((run) =>
      run.window
        ? `<table class="ev-run"><thead><tr class="ctx"><th>${esc(ctx)} · code</th></tr></thead>
           <tbody>${run.items.map((l) => `<tr><td>${codeWindow(l)}</td></tr>`).join('')}</tbody></table>`
        : `<table class="tbl ev"><thead>
             <tr class="ctx"><th colspan="3">${esc(ctx)}</th></tr>
             <tr><th style="width:44%">Location</th><th>What is there</th><th class="r" style="width:64px">Origin</th></tr></thead>
             <tbody>${compactRows(run.items)}</tbody></table>`,
    )
    .join('');

  const all = Math.max(occurrences, locations.length);
  const hidden = omitted + 0;
  const more =
    hidden > 0 || all > locations.length
      ? `<p class="ev-more">${
          hidden > 0 ? `${plural(hidden, 'more location')} not shown. ` : ''
        }${all > locations.length ? `${all} occurrences in total; the scan records the first ${locations.length} per rule. ` : ''}The full list is in the console and the JSON export.</p>`
      : '';
  return html + more;
}
