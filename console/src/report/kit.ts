/**
 * Shared vocabulary for the printable static-analysis report: palette, glyphs
 * and the small HTML fragments every page reuses.
 *
 * Everything here is pure string building. The rules the fragments obey:
 *
 * - **Colour is never the only encoding.** Severity is always a word, a shape
 *   glyph and a five-step level meter as well as a colour, so the report reads
 *   in greyscale and for colour-blind readers.
 * - **Text wears text colours.** Fills (banners, chips) may be saturated;
 *   anything set in running type uses the darker `text` variant of the hue.
 * - **Unknown is not zero.** Helpers return an empty string or an em dash for
 *   missing facts rather than inventing a value.
 */
import type { SastSeverity } from '../sastTypes';
import { pieces } from '../richText';

export type SevKey = SastSeverity;

export const SEVERITY_ORDER: readonly SevKey[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * One entry per severity. `fill`/`ink` are for solid surfaces (ink is chosen for
 * contrast on that fill), `text` is the same hue darkened for type on white,
 * `tint` is a background wash, `level` drives the 5-step meter.
 */
export const SEV: Record<SevKey, {
  label: string; glyph: string; level: number;
  fill: string; ink: string; text: string; tint: string;
}> = {
  critical: { label: 'Critical', glyph: '\u25c6', level: 5, fill: '#8f1230', ink: '#ffffff', text: '#8f1230', tint: '#fbeaee' },
  high:     { label: 'High',     glyph: '\u25b2', level: 4, fill: '#e8590c', ink: '#1a0d02', text: '#b3450a', tint: '#fff0e6' },
  medium:   { label: 'Medium',   glyph: '\u25cf', level: 3, fill: '#f2b705', ink: '#1f1500', text: '#7a5200', tint: '#fff7dc' },
  low:      { label: 'Low',      glyph: '\u25a0', level: 2, fill: '#2b6cb0', ink: '#ffffff', text: '#245a94', tint: '#e9f2fb' },
  info:     { label: 'Info',     glyph: '\u25cb', level: 1, fill: '#66707c', ink: '#ffffff', text: '#4b5563', tint: '#f1f3f5' },
};

export const GOOD = '#157f1f';
export const GOOD_FILL = '#1f9d2f';
export const BAD = SEV.critical.text;
export const WARN = SEV.medium.text;
export const NEUTRAL = '#4b5563';

export const GRADE_COLOR: Record<string, string> = {
  A: '#1f9d2f', B: '#5a9e2f', C: '#f2b705', D: '#e8590c', F: '#8f1230',
};
export const GRADE_TEXT: Record<string, string> = {
  A: '#157f1f', B: '#3f7a1d', C: '#7a5200', D: '#b3450a', F: '#8f1230',
};

/** Position in `SEVERITY_ORDER` (0 = critical); unknown severities sort last. */
export function sevRank(s: string): number {
  const i = SEVERITY_ORDER.indexOf(s as SevKey);
  return i < 0 ? SEVERITY_ORDER.length : i;
}

export function sev(s: string | undefined): (typeof SEV)[SevKey] {
  return SEV[(s as SevKey) in SEV ? (s as SevKey) : 'info'];
}

export function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Escapes text for a CSS string literal (`@page` margin-box `content`). */
export function cssStr(value: string, max = 70): string {
  const trimmed = value.length > max ? `${value.slice(0, max - 1)}\u2026` : value;
  return trimmed.replace(/[\\"]/g, '\\$&').replace(/[\r\n]+/g, ' ').replace(/</g, '\\3c ');
}

export function bytes(n: number | undefined): string {
  if (n === undefined || !Number.isFinite(n)) return '\u2014';
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${n} B`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function fmtDate(iso: string | undefined): string {
  if (!iso) return '\u2014';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

export function fmtDateTime(iso: string | undefined): string {
  if (!iso) return '\u2014';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function val(v: unknown): string {
  if (v === undefined || v === null || v === '') return '<span class="na">\u2014</span>';
  return esc(v);
}

/** The five-step level meter: a shape-based severity cue that survives greyscale. */
export function meter(level: number, color: string, on = 5): string {
  let out = '';
  for (let i = 1; i <= on; i++) {
    out += `<i style="${i <= level ? `background:${color}` : 'background:transparent'}"></i>`;
  }
  return `<span class="meter" aria-hidden="true">${out}</span>`;
}

/** A severity chip: glyph, word and meter. Solid variant for banners and index rows. */
export function sevChip(s: string, opts: { solid?: boolean; meter?: boolean } = {}): string {
  const t = sev(s);
  const style = opts.solid
    ? `background:${t.fill};color:${t.ink};border-color:${t.fill}`
    : `color:${t.text};border-color:${t.fill};background:${t.tint}`;
  return `<span class="chip sevchip" style="${style}"><span class="g">${t.glyph}</span>${esc(t.label)}${
    opts.meter ? meter(t.level, opts.solid ? t.ink : t.fill) : ''
  }</span>`;
}

/** A neutral outlined chip for identifiers (rule id, CWE, MASVS, capabilities). */
export function chip(text: string, cls = ''): string {
  return `<span class="chip ${cls}">${esc(text)}</span>`;
}

export function chips(list: string[], cls = ''): string {
  return list.map((t) => chip(t, cls)).join(' ');
}

/** Boolean rendered as glyph + word; `goodWhen` says which way is healthy. */
export function state(on: boolean, opts: { goodWhen?: boolean; yes?: string; no?: string; neutral?: boolean } = {}): string {
  const goodWhen = opts.goodWhen ?? true;
  const yes = opts.yes ?? 'yes';
  const no = opts.no ?? 'no';
  const good = on === goodWhen;
  if (opts.neutral) return `<span class="st neutral">${on ? '\u25cf' : '\u25cb'} ${on ? yes : no}</span>`;
  return `<span class="st ${good ? 'good' : 'bad'}">${good ? '\u2713' : '\u2715'} ${on ? yes : no}</span>`;
}

/** Definition grid. Empty/undefined values render as an em dash. */
export function facts(
  rows: [string, string | undefined, { wide?: boolean; raw?: boolean; mono?: boolean }?][],
  cols = 3,
): string {
  return `<dl class="facts c${cols}">${rows
    .map(([k, v, o]) => {
      const inner = v === undefined || v === '' ? '<span class="na">\u2014</span>' : o?.raw ? v : esc(v);
      return `<div class="fact${o?.wide ? ' wide' : ''}"><dt>${esc(k)}</dt><dd${o?.mono ? ' class="mono"' : ''}>${inner}</dd></div>`;
    })
    .join('')}</dl>`;
}

/** A row of count tiles. `tone` colours the number; the label stays ink. */
export function tiles(items: { n: number | string; label: string; tone?: string; sub?: string }[]): string {
  return `<div class="tiles" style="--n:${items.length}">${items
    .map(
      (t) => `<div class="tile"><div class="tile-n"${t.tone ? ` style="color:${t.tone}"` : ''}>${esc(t.n)}</div>
        <div class="tile-l">${esc(t.label)}</div>${t.sub ? `<div class="tile-s">${esc(t.sub)}</div>` : ''}</div>`,
    )
    .join('')}</div>`;
}

/** A section opener band: big numeral, title, one-line lead. Page breaks are the caller's business. */
export function opener(id: string, num: string, title: string, lead: string): string {
  return `<header class="opener" id="${id}">
    <div class="opener-num">${esc(num)}</div>
    <div class="opener-body"><h2>${esc(title)}</h2><p>${esc(lead)}</p></div>
  </header>`;
}

/**
 * A sub-section heading with an optional right-aligned aside. The aside is hidden
 * from assistive tech and from the PDF's bookmarks, so a bookmark reads "Severity
 * distribution" rather than "Severity distribution31 findings".
 */
export function h3(title: string, aside = ''): string {
  return `<h3 class="sub"><span>${esc(title)}</span>${aside ? `<span class="aside" aria-hidden="true">${aside}</span>` : ''}</h3>`;
}

export function callout(kind: 'risk' | 'fix' | 'note' | 'warn', title: string, body: string): string {
  return `<div class="callout ${kind}"><div class="callout-t">${esc(title)}</div>${body}</div>`;
}

/**
 * Escapes prose and renders `backtick` spans as code. Scanner text quotes
 * commands and identifiers in backticks; printed raw they look like typos.
 */
export function rich(text: string): string {
  return pieces(text)
    .map((p) => (p.kind === 'text' ? esc(p.value) : p.kind === 'command' ? `<code class="cmdl">${esc(p.value)}</code>` : `<code>${esc(p.value)}</code>`))
    .join('');
}

/* ----------------------------------------------------------------------------
 * App icon
 * ------------------------------------------------------------------------- */

/**
 * The icon as an embeddable URL, or undefined. Only a base64 raster data URL is
 * let through: the value is written into both an `src` attribute and a CSS
 * rule, so anything else (a remote URL, an SVG that could carry script, a
 * stray quote) is dropped rather than escaped.
 */
export function safeIcon(url: string | undefined): string | undefined {
  return url && /^data:image\/(png|webp|jpeg|gif);base64,[A-Za-z0-9+/]+={0,2}$/.test(url) ? url : undefined;
}

/** Deterministic hue from an id, so an app without an icon keeps one stable monogram. */
function hueOf(seed: string): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) % 360;
  return h;
}

/**
 * The app icon in a rounded square, or a monogram tile when the scan carries
 * none. `cls` picks the size (`ico-cover`, `ico-page`). The image sits on a
 * light backing so a transparent launcher icon stays legible on the dark cover.
 */
export function appIcon(icon: string | undefined, name: string, seed: string, cls: string): string {
  const src = safeIcon(icon);
  if (src) return `<span class="appicon ${cls}"><img src="${src}" alt="${esc(name)} icon"></span>`;
  const hue = hueOf(seed || name);
  const letter = (name.trim().charAt(0) || '?').toUpperCase();
  return `<span class="appicon mono ${cls}" style="background:linear-gradient(145deg,hsl(${hue} 55% 46%),hsl(${(hue + 40) % 360} 60% 30%))" aria-hidden="true">${esc(letter)}</span>`;
}

/* ----------------------------------------------------------------------------
 * Dossier packing
 * ------------------------------------------------------------------------- */

/** One dossier section; `cost` is a rough height in mm, used to pack sections onto sheets. */
export type Block = { id: string; html: string; cost: number };

/**
 * Packs dossier sections onto sheets by estimated height: a small section joins
 * the sheet before it (kept whole), a large one starts a fresh sheet. That keeps
 * a nearly empty section from costing a whole sheet, while long lists still
 * break across pages cleanly.
 */
export function packSections(blocks: Block[], pageBudget = 250): string {
  let used = pageBudget; // the first block always opens a sheet
  return blocks
    .map((b) => {
      const fits = used + b.cost <= pageBudget;
      // A long section may begin on a sheet that still has most of a page free;
      // its tables then break between rows with repeated headers.
      const flows = !fits && b.cost > pageBudget * 0.6 && pageBudget - used >= 190;
      used = fits ? used + b.cost : flows ? (used + b.cost) % pageBudget : Math.min(b.cost, pageBudget);
      return `<section class="pg ${fits ? 'cont keep' : flows ? 'cont' : 'newpage'}" id="${b.id}">${b.html}</section>`;
    })
    .join('');
}

/** Runs a section builder; one bad section must not take the whole report down. */
export function safeBlock(id: string, label: string, f: () => Block): Block {
  try {
    return f();
  } catch (err) {
    return { id, cost: 999, html: `<p class="small muted">${esc(label)} could not be rendered: ${esc((err as Error).message)}</p>` };
  }
}
