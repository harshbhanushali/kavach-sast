/**
 * Small visual primitives shared by the iOS and Android views.
 *
 * Every state here is encoded three ways: a colour, a glyph with a distinct
 * shape, and a word. The colour is the fast read; the shape and the word are
 * what a colour-blind reader (or a printout) relies on.
 */
import type { ReactNode } from 'react';
import type { SastSeverity } from '../../sastTypes';
import { Panel } from '../ui';
import type { Tone } from './model';

export const TONE: Record<Tone, { text: string; chip: string; solid: string; glyph: string; word: string }> = {
  good: {
    text: 'text-emerald-300',
    chip: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
    solid: 'bg-emerald-400',
    glyph: '✓',
    word: 'good',
  },
  warn: {
    text: 'text-amber-300',
    chip: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    solid: 'bg-amber-400',
    glyph: '▲',
    word: 'review',
  },
  bad: {
    text: 'text-rose-300',
    chip: 'border-rose-500/45 bg-rose-500/10 text-rose-200',
    solid: 'bg-rose-400',
    glyph: '✕',
    word: 'risk',
  },
  info: {
    text: 'text-sky-300',
    chip: 'border-sky-500/40 bg-sky-500/10 text-sky-200',
    solid: 'bg-sky-400',
    glyph: '●',
    word: 'note',
  },
  muted: {
    text: 'text-slate-400',
    chip: 'border-slate-700 bg-slate-800/50 text-slate-300',
    solid: 'bg-slate-500',
    glyph: '–',
    word: 'n/a',
  },
};

/** Severity styling. Same ramp the rest of the console uses. */
export const SEV: Record<SastSeverity, {
  label: string; text: string; chip: string; solid: string; stripe: string; rank: number;
}> = {
  critical: {
    label: 'Critical', rank: 0,
    text: 'text-rose-300', solid: 'bg-rose-500', stripe: 'border-l-rose-500',
    chip: 'border-rose-500/50 bg-rose-500/15 text-rose-200',
  },
  high: {
    label: 'High', rank: 1,
    text: 'text-orange-300', solid: 'bg-orange-500', stripe: 'border-l-orange-500',
    chip: 'border-orange-500/50 bg-orange-500/15 text-orange-200',
  },
  medium: {
    label: 'Medium', rank: 2,
    text: 'text-amber-300', solid: 'bg-amber-400', stripe: 'border-l-amber-400',
    chip: 'border-amber-500/50 bg-amber-500/15 text-amber-200',
  },
  low: {
    label: 'Low', rank: 3,
    text: 'text-sky-300', solid: 'bg-sky-400', stripe: 'border-l-sky-400',
    chip: 'border-sky-500/50 bg-sky-500/15 text-sky-200',
  },
  info: {
    label: 'Info', rank: 4,
    text: 'text-slate-300', solid: 'bg-slate-500', stripe: 'border-l-slate-500',
    chip: 'border-slate-600 bg-slate-700/40 text-slate-200',
  },
};

/**
 * One shape per severity so the ramp survives without colour:
 * diamond, triangle, square, circle, hollow circle.
 */
export function SevGlyph({ severity, className = '' }: { severity: SastSeverity; className?: string }) {
  const common = { viewBox: '0 0 12 12', 'aria-hidden': true, className: `size-3 shrink-0 ${className}` } as const;
  switch (severity) {
    case 'critical':
      return <svg {...common}><path d="M6 .8 11.2 6 6 11.2.8 6z" fill="currentColor" /></svg>;
    case 'high':
      return <svg {...common}><path d="M6 1.2 11.3 10.6H.7z" fill="currentColor" /></svg>;
    case 'medium':
      return <svg {...common}><rect x="1.6" y="1.6" width="8.8" height="8.8" rx="1.2" fill="currentColor" /></svg>;
    case 'low':
      return <svg {...common}><circle cx="6" cy="6" r="4.6" fill="currentColor" /></svg>;
    default:
      return <svg {...common}><circle cx="6" cy="6" r="3.9" fill="none" stroke="currentColor" strokeWidth="1.6" /></svg>;
  }
}

export function SevChip({ severity, count }: { severity: SastSeverity; count?: number }) {
  const s = SEV[severity];
  return (
    <span className={`pill uppercase tracking-wide ${s.chip}`}>
      <SevGlyph severity={severity} />
      {s.label}
      {count !== undefined && <span className="tabular opacity-80">{count}</span>}
    </span>
  );
}

/** A tone chip: glyph, then the text. The glyph shape differs per tone. */
export function ToneChip({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  const t = TONE[tone];
  return (
    <span className={`pill ${t.chip}`} title={title}>
      <span aria-hidden className="text-[0.65rem] leading-none">{t.glyph}</span>
      {children}
    </span>
  );
}

/** Neutral outlined tag for identifiers (CWE, MASVS, bundle id...). */
export function Tag({ children, title, mono = true }: { children: ReactNode; title?: string; mono?: boolean }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded border border-slate-700 bg-slate-900/60 px-1.5 py-px text-[11px] text-slate-300 ${mono ? 'font-mono' : 'font-medium'}`}
    >
      {children}
    </span>
  );
}

/**
 * A yes/no cell for the hardening matrix. The word is there for screen readers.
 * `partial` is the third state (RELRO that is only partly enforced): amber and a
 * triangle, so it never reads as a pass.
 */
export function Mark({
  ok, partial, yes = 'yes', no = 'no', partialLabel = 'partial',
}: { ok: boolean; partial?: boolean; yes?: string; no?: string; partialLabel?: string }) {
  if (partial) {
    return (
      <span className="inline-flex size-5 items-center justify-center rounded-full bg-amber-500/15 text-[10px] font-bold text-amber-300 ring-1 ring-inset ring-amber-500/40" title={partialLabel}>
        {'▲'}<span className="sr-only">{partialLabel}</span>
      </span>
    );
  }
  return ok ? (
    <span className="inline-flex size-5 items-center justify-center rounded-full bg-emerald-500/15 text-[11px] font-bold text-emerald-300 ring-1 ring-inset ring-emerald-500/40" title={yes}>
      {'✓'}<span className="sr-only">{yes}</span>
    </span>
  ) : (
    <span className="inline-flex size-5 items-center justify-center rounded-full bg-rose-500/15 text-[11px] font-bold text-rose-300 ring-1 ring-inset ring-rose-500/40" title={no}>
      {'✕'}<span className="sr-only">{no}</span>
    </span>
  );
}

/** Row of n pips, `filled` of them lit: a compact "3 of 4" that reads without digits. */
export function Pips({ filled, total, label }: { filled: number; total: number; label: string }) {
  const tone = filled === total ? 'bg-emerald-400' : filled >= total - 1 ? 'bg-amber-400' : 'bg-rose-400';
  return (
    <span className="inline-flex items-center gap-1" role="img" aria-label={`${label}: ${filled} of ${total}`}>
      {Array.from({ length: total }, (_, i) => (
        <span key={i} className={`h-1.5 w-3.5 rounded-sm ${i < filled ? tone : filled === 0 ? 'bg-rose-500/25' : 'bg-slate-700'}`} />
      ))}
    </span>
  );
}

/** The empty state every platform view uses for a fact the build does not carry. */
export function NotPresent({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-center gap-2 rounded-md border border-dashed border-slate-700 px-3 py-2.5 text-sm text-slate-400">
      <span aria-hidden className="text-slate-500">{'–'}</span>
      {children}
    </p>
  );
}

/** Sub-panel used inside a Panel: hairline card with an eyebrow title. */
export function Well({
  title, aside, children, className = '',
}: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-slate-800 bg-slate-900/40 ${className}`}>
      {(title || aside) && (
        <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 px-3.5 py-2">
          {title && <h3 className="eyebrow">{title}</h3>}
          {aside}
        </div>
      )}
      <div className="p-3.5">{children}</div>
    </div>
  );
}

/** A key/value pair for the identity and signing grids. */
export function Kv({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-0.5 break-words text-sm text-slate-100 ${mono ? 'font-mono text-[13px]' : 'font-medium'}`}>
        {children}
      </dd>
    </div>
  );
}

/** A filter toggle chip, `aria-pressed` so the state is announced. */
export function FilterChip({
  active, onClick, children, title,
}: { active: boolean; onClick: () => void; children: ReactNode; title?: string }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      title={title}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
        active
          ? 'border-sky-400/70 bg-sky-500/15 text-sky-100'
          : 'border-slate-700 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-slate-200'
      }`}
    >
      {children}
    </button>
  );
}

/** Scrolls a section into view and moves focus to it, for keyboard users. */
export function jumpTo(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  el.focus({ preventScroll: true });
}

/**
 * A tile on the attack-surface index: a label, one big number and a line saying
 * whether that number is a concern. With `onClick` it jumps to the list below;
 * without, it is a plain box, because a button that does nothing is a lie.
 */
export function SurfaceTile({
  label, value, tone, summary, onClick,
}: { label: string; value: ReactNode; tone: Tone; summary: string; onClick?: () => void }) {
  const t = TONE[tone];
  const empty = value === 0 || value === 'No' || value === 'None' || value === '—';
  const body = (
    <>
      <span className="eyebrow">{label}</span>
      <span className={`mt-1 text-3xl font-bold leading-none tabular-nums ${empty ? 'text-slate-500' : t.text}`}>{value}</span>
      <span className={`mt-2.5 flex items-start gap-1.5 text-xs leading-snug ${t.text}`}>
        <span aria-hidden className="mt-px text-[0.65rem]">{t.glyph}</span>
        <span className="text-slate-400">{summary}</span>
      </span>
    </>
  );
  const base = 'flex flex-col rounded-lg border border-slate-800 bg-slate-900/40 px-3.5 py-3 text-left';
  return onClick ? (
    <button
      type="button"
      onClick={onClick}
      className={`${base} transition duration-150 hover:-translate-y-0.5 hover:border-slate-600 hover:bg-slate-900/70 motion-reduce:hover:translate-y-0`}
    >
      {body}
    </button>
  ) : (
    <div className={base}>{body}</div>
  );
}

/** A titled anchor target: focusable so a tile's jump moves the keyboard too. */
export function AnchorSection({ id, title, subtitle, actions, children }: {
  id: string; title: string; subtitle: ReactNode; actions?: ReactNode; children: ReactNode;
}) {
  return (
    <div id={id} tabIndex={-1} className="scroll-mt-4 outline-none">
      <Panel title={title} subtitle={subtitle} actions={actions}>{children}</Panel>
    </div>
  );
}

/** One protection across all binaries, as a thin coverage bar. */
export function CoverageBar({ label, hint, have, total }: { label: string; hint: string; have: number; total: number }) {
  const pct = total ? Math.round((have / total) * 100) : 0;
  const tone = have === total ? 'bg-emerald-400' : pct >= 60 ? 'bg-amber-400' : 'bg-rose-400';
  return (
    <div title={hint}>
      <div className="flex items-baseline justify-between text-xs">
        <span className="font-medium text-slate-200">{label}</span>
        <span className="tabular-nums text-slate-400">
          <span className="font-semibold text-slate-100">{have}</span>/{total}
          {have === total && <span className="ml-1 text-emerald-300">{'✓'}</span>}
        </span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${tone}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
