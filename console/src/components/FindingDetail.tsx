/**
 * The expanded body of a finding: what it is, the risk, how it gets exploited,
 * and exactly where.
 *
 * Extracted from the scan screen so the comparison renders findings the same
 * way. Two components drifting apart is how a diff ends up showing less than
 * the report it is diffing — which is the wrong way round, since a reviewer
 * reaches for the comparison precisely when something has just changed.
 */
import { createContext, useContext, useState } from 'react';

/**
 * How a location opens itself in the code explorer.
 *
 * Passed by context rather than threaded through four levels of props: the
 * snippet components are nested inside `FindingBody`, which is rendered by two
 * different screens, and only one of them can navigate.
 */
export type ExplorerLink = {
  open: (path: string, line?: number) => void;
  /**
   * Whether this path is one the explorer actually holds.
   *
   * Most iOS findings point at the Mach-O binary, which is not retained as
   * readable text — there is nothing to show. Offering a button that lands on
   * an empty viewer is worse than offering no button.
   */
  canOpen: (path: string) => boolean;
};

export const OpenInExplorer = createContext<ExplorerLink | null>(null);

/** Which findings sit on which line of which file, so a code window can say a line is flagged by another finding too. */
type LineFlag = { ruleId: string; title: string };
export const LineFlags = createContext<Map<string, LineFlag[]> | null>(null);

export function lineFlagIndex(findings: Pick<SastFinding, 'ruleId' | 'title' | 'locations'>[]): Map<string, LineFlag[]> {
  const index = new Map<string, LineFlag[]>();
  for (const f of findings) {
    for (const l of f.locations) {
      if (!l.line) continue;
      const key = `${l.file}:${l.line}`;
      const list = index.get(key) ?? [];
      if (!list.some((x) => x.ruleId === f.ruleId)) list.push({ ruleId: f.ruleId, title: f.title });
      index.set(key, list);
    }
  }
  return index;
}

/** The button a location shows when the explorer can open it. */
export function ViewFileButton({ path, line }: { path: string; line?: number }) {
  const link = useContext(OpenInExplorer);
  if (!link || !link.canOpen(path)) return null;
  const open = link.open;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        open(path, line);
      }}
      title={`Open ${path}${line ? ` at line ${line}` : ''} in the code explorer`}
      className="group/view flex shrink-0 items-center gap-1.5 rounded-full border border-ember-500/40 bg-ember-500/10 py-0.5 pl-1.5 pr-2.5 text-[11px] font-medium text-ember-200 transition-all hover:border-ember-400 hover:bg-ember-500/25 hover:text-ember-100 hover:shadow-[0_0_0_3px_rgba(56,189,248,0.12)]"
    >
      {/* The lens tilts and the handle lengthens on hover — a small nudge that
          the button inspects something rather than navigating away. */}
      <svg
        viewBox="0 0 16 16"
        aria-hidden
        className="size-3.5 shrink-0 transition-transform duration-200 group-hover/view:-rotate-12 group-hover/view:scale-110"
      >
        <circle
          cx="6.8"
          cy="6.8"
          r="4.3"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
        />
        <line
          x1="10.1"
          y1="10.1"
          x2="14"
          y2="14"
          stroke="currentColor"
          strokeWidth="1.9"
          strokeLinecap="round"
        />
        {/* A glint on the lens, so it reads as glass rather than a circle. */}
        <path
          d="M4.6 5.4a2.6 2.6 0 0 1 2-1.7"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.1"
          strokeLinecap="round"
          opacity="0.55"
        />
      </svg>
      View file
      {line ? <span className="tabular-nums opacity-60">:{line}</span> : null}
    </button>
  );
}
import { ORIGIN_LABEL, ORIGIN_MEANING, describeDexContext } from '../sastTypes';
import { highlight } from './highlight';
import { RichText } from './RichText';
import type { FindingOrigin, SastFinding, SastLocation } from '../sastTypes';

/**
 * Whose code this is.
 *
 * Deliberately not styled like the severity badge. Severity already owns the
 * warm end of the palette (rose through amber), and a second filled chip in the
 * same family would read as a second severity. This one is an outline in violet
 * — a different visual language for a different axis, so the eye can tell at a
 * glance that it is answering a different question.
 */
export function OriginTag({
  origin,
  libraries,
}: {
  origin?: FindingOrigin;
  libraries?: string[];
}) {
  if (!origin || origin === 'unknown') return null;

  const style =
    origin === 'first-party'
      ? 'border-violet-500/50 bg-violet-500/10 text-violet-200 hover:bg-violet-500/20'
      : origin === 'mixed'
        ? 'border-violet-500/30 bg-slate-800/60 text-slate-300 hover:border-violet-500/50 hover:text-violet-200'
        : 'border-slate-700 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-slate-200';

  // Naming the library is the actionable part: "Library" tells you not to look
  // in your source, "OkHttp" tells you what to upgrade.
  const named = origin !== 'first-party' && libraries && libraries.length > 0;
  const label = named
    ? libraries.length === 1
      ? libraries[0]
      : `${libraries[0]} +${libraries.length - 1}`
    : ORIGIN_LABEL[origin];

  return (
    <span
      title={`${ORIGIN_MEANING[origin]}${named ? `\n\nIn: ${libraries!.join(', ')}` : ''}`}
      className={`inline-flex shrink-0 cursor-help items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium transition-colors ${style}`}
    >
      <span aria-hidden className="text-[9px]">{origin === 'first-party' ? '\u25c6' : '\u25c7'}</span>
      {label}
    </span>
  );
}

/** The per-location version: quieter, since the finding already carries a tag. */
function LocationOrigin({ location }: { location: SastLocation }) {
  const p = location.provenance;
  if (!p || p.origin === 'unknown') return null;
  return (
    <span
      title={p.because}
      className={`shrink-0 cursor-help text-[10px] ${
        p.origin === 'first-party' ? 'text-violet-300/80' : 'text-slate-500'
      }`}
    >
      {p.origin === 'first-party' ? 'your code' : (p.library ?? 'library')}
    </span>
  );
}

export function Detail({ label, text, tone }: { label: string; text: string; tone?: 'risk' }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      <p
        className={`mt-1 max-w-[80ch] leading-relaxed text-slate-300 ${
          tone === 'risk' ? 'rounded-r-md border-l-2 border-orange-500/60 bg-orange-500/5 px-3 py-1.5' : ''
        }`}
      >
        <RichText text={text} />
      </p>
    </div>
  );
}

/**
 * A code window with the offending line marked.
 *
 * The vulnerable line is called out three ways at once — a left rail, a tinted
 * background and a caret in the gutter — because colour alone fails for a
 * colour-blind reader and a tint alone disappears in a screenshot pasted into
 * a ticket.
 *
 * `tone` lets the comparison tint the frame: a location that is new in this
 * release reads differently from one that has been there all along.
 */
export function CodeSnippet({
  location,
  tone = 'neutral',
  ruleId,
}: {
  location: SastLocation;
  tone?: 'neutral' | 'added' | 'removed';
  /** The finding this window belongs to, so it is not listed as "also flagged" on its own lines. */
  ruleId?: string;
}) {
  const flags = useContext(LineFlags);
  if (!location.snippet?.length) return null;
  const alsoFlagged = (line: number) => flags?.get(`${location.file}:${line}`)?.filter((f) => f.ruleId !== ruleId) ?? [];

  const frame =
    tone === 'added' ? 'border-rose-500/40'
    : tone === 'removed' ? 'border-emerald-500/40'
    : 'border-slate-800';

  return (
    <div className={`group/snip overflow-hidden rounded-md border bg-slate-950/80 ${frame}`}>
      <div className="flex items-start justify-between gap-3 border-b border-slate-800 bg-slate-900/60 px-3 py-1.5">
        <span className="min-w-0">
          {describeDexContext(location) && (
            <span className="block truncate font-mono text-xs text-amber-200/90">
              {describeDexContext(location)}
            </span>
          )}
          <span className="block truncate font-mono text-[11px] text-slate-500">
            decompiled to {location.file}
            {location.line ? `:${location.line}` : ''}
          </span>
        </span>
        <div className="flex shrink-0 items-center gap-2">
          <ViewFileButton path={location.file} line={location.line} />
          <LocationOrigin location={location} />
          {tone !== 'neutral' && (
            <span
              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                tone === 'added'
                  ? 'bg-rose-500/15 text-rose-200 ring-1 ring-inset ring-rose-500/40'
                  : 'bg-emerald-500/15 text-emerald-200 ring-1 ring-inset ring-emerald-500/40'
              }`}
            >
              {tone === 'added' ? 'new here' : 'gone'}
            </span>
          )}
          <button
            type="button"
            onClick={() =>
              navigator.clipboard
                ?.writeText(location.snippet!.map((l) => `${l.line}\t${l.text}`).join('\n'))
                .catch(() => undefined)
            }
            className="rounded border border-slate-700 px-1.5 py-0.5 text-[11px] text-slate-400 opacity-0 transition hover:bg-slate-800 hover:text-slate-200 focus:opacity-100 group-hover/snip:opacity-100"
          >
            Copy
          </button>
        </div>
      </div>
      <pre className="overflow-x-auto py-1 text-[11.5px] leading-[1.6]">
        {location.snippet.map((l) => {
          const others = alsoFlagged(l.line);
          return (
          <div
            key={l.line}
            className={`flex ${
              l.vulnerable
                ? 'border-l-2 border-rose-500 bg-rose-500/10'
                : others.length
                  ? 'border-l-2 border-amber-400/70 bg-amber-400/[0.06]'
                  : 'border-l-2 border-transparent hover:bg-slate-800/40'
            }`}
          >
            <span
              className={`w-12 shrink-0 select-none pr-2 text-right font-mono tabular-nums ${
                l.vulnerable ? 'font-bold text-rose-300' : 'text-slate-600'
              }`}
            >
              {l.line}
            </span>
            <span className={`w-3 shrink-0 select-none ${l.vulnerable ? 'text-rose-400' : 'text-transparent'}`}>
              ›
            </span>
            {/* Same colouring as the explorer, so a value that is the finding
                — a key, a token — is marked here too rather than only there. */}
            <code className={`whitespace-pre pr-4 font-mono ${l.vulnerable ? 'text-rose-50' : 'text-slate-300'}`}>
              {highlight(l.text, location.file)}
            </code>
            {others.length > 0 && (
              <span
                className="ml-auto mr-2 max-w-[20rem] shrink-0 self-center truncate rounded bg-amber-400/15 px-1.5 py-px font-sans text-[10px] font-semibold text-amber-200 ring-1 ring-inset ring-amber-400/40"
                title={others.map((o) => o.title).join('\n')}
              >
                also flagged: {others[0].title}{others.length > 1 ? ` +${others.length - 1}` : ''}
              </span>
            )}
          </div>
          );
        })}
      </pre>
    </div>
  );
}

/** A location with no captured source: a manifest attribute, or an artifact fact. */
export function CompactLocation({
  location,
  tone = 'neutral',
}: {
  location: SastLocation;
  tone?: 'neutral' | 'added' | 'removed';
}) {
  const frame =
    tone === 'added' ? 'border-rose-500/40 bg-rose-500/5'
    : tone === 'removed' ? 'border-emerald-500/40 bg-emerald-500/5'
    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 hover:bg-slate-900/60';

  return (
    <div className={`flex flex-wrap items-baseline gap-x-3 rounded-md border px-2.5 py-1.5 transition ${frame}`}>
      <span className="font-mono text-xs text-ember-300/90">
        {location.file}
        {location.line ? `:${location.line}` : ''}
      </span>
      {describeDexContext(location) && (
        <span className="font-mono text-[11px] text-amber-200/80">{describeDexContext(location)}</span>
      )}
      {location.excerpt && (
        <span className="min-w-0 flex-1 break-all font-mono text-[11px] text-slate-400">
          {location.excerpt}
        </span>
      )}
      <LocationOrigin location={location} />
      <ViewFileButton path={location.file} line={location.line} />
    </div>
  );
}

export function LocationList({
  locations,
  tone = 'neutral',
  ruleId,
}: {
  locations: SastLocation[];
  tone?: 'neutral' | 'added' | 'removed';
  ruleId?: string;
}) {
  return (
    <div className="mt-1.5 space-y-2">
      {locations.map((l, i) =>
        l.snippet?.length ? (
          <CodeSnippet key={i} location={l} tone={tone} ruleId={ruleId} />
        ) : (
          <CompactLocation key={i} location={l} tone={tone} />
        ),
      )}
    </div>
  );
}

/**
 * The full body of a finding.
 *
 * `added`/`removed` are supplied by the comparison. When they are, the changed
 * locations are shown first and labelled, and the unchanged remainder is
 * collapsed — on a rule with 731 occurrences the three that are new are the
 * only ones worth reading.
 */
export function FindingBody({
  finding,
  tone = 'defect',
  added,
  removed,
}: {
  finding: SastFinding;
  tone?: 'defect' | 'hotspot';
  added?: SastLocation[];
  removed?: SastLocation[];
}) {
  const [showAll, setShowAll] = useState(false);
  const hasDiff = (added?.length ?? 0) > 0 || (removed?.length ?? 0) > 0;

  const changedKeys = new Set(
    [...(added ?? []), ...(removed ?? [])].map((l) => `${l.file}:${l.line ?? ''}`),
  );
  const unchanged = hasDiff
    ? finding.locations.filter((l) => !changedKeys.has(`${l.file}:${l.line ?? ''}`))
    : finding.locations;

  return (
    <div className="space-y-3 text-sm">
      <Detail label="What this means" text={finding.description} />

      {/* Said once, prominently, because it changes what the reader does next:
          there is no point reading the remediation as source advice when the
          code belongs to a dependency. */}
      {(finding.origin === 'third-party' || finding.origin === 'mixed') && (
        <p className="rounded-md border border-slate-700/70 bg-slate-800/40 px-3 py-2 text-xs leading-relaxed text-slate-300">
          {finding.origin === 'third-party'
            ? 'This sits entirely in bundled library code'
            : 'This appears both in your own packages and in bundled library code'}
          {finding.libraries && finding.libraries.length > 0
            ? ` (${finding.libraries.join(', ')})`
            : ''}
          .{' '}
          {finding.origin === 'third-party'
            ? 'You cannot fix it by editing your source — upgrade or replace the dependency, or accept it if the code path is unreachable.'
            : 'The matches in your own packages are the ones to act on first.'}
        </p>
      )}

      {finding.impact && <Detail label="Risk if left" text={finding.impact} tone="risk" />}

      {finding.exploitation && finding.exploitation.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-rose-300">
            How this gets exploited
          </p>
          <ol className="mt-1.5 space-y-1.5">
            {finding.exploitation.map((step, i) => (
              <li key={i} className="flex gap-2.5 text-sm leading-relaxed text-slate-300">
                <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full bg-rose-500/20 text-[10px] font-bold text-rose-300">
                  {i + 1}
                </span>
                <span className="max-w-[78ch]"><RichText text={step} /></span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {finding.remediation && (
        <Detail label={tone === 'hotspot' ? 'What to confirm' : 'How to fix it'} text={finding.remediation} />
      )}

      {added && added.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-rose-300">
            New in this release ({added.length})
          </p>
          <LocationList locations={added} tone="added" ruleId={finding.ruleId} />
        </div>
      )}

      {removed && removed.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-emerald-300">
            No longer present ({removed.length})
          </p>
          <LocationList locations={removed} tone="removed" ruleId={finding.ruleId} />
        </div>
      )}

      {unchanged.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            {hasDiff ? `Unchanged locations (${unchanged.length})` : 'Where exactly'}
            {!hasDiff && finding.occurrences > finding.locations.length &&
              ` (${finding.locations.length} of ${finding.occurrences})`}
          </p>
          {hasDiff && !showAll ? (
            <button
              type="button"
              onClick={() => setShowAll(true)}
              className="mt-1 rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 transition hover:bg-slate-800 hover:text-slate-200"
            >
              Show {unchanged.length} unchanged location{unchanged.length === 1 ? '' : 's'}
            </button>
          ) : (
            <LocationList locations={unchanged} ruleId={finding.ruleId} />
          )}
        </div>
      )}
    </div>
  );
}
