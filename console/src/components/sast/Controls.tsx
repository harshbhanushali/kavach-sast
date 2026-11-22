/**
 * Security controls: the protections the app implements (or conspicuously does
 * not), and how each is typically defeated.
 *
 * The other tabs say what is wrong. This one answers a different question: of
 * the checks the app does ship, which buy real time against an attacker who owns
 * the device, and which only look like they do. Every client-side control has a
 * known bypass, so the point of listing it is to show where the bar is low and
 * what would raise it, not to score the app.
 *
 * Shared by both platforms: the backend decides what to look for, this renders
 * whatever it found.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { ControlGroup, SastScan, SecurityControl } from '../../sastTypes';
import { Empty, Panel } from '../ui';
import { ViewFileButton } from '../FindingDetail';
import {
  BYPASS_EFFORT, CONTROL_GROUPS, CONTROL_GROUP_LABEL, controlsOf, summariseControls,
} from './model';
import type { ControlsSummary, Tone } from './model';
import { Lens } from './OverviewParts';
import { FilterChip, SurfaceTile, Tag, ToneChip } from './ui';

type StatusFilter = 'all' | 'detected' | 'not-detected';

const STATUS: Record<SecurityControl['status'], { label: string; tone: Tone; stripe: string }> = {
  detected: { label: 'Detected', tone: 'good', stripe: 'border-l-emerald-500/70' },
  'not-detected': { label: 'Not detected', tone: 'warn', stripe: 'border-l-amber-400/80' },
  'not-assessed': { label: 'Not assessed', tone: 'muted', stripe: 'border-l-slate-600' },
};

/** How many evidence locations a card lists; the backend caps them too. */
const EVIDENCE_SHOWN = 6;

/** A note that says the control is cancelled out elsewhere in the scan reads as a warning, not a footnote. */
const undermined = (note: string) => /weakens or cancels|undermin/i.test(note);

/* ------------------------------------------------------------------- pieces */

/** Four segments, `steps` lit. The word beside it carries the meaning; the meter is the quick read. */
function EffortMeter({ effort }: { effort: SecurityControl['bypassEffort'] }) {
  const e = BYPASS_EFFORT[effort];
  return (
    <span aria-hidden className="inline-flex items-center gap-0.5">
      {[1, 2, 3, 4].map((i) => (
        <span key={i} className={`h-2.5 w-1.5 rounded-sm ${i <= e.steps ? e.solid : 'bg-slate-700'}`} />
      ))}
    </span>
  );
}

function EffortChip({ control }: { control: SecurityControl }) {
  const e = BYPASS_EFFORT[control.bypassEffort];
  const added = control.status === 'not-detected' ? ' once it is added' : '';
  return (
    <span
      className={`pill ${e.chip}`}
      title={`Typical bypass effort${added}: ${e.label.toLowerCase()} (${e.steps} of 4). How hard this is to defeat for someone who controls the device.`}
    >
      <EffortMeter effort={control.bypassEffort} />
      <span className="font-medium opacity-80">Bypass</span>
      {e.label}
    </span>
  );
}

/**
 * Whose code the reference sits in. Same violet outline as the findings' origin
 * tag, and the same rule: nothing is shown when the origin is unknown, since
 * "unattributed" tells a reader nothing they can act on.
 */
function ControlOrigin({ control }: { control: SecurityControl }) {
  const { origin, libraries } = control;
  if (control.status !== 'detected' || !origin || origin === 'unknown') return null;
  const libs = libraries ?? [];
  const lib = libs.length === 0 ? 'bundled library' : libs.length === 1 ? libs[0] : `${libs[0]} +${libs.length - 1}`;
  const label = origin === 'first-party' ? 'Your code' : origin === 'third-party' ? `Bundled library: ${lib}` : `Your code + ${lib}`;
  const style = origin === 'third-party'
    ? 'border-slate-700 bg-slate-900/60 text-slate-400'
    : 'border-violet-500/50 bg-violet-500/10 text-violet-200';
  return (
    <span
      title={`${label}${libs.length ? `\n\nLibraries: ${libs.join(', ')}` : ''}`}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${style}`}
    >
      <span aria-hidden className="text-[9px]">{origin === 'third-party' ? '◇' : '◆'}</span>
      {label}
    </span>
  );
}

function BulletList({ items }: { items: string[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((t, i) => (
        <li key={i} className="flex gap-2 text-sm leading-relaxed text-slate-300">
          <span aria-hidden className="mt-2 h-1 w-1 shrink-0 rounded-full bg-slate-500" />
          <span className="max-w-[80ch]">{t}</span>
        </li>
      ))}
    </ul>
  );
}

function Block({ title, tone, children }: { title: string; tone?: 'risk' | 'good'; children: ReactNode }) {
  return (
    <div>
      <h4 className={`eyebrow ${tone === 'risk' ? '!text-orange-300' : tone === 'good' ? '!text-emerald-300' : ''}`}>{title}</h4>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

/** Where the scanner found it. A path the explorer holds gets the usual "View file" button. */
function Evidence({ control }: { control: SecurityControl }) {
  const shown = control.evidence.slice(0, EVIDENCE_SHOWN);
  const more = control.occurrences - shown.length;
  return (
    <Block title={`Evidence · ${control.occurrences} reference${control.occurrences === 1 ? '' : 's'}`}>
      {shown.length === 0 ? (
        <p className="text-sm text-slate-400">
          No code location to show: this was read from the build’s configuration rather than from code.
        </p>
      ) : (
        <>
          <ul className="space-y-1.5">
            {shown.map((ev, i) => (
              <li key={i} className="rounded-md border border-slate-800 bg-slate-950/60 px-2.5 py-1.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="min-w-0 flex-1 basis-56 break-all font-mono text-xs text-ember-300/90">
                    {ev.file}{ev.line ? `:${ev.line}` : ''}
                  </span>
                  <ViewFileButton path={ev.file} line={ev.line} />
                </div>
                {ev.excerpt && (
                  <code className="mt-1 line-clamp-2 block font-mono text-[11px] leading-relaxed text-slate-400 [overflow-wrap:anywhere]" title={ev.excerpt}>
                    {ev.excerpt}
                  </code>
                )}
              </li>
            ))}
          </ul>
          {more > 0 && (
            <p className="mt-1.5 text-xs text-slate-500">
              Showing {shown.length} of {control.occurrences} references.
            </p>
          )}
        </>
      )}
    </Block>
  );
}

/* --------------------------------------------------------------------- card */

function ControlCard({
  control, open, onToggle,
}: { control: SecurityControl; open: boolean; onToggle: () => void }) {
  const st = STATUS[control.status];
  const bodyId = `control-body-${control.id}`;
  const note = control.note;
  // The backend says whether the note is a warning; the text match only covers scans stored before it did.
  const bad = !!note && (control.noteTone ? control.noteTone === 'warning' : undermined(note));

  // What the two lists mean depends on whether the control exists: against a
  // present one they are "how it falls" and "how to make it hold"; against a
  // missing one they are "what to add" and "what you will be up against".
  const missing = control.status === 'not-detected';

  return (
    <li
      id={`control-${control.id}`}
      tabIndex={-1}
      className={`scroll-mt-4 rounded-lg border border-l-[3px] border-slate-800 bg-slate-900/30 outline-none transition-colors hover:bg-slate-900/60 focus-visible:ring-2 focus-visible:ring-ember-400/60 ${st.stripe}`}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={bodyId}
        className="flex w-full flex-wrap items-start gap-x-3 gap-y-2 px-3.5 py-3 text-left"
      >
        <span className="min-w-0 flex-1 basis-72">
          <span className="block text-sm font-medium leading-snug text-slate-100">{control.title}</span>
          {!open && <span className="mt-1 line-clamp-2 block text-xs leading-relaxed text-slate-400">{control.what}</span>}
        </span>
        <span className="ml-auto flex shrink-0 flex-wrap items-center justify-end gap-1.5">
          <ControlOrigin control={control} />
          <ToneChip tone={st.tone}>{st.label}</ToneChip>
          <EffortChip control={control} />
          <span aria-hidden className={`w-3 text-center text-slate-500 transition-transform ${open ? 'rotate-90' : ''}`}>{'›'}</span>
        </span>
      </button>

      {open && (
        <div id={bodyId} className="space-y-4 border-t border-slate-800/80 px-4 pb-4 pt-3.5">
          <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
            <Block title="What it protects">
              <p className="max-w-[80ch] text-sm leading-relaxed text-slate-300">{control.what}</p>
            </Block>
            {control.masvs && <Tag title="OWASP MASVS control">{control.masvs}</Tag>}
          </div>

          {note && (
            <div
              role="note"
              className={`flex gap-2.5 rounded-lg border-l-[3px] px-3.5 py-2.5 ${
                bad ? 'border-rose-500/70 bg-rose-500/[0.08]' : 'border-ember-400/60 bg-ember-500/[0.06]'
              }`}
            >
              <span aria-hidden className={`mt-0.5 text-xs ${bad ? 'text-rose-300' : 'text-ember-300'}`}>{bad ? '✕' : '●'}</span>
              <div>
                <p className={`eyebrow ${bad ? '!text-rose-300' : '!text-ember-300'}`}>{bad ? 'Undermined in this app' : 'Specific to this app'}</p>
                <p className="mt-1 max-w-[80ch] text-sm leading-relaxed text-slate-200">{note}</p>
              </div>
            </div>
          )}

          {control.status === 'not-assessed' && (
            <p className="flex items-center gap-2 rounded-md border border-dashed border-slate-700 px-3 py-2.5 text-sm text-slate-400">
              <span aria-hidden className="text-slate-500">{'–'}</span>
              The scanner cannot tell either way for this artifact yet. That is not a gap in the app, only a limit of the scan.
            </p>
          )}

          <div className="grid gap-5 @3xl:grid-cols-2">
            {missing ? (
              <>
                <Block title="Recommended" tone="good"><BulletList items={control.harden} /></Block>
                <Block title="What an attacker would do once it is added" tone="risk"><BulletList items={control.bypass} /></Block>
              </>
            ) : (
              <>
                <Block title="How it is typically bypassed" tone="risk"><BulletList items={control.bypass} /></Block>
                <Block title="How to harden it" tone="good"><BulletList items={control.harden} /></Block>
              </>
            )}
          </div>

          {control.status === 'detected' && <Evidence control={control} />}
        </div>
      )}
    </li>
  );
}

/* --------------------------------------------------------------------- view */

export function SastControls({ scan }: { scan: SastScan }) {
  const controls = controlsOf(scan);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState<StatusFilter>('all');
  const [group, setGroup] = useState<ControlGroup | 'all'>('all');
  const [query, setQuery] = useState('');
  // A weakest-link button asks for a card to be opened and scrolled to once the
  // filters have been cleared and the list has re-rendered with it in place.
  const pending = useRef<string | null>(null);

  useEffect(() => {
    const id = pending.current;
    if (!id) return;
    pending.current = null;
    const el = document.getElementById(`control-${id}`);
    el?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    el?.focus({ preventScroll: true });
  });

  const summary = useMemo(() => (controls ? summariseControls(controls) : undefined), [controls]);

  if (!controls || !summary) {
    return (
      <Panel title="Security controls">
        <Empty>This scan was taken before security controls were recorded. Rescan the artifact to see them.</Empty>
      </Panel>
    );
  }

  const q = query.trim().toLowerCase();
  const visible = controls.filter((c) => {
    if (status !== 'all' && c.status !== status) return false;
    if (group !== 'all' && c.group !== group) return false;
    if (!q) return true;
    return [c.title, c.what, c.masvs, CONTROL_GROUP_LABEL(c.group), ...(c.libraries ?? []), ...c.evidence.map((e) => e.file)]
      .some((s) => s?.toLowerCase().includes(q));
  });
  const filtering = status !== 'all' || group !== 'all' || q !== '';
  const groups = CONTROL_GROUPS.filter((g) => controls.some((c) => c.group === g.key));

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const clear = () => { setStatus('all'); setGroup('all'); setQuery(''); };
  const reveal = (id: string) => {
    clear();
    setOpen((prev) => new Set(prev).add(id));
    pending.current = id;
  };
  const allOpen = visible.length > 0 && visible.every((c) => open.has(c.id));
  const setAll = (on: boolean) =>
    setOpen((prev) => {
      const next = new Set(prev);
      for (const c of visible) {
        if (on) next.add(c.id);
        else next.delete(c.id);
      }
      return next;
    });

  const statusCount = (s: StatusFilter) => (s === 'all' ? controls.length : controls.filter((c) => c.status === s).length);

  return (
    <div className="@container space-y-5">
      {/* framing: what this tab does and does not prove */}
      <div className="flex gap-3 rounded-lg border border-ember-500/25 bg-ember-500/[0.05] px-4 py-3">
        <span aria-hidden className="mt-0.5 text-sm text-ember-300">{'●'}</span>
        <div className="text-sm leading-relaxed text-slate-300">
          <p className="max-w-[90ch]">
            <span className="font-medium text-slate-100">Read this as a map of friction, not a score.</span>{' '}
            A control is detected by a reference in the binary or code. That proves the check exists, not that it is
            reachable or that anything acts on its result. Every client-side check runs on a device the attacker
            controls, so each has a known bypass. This tab shows how, so you can see which controls buy real time and
            raise the bar on the ones that do not.
          </p>
        </div>
      </div>

      {/* summary */}
      <div className="space-y-3">
        <div className="grid gap-3 @xl:grid-cols-3">
          <SurfaceTile label="Detected" value={summary.detected} tone="good" summary="A reference was found in the build" />
          <SurfaceTile label="Not detected" value={summary.notDetected} tone="warn" summary="Looked for, and none was found" />
          <SurfaceTile label="Not assessed" value={summary.notAssessed} tone="muted" summary="The scanner cannot tell either way" />
        </div>
        <WeakestLinks summary={summary} onPick={reveal} />
      </div>

      {/* filters */}
      <div className="panel space-y-3 px-4 py-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative min-w-[14rem] flex-1">
            <span className="sr-only">Search controls</span>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search control, library, MASVS or file"
              className="w-full !rounded-lg !py-1.5 !pl-8"
            />
            <span aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">{'⌕'}</span>
          </label>
          <label className="flex items-center gap-2">
            <span className="eyebrow">Group</span>
            <select
              value={group}
              onChange={(e) => setGroup(e.target.value as ControlGroup | 'all')}
              className="!rounded-lg !py-1.5"
            >
              <option value="all">All groups</option>
              {groups.map((g) => (
                <option key={g.key} value={g.key}>{g.label}</option>
              ))}
            </select>
          </label>
          {filtering && (
            <button
              type="button"
              onClick={clear}
              className="rounded-md px-2.5 py-1.5 text-xs font-medium text-ember-300 hover:bg-slate-800"
            >
              Clear filters
            </button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by status">
          <span className="eyebrow mr-1">Status</span>
          {([['all', 'All'], ['detected', 'Detected'], ['not-detected', 'Not detected']] as const).map(([key, label]) => (
            <FilterChip key={key} active={status === key} onClick={() => setStatus(key)}>
              {label}
              <span className="tabular-nums text-slate-500">{statusCount(key)}</span>
            </FilterChip>
          ))}
        </div>
      </div>

      {/* the controls, one heading per group */}
      <Panel
        title={`Controls (${visible.length}${filtering ? ` of ${controls.length}` : ''})`}
        subtitle="Open a control to see what it protects, how it is typically bypassed and how to make it hold."
        actions={
          visible.length > 0 ? (
            <button
              type="button"
              onClick={() => setAll(!allOpen)}
              className="rounded-md border border-slate-700 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              {allOpen ? 'Collapse all' : 'Expand all'}
            </button>
          ) : undefined
        }
      >
        {visible.length === 0 ? (
          <Empty>Nothing matches these filters.</Empty>
        ) : (
          <div className="space-y-5">
            {groups.map((g) => {
              const rows = visible.filter((c) => c.group === g.key);
              if (rows.length === 0) return null;
              const have = rows.filter((c) => c.status === 'detected').length;
              return (
                <section key={g.key} aria-label={`${g.label} controls`}>
                  <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300">
                    {g.label}
                    <span className="rounded-full bg-slate-800 px-1.5 py-px text-[10px] tabular-nums text-slate-300">{rows.length}</span>
                    <span className="text-[10px] font-medium normal-case tracking-normal text-slate-500">{have} detected</span>
                    <span className="h-px flex-1 bg-slate-800" />
                  </h3>
                  <ul className="space-y-2">
                    {rows.map((c) => (
                      <ControlCard key={c.id} control={c} open={open.has(c.id)} onToggle={() => toggle(c.id)} />
                    ))}
                  </ul>
                </section>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}

/** Detected controls that are easy to defeat, easiest first. Each name opens its card. */
function WeakestLinks({ summary, onPick }: { summary: ControlsSummary; onPick: (id: string) => void }) {
  const { weak } = summary;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3.5 py-3">
      <h3 className="eyebrow">Weakest links{weak.length > 0 ? ` (${weak.length})` : ''}</h3>
      {weak.length === 0 ? (
        <p className="mt-1.5 text-sm text-slate-300">
          <span aria-hidden className="mr-1.5 text-[0.65rem] text-emerald-300">{'✓'}</span>
          No detected control is rated trivial or low effort to bypass.
        </p>
      ) : (
        <>
          <p className="mt-1.5 max-w-[90ch] text-sm leading-relaxed text-slate-400">
            Detected, but trivial or low effort to bypass. These mostly add friction rather than a boundary, so do not
            lean on them alone.
          </p>
          <ul className="mt-2.5 flex flex-wrap gap-1.5">
            {weak.map((c) => {
              const e = BYPASS_EFFORT[c.bypassEffort];
              return (
                <li key={c.id}>
                  <button
                    type="button"
                    onClick={() => onPick(c.id)}
                    title={`Show ${c.title}`}
                    className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/60 py-1 pl-2.5 pr-3 text-xs font-medium text-slate-200 transition-colors hover:border-slate-500 hover:bg-slate-800"
                  >
                    <EffortMeter effort={c.bypassEffort} />
                    {c.title}
                    <span className={`font-semibold ${e.text}`}>{e.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------- digest */

/**
 * The overview card for this tab. Renders nothing for a scan without controls,
 * so the overview grid simply has one fewer card rather than an empty one.
 */
export function ControlsLens({
  scan, onOpen,
}: { scan: SastScan; onOpen: () => void }) {
  const controls = controlsOf(scan);
  if (!controls) return null;
  const s = summariseControls(controls);
  return (
    <Lens title="Security controls" cta="Open controls" onClick={onOpen}>
      <p className="flex items-baseline gap-1.5 text-sm text-slate-300">
        <span className="text-3xl font-bold leading-none tabular-nums text-slate-50">{s.detected}</span>
        <span>of {s.assessed} detected</span>
      </p>
      <p className={`flex items-start gap-2 text-sm ${s.weak.length ? 'text-amber-300' : 'text-emerald-300'}`}>
        <span aria-hidden className="mt-0.5 text-[0.65rem]">{s.weak.length ? '▲' : '✓'}</span>
        <span className="text-slate-200">
          {s.weak.length
            ? `${s.weak.length} weakly protected (trivial or low bypass effort)`
            : 'None are trivial or low effort to bypass'}
        </span>
      </p>
      <p className="text-xs text-slate-500">
        {s.notDetected} not detected{s.notAssessed ? ` · ${s.notAssessed} not assessed` : ''}
      </p>
    </Lens>
  );
}
