/**
 * The first thing on a scan: how the build stands, in about two seconds.
 *
 * Left to right, top to bottom: which app this is (icon, name, id, a few facts),
 * its grade, one sentence of verdict, where the severity sits, what to do about
 * it, and a strip of the yes/no questions a reviewer asks first. The dial is
 * decoration for the grade; the verdict and the numbers carry the information.
 *
 * Platform-neutral: the iOS and Android overviews pass in what differs (the
 * fact chips, the signals and the verdict's build note).
 */
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import type { SastScan, SastSeverity } from '../../sastTypes';
import { AppIcon } from './AppIcon';
import { GRADE, SEVERITIES, effectiveOf, identityOf } from './model';
import type { Navigate, Signal, Verdict } from './model';
import { SEV, SevGlyph, TONE } from './ui';

/**
 * The grade dial: a 270 degree arc, tick marks where the grade bands change.
 *
 * Band ticks match `scoreOf`'s grade boundaries (40/60/75/90) so the arc and
 * the letter cannot disagree. The fill animates in once; under reduced motion
 * it simply renders at its final length. `note` extends the accessible name when
 * the score is the post-triage one.
 */
function GradeDial({ score, grade, note }: { score: number; grade: string; note?: string }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  const size = 168;
  const r = 66;
  const c = 2 * Math.PI * r;
  const sweep = c * 0.75;
  const pct = Math.min(100, Math.max(0, shown)) / 100;
  const cx = size / 2;
  const angle = (p: number) => ((135 + 270 * p) * Math.PI) / 180;

  return (
    <div className={`relative shrink-0 ${GRADE[grade]?.text ?? 'text-slate-300'}`}>
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="size-[176px]"
        role="img"
        aria-label={`Security grade ${grade}, score ${score} out of 100${note ? `, ${note}` : ''}`}
      >
        <g transform={`rotate(135 ${cx} ${cx})`} fill="none" strokeLinecap="round">
          <circle cx={cx} cy={cx} r={r} strokeWidth="10" className="stroke-slate-700/70" strokeDasharray={`${sweep} ${c}`} />
          <circle
            cx={cx} cy={cx} r={r} strokeWidth="10" stroke="currentColor"
            strokeDasharray={`${Math.max(0.01, sweep * pct)} ${c}`}
            className="transition-[stroke-dasharray] duration-[900ms] ease-out motion-reduce:transition-none"
          />
        </g>
        {[40, 60, 75, 90].map((t) => {
          const a = angle(t / 100);
          const x1 = cx + Math.cos(a) * (r - 11);
          const y1 = cx + Math.sin(a) * (r - 11);
          const x2 = cx + Math.cos(a) * (r + 7);
          const y2 = cx + Math.sin(a) * (r + 7);
          return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} className="stroke-slate-950" strokeWidth="2.5" />;
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[3.4rem] font-bold leading-none tracking-tight">{grade}</span>
        <span className="mt-1 text-sm font-medium tabular-nums text-slate-300">
          {score}<span className="text-slate-500"> / 100</span>
        </span>
      </div>
    </div>
  );
}

/**
 * Severity distribution as one stacked bar.
 *
 * Segments are separated by a 2px surface-coloured gap and have rounded ends.
 * The legend under it is the data table: label, glyph and count for every
 * severity, so hovering is never required to read a value.
 */
function SeveritySpread({ counts }: { counts: Record<SastSeverity, number> }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  const [hover, setHover] = useState<SastSeverity | null>(null);

  return (
    <div>
      <div
        className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full"
        role="img"
        aria-label={`${total} findings: ${SEVERITIES.map((s) => `${counts[s]} ${s}`).join(', ')}`}
      >
        {total === 0 ? (
          <div className="h-full w-full rounded-full bg-emerald-500/30 ring-1 ring-inset ring-emerald-500/50" />
        ) : (
          SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
            <div
              key={s}
              title={`${SEV[s].label}: ${counts[s]}`}
              onMouseEnter={() => setHover(s)}
              onMouseLeave={() => setHover(null)}
              className={`h-full rounded-sm transition-opacity first:rounded-l-full last:rounded-r-full ${SEV[s].solid} ${
                hover && hover !== s ? 'opacity-35' : ''
              }`}
              style={{ flexGrow: counts[s], flexBasis: 6 }}
            />
          ))
        )}
      </div>
      <ul className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
        {SEVERITIES.map((s) => (
          <li
            key={s}
            onMouseEnter={() => counts[s] && setHover(s)}
            onMouseLeave={() => setHover(null)}
            className={`flex items-center gap-1.5 text-xs ${counts[s] ? 'text-slate-300' : 'text-slate-600'}`}
          >
            <span className={counts[s] ? SEV[s].text : ''}><SevGlyph severity={s} /></span>
            <span>{SEV[s].label}</span>
            <span className={`font-semibold tabular-nums ${counts[s] ? 'text-slate-50' : ''}`}>{counts[s]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** One of the three triage tiles. A button: each one opens the findings tab. */
function TriageTile({
  n, label, hint, glyph, tone, onClick,
}: { n: number; label: string; hint: string; glyph: string; tone: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group rounded-lg border border-slate-800 bg-slate-950/40 px-3.5 py-3 text-left transition duration-150 hover:-translate-y-0.5 hover:border-slate-600 hover:bg-slate-900/70 motion-reduce:hover:translate-y-0"
    >
      <span className={`flex items-baseline gap-2 ${tone}`}>
        <span aria-hidden className="text-sm">{glyph}</span>
        <span className="text-3xl font-bold leading-none tabular-nums">{n}</span>
      </span>
      <span className="mt-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-300">{label}</span>
      <span className="mt-0.5 block text-xs text-slate-500">{hint}</span>
    </button>
  );
}

export function SastHero({
  scan, onNavigate, verdict, signals, chips,
}: {
  scan: SastScan;
  onNavigate: Navigate;
  verdict: Verdict;
  signals: Signal[];
  /** The fact chips under the app id: build kind, version, OS floor, signer... */
  chips: ReactNode;
}) {
  const { name, id } = identityOf(scan);
  // Everything below counts what is still active: decisions a reviewer has made
  // (see `triage.ts`) move the severity bar, the tiles and the dial.
  const eff = effectiveOf(scan);
  const grade = GRADE[eff.grade] ?? GRADE.C;
  const rescored = eff.score !== eff.scanned.score;
  const { summary } = eff;

  return (
    <section
      aria-label="Build summary"
      className="@container relative overflow-hidden rounded-2xl border border-slate-800"
      style={{
        background: [
          `radial-gradient(90% 120% at 100% 0%, ${grade.glow}, transparent 60%)`,
          'linear-gradient(rgb(148 163 184 / 0.035) 1px, transparent 1px) 0 0 / 100% 28px',
          'var(--color-surface)',
        ].join(', '),
      }}
    >
      <div className="grid gap-x-8 gap-y-6 p-5 @2xl:p-6">
        <div className="grid items-center gap-x-8 gap-y-6 @3xl:grid-cols-[minmax(0,1fr)_auto]">
          <div className="min-w-0 space-y-6">
            {/* identity */}
            <div className="flex min-w-0 items-start gap-4">
              <AppIcon src={scan.artifact.iconDataUrl} name={name} seed={id ?? name} size="lg" />
              <div className="min-w-0">
                <h2 className="truncate text-2xl font-semibold leading-tight tracking-tight text-slate-50">{name}</h2>
                <p className="mt-0.5 truncate font-mono text-[13px] text-slate-400">{id ?? 'unknown app id'}</p>
                <div className="mt-3 flex flex-wrap items-center gap-1.5">{chips}</div>
              </div>
            </div>

            {/* verdict + severity spread */}
            <div>
              <p className="flex items-start gap-2 text-lg font-semibold leading-snug">
                <span aria-hidden className={`mt-0.5 text-base ${TONE[verdict.tone].text}`}>{TONE[verdict.tone].glyph}</span>
                <span className="text-slate-50">{verdict.headline}</span>
              </p>
              <p className="mb-4 mt-1 max-w-[62ch] pl-6 text-sm leading-relaxed text-slate-400">{verdict.detail}</p>
              <SeveritySpread counts={eff.counts} />
            </div>
          </div>
          <div className="flex flex-col items-center gap-2 @3xl:items-end">
            <GradeDial
              score={eff.score}
              grade={eff.grade}
              note={rescored ? `after triage; ${eff.scanned.score}, grade ${eff.scanned.grade} as scanned` : undefined}
            />
            {rescored && (
              <p className="text-center text-xs leading-snug text-slate-400 @3xl:text-right">
                <span className="block font-semibold text-slate-200">{eff.score} ({eff.grade}) after triage</span>
                <span className="block">{eff.scanned.score} ({eff.scanned.grade}) as scanned</span>
              </p>
            )}
          </div>
        </div>

        {/* triage */}
        <div className="grid grid-cols-3 gap-2.5">
          <TriageTile
            n={eff.findings.length} label="To fix" hint="Defects with a known remedy" glyph={'\u2297'}
            tone={eff.findings.length ? 'text-rose-300' : 'text-emerald-300'}
            onClick={() => onNavigate('findings')}
          />
          <TriageTile
            n={summary.decided} label="Reviewed" hint={`of ${eff.findings.length + eff.excluded} findings decided on`} glyph={'\u2610'}
            tone={summary.decided ? 'text-sky-300' : 'text-slate-400'}
            onClick={() => onNavigate('findings')}
          />
          <TriageTile
            n={scan.secure.length} label="Done right" hint="Verified good practice" glyph={'\u2713'}
            tone="text-emerald-300"
            onClick={() => onNavigate('findings')}
          />
        </div>

        {/* what triage took out, with the way to see it */}
        {(eff.excluded > 0 || summary.expiredAcceptances > 0) && (
          <p className="-mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
            {eff.excluded > 0 && (
              <button
                type="button"
                onClick={() => onNavigate('findings', { status: 'excluded' })}
                className="group inline-flex items-center gap-1.5 rounded-md text-slate-300 hover:text-ember-200"
              >
                <span aria-hidden className="text-slate-500">{'\u2298'}</span>
                <span className="font-semibold tabular-nums">{eff.excluded}</span> excluded by triage
                <span className="text-slate-500">
                  ({[
                    summary.falsePositive && `${summary.falsePositive} false positive`,
                    summary.acceptedRisk && `${summary.acceptedRisk} accepted`,
                    summary.fixed && `${summary.fixed} fixed`,
                  ].filter(Boolean).join(', ')})
                </span>
                <span className="text-ember-300 underline-offset-2 group-hover:underline">view {'\u2192'}</span>
              </button>
            )}
            {summary.expiredAcceptances > 0 && (
              <button
                type="button"
                onClick={() => onNavigate('findings', { status: 'accepted_risk' })}
                className="inline-flex items-center gap-1.5 rounded-md text-amber-300 hover:text-amber-200"
              >
                <span aria-hidden>{'\u25b2'}</span>
                {summary.expiredAcceptances} accepted risk{summary.expiredAcceptances === 1 ? ' has' : 's have'} expired and count{summary.expiredAcceptances === 1 ? 's' : ''} again
              </button>
            )}
          </p>
        )}

        {/* signals */}
        {signals.length > 0 && (
          <ul className="flex flex-wrap gap-2 border-t border-slate-800/80 pt-4" aria-label="Key build signals">
            {signals.map((s) => (
              <li key={s.key}>
                <span
                  title={s.detail}
                  className={`inline-flex cursor-help items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs ${TONE[s.tone].chip}`}
                >
                  <span aria-hidden className="text-[0.65rem] leading-none">{TONE[s.tone].glyph}</span>
                  <span className="text-slate-300">{s.label}</span>
                  <span className="font-semibold">{s.state}</span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
