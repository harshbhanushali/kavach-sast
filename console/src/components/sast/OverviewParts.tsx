/**
 * The overview blocks that read the same on both platforms: the digest card that
 * links to a tab, the "fix these first" list, and the scorecard. Each platform's
 * overview composes these with its own hero chips, lenses and build facts.
 */
import type { ReactNode } from 'react';
import type { SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { effectiveOf } from './model';
import type { Navigate } from './model';
import { SEV, SevChip, ToneChip } from './ui';

/** A digest card: a whole-card button, so it is one tab stop and one big target. */
export function Lens({
  title, cta, onClick, children,
}: { title: string; cta: string; onClick: () => void; children: ReactNode }) {
  return (
    <div className="group relative flex flex-col rounded-xl border border-slate-800 bg-slate-900/40 p-4 transition duration-150 hover:border-slate-600 hover:bg-slate-900/70">
      <h3 className="eyebrow">{title}</h3>
      <div className="mt-3 flex-1 space-y-2.5">{children}</div>
      <button
        type="button"
        onClick={onClick}
        className="mt-4 self-start rounded-md text-xs font-medium text-ember-300 after:absolute after:inset-0 after:content-[''] hover:text-ember-200 focus-visible:outline-offset-4"
      >
        {cta} <span aria-hidden>{'→'}</span>
      </button>
    </div>
  );
}

/** The worst findings by severity, then by how many places they occur. */
export function FixFirst({ scan, onNavigate }: { scan: SastScan; onNavigate: Navigate }) {
  // Active findings only: one a reviewer has called a false positive or fixed is not "first".
  const active = effectiveOf(scan).findings;
  const worst = [...active]
    .sort((x, y) => SEV[x.severity].rank - SEV[y.severity].rank || y.occurrences - x.occurrences)
    .slice(0, 5);
  if (worst.length === 0) return null;
  return (
    <Panel
      title="Fix these first"
      subtitle="The worst findings by severity, then by how many places they occur."
      actions={
        <button
          type="button"
          onClick={() => onNavigate('findings')}
          className="rounded-md border border-slate-700 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-800"
        >
          {active.length === scan.findings.length ? 'All' : 'All active'} {active.length} findings {'→'}
        </button>
      }
    >
      <ol className="divide-y divide-slate-800/80">
        {worst.map((f, i) => (
          <li key={f.ruleId} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 first:pt-0 last:pb-0">
            <span className="w-4 text-xs tabular-nums text-slate-600">{i + 1}</span>
            <span className="w-[5.5rem] shrink-0"><SevChip severity={f.severity} /></span>
            <span className="min-w-0 flex-1 basis-56 text-sm text-slate-100">{f.title}</span>
            {f.cwe && <span className="font-mono text-[11px] text-slate-500">{f.cwe}</span>}
            <span className="text-xs tabular-nums text-slate-400">{'×'}{f.occurrences}</span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}

/**
 * The rule categories, as chips.
 *
 * Once a reviewer has made decisions, each category counts its active findings
 * and passes on the same rule the scanner uses (nothing at medium or above), so
 * a category whose only blocker was marked a false positive reads as passing.
 */
export function Scorecard({ scan }: { scan: SastScan }) {
  const eff = effectiveOf(scan);
  const triaged = eff.summary.decided > 0;
  const active = eff.findings;
  return (
    <Panel
      title="Scorecard"
      subtitle={
        `Pass means every rule in the category looked and found nothing above low severity. Not assessed means no rule applies here, which is not the same as passing.${
          triaged ? ' Counts here leave out findings a reviewer has excluded.' : ''}`
      }
    >
      <ul className="grid gap-2.5 @2xl:grid-cols-2 @4xl:grid-cols-3">
        {scan.categories.map((c) => {
          // A review item the scanner did not call a defect only counts against a category once confirmed.
          const own = active.filter((f) => f.category === c.category && (!f.fromReview || scan.triage?.[f.ruleId]?.status === 'confirmed'));
          const findings = triaged ? own.length : c.findings;
          const pass = triaged ? !own.some((f) => SEV[f.severity].rank <= SEV.medium.rank) : c.pass;
          const tone = !c.applicable ? 'muted' : pass ? 'good' : 'bad';
          return (
            <li key={c.category} className={`rounded-lg border px-3 py-2.5 ${!c.applicable ? 'border-slate-800 bg-slate-900/30' : pass ? 'border-emerald-500/25 bg-emerald-500/[0.04]' : 'border-rose-500/30 bg-rose-500/[0.05]'}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-slate-100">{c.title}</span>
                <ToneChip tone={tone}>{!c.applicable ? 'not assessed' : pass ? 'pass' : 'fail'}</ToneChip>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{c.blurb}</p>
              <p className="mt-1.5 text-xs text-slate-500">
                {c.applicable ? `${c.rulesEvaluated} rules · ${findings} finding${findings === 1 ? '' : 's'}` : 'no rules apply to this artifact'}
              </p>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
