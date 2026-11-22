/**
 * A compact, persistent identity strip above the tab bar: icon, app name,
 * package or bundle id, platform, and the grade. It stays put while the reader
 * moves between tabs, so it is always clear which app and which scan this is.
 */
import type { ReactNode } from 'react';
import type { SastScan } from '../../sastTypes';
import { AppIcon } from './AppIcon';
import { GRADE, effectiveOf, identityOf } from './model';
import { Tag } from './ui';

export function IdentityStrip({ scan, actions }: { scan: SastScan; actions: ReactNode }) {
  const a = scan.artifact;
  const { name, id } = identityOf(scan);
  // The grade a reviewer's decisions leave: see `effectiveOf`.
  const eff = effectiveOf(scan);
  const grade = GRADE[eff.grade] ?? GRADE.C;
  const rescored = eff.score !== eff.scanned.score;
  const gradeTitle = `Security grade ${eff.grade}, score ${eff.score} out of 100${rescored ? ` after triage (${eff.scanned.score}, grade ${eff.scanned.grade} as scanned)` : ''}`;

  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3">
      <div className="flex min-w-0 items-center gap-3.5">
        <AppIcon src={a.iconDataUrl} name={name} seed={id ?? name} size="md" />
        <div className="min-w-0">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1">
            <h2 className="truncate text-lg font-semibold leading-tight text-slate-50">{name}</h2>
            <Tag mono={false}>{a.platform === 'android' ? 'Android' : 'iOS'}</Tag>
            <span
              className={`inline-flex items-center gap-1.5 rounded-md border px-1.5 py-px text-xs font-semibold ${grade.chip} ${grade.text}`}
              title={gradeTitle}
            >
              <span aria-hidden className="text-sm leading-none">{eff.grade}</span>
              <span className="sr-only">Grade {eff.grade},</span>
              <span className="tabular-nums text-slate-300">{eff.score}<span className="text-slate-500">/100</span></span>
              {rescored && <span className="font-normal text-slate-500">after triage</span>}
            </span>
          </div>
          <p className="mt-0.5 truncate font-mono text-xs text-slate-400">
            {id ?? 'unknown app id'}
            <span className="font-sans text-slate-600"> {'·'} </span>
            <span className="font-sans text-slate-500" title={a.fileName}>{a.fileName}</span>
            <span className="font-sans text-slate-600"> {'·'} </span>
            <span className="font-sans text-slate-500">scanned in {(scan.durationMs / 1000).toFixed(1)}s</span>
          </p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">{actions}</div>
    </div>
  );
}
