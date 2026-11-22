/**
 * The panels beside the map. Shared by the live view and the replay, so a flag means the same thing and sits in the
 * same place in both.
 */
import { SEV } from './ui';
import { base, dir } from './MapView.tsx';
import type { LiveMap, Severity } from './liveModel.ts';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function ReadingNow({ path, empty }: { path?: string; empty: string }) {
  return (
    <div className="rounded-lg border border-hairline bg-surface p-3">
      <div className="text-[10px] uppercase tracking-widest text-slate-500">Reading now</div>
      {path ? (
        <p className="mt-1 break-all font-mono text-xs leading-snug">
          <span className="text-slate-500">{dir(path)}{dir(path) ? '/' : ''}</span>
          <span className="text-slate-50">{base(path)}</span>
        </p>
      ) : (
        <p className="mt-1 text-xs text-slate-500">{empty}</p>
      )}
    </div>
  );
}

/** Flags by severity. `totals`, when given, is what the bars fill toward (a replay knows its end state). */
export function SeverityBars({ map, heading, totals, note }: { map: LiveMap; heading: React.ReactNode; totals?: Record<Severity, number>; note?: string }) {
  const sum = totals ? ORDER.reduce((n, s) => n + totals[s], 0) : map.total;
  return (
    <div className="rounded-lg border border-hairline bg-surface p-3">
      <div className="text-[10px] uppercase tracking-widest text-slate-500">{heading}</div>
      <ul className="mt-2 space-y-1.5">
        {ORDER.map((s) => {
          const denom = totals ? totals[s] : map.total;
          return (
            <li key={s} className="flex items-center gap-2 text-xs">
              <span className="w-14 text-slate-400">{SEV[s].label}</span>
              <span className="h-1.5 flex-1 rounded bg-slate-800">
                <span className={`block h-1.5 rounded ${SEV[s].solid}`} style={{ width: denom ? `${(map.counts[s] / denom) * 100}%` : 0 }} />
              </span>
              <span className="w-6 text-right font-mono text-slate-300">{map.counts[s]}</span>
            </li>
          );
        })}
      </ul>
      {note && sum >= 0 && <p className="mt-2 text-[10px] leading-snug text-slate-500">{note}</p>}
    </div>
  );
}

export function ActivityLog({ map }: { map: LiveMap }) {
  return (
    <div className="rounded-lg border border-hairline bg-surface p-3">
      <div className="text-[10px] uppercase tracking-widest text-slate-500">Log</div>
      {map.log.length === 0 ? (
        <p className="mt-2 text-xs text-slate-500">Nothing flagged yet.</p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {map.log.slice(0, 7).map((f, i) => (
            <li key={`${f.at}-${i}`} className="flex gap-2 text-xs">
              <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${SEV[f.severity].solid}`} aria-hidden />
              <span className="min-w-0">
                <span className="block truncate text-slate-100">{f.title}</span>
                <span className="block truncate font-mono text-slate-500">{base(f.file)}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
