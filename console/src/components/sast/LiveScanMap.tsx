/**
 * The map of the app, drawn while the scan is still running.
 *
 * Files appear as the decompiler writes them, then the hub walks them as the rule pass reads them and a flag
 * lights up where a rule matches. It is fed by the scan's own events (`liveModel.ts`), not a simulation. A
 * flag here is a rule match; the report merges matches into findings at the end, so the final list can be
 * shorter than this count and the page says so.
 *
 * The map and the panels are the same ones the replay uses (`MapView`, `MapAside`).
 */
import { Button } from '../ui';
import { MapView } from './MapView.tsx';
import { ActivityLog, ReadingNow, SeverityBars } from './MapAside.tsx';
import { useEffect, useState } from 'react';
import type { LiveMap } from './liveModel.ts';

export function LiveScanMap({ map, label, percent, onSkip }: { map: LiveMap; label: string; percent: number; onSkip?: () => void }) {
  // The panels read the map as it changes; a few times a second is plenty.
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), 140);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_340px]">
      <MapView
        map={map}
        running
        step={(dt) => map.advance(dt)}
        label={`Live map: ${map.discovered} files found, ${map.read} read, ${map.total} rule matches so far`}
        caption={`live · ${map.discovered.toLocaleString()} files · ${map.clusters.length} folders`}
      />
      <aside className="space-y-3">
        <div className="rounded-lg border border-hairline bg-surface p-3">
          <div className="flex items-baseline justify-between text-[10px] uppercase tracking-widest text-slate-500">
            <span>{label}</span>
            <span className="font-mono text-slate-300">{percent}%</span>
          </div>
          <div className="mt-2 h-1.5 rounded bg-slate-800">
            <div className="h-1.5 rounded bg-ember-500 transition-all" style={{ width: `${Math.max(2, percent)}%` }} />
          </div>
          {onSkip && (
            <div className="mt-3">
              <Button variant="default" onClick={onSkip}>
                Show the report now
              </Button>
            </div>
          )}
          <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
            <div>
              <dt className="text-slate-500">Files found</dt>
              <dd className="font-mono text-slate-100">{map.discovered.toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Files read</dt>
              <dd className="font-mono text-slate-100">{map.read.toLocaleString()}</dd>
            </div>
          </dl>
        </div>
        <ReadingNow path={map.current?.path} empty="The rules start once the app is unpacked." />
        <SeverityBars
          map={map}
          heading={<>Rule matches so far <b className="text-slate-100">{map.total}</b></>}
          note="Matches, not yet findings: the report merges them, so its list can be shorter."
        />
        <ActivityLog map={map} />
      </aside>
    </div>
  );
}
