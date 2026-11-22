/**
 * Scan replay: the finished scan played back on the same map the live view draws.
 *
 * `replayTimeline.ts` turns the report into the steps a running scan sends (a file appears, a file is read,
 * a rule matches), and this feeds them to the same `LiveMap`, drawn by the same `MapView`, beside the same
 * panels. So a replay looks like the scan did while it ran.
 *
 * It is a re-enactment, not a recording: the scan did not keep the order it read files in, so the walk goes
 * folder by folder and only the end state is real. The page says so, and nothing here is a number the
 * report does not hold.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { request } from '../../api';
import { Button } from '../ui';
import { SEV } from './ui';
import { LiveMap } from './liveModel.ts';
import { MapView, clip, type MapViewHandle } from './MapView.tsx';
import { ActivityLog, ReadingNow, SeverityBars } from './MapAside.tsx';
import { buildTimeline, stepsDoneBy, type FileRef } from './replayTimeline.ts';
import type { SastFinding, SastScan } from '../../sastTypes';

const SPEEDS = [0.5, 1, 2, 4];

export function ScanReplay({ scan, findings }: { scan: SastScan; findings: SastFinding[] }) {
  const [files, setFiles] = useState<FileRef[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [clock, setClock] = useState(0); // seconds, for the scrubber and the panels

  useEffect(() => {
    let live = true;
    setFiles(null);
    setError(null);
    request<{ files: FileRef[] }>(`/v1/sast/scans/${scan.scanId}/files`)
      .then((r) => live && setFiles(r.files))
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : 'could not load the file list'));
    return () => {
      live = false;
    };
  }, [scan.scanId]);

  // The files the Explorer kept, and, for an iOS bundle, every file the scan saw: the replay draws the whole app, as the live view did.
  const timeline = useMemo(() => {
    if (!files) return null;
    const known = new Set(files.map((f) => f.path));
    const listed = (scan.artifact.fileListing ?? []).filter((path) => !known.has(path)).map((path) => ({ path, bytes: 1 }));
    return buildTimeline([...files, ...listed], findings);
  }, [files, findings, scan.artifact.fileListing]);

  // The whole app, drawn and settled before anything is read.
  const map = useMemo(() => {
    if (!timeline) return null;
    const m = new LiveMap();
    m.quiet = true;
    // An iOS bundle's own folder is the `.app` the files sit in; an Android app's is its package.
    const bundle = timeline.files.map((f) => f.split('/')[0]).find((top) => top.endsWith('.app'));
    if (bundle) m.setApp(bundle, true);
    else if (scan.artifact.packageName) m.setApp(scan.artifact.packageName);
    for (const path of timeline.files) m.apply({ k: 'add', path });
    m.settle();
    m.quiet = false;
    return m;
  }, [timeline, scan.artifact.packageName]);

  const view = useRef<MapViewHandle>(null);
  const time = useRef(0);
  const cursor = useRef(0);
  const shown = useRef(-1);

  // A different scan or a rebuilt map starts from the beginning.
  useEffect(() => {
    time.current = 0;
    cursor.current = 0;
    shown.current = -1;
    setClock(0);
    setPlaying(false);
  }, [map]);

  if (error) return <p className="text-sm text-rose-300">Could not load this scan’s files: {error}</p>;
  if (!timeline || !map) return <p className="text-sm text-slate-400">Reading the file list…</p>;
  if (timeline.files.length === 0) return <p className="text-sm text-slate-400">This scan kept no files to draw.</p>;

  const { steps, duration } = timeline;

  /** Plays the steps that have come due, then lets the map animate. */
  const stepFrame = (dt: number) => {
    time.current = Math.min(duration, time.current + dt * speed);
    while (cursor.current < steps.length && steps[cursor.current].at <= time.current) map.apply(steps[cursor.current++].item);
    map.advance(dt);
    const whole = Math.floor(time.current * 10);
    if (whole !== shown.current) {
      shown.current = whole;
      setClock(time.current);
    }
    if (time.current >= duration) {
      setClock(duration);
      setPlaying(false);
    }
  };

  /** Jumps to `t`: everything before it has happened, quietly, and playback continues from there. */
  const seek = (t: number) => {
    const to = Math.max(0, Math.min(duration, t));
    map.resetProgress();
    const done = stepsDoneBy(steps, to);
    for (let i = 0; i < done; i += 1) map.apply(steps[i].item, true);
    cursor.current = done;
    time.current = to;
    if (map.current) Object.assign(map.hub, map.clusters[map.current.cluster]);
    shown.current = Math.floor(to * 10);
    setClock(to);
    view.current?.redraw();
  };

  const done = clock >= duration;
  const play = () => {
    if (done) seek(0);
    setPlaying(true);
  };

  const last = map.log[0];
  const lastFinding = last?.ref !== undefined ? findings[last.ref] : undefined;
  const place = lastFinding?.locations.find((l) => l.file === last?.file) ?? lastFinding?.locations[0];

  return (
    <div className="space-y-3">
      <p className="text-xs leading-relaxed text-slate-400">
        A re-enactment of the finished scan on the same map the live scan draws, not a recording of it: the scan did not keep
        the order it read files in, so the walk goes folder by folder. What is real is the map (the app’s files, grouped by
        folder) and where each flag sits (the file its finding names).
        {timeline.filesShown < timeline.filesTotal &&
          ` Showing ${timeline.filesShown.toLocaleString()} of ${timeline.filesTotal.toLocaleString()} files: every flagged file, and an even sample of the rest.`}
      </p>

      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-hairline bg-surface px-3 py-2">
        <Button variant="primary" onClick={playing ? () => setPlaying(false) : play}>
          {playing ? 'Pause' : done ? 'Play again' : clock > 0 ? 'Resume' : 'Play'}
        </Button>
        <Button variant="ghost" onClick={() => { setPlaying(false); seek(0); }} disabled={clock === 0}>
          Restart
        </Button>
        <Button variant="ghost" onClick={() => { setPlaying(false); seek(duration); }} disabled={done}>
          Skip to end
        </Button>
        <div className="flex items-center gap-1" role="group" aria-label="Speed">
          {SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={speed === s}
              onClick={() => setSpeed(s)}
              className={`rounded px-2 py-1 text-xs ${speed === s ? 'bg-ember-500/20 text-ember-200' : 'text-slate-400 hover:text-slate-100'}`}
            >
              {s}×
            </button>
          ))}
        </div>
        <input
          type="range"
          min={0}
          max={duration}
          step={0.05}
          value={clock}
          onChange={(e) => { setPlaying(false); seek(Number(e.target.value)); }}
          aria-label="Position in the replay"
          className="min-w-[160px] flex-1 accent-orange-500"
        />
        <span className="w-24 text-right font-mono text-xs text-slate-400">{map.read.toLocaleString()}/{timeline.filesShown.toLocaleString()}</span>
      </div>

      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_340px]">
        <MapView
          ref={view}
          map={map}
          running={playing}
          step={stepFrame}
          label={`Map of ${timeline.filesShown} files in ${map.clusters.length} folders; ${map.total} of ${timeline.placed} findings flagged so far`}
          caption={`${scan.artifact.fileName} · ${map.clusters.length} folders`}
        />
        <aside className="space-y-3">
          <ReadingNow path={map.current?.path} empty="Press play." />

          <div className="rounded-lg border border-hairline bg-surface p-3">
            <div className="text-[10px] uppercase tracking-widest text-slate-500">Last flagged</div>
            {lastFinding ? (
              <>
                <p className="mt-1 flex items-start gap-2 text-sm text-slate-50">
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEV[lastFinding.severity].solid}`} aria-hidden />
                  {lastFinding.title}
                </p>
                <pre className="mt-2 max-h-44 overflow-hidden rounded bg-canvas p-2 font-mono text-[11px] leading-snug text-slate-300">
                  {place?.snippet && place.snippet.length > 0
                    ? place.snippet.slice(0, 9).map((l) => (
                        <div key={l.line} className={l.vulnerable ? 'bg-rose-500/15 text-rose-100' : ''}>
                          <span className="mr-2 select-none text-slate-600">{String(l.line).padStart(4)}</span>
                          {clip(l.text, 60)}
                        </div>
                      ))
                    : clip(place?.excerpt ?? 'No excerpt was kept for this finding.', 240)}
                </pre>
              </>
            ) : (
              <p className="mt-1 text-xs text-slate-500">Nothing flagged yet.</p>
            )}
          </div>

          <SeverityBars
            map={map}
            totals={timeline.totals}
            heading={<>Flagged <b className="text-slate-100">{map.total}</b> of {timeline.placed}</>}
          />
          <ActivityLog map={map} />
        </aside>
      </div>
    </div>
  );
}
