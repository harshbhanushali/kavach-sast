/**
 * Progress across scans of the same app.
 *
 * Answers one question: is this app getting better? A score line says how far,
 * stacked severities say where the findings went, and the tiles say what changed
 * since the scan before. Scans are matched on platform and package name, so it
 * works whether or not an app was picked when they were taken.
 *
 * Plotted points are scans in order, not a time scale: two scans an hour apart
 * and two a month apart are both just "the next build".
 */
import { useState } from 'react';
import { Button, Panel } from '../ui';
import { SEV, SevGlyph } from './ui';
import type { ScanSummary } from '../../sastTypes';

type Severity = keyof typeof SEV;

/** Bottom of the stack first: the worst findings sit on the baseline. */
const STACK: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const MAX_POINTS = 12;

const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
const worstTwo = (s: ScanSummary) => (s.counts.critical ?? 0) + (s.counts.high ?? 0);

function pointLabel(s: ScanSummary): string {
  return s.versionName ? s.versionName.slice(0, 9) : day(s.createdAt);
}

/** Signed change, with the direction in words so colour is never the only signal. */
function Delta({ now, before, upIsGood, unit = '' }: { now: number; before: number; upIsGood: boolean; unit?: string }) {
  const d = now - before;
  if (d === 0) return <span className="text-xs text-slate-400">— no change</span>;
  const good = upIsGood ? d > 0 : d < 0;
  return (
    <span className={`text-xs font-medium ${good ? 'text-emerald-300' : 'text-rose-300'}`}>
      {d > 0 ? '▲' : '▼'} {d > 0 ? '+' : '−'}{Math.abs(d)}{unit} {good ? 'better' : 'worse'}
    </span>
  );
}

function Tile({ label, value, children }: { label: string; value: string | number; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3">
      <p className="eyebrow">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-50">{value}</p>
      <p className="mt-0.5">{children}</p>
    </div>
  );
}

/**
 * What hovering or focusing a scan shows. Values lead, the label follows.
 *
 * Sits beside the column rather than over it: the point of hovering is to look
 * at that mark, so a readout on top of it defeats the gesture. `at` is the
 * column's centre as a percentage of the chart's width.
 */
function Tip({ s, at, index, count, current }: { s: ScanSummary; at: number; index: number; count: number; current: boolean }) {
  const side = index < count / 2 ? { left: `calc(${at}% + 16px)` } : { right: `calc(${100 - at}% + 16px)` };
  return (
    <div
      role="status"
      className="pointer-events-none absolute top-0 z-10 w-52 rounded-md border border-slate-700 bg-slate-900/95 px-3 py-2 text-xs shadow-lg"
      style={side}
    >
      <p className="font-semibold text-slate-50">
        {s.versionName ?? s.fileName}{current && <span className="ml-1.5 font-normal text-slate-400">(latest)</span>}
      </p>
      <p className="text-slate-400">{new Date(s.createdAt).toLocaleString()}</p>
      <p className="mt-1.5 text-slate-200">
        <span className="font-semibold text-slate-50">{s.score}</span> score ({s.grade}) ·{' '}
        <span className="font-semibold text-slate-50">{s.findings}</span> findings
      </p>
      <ul className="mt-1 space-y-0.5">
        {STACK.filter((k) => (s.counts[k] ?? 0) > 0).map((k) => (
          <li key={k} className="flex items-center gap-1.5 text-slate-300">
            <SevGlyph severity={k} className={SEV[k].text} />
            <span className="font-semibold text-slate-50">{s.counts[k]}</span> {SEV[k].label.toLowerCase()}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Which scan is under the pointer, and in which chart. The other chart still highlights the same scan. */
type Hover = { index: number; source: 'line' | 'bars' } | null;

const W = 640;
const H = 176;
const PAD = { l: 34, r: 40, t: 14, b: 26 };

function ScoreLine({ series, labels, currentId, hover, setHover }: {
  series: ScanSummary[];
  labels: string[];
  currentId: string;
  hover: Hover;
  setHover: (h: Hover) => void;
}) {
  const active = hover?.index ?? null;
  const n = series.length;
  const x = (i: number) => PAD.l + (n === 1 ? 0 : (i * (W - PAD.l - PAD.r)) / (n - 1));
  const y = (v: number) => PAD.t + ((100 - v) / 100) * (H - PAD.t - PAD.b);
  const step = n === 1 ? W - PAD.l - PAD.r : (W - PAD.l - PAD.r) / (n - 1);
  const path = series.map((s, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(s.score).toFixed(1)}`).join(' ');
  const labelEvery = n > 8 ? 2 : 1;
  const last = series[n - 1];

  return (
    <div className="relative">
      {hover?.source === 'line' && (
        <Tip s={series[hover.index]} at={(x(hover.index) / W) * 100} index={hover.index} count={n} current={series[hover.index].scanId === currentId} />
      )}
      <svg viewBox={`0 0 ${W} ${H}`} className="mt-1 w-full" role="img" aria-label={`Score by scan, ${series.map((s, i) => `${labels[i]} ${s.score}`).join(', ')}`}>
        {[0, 50, 100].map((v) => (
          <g key={v}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(v)} y2={y(v)} stroke="var(--color-hairline)" strokeWidth="1" />
            <text x={PAD.l - 8} y={y(v) + 4} textAnchor="end" className="fill-slate-500" fontSize="11">{v}</text>
          </g>
        ))}

        {active !== null && (
          <line x1={x(active)} x2={x(active)} y1={PAD.t} y2={H - PAD.b} stroke="var(--color-hairline-strong)" strokeWidth="1" />
        )}

        <path d={path} fill="none" stroke="var(--color-accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

        {series.map((s, i) => (
          <g key={s.scanId}>
            {s.scanId === currentId && (
              <circle cx={x(i)} cy={y(s.score)} r="9" fill="none" stroke="var(--color-accent)" strokeWidth="1.5" opacity="0.6" />
            )}
            <circle cx={x(i)} cy={y(s.score)} r="4.5" fill="var(--color-accent)" stroke="var(--color-surface)" strokeWidth="2" />
            {i % labelEvery === 0 && (
              <text x={x(i)} y={H - 8} textAnchor="middle" className="fill-slate-500" fontSize="11">{labels[i]}</text>
            )}
          </g>
        ))}

        {/* The endpoint is the one value worth printing; the rest live in the tooltip and the table. */}
        <text x={x(n - 1) + 12} y={y(last.score) + 4} className="fill-slate-50" fontSize="13" fontWeight="600">{last.score}</text>

        {/* Hit areas span the full height and the gap to the next scan, far larger than the dots. */}
        {series.map((s, i) => (
          <rect
            key={`hit-${s.scanId}`}
            x={x(i) - step / 2}
            y={PAD.t - 6}
            width={step}
            height={H - PAD.t - PAD.b + 12}
            fill="transparent"
            tabIndex={0}
            className="focus:outline-none"
            aria-label={`${labels[i]}: score ${s.score}, grade ${s.grade}, ${plural(s.findings, 'finding')}`}
            onPointerEnter={() => setHover({ index: i, source: 'line' })}
            onPointerMove={() => setHover({ index: i, source: 'line' })}
            onPointerLeave={() => setHover(null)}
            onFocus={() => setHover({ index: i, source: 'line' })}
            onBlur={() => setHover(null)}
          />
        ))}
      </svg>
    </div>
  );
}

const BAR_AREA = 130;

function SeverityBars({ series, labels, currentId, hover, setHover }: {
  series: ScanSummary[];
  labels: string[];
  currentId: string;
  hover: Hover;
  setHover: (h: Hover) => void;
}) {
  const active = hover?.index ?? null;
  const n = series.length;
  const max = Math.max(1, ...series.map((s) => s.findings));
  const labelEvery = n > 8 ? 2 : 1;

  return (
    <div className="relative">
      {hover?.source === 'bars' && (
        <Tip s={series[hover.index]} at={((hover.index + 0.5) / n) * 100} index={hover.index} count={n} current={series[hover.index].scanId === currentId} />
      )}
      <div className="mt-1 flex items-stretch gap-1" style={{ height: BAR_AREA + 40 }}>
        {series.map((s, i) => {
          // Top of the visual stack first, so the worst findings end up on the baseline.
          const segments = [...STACK].reverse().filter((k) => (s.counts[k] ?? 0) > 0);
          const isLast = i === n - 1;
          return (
            <div
              key={s.scanId}
              tabIndex={0}
              role="img"
              aria-label={`${labels[i]}: ${plural(s.findings, 'finding')}`}
              className={`flex min-w-0 flex-1 flex-col items-center justify-end rounded focus:outline-none ${active === i ? 'bg-slate-500/10' : ''}`}
              onPointerEnter={() => setHover({ index: i, source: 'bars' })}
              onPointerLeave={() => setHover(null)}
              onFocus={() => setHover({ index: i, source: 'bars' })}
              onBlur={() => setHover(null)}
            >
              {isLast && <span className="mb-1 text-xs font-semibold text-slate-50">{s.findings}</span>}
              <div className="flex w-6 flex-col gap-[2px]" style={{ height: (s.findings / max) * BAR_AREA }}>
                {segments.map((k, idx) => (
                  <div
                    key={k}
                    className={`${SEV[k].solid} ${idx === 0 ? 'rounded-t-[4px]' : ''} transition hover:brightness-125`}
                    style={{ height: `${((s.counts[k] ?? 0) / s.findings) * 100}%`, minHeight: 2 }}
                  />
                ))}
              </div>
              <span className="mt-2 h-4 text-[11px] text-slate-500">{i % labelEvery === 0 ? labels[i] : ''}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ScanProgress({ scans, onCompare }: {
  /** The scans of one app, in any order. */
  scans: ScanSummary[];
  /** Compare these two scans, the older first. */
  onCompare: (baselineId: string, candidateId: string) => void;
}) {
  const [hover, setHover] = useState<Hover>(null);

  const series = scans
    .slice()
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    .slice(-MAX_POINTS);
  const pkg = series[series.length - 1]?.packageName;

  // Two builds can share a version name; number the repeats so the axis never shows the same label twice.
  const base = series.map(pointLabel);
  const seen: Record<string, number> = {};
  const labels = base.map((l) => {
    if (base.filter((b) => b === l).length === 1) return l;
    seen[l] = (seen[l] ?? 0) + 1;
    return `${l} #${seen[l]}`;
  });

  // The newest scan against the one before it.
  const current = series[series.length - 1];
  const previous = series.length > 1 ? series[series.length - 2] : undefined;

  if (series.length < 2) {
    return (
      <Panel title="Progress across scans" subtitle={pkg ? `First scan of ${pkg}.` : 'Not enough scans to show progress.'}>
        <p className="text-sm text-slate-400">
          Scan another build of this app and this panel will show whether it is getting better: the score over time,
          where the findings went, and what changed since the last scan.
        </p>
      </Panel>
    );
  }

  return (
    <Panel
      title="Progress across scans"
      subtitle={`${plural(series.length, 'scan')} of ${pkg ?? 'this app'}. Scanner score, before any triage decisions.`}
      actions={previous && (
        <Button onClick={() => onCompare(previous.scanId, current.scanId)} title="See exactly what was introduced and resolved since the previous scan">
          Compare with previous scan
        </Button>
      )}
    >
      {previous && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Tile label="Score" value={current.score}>
            <Delta now={current.score} before={previous.score} upIsGood />
            <span className="ml-2 text-xs text-slate-500">was {previous.score}</span>
          </Tile>
          <Tile label="Findings" value={current.findings}>
            <Delta now={current.findings} before={previous.findings} upIsGood={false} />
            <span className="ml-2 text-xs text-slate-500">was {previous.findings}</span>
          </Tile>
          <Tile label="Critical + high" value={worstTwo(current)}>
            <Delta now={worstTwo(current)} before={worstTwo(previous)} upIsGood={false} />
            <span className="ml-2 text-xs text-slate-500">was {worstTwo(previous)}</span>
          </Tile>
        </div>
      )}

      <div className="mt-5 grid gap-6 lg:grid-cols-2">
        <section aria-labelledby="score-trend">
          <h3 id="score-trend" className="text-sm font-semibold text-slate-100">Score by scan</h3>
          <p className="text-xs text-slate-400">Higher is better. 100 means nothing was found.</p>
          <ScoreLine series={series} labels={labels} currentId={current.scanId} hover={hover} setHover={setHover} />
        </section>

        <section aria-labelledby="sev-trend">
          <h3 id="sev-trend" className="text-sm font-semibold text-slate-100">Findings by severity</h3>
          <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-300" aria-label="Severity legend">
            {STACK.map((k) => (
              <li key={k} className="flex items-center gap-1.5">
                <SevGlyph severity={k} className={SEV[k].text} />
                {SEV[k].label}
              </li>
            ))}
          </ul>
          <SeverityBars series={series} labels={labels} currentId={current.scanId} hover={hover} setHover={setHover} />
        </section>
      </div>

      <details className="mt-4 rounded-md border border-slate-800 bg-slate-900/40 px-3.5 py-2.5 text-sm">
        <summary className="cursor-pointer font-medium text-slate-200">View as a table</summary>
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead>
              <tr className="text-slate-500">
                <th className="py-1 pr-3 font-medium">Scan</th>
                <th className="py-1 pr-3 font-medium">Date</th>
                <th className="py-1 pr-3 text-right font-medium">Score</th>
                {STACK.map((k) => <th key={k} className="py-1 pr-3 text-right font-medium">{SEV[k].label}</th>)}
                <th className="py-1 text-right font-medium">Total</th>
              </tr>
            </thead>
            <tbody>
              {series.map((s, i) => (
                <tr key={s.scanId} className="border-t border-slate-800">
                  <td className="py-1 pr-3 text-slate-100">{labels[i]}{s.scanId === current.scanId && ' (latest)'}</td>
                  <td className="py-1 pr-3">{new Date(s.createdAt).toLocaleString()}</td>
                  <td className="tabular py-1 pr-3 text-right">{s.score} ({s.grade})</td>
                  {STACK.map((k) => <td key={k} className="tabular py-1 pr-3 text-right">{s.counts[k] ?? 0}</td>)}
                  <td className="tabular py-1 text-right">{s.findings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </Panel>
  );
}
