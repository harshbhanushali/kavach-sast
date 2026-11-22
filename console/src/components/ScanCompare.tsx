/**
 * Comparing two scans.
 *
 * Organised around the question people actually open a diff to answer: did we
 * break anything. Regressions lead, fixes follow, and the unchanged bulk is
 * collapsed behind a toggle rather than shown by default — a release where
 * twenty findings stayed the same and one appeared should read as "one
 * appeared".
 */
import { useEffect, useState } from 'react';
import { ApiError, request } from '../api';
import { Button, Empty, Panel } from '../components/ui';
import { ScanProgress } from './sast/ScanProgress';
import { ScrollSelect } from './ScrollSelect';
import { FindingBody, OriginTag } from './FindingDetail';
import type { SastFinding, SastLocation, ScanSummary } from '../sastTypes';

type FindingChange = {
  ruleId: string;
  title: string;
  category: string;
  status: 'introduced' | 'resolved' | 'worsened' | 'improved' | 'unchanged';
  before?: { severity: string; occurrences: number };
  after?: { severity: string; occurrences: number };
  /** The finding itself, for the expanded detail. */
  finding: SastFinding;
  locationsAdded: SastLocation[];
  locationsRemoved: SastLocation[];
};

type DependencyChange = {
  coordinate: string;
  status: 'added' | 'removed' | 'upgraded' | 'downgraded' | 'unchanged';
  before?: string;
  after?: string;
  advisoriesBefore: number;
  advisoriesAfter: number;
};

type ListChange = { value: string; status: 'added' | 'removed' };

type ScanRef = {
  scanId: string; fileName: string; packageName?: string; versionName?: string;
  createdAt: string; score: number; grade: string; sha256: string;
};

type Comparison = {
  baseline: ScanRef;
  candidate: ScanRef;
  headline: string;
  scoreDelta: number;
  counts: Record<'introduced' | 'resolved' | 'worsened' | 'improved' | 'unchanged', number>;
  findings: FindingChange[];
  dependencies: DependencyChange[];
  permissions: ListChange[];
  trackers: ListChange[];
  hosts: ListChange[];
  notes: string[];
};

const STATUS_STYLE: Record<string, string> = {
  introduced: 'bg-rose-500/15 text-rose-200 ring-rose-500/40',
  worsened: 'bg-orange-500/15 text-orange-200 ring-orange-500/40',
  improved: 'bg-lime-500/15 text-lime-200 ring-lime-500/40',
  resolved: 'bg-emerald-500/15 text-emerald-200 ring-emerald-500/40',
  unchanged: 'bg-slate-500/10 text-slate-400 ring-slate-600/40',
  added: 'bg-rose-500/15 text-rose-200 ring-rose-500/40',
  removed: 'bg-emerald-500/15 text-emerald-200 ring-emerald-500/40',
  upgraded: 'bg-sky-500/15 text-sky-200 ring-sky-500/40',
  downgraded: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
};

function Tag({ value }: { value: string }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${
        STATUS_STYLE[value] ?? STATUS_STYLE.unchanged
      }`}
    >
      {value}
    </span>
  );
}

function scanLabel(s: ScanSummary): string {
  const when = new Date(s.createdAt).toLocaleString();
  return `${s.fileName}${s.versionName ? ` ${s.versionName}` : ''} — ${s.score}/100 — ${when}`;
}

/** Scans of one app: same platform and package. A scan with no package can only be grouped with itself, by file name. */
type AppGroup = { key: string; label: string; scans: ScanSummary[] };

const groupKey = (s: ScanSummary) => `${s.platform}:${s.packageName ?? `file:${s.fileName}`}`;

/** Every app that has been scanned, most recently scanned first. One with a single scan is listed but cannot be picked: it has nothing to compare against yet. */
function appGroups(scans: ScanSummary[]): AppGroup[] {
  const byKey = new Map<string, ScanSummary[]>();
  for (const s of scans) byKey.set(groupKey(s), [...(byKey.get(groupKey(s)) ?? []), s]);
  return [...byKey.entries()]
    .map(([key, list]) => {
      const sorted = list.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const latest = sorted[0];
      return {
        key,
        scans: sorted,
        label: `${latest.fileName}${latest.packageName ? ` — ${latest.packageName}` : ''} (${latest.platform}, ${
          sorted.length === 1 ? '1 scan — scan it again to compare' : `${sorted.length} scans`
        })`,
      };
    })
    .sort((a, b) => b.scans[0].createdAt.localeCompare(a.scans[0].createdAt));
}

export function ScanCompare({ scans, appSelected }: {
  scans: ScanSummary[];
  /** True when an app is selected in the header; `scans` is then that app's scans only. */
  appSelected?: boolean;
}) {
  const groups = appGroups(scans);
  const comparable = groups.filter((g) => g.scans.length >= 2);
  const [appKey, setAppKey] = useState('');
  const [baseline, setBaseline] = useState('');
  const [candidate, setCandidate] = useState('');
  const group = comparable.find((g) => g.key === appKey) ?? comparable[0];
  const [result, setResult] = useState<Comparison | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showUnchanged, setShowUnchanged] = useState(false);
  const [open, setOpen] = useState<Set<string>>(new Set());

  function toggle(ruleId: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(ruleId)) next.delete(ruleId);
      else next.add(ruleId);
      return next;
    });
  }

  // Both scans must belong to the chosen app. Whenever they do not (first
  // render, or the app was changed), default to its two most recent, which is
  // the comparison people want most of the time: the release before this one
  // against this one.
  useEffect(() => {
    if (!group) return;
    const ids = new Set(group.scans.map((x) => x.scanId));
    if (!ids.has(baseline) || !ids.has(candidate)) {
      setBaseline(group.scans[1].scanId);
      setCandidate(group.scans[0].scanId);
    }
  }, [group?.key, scans]);

  function chooseApp(key: string) {
    setAppKey(key);
    setResult(null);
    setError(null);
    const next = comparable.find((g) => g.key === key);
    if (next) {
      setBaseline(next.scans[1].scanId);
      setCandidate(next.scans[0].scanId);
    }
  }

  async function run(base = baseline, cand = candidate) {
    if (!base || !cand) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await request<Comparison>(
          `/v1/sast/compare?baseline=${encodeURIComponent(base)}&candidate=${encodeURIComponent(cand)}`,
        ),
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const changed = result?.findings.filter((f) => f.status !== 'unchanged') ?? [];
  const unchanged = result?.findings.filter((f) => f.status === 'unchanged') ?? [];
  const changedDeps = result?.dependencies.filter((d) => d.status !== 'unchanged') ?? [];

  if (!group) {
    return (
      <Panel title="Compare two scans" subtitle="Scans are compared within one app, so an app needs two scans before there is anything to compare.">
        <Empty>
          {appSelected
            ? `The selected app has ${scans.length === 0 ? 'no scans' : 'one scan'}. Scan another build of it to compare, or choose "Auto" in the App menu to compare other apps.`
            : 'Scan another build of the same app. Scans of different apps cannot be compared with each other.'}
        </Empty>
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      <Panel
        title="Compare two scans"
        subtitle="Pick an app, then two of its scans. Apps with a single scan are listed but need a second scan first. Baseline is what you had; candidate is what you are about to ship. The diff reads in that direction."
      >
        <div className="mb-3">
          <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">App</span>
          <ScrollSelect
            label="App"
            value={group.key}
            onChange={chooseApp}
            options={groups.map((g) => ({ value: g.key, label: g.label, disabled: g.scans.length < 2 }))}
          />
        </div>

        <div className="grid gap-3 lg:grid-cols-[1fr_1fr_auto] lg:items-end">
          <div className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
              Baseline
            </span>
            <ScrollSelect
              label="Baseline"
              value={baseline}
              onChange={setBaseline}
              options={group.scans.map((s) => ({ value: s.scanId, label: scanLabel(s) }))}
            />
          </div>

          <div className="block">
            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
              Candidate
            </span>
            <ScrollSelect
              label="Candidate"
              value={candidate}
              onChange={setCandidate}
              options={group.scans.map((s) => ({ value: s.scanId, label: scanLabel(s) }))}
            />
          </div>

          <Button onClick={() => run()} variant="primary" disabled={busy || !baseline || !candidate || baseline === candidate}>
            {busy ? 'Comparing…' : 'Compare'}
          </Button>
        </div>

        {error && (
          <p className="mt-3 rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-200 ring-1 ring-inset ring-rose-500/30">
            {error}
          </p>
        )}
      </Panel>

      <ScanProgress
        scans={group.scans}
        onCompare={(b, c) => {
          setBaseline(b);
          setCandidate(c);
          void run(b, c);
        }}
      />

      {result && (
        <>
          <Panel title={result.headline} subtitle={`${result.baseline.fileName} → ${result.candidate.fileName}`}>
            <div className="flex flex-wrap items-center gap-8">
              <div className="flex items-baseline gap-2.5">
                <span className="text-3xl font-bold tabular-nums text-slate-400">{result.baseline.score}</span>
                <span className="text-slate-600">→</span>
                <span className="text-4xl font-bold tabular-nums text-slate-100">{result.candidate.score}</span>
                <span
                  className={`text-sm font-semibold tabular-nums ${
                    result.scoreDelta > 0 ? 'text-emerald-300'
                      : result.scoreDelta < 0 ? 'text-rose-300' : 'text-slate-500'
                  }`}
                >
                  {result.scoreDelta > 0 ? '+' : ''}{result.scoreDelta}
                </span>
              </div>

              <div className="flex flex-wrap gap-3">
                {([
                  ['introduced', 'text-rose-300'],
                  ['worsened', 'text-orange-300'],
                  ['improved', 'text-lime-300'],
                  ['resolved', 'text-emerald-300'],
                  ['unchanged', 'text-slate-500'],
                ] as const).map(([key, cls]) => (
                  <div
                    key={key}
                    className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2 text-center transition duration-150 hover:-translate-y-0.5 hover:border-slate-700"
                  >
                    <div className={`text-xl font-bold tabular-nums ${cls}`}>{result.counts[key]}</div>
                    <div className="text-[11px] uppercase tracking-wide text-slate-500">{key}</div>
                  </div>
                ))}
              </div>
            </div>

            {result.notes.length > 0 && (
              <ul className="mt-4 space-y-2 border-t border-slate-800 pt-3">
                {result.notes.map((n, i) => (
                  <li key={i} className="flex gap-2 text-sm leading-relaxed text-slate-400">
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-amber-500/70" />
                    <span className="max-w-[92ch]">{n}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title={`Findings that changed (${changed.length})`}
            subtitle="Regressions first. Unchanged findings are collapsed — a release where one thing appeared should read as one thing appearing."
            actions={
              unchanged.length > 0 ? (
                <Button onClick={() => setShowUnchanged(!showUnchanged)}>
                  {showUnchanged ? 'Hide' : 'Show'} {unchanged.length} unchanged
                </Button>
              ) : undefined
            }
          >
            {changed.length === 0 ? (
              <Empty>Nothing changed between these two scans.</Empty>
            ) : (
              <ul className="divide-y divide-slate-800">
                {changed.map((c) => (
                  <ChangeRow
                    key={c.ruleId}
                    change={c}
                    open={open.has(c.ruleId)}
                    onToggle={() => toggle(c.ruleId)}
                  />
                ))}
              </ul>
            )}

            {showUnchanged && unchanged.length > 0 && (
              <ul className="mt-2 divide-y divide-slate-800/60 border-t border-slate-800 pt-2">
                {unchanged.map((c) => (
                  <ChangeRow
                    key={c.ruleId}
                    change={c}
                    open={open.has(c.ruleId)}
                    onToggle={() => toggle(c.ruleId)}
                  />
                ))}
              </ul>
            )}
          </Panel>

          {changedDeps.length > 0 && (
            <Panel
              title={`Dependency changes (${changedDeps.length})`}
              subtitle="Version movement, with the advisory count either side — the quickest way to see whether an upgrade actually cleared anything."
            >
              <div className="overflow-hidden rounded-md border border-slate-800">
                <table className="w-full text-xs">
                  <tbody className="divide-y divide-slate-800/70">
                    {changedDeps.map((d) => (
                      <tr key={d.coordinate} className="transition-colors hover:bg-slate-800/40">
                        <td className="py-1.5 pl-2.5 pr-3"><Tag value={d.status} /></td>
                        <td className="py-1.5 pr-3 font-mono text-slate-300">{d.coordinate}</td>
                        <td className="py-1.5 pr-3 font-mono tabular-nums text-slate-500">
                          {d.before ?? '—'} <span className="text-slate-600">→</span>{' '}
                          <span className="text-slate-300">{d.after ?? '—'}</span>
                        </td>
                        <td className="py-1.5 pr-2.5 text-right">
                          {d.advisoriesBefore !== d.advisoriesAfter && (
                            <span
                              className={
                                d.advisoriesAfter < d.advisoriesBefore ? 'text-emerald-300' : 'text-rose-300'
                              }
                            >
                              {d.advisoriesBefore} → {d.advisoriesAfter} advisories
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

          {(result.permissions.length > 0 || result.trackers.length > 0 || result.hosts.length > 0) && (
            <Panel
              title="Surface changes"
              subtitle="What the app now asks for, ships, or talks to that it did not before — and what it stopped."
            >
              <div className="grid gap-5 lg:grid-cols-3">
                {([
                  ['Permissions', result.permissions],
                  ['Trackers', result.trackers],
                  ['Hosts', result.hosts],
                ] as const).map(([label, list]) => (
                  <div key={label}>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      {label} ({list.length})
                    </p>
                    {list.length === 0 ? (
                      <p className="mt-1 text-sm text-slate-600">No change.</p>
                    ) : (
                      <ul className="mt-1.5 space-y-1">
                        {list.slice(0, 20).map((c) => (
                          <li key={c.value} className="flex items-baseline gap-2">
                            <span className={c.status === 'added' ? 'text-rose-400' : 'text-emerald-400'}>
                              {c.status === 'added' ? '+' : '−'}
                            </span>
                            <span className="min-w-0 break-all font-mono text-xs text-slate-400">
                              {c.value.replace('android.permission.', '')}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}

function ChangeRow({
  change, open, onToggle,
}: { change: FindingChange; open: boolean; onToggle: () => void }) {
  const severity = (change.after ?? change.before)?.severity;
  const movedSeverity =
    change.before && change.after && change.before.severity !== change.after.severity;
  const movedCount =
    change.before && change.after && change.before.occurrences !== change.after.occurrences;

  return (
    <li className="-mx-2 rounded-lg px-2 py-2.5 transition-colors hover:bg-slate-800/30">
      <button type="button" onClick={onToggle} className="flex w-full items-start gap-3 text-left">
        <Tag value={change.status} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm text-slate-100">{change.title}</span>
          <span className="mt-1 flex flex-wrap items-center gap-2 font-mono text-xs text-slate-500">
            <OriginTag origin={change.finding.origin} libraries={change.finding.libraries} />
          </span>
          {/* The count alone is not actionable; name how many sites moved. */}
          {(change.locationsAdded.length > 0 || change.locationsRemoved.length > 0) && (
            <span className="mt-0.5 block text-xs">
              {change.locationsAdded.length > 0 && (
                <span className="text-rose-300">+{change.locationsAdded.length} new location
                  {change.locationsAdded.length === 1 ? '' : 's'}</span>
              )}
              {change.locationsAdded.length > 0 && change.locationsRemoved.length > 0 && (
                <span className="text-slate-600"> · </span>
              )}
              {change.locationsRemoved.length > 0 && (
                <span className="text-emerald-300">−{change.locationsRemoved.length} gone</span>
              )}
            </span>
          )}
        </span>
        <span className="shrink-0 text-right text-xs">
          {movedSeverity ? (
            <span className="text-slate-400">
              {change.before!.severity} <span className="text-slate-600">→</span>{' '}
              <span className="text-slate-200">{change.after!.severity}</span>
            </span>
          ) : (
            <span className="text-slate-500">{severity}</span>
          )}
          {movedCount && (
            <span className="mt-0.5 block text-slate-500">
              {change.before!.occurrences} → {change.after!.occurrences} places
            </span>
          )}
          <span className="mt-0.5 block text-slate-500 transition-colors group-hover:text-sky-300">
            {open ? 'Hide' : 'Details'}
          </span>
        </span>
      </button>

      {open && (
        <div className="mt-3 pl-[4.5rem]">
          <FindingBody
            finding={change.finding}
            added={change.locationsAdded}
            removed={change.locationsRemoved}
          />
        </div>
      )}
    </li>
  );
}
