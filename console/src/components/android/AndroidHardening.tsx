/**
 * Android hardening: the native libraries, then everything third-party the app
 * ships (libraries with versions and advisories, detected SDKs, trackers).
 *
 * Native libraries use the shared matrix (`sast/BinaryMatrix`). The ELF headers
 * are read from one ABI, so the matrix describes that ABI's copy of each `.so`.
 */
import { useMemo, useState } from 'react';
import type { SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { BinaryMatrix } from '../sast/BinaryMatrix';
import type { MatrixCopy, MatrixRow } from '../sast/BinaryMatrix';
import { FilterChip, Kv, NotPresent, Tag, ToneChip } from '../sast/ui';
import { NATIVE_PROTECTIONS, advisoryCount, nativeChecks } from './androidModel';

const COPY: MatrixCopy = {
  title: 'Native libraries',
  emptySubtitle: 'Compiled code (.so) bundled in the APK.',
  empty: 'This APK bundles no native libraries. Everything runs as Dalvik bytecode.',
  allGood: 'Every native library has all six protections.',
  columnLabel: 'Library',
  tableTitle: 'All native libraries',
  searchLabel: 'Search native libraries',
  searchPlaceholder: 'Search library name',
  nounPlural: 'libraries',
  noMatch: 'No library matches.',
};

function Native({ scan }: { scan: SastScan }) {
  const libs = scan.artifact.nativeLibraryDetail;
  const abis = scan.artifact.android?.nativeAbis ?? [];
  const rows = useMemo<MatrixRow[]>(() => libs.map((l) => ({
    id: l.name,
    name: l.name,
    sub: `RELRO ${l.relro}`,
    weakSub: `RELRO ${l.relro}`,
    checks: nativeChecks(l),
  })), [libs]);
  return (
    <>
      {abis.length > 0 && (
        <Panel title="ABIs" subtitle="CPU architectures the APK ships native code for. Hardening below is read from one of them.">
          <div className="flex flex-wrap gap-1.5">{abis.map((a) => <Tag key={a}>{a}</Tag>)}</div>
        </Panel>
      )}
      <BinaryMatrix copy={COPY} protections={NATIVE_PROTECTIONS} rows={rows} />
    </>
  );
}

function Libraries({ scan }: { scan: SastScan }) {
  const a = scan.artifact;
  const [query, setQuery] = useState('');
  const [advOnly, setAdvOnly] = useState(false);
  const [limit, setLimit] = useState(40);
  const withAdv = advisoryCount(scan);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return a.dependencies
      .filter((d) => (!advOnly || d.advisoryCount > 0) && (!q || `${d.coordinate} ${d.version}`.toLowerCase().includes(q)))
      .sort((x, y) => y.advisoryCount - x.advisoryCount || x.coordinate.localeCompare(y.coordinate));
  }, [a.dependencies, query, advOnly]);

  return (
    <Panel
      title={`Third-party libraries (${a.dependencies.length})`}
      subtitle="Versions read from META-INF/*.version and pom.properties — what the build actually wrote into the artifact, not inferred from package names."
      actions={
        a.dependencies.length > 0 && (
          <>
            <ToneChip tone={withAdv ? 'bad' : 'good'}>{withAdv} with advisories</ToneChip>
            <ToneChip tone="good">{a.dependencies.length - withAdv} clear</ToneChip>
          </>
        )
      }
    >
      {a.detectedLibraries.length > 0 && (
        <div className="mb-4">
          <p className="eyebrow mb-1.5">Detected SDKs</p>
          <ul className="flex flex-wrap gap-1.5">{a.detectedLibraries.map((l) => <li key={l}><Tag mono={false}>{l}</Tag></li>)}</ul>
        </div>
      )}
      {a.dependencies.length === 0 ? (
        <NotPresent>No versioned libraries were found in the archive metadata.</NotPresent>
      ) : (
        <>
          <div className="mb-3.5 flex flex-wrap items-center gap-2">
            <label className="min-w-[12rem] flex-1 @2xl:max-w-xs">
              <span className="sr-only">Search libraries</span>
              <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search coordinate or version" className="w-full" />
            </label>
            <FilterChip active={advOnly} onClick={() => setAdvOnly((v) => !v)}>
              <span aria-hidden className="text-[0.65rem] text-rose-300">{'✕'}</span> With advisories
            </FilterChip>
            <span className="ml-auto text-xs tabular-nums text-slate-500">{rows.length} shown</span>
          </div>
          {rows.length === 0 ? (
            <NotPresent>No library matches.</NotPresent>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[32rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-left">
                    <th scope="col" className="px-3 py-2 eyebrow">Library</th>
                    <th scope="col" className="px-3 py-2 eyebrow">Version</th>
                    <th scope="col" className="px-3 py-2 text-right eyebrow">Advisories</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {rows.slice(0, limit).map((d) => (
                    <tr key={d.coordinate} className={`check-row ${d.advisoryCount > 0 ? 'bg-rose-500/[0.05]' : ''}`}>
                      <td className="px-3 py-2 font-mono text-[13px] text-slate-100 [overflow-wrap:anywhere]" title={d.source}>{d.coordinate}</td>
                      <td className="px-3 py-2 font-mono text-[13px] tabular-nums text-slate-400">{d.version}</td>
                      <td className="px-3 py-2 text-right">
                        {d.advisoryCount > 0
                          ? <ToneChip tone="bad">{d.advisoryCount} advisory</ToneChip>
                          : <span className="text-slate-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {rows.length > limit && (
            <div className="mt-3 text-center">
              <FilterChip active={false} onClick={() => setLimit((n) => n + 60)}>Show {Math.min(60, rows.length - limit)} more</FilterChip>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function Trackers({ scan }: { scan: SastScan }) {
  const t = scan.recon.trackers;
  return (
    <Panel title={`Privacy trackers (${t.length})`} subtitle="Known analytics, advertising and attribution SDKs matched by signature. Extracted from the artifact only.">
      {t.length === 0 ? (
        <p className="flex items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.05] px-3.5 py-2.5 text-sm text-emerald-200">
          <span aria-hidden>{'✓'}</span> None detected.
        </p>
      ) : (
        <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2 @3xl:grid-cols-3">
          {t.map((k) => <Kv key={k.name} label={k.category}>{k.name}</Kv>)}
        </dl>
      )}
    </Panel>
  );
}

export function AndroidHardening({ scan }: { scan: SastScan }) {
  return (
    <div className="@container space-y-5">
      <Native scan={scan} />
      <Libraries scan={scan} />
      <Trackers scan={scan} />
    </div>
  );
}
