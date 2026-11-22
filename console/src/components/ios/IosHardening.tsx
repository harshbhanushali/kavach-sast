/**
 * Binary hardening: the main executable, then every Mach-O bundled with it.
 *
 * The bundled binaries use the shared hardening matrix (`sast/BinaryMatrix`),
 * which leads with the weakest ones and shows the rest as one row per binary and
 * one column per protection.
 */
import { useMemo, useState } from 'react';
import type { IosFacts, SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { PROTECTIONS } from './iosModel';
import type { IosBinary } from './iosModel';
import { formatBytes } from '../sast/model';
import { BinaryMatrix } from '../sast/BinaryMatrix';
import type { MatrixCopy, MatrixRow } from '../sast/BinaryMatrix';
import { Kv, Mark, NotPresent, Tag, ToneChip } from '../sast/ui';

const KIND_LABEL: Record<IosBinary['kind'], string> = {
  framework: 'Framework', dylib: 'Dylib', extension: 'Extension', watch: 'Watch',
};

function MainBinary({ scan, ios }: { scan: SastScan; ios: IosFacts }) {
  const m = ios.main;
  const bp = scan.artifact.binaryProtections;
  const [showLibs, setShowLibs] = useState(false);

  // Bundled libraries resolve through @rpath or the app directory; the rest are the OS's.
  const bundled = m.linkedLibraries.filter((l) => /^@(rpath|executable_path|loader_path)/.test(l));
  const system = m.linkedLibraries.filter((l) => !bundled.includes(l));

  const cells: { label: string; hint: string; ok: boolean; yes?: string; no?: string; known: boolean }[] = [
    { label: 'PIE / ASLR', hint: 'Loads at a random address', ok: !!bp?.pie, known: !!bp, yes: 'enabled', no: 'missing' },
    { label: 'ARC', hint: 'Compiler-managed memory', ok: !!bp?.arc, known: !!bp, yes: 'enabled', no: 'missing' },
    { label: 'Stack canary', hint: 'Stack smashing detected', ok: !!bp?.stackCanary, known: !!bp, yes: 'enabled', no: 'missing' },
    { label: 'Non-exec stack', hint: 'Stack pages cannot run code', ok: !!bp?.nonExecutableStack, known: !!bp, yes: 'enabled', no: 'missing' },
    { label: 'Stripped', hint: `${m.localSymbols.toLocaleString()} local symbols left`, ok: m.stripped, known: true, yes: 'stripped', no: 'symbols kept' },
    { label: 'Signed', hint: 'Has a code signature', ok: ios.signing.signed, known: true, yes: 'signed', no: 'unsigned' },
  ];

  return (
    <Panel
      title="Main binary"
      subtitle={`${ios.executable ?? 'Executable'} · the code that runs first. Read from its Mach-O load commands.`}
      actions={
        <>
          {m.swift && <Tag mono={false}>Swift</Tag>}
          {m.objc && <Tag mono={false}>Objective-C</Tag>}
        </>
      }
    >
      <ul className="grid grid-cols-2 gap-2.5 @2xl:grid-cols-3 @5xl:grid-cols-6">
        {cells.map((c) => (
          <li
            key={c.label}
            title={c.hint}
            className={`flex items-center gap-2.5 rounded-lg border px-3 py-2.5 ${
              !c.known ? 'border-slate-800 bg-slate-900/40' : c.ok ? 'border-emerald-500/25 bg-emerald-500/[0.05]' : 'border-rose-500/35 bg-rose-500/[0.07]'
            }`}
          >
            {c.known ? <Mark ok={c.ok} yes={c.yes} no={c.no} /> : <span className="text-slate-500">{'–'}</span>}
            <span className="min-w-0">
              <span className="block text-sm font-medium leading-tight text-slate-100">{c.label}</span>
              <span className="block text-xs text-slate-500">{c.known ? (c.ok ? c.yes : c.no) : 'unknown'}</span>
            </span>
          </li>
        ))}
      </ul>

      <dl className="mt-5 grid gap-x-8 gap-y-4 border-t border-slate-800 pt-4 sm:grid-cols-2 @3xl:grid-cols-4">
        <Kv label="Architecture">{[m.arch, m.cpu].filter(Boolean).join(' · ') || '—'}</Kv>
        <Kv label="Minimum iOS">{m.minOs ?? '—'}</Kv>
        <Kv label="Built with SDK">{m.sdk ?? ios.sdkName ?? '—'}</Kv>
        <Kv label="Size">{formatBytes(m.sizeBytes)}</Kv>
        <Kv label="Encryption">
          <ToneChip tone={m.encrypted ? 'good' : 'muted'} title={m.encrypted ? 'FairPlay encrypted: strings are unreadable in this copy' : 'Not encrypted. Expected outside the App Store.'}>
            {m.encrypted ? 'FairPlay' : 'not encrypted'}
          </ToneChip>
        </Kv>
        <Kv label="Local symbols">{m.localSymbols.toLocaleString()}</Kv>
        <Kv label="Runpaths" mono>{m.rpaths.length ? m.rpaths.join(', ') : '—'}</Kv>
        <Kv label="UUID" mono>{m.uuid ?? '—'}</Kv>
      </dl>

      {m.linkedLibraries.length > 0 && (
        <div className="mt-4 border-t border-slate-800 pt-3.5">
          <button
            type="button"
            onClick={() => setShowLibs((v) => !v)}
            aria-expanded={showLibs}
            className="flex w-full items-center justify-between gap-3 text-left"
          >
            <span className="text-sm font-medium text-slate-200">
              Linked libraries
              <span className="ml-2 text-xs font-normal text-slate-500">
                {system.length} system · {bundled.length} bundled{m.weakLibraries.length ? ` · ${m.weakLibraries.length} weak` : ''}
              </span>
            </span>
            <span aria-hidden className={`text-slate-500 transition-transform ${showLibs ? 'rotate-90' : ''}`}>{'›'}</span>
          </button>
          {showLibs && (
            <div className="mt-3 grid gap-4 @3xl:grid-cols-2">
              {[['Bundled with the app', bundled], ['System', system]].map(([title, list]) => (
                <div key={title as string}>
                  <p className="eyebrow mb-1.5">{title as string}</p>
                  {(list as string[]).length === 0 ? (
                    <p className="text-xs text-slate-500">None.</p>
                  ) : (
                    <ul className="max-h-56 space-y-0.5 overflow-y-auto pr-2">
                      {(list as string[]).map((l) => (
                        <li key={l} className="break-all font-mono text-xs text-slate-400">
                          {l}
                          {m.weakLibraries.includes(l) && <span className="ml-1.5 text-amber-300">weak</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

const COPY: MatrixCopy = {
  title: 'Bundled binaries',
  emptySubtitle: 'Frameworks, dylibs and extensions embedded in the app.',
  empty: 'This build embeds no frameworks, dylibs or extensions. Everything runs from the main binary.',
  allGood: 'Every embedded binary has all four protections.',
  columnLabel: 'Binary',
  tableTitle: 'All binaries',
  searchLabel: 'Search binaries',
  searchPlaceholder: 'Search name, path or bundle id',
  nounPlural: 'binaries',
  noMatch: 'No binary matches.',
};

function Bundled({ binaries }: { binaries: IosBinary[] }) {
  const rows = useMemo<MatrixRow[]>(() => binaries.map((b) => ({
    id: b.path,
    name: b.name,
    kind: b.kind,
    note: b.swift ? 'Swift' : undefined,
    sub: `${b.version ? `v${b.version} · ` : ''}${b.bundleId ?? b.path}`,
    subTitle: b.path,
    weakSub: `${KIND_LABEL[b.kind]}${b.version ? ` · ${b.version}` : ''} \u00b7 ${formatBytes(b.sizeBytes)}`,
    sizeBytes: b.sizeBytes,
    searchText: `${b.path} ${b.bundleId ?? ''}`,
    checks: Object.fromEntries(PROTECTIONS.map((p) => [p.key, b[p.key] ? 'yes' : 'no'])) as MatrixRow['checks'],
  })), [binaries]);
  return <BinaryMatrix copy={COPY} protections={[...PROTECTIONS]} rows={rows} kindLabels={KIND_LABEL} />;
}

export function IosHardening({ scan }: { scan: SastScan }) {
  const ios = scan.artifact.ios;
  if (!ios) {
    return (
      <Panel title="Binary hardening">
        <NotPresent>This scan was taken before iOS build facts were recorded. Run it again to see per-binary hardening.</NotPresent>
      </Panel>
    );
  }
  return (
    <div className="@container space-y-5">
      <MainBinary scan={scan} ios={ios} />
      <Bundled binaries={ios.binaries} />
    </div>
  );
}
