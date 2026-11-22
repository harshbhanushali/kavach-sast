/**
 * Trust and signing for an Android build: what kind of build it is, who signed
 * it and how, and what it asked the user for.
 *
 * Three questions in order: is this a release build (build kind), does the
 * signature mean anything (schemes and certificates), and what may it do
 * (permissions, each with its protection level and what it allows).
 */
import { useMemo, useState } from 'react';
import type { SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { FilterChip, Kv, Mark, NotPresent, TONE, ToneChip, Well } from '../sast/ui';
import {
  PERM_HINT, PERM_LEVELS, PERM_TONE, SIGNING_SCHEMES, buildKind, isDebugCert, parseSigner, permLevel, schemesOf,
} from './androidModel';
import type { PermLevel } from './androidModel';

function BuildAndSchemes({ scan }: { scan: SastScan }) {
  const a = scan.artifact;
  const x = a.android;
  const kind = buildKind(scan);
  const t = TONE[kind.tone];
  const schemes = schemesOf(scan);

  return (
    <div className="grid items-stretch gap-5 @3xl:grid-cols-2">
      <div className={`flex flex-col rounded-xl border p-5 ${t.chip}`}>
        <p className="eyebrow !text-current opacity-80">Build type</p>
        <p className="mt-1 flex items-center gap-2.5 text-2xl font-semibold text-slate-50">
          <span aria-hidden className={`text-lg ${t.text}`}>{t.glyph}</span>
          {kind.label}
        </p>
        <p className="mt-2 max-w-[52ch] text-sm leading-relaxed text-slate-300">{kind.meaning}</p>
        <dl className="mt-auto grid gap-x-6 gap-y-3 border-t border-white/10 pt-4 sm:grid-cols-2 @3xl:grid-cols-1 @4xl:grid-cols-2">
          {x ? (
            <>
              <Kv label="Debuggable"><span className={x.debuggable ? 'text-rose-300' : 'text-emerald-300'}>{x.debuggable ? '✕ yes' : '✓ no'}</span></Kv>
              <Kv label="Test-only"><span className={x.testOnly ? 'text-rose-300' : 'text-emerald-300'}>{x.testOnly ? '✕ yes' : '✓ no'}</span></Kv>
              <Kv label="Allow backup"><span className={x.allowBackup ? 'text-amber-300' : 'text-emerald-300'}>{x.allowBackup ? '▲ allowed' : '✓ off'}</span></Kv>
              <Kv label="Debug certificate"><span className={isDebugCert(a.signers) ? 'text-rose-300' : 'text-emerald-300'}>{isDebugCert(a.signers) ? '✕ yes' : '✓ no'}</span></Kv>
            </>
          ) : (
            <Kv label="Manifest flags">Not recorded in this scan</Kv>
          )}
        </dl>
      </div>

      <Well title="Signature schemes">
        {a.signatureSchemes.length === 0 && a.signers.length === 0 ? (
          <NotPresent>No signing block was read from this APK.</NotPresent>
        ) : (
          <ul>
            {SIGNING_SCHEMES.filter((s) => s.key !== 'v4' || schemes.has('v4')).map((s) => (
              <li key={s.key} className="flex items-center justify-between gap-4 border-b border-slate-800/70 py-2.5 last:border-0">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-100">{s.label}</p>
                  <p className="text-xs text-slate-500">{s.hint}</p>
                </div>
                <Mark ok={schemes.has(s.key)} yes="present" no="absent" />
              </li>
            ))}
          </ul>
        )}
      </Well>
    </div>
  );
}

function Certificates({ signers }: { signers: string[] }) {
  return (
    <Panel
      title={`Signing certificates (${signers.length})`}
      subtitle="Read from the APK signing block. A signature proves who built it, not that the code is safe."
    >
      {signers.length === 0 ? (
        <NotPresent>No certificate could be read from this APK.</NotPresent>
      ) : (
        <ul className="space-y-3">
          {signers.map((s) => {
            const { subject, rest } = parseSigner(s);
            const debug = isDebugCert([s]);
            return (
              <li key={s} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3.5">
                <div className="mb-2.5">
                  <ToneChip tone={debug ? 'bad' : 'good'} title={debug ? 'The well-known debug key; anyone can sign an update with it' : undefined}>
                    {debug ? 'debug certificate' : 'release certificate'}
                  </ToneChip>
                </div>
                <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2 @3xl:grid-cols-3">
                  {subject.map((p, i) => <Kv key={i} label={p.key || 'Subject'}>{p.value}</Kv>)}
                </dl>
                {rest && <p className="mt-2.5 break-all font-mono text-xs text-slate-400">{rest}</p>}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function Permissions({ scan }: { scan: SastScan }) {
  const all = scan.artifact.permissionDetail;
  const [level, setLevel] = useState<PermLevel | 'all'>('all');
  const [query, setQuery] = useState('');

  const counts = useMemo(() => {
    const c: Record<PermLevel, number> = { dangerous: 0, signature: 0, normal: 0, unknown: 0 };
    for (const p of all) c[permLevel(p.level)] += 1;
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all
      .filter((p) => (level === 'all' || permLevel(p.level) === level) && (!q || `${p.name} ${p.description}`.toLowerCase().includes(q)))
      .sort((a, b) => PERM_LEVELS.indexOf(permLevel(a.level)) - PERM_LEVELS.indexOf(permLevel(b.level)) || a.name.localeCompare(b.name));
  }, [all, level, query]);

  return (
    <Panel
      title={`Permissions (${all.length})`}
      subtitle="Dangerous permissions prompt the user; normal ones are granted silently at install. Riskiest first."
    >
      {all.length === 0 ? (
        <NotPresent>The manifest requests no permissions.</NotPresent>
      ) : (
        <>
          <div className="mb-3.5 flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by protection level">
              <FilterChip active={level === 'all'} onClick={() => setLevel('all')}>All <span className="tabular-nums text-slate-500">{all.length}</span></FilterChip>
              {PERM_LEVELS.filter((l) => counts[l] > 0).map((l) => (
                <FilterChip key={l} active={level === l} title={PERM_HINT[l]} onClick={() => setLevel(level === l ? 'all' : l)}>
                  <span aria-hidden className={`text-[0.65rem] ${TONE[PERM_TONE[l]].text}`}>{TONE[PERM_TONE[l]].glyph}</span>
                  {l} <span className="tabular-nums text-slate-500">{counts[l]}</span>
                </FilterChip>
              ))}
            </div>
            <label className="ml-auto min-w-[12rem]">
              <span className="sr-only">Search permissions</span>
              <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search permissions" className="w-full" />
            </label>
          </div>
          {rows.length === 0 ? (
            <NotPresent>No permission matches.</NotPresent>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[36rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-left">
                    <th scope="col" className="w-32 px-3 py-2 eyebrow">Level</th>
                    <th scope="col" className="px-3 py-2 eyebrow">Permission</th>
                    <th scope="col" className="px-3 py-2 eyebrow">What it allows</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {rows.map((p) => (
                    <tr key={p.name} className="check-row align-top">
                      <td className="px-3 py-2.5"><span title={PERM_HINT[permLevel(p.level)]}><ToneChip tone={PERM_TONE[permLevel(p.level)]}>{p.level}</ToneChip></span></td>
                      <td className="px-3 py-2.5 font-mono text-[13px] text-slate-100 [overflow-wrap:anywhere]" title={p.name}>{p.name.replace('android.permission.', '')}</td>
                      <td className="px-3 py-2.5 text-xs leading-relaxed text-slate-400">{p.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

export function AndroidTrust({ scan }: { scan: SastScan }) {
  return (
    <div className="@container space-y-5">
      <Panel title="Trust and build type" subtitle="What kind of build this is, and how it is signed.">
        <BuildAndSchemes scan={scan} />
      </Panel>
      <Certificates signers={scan.artifact.signers} />
      <Permissions scan={scan} />
    </div>
  );
}
