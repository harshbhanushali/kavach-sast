/**
 * The Android attack surface: every way another app or a link can reach in, and
 * the network posture the app declares.
 *
 * The tiles are an index; the component table is the evidence. None of these is
 * a vulnerability by itself, they are the places to look. Scans taken before
 * `artifact.android` existed still show the component counts and deep links.
 */
import { useMemo, useState } from 'react';
import type { SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { AnchorSection, FilterChip, NotPresent, SurfaceTile, Tag, ToneChip, jumpTo } from '../sast/ui';
import type { AndroidComponent, SurfaceKey } from './androidModel';
import {
  EXPOSURE, KIND_LABEL, cleartextEndpoints, cleartextState, exposureOf, exposureTone, linkKind, nscPermitsCleartext,
  splitName, surfaceOf,
} from './androidModel';

const TARGET: Partial<Record<SurfaceKey, string>> = {
  components: 'and-surface-components', open: 'and-surface-components', providers: 'and-surface-components',
  links: 'and-surface-links', permissions: 'and-surface-perms', cleartext: 'and-surface-net',
  nsc: 'and-surface-net', features: 'and-surface-features',
};

const KINDS: AndroidComponent['kind'][] = ['activity', 'service', 'receiver', 'provider'];

function Components({ scan }: { scan: SastScan }) {
  const x = scan.artifact.android!;
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<AndroidComponent['kind'] | 'all'>('all');
  const [exportedOnly, setExportedOnly] = useState(false);
  const [unguarded, setUnguarded] = useState(false);
  const [limit, setLimit] = useState(40);
  const [openRow, setOpenRow] = useState<Set<string>>(new Set());

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return x.components
      .filter((c) => (kind === 'all' || c.kind === kind)
        && (!exportedOnly || c.exported)
        && (!unguarded || exposureOf(c, x) === 'open')
        && (!q || `${c.name} ${c.permission ?? ''} ${c.actions.join(' ')} ${c.schemes.join(' ')}`.toLowerCase().includes(q)))
      .sort((a, b) => EXPOSURE[exposureOf(a, x)].rank - EXPOSURE[exposureOf(b, x)].rank || a.name.localeCompare(b.name));
  }, [x, query, kind, exportedOnly, unguarded]);

  const count = (k: AndroidComponent['kind']) => x.components.filter((c) => c.kind === k).length;

  return (
    <AnchorSection
      id="and-surface-components"
      title={`Components (${x.components.length})`}
      subtitle="Everything the manifest declares. Exported ones are reachable by other apps; a guard permission narrows that to apps holding it. Worst exposure first."
    >
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
        <label className="min-w-[12rem] flex-1 @2xl:max-w-xs">
          <span className="sr-only">Search components</span>
          <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, permission, action or scheme" className="w-full" />
        </label>
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter components">
          <FilterChip active={kind === 'all'} onClick={() => setKind('all')}>All kinds</FilterChip>
          {KINDS.filter((k) => count(k) > 0).map((k) => (
            <FilterChip key={k} active={kind === k} onClick={() => setKind(kind === k ? 'all' : k)}>
              {KIND_LABEL[k]} <span className="tabular-nums text-slate-500">{count(k)}</span>
            </FilterChip>
          ))}
          <FilterChip active={exportedOnly} onClick={() => setExportedOnly((v) => !v)}>Exported only</FilterChip>
          <FilterChip active={unguarded} onClick={() => setUnguarded((v) => !v)}>
            <span aria-hidden className="text-[0.65rem] text-rose-300">{'✕'}</span> Unguarded
          </FilterChip>
        </div>
        <span className="ml-auto text-xs tabular-nums text-slate-500">{rows.length} shown</span>
      </div>

      {rows.length === 0 ? (
        <NotPresent>No component matches.</NotPresent>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[46rem] text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/60 text-left">
                {['Component', 'Kind', 'Exposure', 'Guard', 'Entry points'].map((h) => (
                  <th key={h} scope="col" className="px-3 py-2 eyebrow">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {rows.slice(0, limit).map((c) => {
                const e = exposureOf(c, x);
                const { pkg, cls } = splitName(c.name);
                const many = c.actions.length > 2;
                const isOpen = openRow.has(c.name);
                const actions = many && !isOpen ? c.actions.slice(0, 2) : c.actions;
                return (
                  <tr key={c.name} className="check-row align-top">
                    <td className="max-w-[20rem] px-3 py-2.5">
                      <span className="block break-words text-sm font-medium text-slate-100 [overflow-wrap:anywhere]" title={c.name}>{cls}</span>
                      <span className="block truncate font-mono text-[11px] text-slate-500" title={c.name}>{pkg}</span>
                    </td>
                    <td className="px-3 py-2.5 text-xs text-slate-300">{KIND_LABEL[c.kind]}</td>
                    <td className="px-3 py-2.5">
                      <span title={EXPOSURE[e].hint}><ToneChip tone={exposureTone(c, x)}>{EXPOSURE[e].label}</ToneChip></span>
                    </td>
                    <td className="max-w-[14rem] px-3 py-2.5">
                      {c.permission
                        ? <span className="font-mono text-[11px] text-slate-300 [overflow-wrap:anywhere]" title={c.permission}>{c.permission}</span>
                        : <span className={c.exported ? 'text-xs text-rose-300' : 'text-xs text-slate-600'}>{c.exported ? 'none' : '—'}</span>}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-1">
                        {c.browsable && <ToneChip tone="warn" title="Has a BROWSABLE intent filter: a link can open this">deep link</ToneChip>}
                        {c.schemes.map((s) => <Tag key={s}>{s}://</Tag>)}
                        {actions.map((a) => (
                          <span key={a} className="max-w-full break-all font-mono text-[11px] text-slate-400" title={a}>{a.replace(/^android\.intent\.action\./, '')}</span>
                        ))}
                        {many && (
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            onClick={() => setOpenRow((p) => { const n = new Set(p); if (n.has(c.name)) n.delete(c.name); else n.add(c.name); return n; })}
                            className="text-[11px] font-medium text-ember-300 hover:text-ember-200"
                          >
                            {isOpen ? 'fewer' : `+${c.actions.length - 2} more`}
                          </button>
                        )}
                        {!c.browsable && c.schemes.length === 0 && c.actions.length === 0 && <span className="text-xs text-slate-600">—</span>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > limit && (
        <div className="mt-3 text-center">
          <FilterChip active={false} onClick={() => setLimit((n) => n + 60)}>Show {Math.min(60, rows.length - limit)} more</FilterChip>
        </div>
      )}
    </AnchorSection>
  );
}

/** Counts only: what an old scan still knows about its components. */
function ComponentCounts({ scan }: { scan: SastScan }) {
  const c = scan.artifact.components;
  return (
    <Panel
      title="Application components"
      subtitle="This scan predates per-component facts, so only the counts are known. Run it again to see each component, its guard permission and its entry points."
    >
      <dl className="grid grid-cols-2 gap-3 @2xl:grid-cols-5">
        {([['Activities', c.activities], ['Services', c.services], ['Receivers', c.receivers], ['Providers', c.providers], ['Exported', c.exported]] as const).map(([l, n]) => (
          <div key={l} className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2.5">
            <dt className="eyebrow">{l}</dt>
            <dd className={`mt-0.5 text-2xl font-bold tabular-nums ${l === 'Exported' && n > 0 ? 'text-amber-300' : 'text-slate-100'}`}>{n}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

export function AndroidSurface({ scan }: { scan: SastScan }) {
  const a = scan.artifact;
  const x = a.android;
  const tiles = useMemo(() => surfaceOf(scan), [scan]);
  const links = a.components.browsable;
  const cleartext = cleartextEndpoints(scan);
  const ct = cleartextState(scan);
  const byComponent = links.reduce<Record<string, typeof links>>((acc, l) => { (acc[l.component] ??= []).push(l); return acc; }, {});

  const absent = [
    links.length === 0 && { label: 'Deep links', why: 'no intent filter lets a link open the app' },
    x && x.customPermissions.length === 0 && { label: 'Custom permissions', why: 'no permission is declared for other apps to request' },
    x && x.usesFeatures.length === 0 && { label: 'Hardware features', why: 'no uses-feature declarations' },
    cleartext.length === 0 && { label: 'Plain http:// URLs', why: 'none found in code or resources' },
  ].filter((v): v is { label: string; why: string } => !!v);

  return (
    <div className="@container space-y-5">
      <div className="grid grid-cols-2 gap-3 @2xl:grid-cols-4">
        {tiles.map((t) => {
          const target = TARGET[t.key];
          const goes = target && (typeof t.value === 'number' ? t.value > 0 : t.value !== '—') && !(t.key === 'components' && !x);
          return (
            <SurfaceTile
              key={t.key} label={t.label} value={t.value} tone={t.tone} summary={t.summary}
              onClick={goes ? () => jumpTo(target) : undefined}
            />
          );
        })}
      </div>

      {x ? <Components scan={scan} /> : <ComponentCounts scan={scan} />}

      <div className="grid items-start gap-5 @3xl:grid-cols-2">
        <div className="space-y-5">
          {links.length > 0 && (
            <AnchorSection
              id="and-surface-links"
              title={`Deep links (${links.length})`}
              subtitle="Intent filters a link can open. A custom scheme can be claimed by any app; an https link can be verified against the site with autoVerify."
            >
              <ul className="space-y-2.5">
                {Object.entries(byComponent).map(([comp, list]) => (
                  <li key={comp} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                    <p className="break-all font-mono text-xs text-slate-400" title={comp}>{splitName(comp).cls}</p>
                    <ul className="mt-1.5 space-y-1">
                      {list.map((l, i) => (
                        <li key={i} className="flex flex-wrap items-center gap-1.5 text-[13px]">
                          <span className="font-mono text-slate-200">
                            {l.schemes.join(', ')}{l.hosts.length > 0 ? ` @ ${l.hosts.join(', ')}` : ''}
                          </span>
                          {linkKind(l.schemes) !== 'web' && <ToneChip tone="warn" title="Any installed app can register the same scheme">custom scheme</ToneChip>}
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            </AnchorSection>
          )}

          {x && x.customPermissions.length > 0 && (
            <AnchorSection
              id="and-surface-perms"
              title={`Custom permissions (${x.customPermissions.length})`}
              subtitle="Permissions this app declares for other apps to request. Only a signature-level one keeps out apps from other developers."
            >
              <ul className="divide-y divide-slate-800/70">
                {x.customPermissions.map((p) => {
                  const sig = p.protection.startsWith('signature');
                  return (
                    <li key={p.name} className="flex flex-wrap items-center justify-between gap-2 py-2 first:pt-0 last:pb-0">
                      <span className="font-mono text-[13px] text-slate-100 [overflow-wrap:anywhere]">{p.name}</span>
                      <ToneChip tone={sig ? 'good' : 'warn'}>{p.protection || 'normal'}</ToneChip>
                    </li>
                  );
                })}
              </ul>
            </AnchorSection>
          )}
        </div>

        <div className="space-y-5">
          <AnchorSection
            id="and-surface-net"
            title="Network posture"
            subtitle="Android blocks plain HTTP for apps targeting API 28+ unless the manifest or a network security config says otherwise."
            actions={ct && <ToneChip tone={ct.tone}>{ct.state}</ToneChip>}
          >
            {x ? (
              <ul>
                <li className="flex items-start justify-between gap-4 border-b border-slate-800/70 py-2.5">
                  <div className="min-w-0">
                    <p className="font-mono text-[13px] text-slate-100">usesCleartextTraffic</p>
                    <p className="mt-0.5 text-xs text-slate-500">{x.cleartextTraffic === undefined ? 'Not set: the platform default for the target SDK applies.' : 'Manifest attribute on the application.'}</p>
                  </div>
                  <ToneChip tone={x.cleartextTraffic ? 'bad' : x.cleartextTraffic === false ? 'good' : 'muted'}>
                    {x.cleartextTraffic === undefined ? 'unset' : x.cleartextTraffic ? 'true' : 'false'}
                  </ToneChip>
                </li>
                <li className="flex items-start justify-between gap-4 py-2.5">
                  <div className="min-w-0">
                    <p className="font-mono text-[13px] text-slate-100">networkSecurityConfig</p>
                    <p className="mt-0.5 text-xs text-slate-500">
                      {nscPermitsCleartext(scan) ? 'The config permits cleartext traffic (see the finding).' : x.networkSecurityConfig ? 'The app ships its own per-domain trust rules.' : 'None: platform TLS defaults apply.'}
                    </p>
                  </div>
                  <ToneChip tone={nscPermitsCleartext(scan) ? 'bad' : x.networkSecurityConfig ? 'info' : 'good'}>
                    {nscPermitsCleartext(scan) ? 'permits cleartext' : x.networkSecurityConfig ? 'custom' : 'default'}
                  </ToneChip>
                </li>
              </ul>
            ) : (
              <NotPresent>Manifest network flags were not recorded in this scan.</NotPresent>
            )}
            {cleartext.length > 0 && (
              <div className="mt-3.5 border-t border-slate-800 pt-3">
                <p className="eyebrow mb-1.5 !text-rose-300">Cleartext endpoints ({cleartext.length})</p>
                <ul className="space-y-0.5">
                  {cleartext.slice(0, 15).map((e) => <li key={e.url} className="break-all font-mono text-xs text-slate-400">{e.url}</li>)}
                </ul>
                {cleartext.length > 15 && <p className="mt-1 text-xs text-slate-500">{cleartext.length - 15} more on the Domains tab.</p>}
              </div>
            )}
          </AnchorSection>

          {x && x.usesFeatures.length > 0 && (
            <AnchorSection
              id="and-surface-features"
              title={`Hardware features (${x.usesFeatures.length})`}
              subtitle="Declared with uses-feature. A required feature limits who can install the app; an optional one is just a capability it may use."
            >
              <ul className="flex flex-wrap gap-2">
                {x.usesFeatures.map((f) => (
                  <li key={f.name}>
                    <ToneChip tone={f.required ? 'warn' : 'info'} title={f.required ? 'required' : 'optional'}>
                      {f.name.replace(/^android\.(hardware|software)\./, '')} <span className="opacity-70">{f.required ? 'required' : 'optional'}</span>
                    </ToneChip>
                  </li>
                ))}
              </ul>
            </AnchorSection>
          )}
        </div>
      </div>

      {absent.length > 0 && (
        <Panel title="Not present in this build" subtitle="Nothing to review here.">
          <ul className="grid gap-x-8 gap-y-2 @2xl:grid-cols-2">
            {absent.map((v) => (
              <li key={v.label} className="flex items-start gap-2 text-sm">
                <span aria-hidden className="mt-0.5 text-xs text-emerald-400">{'✓'}</span>
                <span>
                  <span className="font-medium text-slate-200">{v.label}</span>
                  <span className="text-slate-500"> {'—'} {v.why}</span>
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
