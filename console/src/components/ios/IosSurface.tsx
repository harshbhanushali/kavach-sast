/**
 * The attack surface: every way something outside the app can reach in, or the
 * app can reach out, that the build declares.
 *
 * The tiles are an index. Each one states how many entry points of that kind
 * exist and whether that number is a concern, and jumps to the list below it.
 * None of these is a vulnerability by itself; they are the places to look.
 */
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { IosFacts, SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import {
  SERVICE_LABEL, backgroundMode, extensionKind, parseAssociatedDomain, surfaceOf,
} from './iosModel';
import type { SurfaceItem } from './iosModel';
import { AnchorSection as Section, FilterChip, NotPresent, SurfaceTile, Tag, ToneChip, jumpTo } from '../sast/ui';

function AtsFlag({ label, hint, on, badWhenOn = true }: { label: string; hint: string; on: boolean; badWhenOn?: boolean }) {
  const tone = on ? (badWhenOn ? 'bad' : 'info') : 'good';
  return (
    <li className="flex items-start justify-between gap-4 border-b border-slate-800/70 py-2.5 last:border-0">
      <div className="min-w-0">
        <p className="font-mono text-[13px] text-slate-100">{label}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-slate-500">{hint}</p>
      </div>
      <ToneChip tone={tone}>{on ? 'enabled' : 'off'}</ToneChip>
    </li>
  );
}

function Ats({ ats }: { ats: IosFacts['ats'] }) {
  const exceptions = ats.domains.filter((d) => d.allowsHttp).length;

  return (
    <Panel
      title="App Transport Security"
      subtitle="iOS refuses plain HTTP and weak TLS by default. Anything listed here is the app opting out of that."
      actions={
        <ToneChip tone={ats.arbitraryLoads ? 'bad' : exceptions ? 'warn' : 'good'}>
          {ats.arbitraryLoads ? 'Arbitrary loads allowed' : exceptions ? `${exceptions} HTTP exception${exceptions === 1 ? '' : 's'}` : 'Enforced'}
        </ToneChip>
      }
    >
      <div className="grid gap-6 @3xl:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <ul>
          <AtsFlag
            label="NSAllowsArbitraryLoads"
            hint="Turns ATS off for every connection. Traffic can be read or altered on the network."
            on={ats.arbitraryLoads}
          />
          <AtsFlag
            label="…InWebContent"
            hint="Same relaxation, but only for WKWebView and Safari-style content."
            on={ats.arbitraryLoadsInWebContent}
          />
          <AtsFlag
            label="…ForMedia"
            hint="Allows plain HTTP for AV Foundation media loads."
            on={ats.arbitraryLoadsForMedia}
          />
          <AtsFlag
            label="NSAllowsLocalNetworking"
            hint="Allows unencrypted connections to local hosts and .local names."
            on={ats.localNetworking}
            badWhenOn={false}
          />
        </ul>
        <div className="min-w-0">
          {ats.domains.length === 0 ? (
            <NotPresent>No per-domain exceptions.</NotPresent>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[30rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-left">
                    {['Domain', 'HTTP', 'Min TLS', 'Fwd secrecy'].map((h) => (
                      <th key={h} scope="col" className="px-3 py-2 eyebrow">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {ats.domains.map((d) => (
                    <tr key={d.domain} className="check-row">
                      <td className="px-3 py-2">
                        <span className="font-mono text-[13px] text-slate-100">{d.domain}</span>
                        <span className="ml-2 inline-flex gap-1 align-middle">
                          {d.includesSubdomains && <Tag mono={false} title="Applies to all subdomains">+subdomains</Tag>}
                          {d.thirdParty && <Tag mono={false} title="Not a host the app itself owns">3rd party</Tag>}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <ToneChip tone={d.allowsHttp ? 'bad' : 'good'}>{d.allowsHttp ? 'allowed' : 'blocked'}</ToneChip>
                      </td>
                      <td className="px-3 py-2 font-mono text-[13px] text-slate-300">{d.minTls ?? 'default'}</td>
                      <td className="px-3 py-2">
                        {d.forwardSecrecy === undefined
                          ? <span className="text-slate-500">default</span>
                          : <ToneChip tone={d.forwardSecrecy ? 'good' : 'warn'}>{d.forwardSecrecy ? 'required' : 'not required'}</ToneChip>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}

export function IosSurface({ scan, onNavigate }: { scan: SastScan; onNavigate: (t: 'trust') => void }) {
  const ios = scan.artifact.ios;
  const [showAllQueried, setShowAllQueried] = useState(false);
  const tiles = useMemo(() => (ios ? surfaceOf(ios) : []), [ios]);

  if (!ios) {
    return (
      <Panel title="Attack surface">
        <NotPresent>This scan was taken before iOS build facts were recorded. Run it again to see the attack surface.</NotPresent>
      </Panel>
    );
  }

  const schemes = ios.urlSchemes;
  const domains = ios.associatedDomains.map(parseAssociatedDomain);
  const byService = domains.reduce<Record<string, typeof domains>>((acc, d) => {
    (acc[d.service] ??= []).push(d);
    return acc;
  }, {});
  const atsDeclared = ios.ats.configured || ios.ats.arbitraryLoads || ios.ats.domains.length > 0;
  const absent = [
    schemes.length === 0 && { label: 'Custom URL schemes', why: 'no other app can open this one by scheme' },
    domains.length === 0 && { label: 'Associated domains', why: 'no universal links or shared web credentials' },
    ios.extensions.length === 0 && { label: 'App extensions', why: 'everything runs inside the main app' },
    ios.backgroundModes.length === 0 && { label: 'Background modes', why: 'the app is suspended when backgrounded' },
    ios.queriedSchemes.length === 0 && { label: 'Queried schemes', why: 'the app cannot probe for other installed apps' },
    !atsDeclared && { label: 'ATS exceptions', why: 'no NSAppTransportSecurity block, so iOS enforces HTTPS, TLS 1.2 and forward secrecy' },
  ].filter((x): x is { label: string; why: string } => !!x);
  const queried = showAllQueried ? ios.queriedSchemes : ios.queriedSchemes.slice(0, 24);

  const target: Record<SurfaceItem['key'], string> = {
    schemes: 'ios-surface-schemes', links: 'ios-surface-links', ats: 'ios-surface-ats',
    extensions: 'ios-surface-ext', background: 'ios-surface-bg', queried: 'ios-surface-queried',
    entitlements: '', privacy: '',
  };

  // Each populated section becomes a card; cards are dealt into two columns by
  // rough height so the columns balance without leaving a gap under a short one.
  const cards: { key: string; weight: number; node: ReactNode }[] = [];
  if (schemes.length > 0) {
    cards.push({
      key: 'schemes',
      weight: schemes.length + 1,
      node: (
        <Section
          id="ios-surface-schemes"
          title={`Custom URL schemes (${schemes.flatMap((s) => s.schemes).length})`}
          subtitle="Any app on the device can open these. Every parameter that reaches the app this way is untrusted input, and a scheme is not owned by whoever registers it first."
        >
          <ul className="space-y-2.5">
            {schemes.map((u, i) => (
              <li key={i} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                <div className="flex flex-wrap gap-1.5">
                  {u.schemes.map((s) => (
                    <code key={s} className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[13px] text-amber-200 ring-1 ring-inset ring-amber-500/30">
                      {s}://
                    </code>
                  ))}
                </div>
                {(u.name || u.role) && (
                  <p className="mt-1.5 text-xs text-slate-500">
                    {u.name && <span className="font-mono">{u.name}</span>}
                    {u.name && u.role && ' \u00b7 '}
                    {u.role && <span>{u.role}</span>}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </Section>
      ),
    });
  }
  if (domains.length > 0) {
    cards.push({
      key: 'links',
      weight: domains.length + 2,
      node: (
        <Section
          id="ios-surface-links"
          title={`Associated domains (${domains.length})`}
          subtitle="Web domains tied to the app. Universal links open it from a tap on a URL, and unlike a scheme they are verified against the site."
        >
          <div className="space-y-3">
            {Object.entries(byService).map(([service, list]) => (
              <div key={service}>
                <p className="eyebrow mb-1.5">{SERVICE_LABEL[service] ?? service}</p>
                <ul className="space-y-1">
                  {list.map((d, i) => (
                    <li key={i} className="flex flex-wrap items-center gap-2 font-mono text-[13px] text-slate-200">
                      {d.host}
                      {d.developer && (
                        <ToneChip tone="warn" title="?mode=developer bypasses Apple's CDN and is meant for testing only">developer mode</ToneChip>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Section>
      ),
    });
  }
  if (ios.extensions.length > 0) {
    cards.push({
      key: 'ext',
      weight: ios.extensions.length + 1,
      node: (
        <Section
          id="ios-surface-ext"
          title={`App extensions (${ios.extensions.length})`}
          subtitle="Separate processes shipped inside the app. Each one is another entry point with its own inputs."
        >
          <ul className="divide-y divide-slate-800/70">
            {ios.extensions.map((e) => (
              <li key={e.name} className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 py-2 first:pt-0 last:pb-0">
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-slate-100">{e.name}</span>
                  {e.bundleId && <span className="block truncate font-mono text-xs text-slate-500">{e.bundleId}</span>}
                </span>
                <span title={e.point}><Tag mono={false}>{extensionKind(e.point)}</Tag></span>
              </li>
            ))}
          </ul>
        </Section>
      ),
    });
  }
  if (ios.backgroundModes.length > 0) {
    cards.push({
      key: 'bg',
      weight: 2,
      node: (
        <Section
          id="ios-surface-bg"
          title={`Background modes (${ios.backgroundModes.length})`}
          subtitle="Work the app is allowed to keep doing after the user leaves it."
        >
          <ul className="flex flex-wrap gap-2">
            {ios.backgroundModes.map((m) => {
              const { label, sensitive } = backgroundMode(m);
              return (
                <li key={m}>
                  <ToneChip
                    tone={sensitive ? 'warn' : 'info'}
                    title={sensitive ? `${m}: can track or listen while the app is not visible` : m}
                  >
                    {label}
                  </ToneChip>
                </li>
              );
            })}
          </ul>
        </Section>
      ),
    });
  }
  const left: ReactNode[] = [];
  const right: ReactNode[] = [];
  let leftWeight = 0;
  let rightWeight = 0;
  for (const c of cards) {
    const node = <div key={c.key}>{c.node}</div>;
    if (leftWeight <= rightWeight) { left.push(node); leftWeight += c.weight; }
    else { right.push(node); rightWeight += c.weight; }
  }

  return (
    <div className="@container space-y-5">
      <div className="grid grid-cols-2 gap-3 @2xl:grid-cols-4">
        {tiles.map((item) => (
          <SurfaceTile
            key={item.key}
            label={item.label}
            value={item.count}
            tone={item.tone}
            summary={item.summary}
            // A count of zero has no section to jump to, so it is not a button.
            onClick={
              item.key === 'entitlements'
                ? () => onNavigate('trust')
                : item.count > 0 || (item.key === 'ats' && atsDeclared)
                  ? () => jumpTo(target[item.key])
                  : undefined
            }
          />
        ))}
        <SurfaceTile
          label="Privacy manifest"
          value={ios.privacyManifest ? 'Yes' : 'No'}
          tone={ios.privacyManifest ? 'good' : 'warn'}
          summary={ios.privacyManifest ? 'PrivacyInfo.xcprivacy bundled' : 'No privacy manifest found'}
        />
      </div>

      {/* Only what the build actually declares gets a panel. The rest is listed
          once at the end, so a quiet app is not a page of empty boxes. */}
      <div className="grid items-start gap-5 @3xl:grid-cols-2">
        {[left, right].map((col, i) => (
          <div key={i} className="space-y-5">{col}</div>
        ))}
      </div>

      {ios.queriedSchemes.length > 0 && (
        <Section
          id="ios-surface-queried"
          title={`Queried schemes (${ios.queriedSchemes.length})`}
          subtitle="Schemes the app may ask iOS about with canOpenURL. It is how an app learns which other apps are installed; iOS caps the list at 50."
        >
          <ul className="flex flex-wrap gap-1.5">
            {queried.map((s) => (
              <li key={s}><Tag>{s}</Tag></li>
            ))}
          </ul>
          {ios.queriedSchemes.length > 24 && (
            <div className="mt-3">
              <FilterChip active={showAllQueried} onClick={() => setShowAllQueried((v) => !v)}>
                {showAllQueried ? 'Show fewer' : `Show all ${ios.queriedSchemes.length}`}
              </FilterChip>
            </div>
          )}
        </Section>
      )}

      {absent.length > 0 && (
        <Panel title="Not present in this build" subtitle="Nothing to review here.">
          <ul className="grid gap-x-8 gap-y-2 @2xl:grid-cols-2">
            {absent.map((a) => (
              <li key={a.label} className="flex items-start gap-2 text-sm">
                <span aria-hidden className="mt-0.5 text-xs text-emerald-400">{'\u2713'}</span>
                <span>
                  <span className="font-medium text-slate-200">{a.label}</span>
                  <span className="text-slate-500"> {'\u2014'} {a.why}</span>
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {atsDeclared && (
        <div id="ios-surface-ats" tabIndex={-1} className="scroll-mt-4 outline-none">
          <Ats ats={ios.ats} />
        </div>
      )}
    </div>
  );
}
