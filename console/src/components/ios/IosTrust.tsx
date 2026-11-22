/**
 * Trust and signing: who built this, how it is allowed to run, and what the OS
 * has been told it may do.
 *
 * Three questions, in order: what kind of build is this (distribution), is the
 * permission slip still valid (profile timeline), and what did it ask for
 * (entitlements, each with a plain-language note and a risk).
 */
import { useMemo, useState } from 'react';
import type { IosFacts, IosRisk, SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import {
  RISK_ORDER, RISK_TONE, distributionInfo, profileStatus,
} from './iosModel';
import type { ProfileStatus } from './iosModel';
import { formatDate } from '../sast/model';
import { FilterChip, Kv, NotPresent, TONE, ToneChip, Well } from '../sast/ui';

const RISKS: IosRisk[] = ['high', 'medium', 'low', 'info'];
const RISK_LABEL: Record<IosRisk, string> = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

/**
 * A profile's life as a track: created on the left, expiry on the right, "now"
 * as a marker. Past the end, the marker sits on the edge and the bar turns
 * red, so an expired profile looks different from one with a week left even
 * before the words are read.
 */
function ProfileTimeline({ profile, status }: { profile: NonNullable<IosFacts['profile']>; status: ProfileStatus }) {
  const t = TONE[status.tone];
  const pct = status.progress === undefined ? undefined : Math.round(status.progress * 100);
  return (
    <div>
      <p className={`flex items-center gap-2 text-lg font-semibold ${t.text}`}>
        <span aria-hidden className="text-base">{t.glyph}</span>
        <span className="text-slate-50">{status.headline}</span>
      </p>
      {pct !== undefined ? (
        <div className="mt-4">
          <div className="relative h-2 rounded-full bg-slate-800" role="img" aria-label={`${pct}% of the profile's lifetime has elapsed`}>
            <div className={`absolute inset-y-0 left-0 rounded-full ${t.solid} opacity-70`} style={{ width: `${pct}%` }} />
            <div
              className={`absolute top-1/2 size-4 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-slate-950 ${t.solid}`}
              style={{ left: `${Math.min(97, Math.max(3, pct))}%` }}
            />
          </div>
          <div className="mt-2 flex justify-between text-xs text-slate-400">
            <span><span className="text-slate-500">Issued</span> {formatDate(profile.created)}</span>
            <span><span className="text-slate-500">Expires</span> {formatDate(profile.expires)}</span>
          </div>
        </div>
      ) : (
        <p className="mt-2 text-sm text-slate-400">Expires {formatDate(profile.expires)}</p>
      )}
    </div>
  );
}

function Distribution({ ios, now }: { ios: IosFacts; now: number }) {
  const dist = distributionInfo(ios.distribution);
  const status = profileStatus(ios.profile, now);
  const p = ios.profile;
  const t = TONE[dist.tone];
  const debuggable = ios.entitlements.some((e) => e.key === 'get-task-allow' && /^(true|1|yes)$/i.test(e.value.trim()));

  return (
    <div className="grid items-stretch gap-5 @3xl:grid-cols-2">
      <div className={`flex flex-col rounded-xl border p-5 ${t.chip}`}>
        <p className="eyebrow !text-current opacity-80">Distribution</p>
        <p className="mt-1 flex items-center gap-2.5 text-2xl font-semibold text-slate-50">
          <span aria-hidden className={`text-lg ${t.text}`}>{t.glyph}</span>
          {dist.label}
        </p>
        <p className="mt-2 max-w-[52ch] text-sm leading-relaxed text-slate-300">{dist.meaning}</p>
        <dl className="mt-auto grid gap-x-6 gap-y-3 border-t border-white/10 pt-4 sm:grid-cols-2 @3xl:grid-cols-1 @4xl:grid-cols-2">
          <Kv label="Installs on">{dist.installsOn}</Kv>
          <Kv label="Reaches users via">{dist.channel}</Kv>
          <Kv label="Debugger attach">
            <span className={debuggable ? 'text-rose-300' : 'text-emerald-300'}>
              {debuggable ? '\u2715 allowed (get-task-allow)' : '\u2713 blocked'}
            </span>
          </Kv>
          {p?.deviceCount !== undefined && (
            <Kv label="Registered devices">{p.deviceCount}</Kv>
          )}
        </dl>
      </div>

      <Well title="Provisioning profile">
        {p ? (
          <div className="space-y-4">
            <ProfileTimeline profile={p} status={status} />
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-slate-800 pt-3.5">
              <Kv label="Name">{p.name ?? '—'}</Kv>
              <Kv label="Team">{p.teamName ?? '—'}</Kv>
              <Kv label="Team ID" mono>{p.teamId ?? '—'}</Kv>
              <Kv label="Platform">{p.platform ?? '—'}</Kv>
            </dl>
          </div>
        ) : (
          <NotPresent>
            No embedded.mobileprovision. Expected for App Store and TestFlight builds, whose profiles Apple removes on re-signing.
          </NotPresent>
        )}
      </Well>
    </div>
  );
}

function Signing({ ios }: { ios: IosFacts }) {
  const s = ios.signing;
  const source = { binary: 'Signed binary', profile: 'Provisioning profile', none: 'None found' }[s.entitlementsSource];
  return (
    <Panel title="Code signature" subtitle="Read from the main binary's LC_CODE_SIGNATURE. A signature proves who built it, not that the code is safe.">
      <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 @3xl:grid-cols-3">
        <Kv label="Signed">
          <ToneChip tone={s.signed ? 'good' : 'bad'}>{s.signed ? 'signed' : 'unsigned'}</ToneChip>
        </Kv>
        <Kv label="Signature type">
          <ToneChip tone={s.adhoc ? 'warn' : 'good'} title="An ad-hoc signature has no certificate behind it">
            {s.adhoc ? 'ad hoc (no certificate)' : 'certificate-backed'}
          </ToneChip>
        </Kv>
        <Kv label="Entitlements read from">{source}</Kv>
        <Kv label="Team ID" mono>{s.teamId ?? '—'}</Kv>
        <Kv label="Signing identifier" mono>{s.identifier ?? '—'}</Kv>
        <Kv label="Digest">{s.hashType ?? '—'}</Kv>
      </dl>
    </Panel>
  );
}

function Entitlements({ ios }: { ios: IosFacts }) {
  const [risk, setRisk] = useState<IosRisk | 'all'>('all');
  const [query, setQuery] = useState('');
  const all = ios.entitlements;

  const counts = useMemo(() => {
    const c: Record<IosRisk, number> = { high: 0, medium: 0, low: 0, info: 0 };
    for (const e of all) c[e.risk] += 1;
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all
      .filter((e) => (risk === 'all' || e.risk === risk) && (!q || `${e.key} ${e.value} ${e.note}`.toLowerCase().includes(q)))
      .sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || a.key.localeCompare(b.key));
  }, [all, risk, query]);

  return (
    <Panel
      title={`Entitlements (${all.length})`}
      subtitle="Capabilities the OS grants the app beyond the sandbox default. Risky ones first, each with what it means in practice."
    >
      {all.length === 0 ? (
        <NotPresent>No entitlements were found in the binary or the profile.</NotPresent>
      ) : (
        <>
          <div className="mb-3.5 flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by risk">
              <FilterChip active={risk === 'all'} onClick={() => setRisk('all')}>All <span className="tabular-nums text-slate-500">{all.length}</span></FilterChip>
              {RISKS.filter((r) => counts[r] > 0).map((r) => (
                <FilterChip key={r} active={risk === r} onClick={() => setRisk(risk === r ? 'all' : r)}>
                  <span aria-hidden className={`text-[0.65rem] ${TONE[RISK_TONE[r]].text}`}>{TONE[RISK_TONE[r]].glyph}</span>
                  {RISK_LABEL[r]} <span className="tabular-nums text-slate-500">{counts[r]}</span>
                </FilterChip>
              ))}
            </div>
            <label className="ml-auto min-w-[12rem]">
              <span className="sr-only">Search entitlements</span>
              <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search entitlements" className="w-full" />
            </label>
          </div>

          {rows.length === 0 ? (
            <NotPresent>No entitlement matches.</NotPresent>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[40rem] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-left">
                    <th scope="col" className="w-28 px-3 py-2 eyebrow">Risk</th>
                    <th scope="col" className="px-3 py-2 eyebrow">Entitlement</th>
                    <th scope="col" className="px-3 py-2 eyebrow">Value</th>
                    <th scope="col" className="px-3 py-2 eyebrow">What it means</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {rows.map((e) => (
                    <tr key={e.key} className="check-row align-top">
                      <td className="px-3 py-2.5"><ToneChip tone={RISK_TONE[e.risk]}>{RISK_LABEL[e.risk]}</ToneChip></td>
                      <td className="px-3 py-2.5 font-mono text-[13px] text-slate-100 [overflow-wrap:anywhere]">{e.key}</td>
                      <td className="max-w-[16rem] px-3 py-2.5">
                        <span className="line-clamp-2 font-mono text-xs text-slate-300 [overflow-wrap:anywhere]" title={e.value}>{e.value || '—'}</span>
                      </td>
                      <td className="px-3 py-2.5 text-xs leading-relaxed text-slate-400">{e.note || '—'}</td>
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

export function IosTrust({ scan }: { scan: SastScan }) {
  const ios = scan.artifact.ios;
  // A page render is a snapshot: "days left" does not need to tick live.
  const now = useMemo(() => Date.now(), []);

  if (!ios) {
    return (
      <Panel title="Trust and signing">
        <NotPresent>This scan was taken before iOS build facts were recorded. Run it again to see signing and entitlements.</NotPresent>
      </Panel>
    );
  }
  return (
    <div className="@container space-y-5">
      <Panel title="Trust and distribution" subtitle="What kind of build this is, and whether the profile behind it is still valid.">
        <Distribution ios={ios} now={now} />
      </Panel>
      <Signing ios={ios} />
      <Entitlements ios={ios} />
    </div>
  );
}
