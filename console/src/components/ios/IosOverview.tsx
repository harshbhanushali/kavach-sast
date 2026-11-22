/**
 * The iOS overview: the hero, then three lenses on the build, then what to do
 * first. Each lens is a digest of a tab of its own and links to it, so the
 * overview answers "where do I look" without becoming the whole report.
 */
import type { ReactNode } from 'react';
import type { SastScan } from '../../sastTypes';
import { Panel } from '../ui';
import { SastHero } from '../sast/Hero';
import { controlsOf, formatBytes, verdictOf } from '../sast/model';
import type { Navigate } from '../sast/model';
import { ControlsLens } from '../sast/Controls';
import { FixFirst, Lens, Scorecard } from '../sast/OverviewParts';
import { Kv, Mark, Tag, TONE, ToneChip } from '../sast/ui';
import {
  PROTECTIONS, deriveSignals, distributionInfo, hardeningScore, profileStatus, riskyEntitlements, surfaceOf,
} from './iosModel';

export function IosOverview({
  scan, onNavigate, children,
}: { scan: SastScan; onNavigate: Navigate; children?: ReactNode }) {
  const a = scan.artifact;
  const ios = a.ios;
  const now = Date.now();

  const dist = distributionInfo(ios?.distribution);
  const team = ios?.profile?.teamName ?? ios?.signing.teamId;
  const devices = ios?.deviceFamily ?? [];
  const deviceLabel = [devices.includes('1') && 'iPhone', devices.includes('2') && 'iPad'].filter(Boolean).join(' + ');
  const verdict = verdictOf(scan, ios?.distribution === 'development' ? 'This is a development-signed build, not a release build.' : undefined);

  return (
    <div className="@container space-y-5">
      <SastHero
        scan={scan}
        onNavigate={onNavigate}
        verdict={verdict}
        signals={deriveSignals(scan)}
        chips={
          <>
            {ios && <ToneChip tone={dist.tone} title={dist.meaning}>{dist.label} build</ToneChip>}
            <Tag mono={false}>v{a.versionName ?? '?'}{a.versionCode ? ` (${a.versionCode})` : ''}</Tag>
            <Tag mono={false}>iOS {a.minimumOsVersion ?? ios?.main.minOs ?? '?'}+</Tag>
            {deviceLabel && <Tag mono={false}>{deviceLabel}</Tag>}
            {team && <Tag mono={false} title="Signing team">{'\u2318'} {team}</Tag>}
            <Tag mono={false} title={a.fileName}>{formatBytes(a.sizeBytes)}</Tag>
          </>
        }
      />

      {/* build facts + integrity */}
      <Panel title="Build and file" subtitle="What produced this artifact, and the digests that identify it.">
        <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 @3xl:grid-cols-4">
          <Kv label="File">{a.fileName}</Kv>
          <Kv label="Size">{formatBytes(a.sizeBytes)}</Kv>
          <Kv label="Files in bundle">{(ios?.fileCount ?? a.fileCount).toLocaleString()}</Kv>
          <Kv label="Info.plist keys">{ios ? ios.plistKeys.toLocaleString() : '—'}</Kv>
          <Kv label="Xcode" mono>{ios?.xcode ?? '—'}</Kv>
          <Kv label="SDK">{ios?.sdkName ?? '—'}</Kv>
          <Kv label="Build OS" mono>{ios?.buildOs ?? '—'}</Kv>
          <Kv label="Requires">{ios?.requiredCapabilities.join(', ') || '—'}</Kv>
        </dl>
        {children}
      </Panel>

      {ios && (
        <div className={`grid gap-4 ${controlsOf(scan) ? '@3xl:grid-cols-2 @6xl:grid-cols-4' : '@3xl:grid-cols-3'}`}>
          {/* attack surface */}
          <Lens title="Attack surface" cta="Open attack surface" onClick={() => onNavigate('surface')}>
            <ul className="space-y-1.5">
              {surfaceOf(ios).filter((s) => s.key !== 'privacy').map((s) => (
                <li key={s.key} className="flex items-center justify-between gap-3 text-sm">
                  <span className="flex items-center gap-2 text-slate-300">
                    <span aria-hidden className={`w-3 text-center text-[0.65rem] ${TONE[s.tone].text}`}>{TONE[s.tone].glyph}</span>
                    {s.label}
                  </span>
                  <span className={`font-semibold tabular-nums ${s.count ? 'text-slate-50' : 'text-slate-600'}`}>{s.count}</span>
                </li>
              ))}
            </ul>
          </Lens>

          {/* trust */}
          <Lens title="Trust and signing" cta="Open trust and signing" onClick={() => onNavigate('trust')}>
            {(() => {
              const dist = distributionInfo(ios.distribution);
              const status = profileStatus(ios.profile, now);
              const risky = riskyEntitlements(ios);
              const high = risky.filter((e) => e.risk === 'high').length;
              return (
                <>
                  <ToneChip tone={dist.tone} title={dist.meaning}>{dist.label} distribution</ToneChip>
                  <p className={`flex items-start gap-2 text-sm ${TONE[status.tone].text}`}>
                    <span aria-hidden className="mt-0.5 text-[0.65rem]">{TONE[status.tone].glyph}</span>
                    <span className="text-slate-200">{status.headline}</span>
                  </p>
                  <p className={`flex items-start gap-2 text-sm ${risky.length ? (high ? 'text-rose-300' : 'text-amber-300') : 'text-emerald-300'}`}>
                    <span aria-hidden className="mt-0.5 text-[0.65rem]">{risky.length ? (high ? '✕' : '▲') : '✓'}</span>
                    <span className="text-slate-200">
                      {risky.length
                        ? `${risky.length} risky entitlement${risky.length === 1 ? '' : 's'}${high ? ` (${high} high)` : ''}`
                        : `${ios.entitlements.length} entitlements, none risky`}
                    </span>
                  </p>
                  <p className="text-xs text-slate-500">
                    {ios.signing.signed ? (ios.signing.adhoc ? 'Ad-hoc signature' : 'Certificate-signed') : 'Unsigned'}
                    {ios.signing.teamId ? ` · team ${ios.signing.teamId}` : ''}
                  </p>
                </>
              );
            })()}
          </Lens>

          {/* hardening */}
          <Lens title="Hardening" cta="Open hardening" onClick={() => onNavigate('binary')}>
            {(() => {
              const bp = a.binaryProtections;
              const total = ios.binaries.length;
              const full = ios.binaries.filter((b) => hardeningScore(b) === PROTECTIONS.length).length;
              const weak = [...ios.binaries].sort((x, y) => hardeningScore(x) - hardeningScore(y))[0];
              return (
                <>
                  <ul className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                    {[
                      ['PIE', bp?.pie], ['ARC', bp?.arc], ['Canary', bp?.stackCanary], ['Stripped', ios.main.stripped],
                    ].map(([label, ok]) => (
                      <li key={label as string} className="flex items-center gap-2 text-sm text-slate-300">
                        {ok === undefined ? <span className="w-5 text-center text-slate-500">{'–'}</span> : <Mark ok={!!ok} />}
                        {label as string}
                      </li>
                    ))}
                  </ul>
                  <p className="border-t border-slate-800 pt-2.5 text-sm text-slate-200">
                    {total === 0 ? (
                      'No embedded frameworks.'
                    ) : full === total ? (
                      <><span className="text-emerald-300">{'✓'}</span> All {total} bundled binaries fully hardened</>
                    ) : (
                      <>
                        <span className="font-semibold tabular-nums text-rose-300">{total - full}</span> of {total} bundled binaries miss a protection
                        {weak && <span className="block text-xs text-slate-500">Weakest: {weak.name}</span>}
                      </>
                    )}
                  </p>
                </>
              );
            })()}
          </Lens>

          {/* security controls */}
          <ControlsLens scan={scan} onOpen={() => onNavigate('controls')} />
        </div>
      )}

      <FixFirst scan={scan} onNavigate={onNavigate} />

      <Scorecard scan={scan} />
    </div>
  );
}
