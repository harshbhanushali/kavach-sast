/**
 * The Android overview: the hero, three lenses on the build, then what to do
 * first. Same shape as the iOS overview; each lens is a digest of a tab of its
 * own and links to it.
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
  advisoryCount, buildKind, deriveSignals, isDebugCert, nativeCoverage, permLevel, schemesOf, sdkName, surfaceOf, weakNative,
} from './androidModel';

export function AndroidOverview({
  scan, onNavigate, children,
}: { scan: SastScan; onNavigate: Navigate; children?: ReactNode }) {
  const a = scan.artifact;
  const x = a.android;
  const kind = buildKind(scan);
  const schemes = [...schemesOf(scan)].sort();
  const verdict = verdictOf(
    scan,
    kind.tone === 'bad' ? `This is a ${kind.label.toLowerCase()} build, not a release build.` : undefined,
  );
  const libs = a.nativeLibraryDetail;
  const dangerous = a.permissionDetail.filter((p) => permLevel(p.level) === 'dangerous').length;

  return (
    <div className="@container space-y-5">
      <SastHero
        scan={scan}
        onNavigate={onNavigate}
        verdict={verdict}
        signals={deriveSignals(scan)}
        chips={
          <>
            <ToneChip tone={kind.tone} title={kind.meaning}>{kind.label} build</ToneChip>
            <Tag mono={false}>v{a.versionName ?? '?'}{a.versionCode ? ` (${a.versionCode})` : ''}</Tag>
            <Tag mono={false} title={`Minimum ${sdkName(a.minSdk)}, targets ${sdkName(a.targetSdk)}`}>
              SDK {a.minSdk ?? '?'} {'→'} {a.targetSdk ?? '?'}
            </Tag>
            {schemes.length > 0 && <Tag mono={false} title="APK signature schemes">Signing {schemes.join(' + ')}</Tag>}
            {x?.allowBackup && <ToneChip tone="warn" title="android:allowBackup is true: app data can be backed up off the device">Backup allowed</ToneChip>}
            <Tag mono={false} title={a.fileName}>{formatBytes(a.sizeBytes)}</Tag>
          </>
        }
      />

      {/* build facts + integrity */}
      <Panel title="Build and file" subtitle="What produced this artifact, and the digests that identify it.">
        <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 @3xl:grid-cols-4">
          <Kv label="File">{a.fileName}</Kv>
          <Kv label="Size">{formatBytes(a.sizeBytes)}</Kv>
          <Kv label="Package" mono>{a.packageName ?? 'unknown'}</Kv>
          <Kv label="Version">{a.versionName ?? '?'} ({a.versionCode ?? '?'})</Kv>
          <Kv label="Minimum SDK">{sdkName(a.minSdk)}</Kv>
          <Kv label="Target SDK">{sdkName(a.targetSdk)}</Kv>
          <Kv label="Signing">{schemes.length ? schemes.join(', ') : (a.signatureSchemes.join(', ') || 'unknown')}</Kv>
          <Kv label="Native ABIs" mono>{x?.nativeAbis.length ? x.nativeAbis.join(', ') : '—'}</Kv>
          <Kv label="Application class" mono>{x?.applicationClass ?? '—'}</Kv>
          <Kv label="Launcher activity" mono>{x?.launcherActivity ?? '—'}</Kv>
          <Kv label="Label">{x?.label ?? '—'}</Kv>
          <Kv label="Scanned in">{(scan.durationMs / 1000).toFixed(1)}s</Kv>
        </dl>
        {children}
      </Panel>

      <div className={`grid gap-4 ${controlsOf(scan) ? '@3xl:grid-cols-2 @6xl:grid-cols-4' : '@3xl:grid-cols-3'}`}>
        {/* attack surface */}
        <Lens title="Attack surface" cta="Open attack surface" onClick={() => onNavigate('surface')}>
          <ul className="space-y-1.5">
            {surfaceOf(scan).filter((s) => ['components', 'open', 'providers', 'links', 'permissions', 'cleartext'].includes(s.key)).map((s) => (
              <li key={s.key} className="flex items-center justify-between gap-3 text-sm">
                <span className="flex items-center gap-2 text-slate-300">
                  <span aria-hidden className={`w-3 text-center text-[0.65rem] ${TONE[s.tone].text}`}>{TONE[s.tone].glyph}</span>
                  {s.label}
                </span>
                <span className={`font-semibold tabular-nums ${s.value ? 'text-slate-50' : 'text-slate-600'}`}>{s.value}</span>
              </li>
            ))}
          </ul>
        </Lens>

        {/* trust */}
        <Lens title="Trust and signing" cta="Open trust and signing" onClick={() => onNavigate('trust')}>
          <ToneChip tone={kind.tone} title={kind.meaning}>{kind.label} build</ToneChip>
          <p className={`flex items-start gap-2 text-sm ${schemes.length ? (isDebugCert(a.signers) ? 'text-rose-300' : 'text-emerald-300') : 'text-slate-400'}`}>
            <span aria-hidden className="mt-0.5 text-[0.65rem]">{schemes.length ? (isDebugCert(a.signers) ? '✕' : '✓') : '–'}</span>
            <span className="text-slate-200">
              {isDebugCert(a.signers)
                ? 'Signed with the debug certificate'
                : schemes.length ? `Signed with ${schemes.join(' + ')}` : 'Signature scheme not recorded'}
            </span>
          </p>
          <p className={`flex items-start gap-2 text-sm ${dangerous ? 'text-amber-300' : 'text-emerald-300'}`}>
            <span aria-hidden className="mt-0.5 text-[0.65rem]">{dangerous ? '▲' : '✓'}</span>
            <span className="text-slate-200">
              {a.permissionDetail.length
                ? `${dangerous} dangerous of ${a.permissionDetail.length} permissions`
                : 'No permissions requested'}
            </span>
          </p>
          <p className="text-xs text-slate-500">
            {a.signers[0] ? a.signers[0].split(',')[0].replace(/\s*\(.*$/, '') : 'No certificate read'}
            {x ? ` · backup ${x.allowBackup ? 'allowed' : 'off'}` : ''}
          </p>
        </Lens>

        {/* hardening */}
        <Lens title="Hardening" cta="Open hardening" onClick={() => onNavigate('binary')}>
          {libs.length > 0 ? (
            <>
              <ul className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                {nativeCoverage(libs).filter((c) => ['nx', 'pie', 'stackCanary', 'relro'].includes(c.key)).map((c) => (
                  <li key={c.key} className="flex items-center gap-2 text-sm text-slate-300">
                    <Mark ok={c.have === c.total} partial={c.have > 0 && c.have < c.total} yes="all libraries" no="no library" partialLabel={`${c.have} of ${c.total}`} />
                    {c.label}
                  </li>
                ))}
              </ul>
              <p className="border-t border-slate-800 pt-2.5 text-sm text-slate-200">
                {weakNative(libs).length === 0 ? (
                  <><span className="text-emerald-300">{'✓'}</span> All {libs.length} native libraries hardened</>
                ) : (
                  <>
                    <span className="font-semibold tabular-nums text-rose-300">{weakNative(libs).length}</span> of {libs.length} native libraries miss a protection
                    <span className="block text-xs text-slate-500">Weakest: {weakNative(libs)[0].name}</span>
                  </>
                )}
              </p>
            </>
          ) : (
            <p className="text-sm text-slate-400">No native libraries bundled.</p>
          )}
          {a.dependencies.length > 0 && (
            <p className={`flex items-start gap-2 text-sm ${advisoryCount(scan) ? 'text-rose-300' : 'text-emerald-300'}`}>
              <span aria-hidden className="mt-0.5 text-[0.65rem]">{advisoryCount(scan) ? '✕' : '✓'}</span>
              <span className="text-slate-200">
                {advisoryCount(scan) ? `${advisoryCount(scan)} librar${advisoryCount(scan) === 1 ? 'y' : 'ies'} with advisories` : `${a.dependencies.length} libraries, none with advisories`}
              </span>
            </p>
          )}
        </Lens>

        {/* security controls */}
        <ControlsLens scan={scan} onOpen={() => onNavigate('controls')} />
      </div>

      <FixFirst scan={scan} onNavigate={onNavigate} />

      <Scorecard scan={scan} />
    </div>
  );
}
