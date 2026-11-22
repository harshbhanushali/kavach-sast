/**
 * A one-page app profile for the executive edition: what the app is, how it is
 * signed and built, and the few facts a manager asks first. The full report
 * has the multi-page dossier; this is its summary.
 *
 * Every field is read defensively: older scans lack platform facts, and a gap
 * renders as an em dash, never as a guess.
 */
import type { SastScan } from '../sastTypes';
import { NEUTRAL, WARN, BAD, appIcon, bytes, esc, facts, h3, opener, tiles } from './kit';

export function appProfilePage(scan: SastScan, num: string): string {
  const a = scan.artifact;
  const isIos = a.platform === 'ios';
  const ios = isIos ? a.ios : undefined;
  const and = !isIos ? a.android : undefined;
  const name = ios?.displayName ?? and?.label ?? a.packageName ?? a.fileName;
  const id = ios?.bundleId ?? a.packageName ?? a.fileName;
  const hosts = scan.recon?.hosts?.length ?? 0;
  const cleartext = (scan.domains ?? []).filter((d) => d.cleartext).length;
  const perms = a.permissionDetail?.length || a.permissions?.length || 0;
  const dangerous = (a.permissionDetail ?? []).filter((p) => p.level === 'dangerous').length;
  const libs = a.detectedLibraries?.length ?? 0;
  const advisories = (a.dependencies ?? []).filter((d) => d.advisoryCount > 0).length;
  const exported = and ? (and.components ?? []).filter((c) => c.exported).length : (a.components?.exported ?? 0);
  const native = (a.nativeLibraryDetail ?? []).length;
  const bundled = ios ? (ios.binaries ?? []).length : native;
  const trackers = scan.recon?.trackers?.length ?? 0;

  const signing = isIos
    ? [ios?.distribution && ios.distribution !== 'unknown' ? `${ios.distribution} build` : '', ios?.profile?.teamName ?? ios?.signing?.teamId ?? '']
        .filter(Boolean)
        .join(' · ') || (ios?.signing?.signed === false ? 'unsigned' : '')
    : (a.signatureSchemes ?? []).join(' + ');

  const minOs = isIos ? `iOS ${a.minimumOsVersion ?? ios?.main?.minOs ?? '?'}+` : `Android API ${a.minSdk ?? '?'} to ${a.targetSdk ?? '?'}`;

  return `
  <section class="pg newpage" id="profile">
    ${opener('profile-top', num, 'App profile', 'What the app is, how it is built and signed, and its footprint, on one page.')}
    <div class="app-id">
      ${appIcon(a.iconDataUrl, name, id, 'ico-page')}
      <div class="app-id-t"><div class="nm">${esc(name)}</div>
        <div class="bid">${esc(id)}</div>
        <div class="app-id-c">${[
          a.versionName ? `v${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : '',
          isIos ? 'iOS' : 'Android',
          bytes(a.sizeBytes),
        ].filter(Boolean).map((t) => `<span class="chip cap">${esc(t)}</span>`).join(' ')}</div></div>
    </div>

    ${h3('Identity')}
    ${facts([
      ['File', a.fileName],
      ['Platform', isIos ? 'iOS (IPA)' : 'Android (APK)'],
      [isIos ? 'Runs on' : 'SDK range', minOs],
      [isIos ? 'Distribution and team' : 'Signature schemes', signing || undefined],
      ['Files inside', String(a.fileCount)],
      ['Signing certificate', (a.signers ?? []).length ? a.signers.join(' · ') : undefined, { wide: true }],
      ['Application SHA-256', a.sha256, { wide: true, mono: true }],
    ])}

    ${h3('Footprint')}
    ${tiles([
      { n: hosts, label: 'Hosts referenced' },
      { n: cleartext, label: 'Plain-http hosts', tone: cleartext ? BAD : undefined },
      { n: perms, label: isIos ? 'Purpose strings' : 'Permissions', sub: dangerous ? `${dangerous} dangerous` : undefined, tone: dangerous ? WARN : undefined },
      { n: libs, label: 'Libraries detected', sub: advisories ? `${advisories} with advisories` : undefined, tone: advisories ? BAD : undefined },
    ])}
    <div style="height:6px"></div>
    ${tiles([
      isIos
        ? { n: (ios?.urlSchemes ?? []).reduce((n, u) => n + (u.schemes?.length ?? 0), 0), label: 'URL schemes', tone: NEUTRAL }
        : { n: exported, label: 'Exported components', tone: exported ? WARN : undefined },
      { n: bundled, label: isIos ? 'Embedded binaries' : 'Native libraries' },
      { n: trackers, label: 'Privacy trackers', tone: trackers ? WARN : undefined },
      { n: isIos ? (ios?.entitlements ?? []).filter((e) => e.risk === 'high').length : (and?.components ?? []).filter((c) => c.browsable).length,
        label: isIos ? 'High-risk entitlements' : 'Web-link entry points', tone: NEUTRAL },
    ])}
  </section>`;
}
