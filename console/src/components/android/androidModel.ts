/**
 * What the Android views derive from a scan, kept out of the components.
 *
 * Mirrors `ios/iosModel.ts`. Every function tolerates missing facts: a scan
 * taken before the backend recorded `artifact.android` still has the component
 * counts, permissions, signing schemes and native-library detail, so those are
 * used when the richer facts are absent and the views say "not recorded"
 * rather than showing NaN or a blank.
 */
import type { AndroidFacts, SastScan } from '../../sastTypes';
import type { CellState, MatrixProtection } from '../sast/BinaryMatrix';
import type { Signal, Tone } from '../sast/model';

export type AndroidComponent = AndroidFacts['components'][number];
export type NativeLib = SastScan['artifact']['nativeLibraryDetail'][number];

/* ------------------------------------------------------------------------- SDK */

const ANDROID_VERSION: Record<number, string> = {
  19: '4.4', 21: '5.0', 22: '5.1', 23: '6', 24: '7', 25: '7.1', 26: '8', 27: '8.1', 28: '9',
  29: '10', 30: '11', 31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16',
};

/** `29` -> `Android 10 (API 29)`; an API level this table has not heard of is shown as is. */
export function sdkName(api: string | undefined): string {
  const n = Number(api);
  if (!api || Number.isNaN(n)) return 'unknown';
  return ANDROID_VERSION[n] ? `Android ${ANDROID_VERSION[n]} (API ${n})` : `API ${n}`;
}

/* --------------------------------------------------------------------- signing */

export const SIGNING_SCHEMES = [
  { key: 'v1', label: 'v1 (JAR signature)', hint: 'Legacy; forgeable on its own from Android 7 onward' },
  { key: 'v2', label: 'v2 (APK Signature Scheme)', hint: 'Signs the whole archive — the minimum for a modern build' },
  { key: 'v3', label: 'v3 (key rotation)', hint: 'Allows the signing key to be rotated without reinstalling' },
  { key: 'v4', label: 'v4 (streaming installs)', hint: 'Detached signature for incremental installs; additive to v2 or v3' },
] as const;

/** Signing scheme keys as the scanner reports them (`v2`, `V2`, `v2+v3`...). */
export function schemesOf(scan: SastScan): Set<string> {
  return new Set(scan.artifact.signatureSchemes.flatMap((s) => s.toLowerCase().match(/v\d/g) ?? []));
}

export function isDebugCert(signers: string[]): boolean {
  return signers.some((s) => /android debug/i.test(s));
}

/** `CN=Android Debug, OU=Android, ...` -> the readable parts. */
export function parseSigner(raw: string): { subject: { key: string; value: string }[]; rest: string } {
  const paren = raw.indexOf(' (');
  const dn = paren > 0 ? raw.slice(0, paren) : raw;
  const rest = paren > 0 ? raw.slice(paren + 1) : '';
  const subject = dn.split(/,\s*(?=[A-Z]{1,3}=)/).map((part) => {
    const i = part.indexOf('=');
    return i > 0 ? { key: part.slice(0, i).trim(), value: part.slice(i + 1).trim() } : { key: '', value: part.trim() };
  });
  return { subject, rest };
}

export type BuildKind = { label: string; tone: Tone; meaning: string };

/** What kind of build this is, judged from the manifest flag and the signing key. */
export function buildKind(scan: SastScan): BuildKind {
  const x = scan.artifact.android;
  const debugKey = isDebugCert(scan.artifact.signers);
  if (x?.testOnly) {
    return { label: 'Test-only', tone: 'bad', meaning: 'android:testOnly is set: Play refuses it and it installs only over adb. Not a build meant to reach users.' };
  }
  if (x?.debuggable) {
    return {
      label: 'Debuggable', tone: 'bad',
      meaning: 'android:debuggable is true: a debugger can attach to the app and read its private files on any device, without root.',
    };
  }
  if (debugKey) {
    return {
      label: 'Debug-signed', tone: 'bad',
      meaning: 'Signed with the well-known Android debug key, which anyone can use to publish an update over this app.',
    };
  }
  if (!x) {
    return { label: 'Unknown', tone: 'muted', meaning: 'This scan predates manifest facts, so whether the build is debuggable is not recorded. Run it again to see.' };
  }
  return { label: 'Release', tone: 'good', meaning: 'Not debuggable and not signed with the debug key.' };
}

/* -------------------------------------------------------------- components */

/** The launcher activity is meant to be exported; it is not an exposure finding. */
export function isLauncher(c: AndroidComponent, x: AndroidFacts | undefined): boolean {
  return !!x && c.name === x.launcherActivity;
}

/**
 * How exposed one component is.
 *
 * Exported and unguarded is the case that matters; a guard permission (even one
 * the scanner cannot judge the strength of) changes it from "anyone" to "apps
 * holding that permission".
 */
export type Exposure = 'open' | 'guarded' | 'launcher' | 'internal';

export function exposureOf(c: AndroidComponent, x: AndroidFacts | undefined): Exposure {
  if (!c.exported) return 'internal';
  if (c.permission) return 'guarded';
  if (isLauncher(c, x)) return 'launcher';
  return 'open';
}

export const EXPOSURE: Record<Exposure, { label: string; tone: Tone; rank: number; hint: string }> = {
  open: { label: 'exported, unguarded', tone: 'bad', rank: 0, hint: 'Any app on the device can start or bind to this component.' },
  guarded: { label: 'exported, guarded', tone: 'info', rank: 1, hint: 'Only apps holding the guard permission can reach it.' },
  launcher: { label: 'launcher', tone: 'muted', rank: 2, hint: 'The main entry point. Exported by design.' },
  internal: { label: 'internal', tone: 'muted', rank: 3, hint: 'Not reachable from other apps.' },
};

/** Unguarded and exported non-activity components are the sharper edge: no UI to hide behind. */
export function exposureTone(c: AndroidComponent, x: AndroidFacts | undefined): Tone {
  const e = exposureOf(c, x);
  if (e !== 'open') return EXPOSURE[e].tone;
  return c.kind === 'activity' ? 'warn' : 'bad';
}

export const KIND_LABEL: Record<AndroidComponent['kind'], string> = {
  activity: 'Activity', service: 'Service', receiver: 'Receiver', provider: 'Provider',
};

/** `com.example.app.ui.MainActivity` -> package prefix and class, so the class leads. */
export function splitName(name: string): { pkg: string; cls: string } {
  const i = name.lastIndexOf('.');
  return i > 0 ? { pkg: name.slice(0, i + 1), cls: name.slice(i + 1) } : { pkg: '', cls: name };
}

export function componentStats(scan: SastScan) {
  const x = scan.artifact.android;
  const list = x?.components ?? [];
  const exported = x ? list.filter((c) => c.exported) : [];
  const open = exported.filter((c) => exposureOf(c, x) === 'open');
  return {
    known: !!x,
    total: x ? list.length : (scan.artifact.components.activities + scan.artifact.components.services + scan.artifact.components.receivers + scan.artifact.components.providers),
    exported: x ? exported.length : scan.artifact.components.exported,
    open: open.length,
    openNonActivity: open.filter((c) => c.kind !== 'activity').length,
    exportedProviders: exported.filter((c) => c.kind === 'provider').length,
  };
}

/* -------------------------------------------------------------- native libs */

export const NATIVE_PROTECTIONS: MatrixProtection[] = [
  { key: 'nx', label: 'NX', hint: 'Non-executable stack: injected data cannot run as code' },
  { key: 'pie', label: 'PIE', hint: 'Position-independent: the library loads at a random address' },
  { key: 'stackCanary', label: 'Canary', hint: 'Stack canary: a smashed stack is detected before the function returns' },
  { key: 'relro', label: 'RELRO', hint: 'Full RELRO makes the GOT read-only after load. Partial leaves it writable.' },
  { key: 'symbolsStripped', label: 'Stripped', hint: 'Symbols removed: harder to read and to find useful names' },
  { key: 'fortified', label: 'Fortify', hint: 'FORTIFY_SOURCE: bounds-checked libc calls' },
];

export function nativeChecks(l: NativeLib): Record<string, CellState> {
  const b = (ok: boolean): CellState => (ok ? 'yes' : 'no');
  return {
    nx: b(l.nx), pie: b(l.pie), stackCanary: b(l.stackCanary),
    relro: l.relro === 'full' ? 'yes' : l.relro === 'partial' ? 'partial' : 'no',
    symbolsStripped: b(l.symbolsStripped), fortified: b(l.fortified),
  };
}

/** Per protection: how many libraries have it (full RELRO only counts as having RELRO). */
export function nativeCoverage(libs: NativeLib[]) {
  const cs = libs.map(nativeChecks);
  return NATIVE_PROTECTIONS.map((p) => ({ ...p, have: cs.filter((c) => c[p.key] === 'yes').length, total: libs.length }));
}

/** Libraries missing something that a modern toolchain enables by default (fortify is opt-in, so it is not counted). */
export function weakNative(libs: NativeLib[]): NativeLib[] {
  const core = ['nx', 'pie', 'stackCanary', 'relro'];
  return libs.filter((l) => core.some((k) => nativeChecks(l)[k] !== 'yes'));
}

/* ---------------------------------------------------------------- permissions */

export type PermLevel = 'dangerous' | 'signature' | 'normal' | 'unknown';

export const PERM_LEVELS: PermLevel[] = ['dangerous', 'signature', 'normal', 'unknown'];

export const PERM_TONE: Record<PermLevel, Tone> = {
  dangerous: 'bad', signature: 'warn', normal: 'good', unknown: 'muted',
};

export const PERM_HINT: Record<PermLevel, string> = {
  dangerous: 'Prompts the user at runtime.',
  signature: 'Granted only to apps signed by the same key as the declaring app (or the system).',
  normal: 'Granted silently at install.',
  unknown: 'Not in the scanner’s permission table.',
};

export function permLevel(level: string): PermLevel {
  return (PERM_LEVELS as string[]).includes(level) ? (level as PermLevel) : 'unknown';
}

/* ---------------------------------------------------------------- dependencies */

export function advisoryCount(scan: SastScan): number {
  return scan.artifact.dependencies.filter((d) => d.advisoryCount > 0).length;
}

/* ------------------------------------------------------------------- network */

export function cleartextEndpoints(scan: SastScan) {
  return scan.recon.endpoints.filter((e) => e.cleartext);
}

/** The scanner's own finding for a network-security-config that re-enables cleartext. */
export function nscPermitsCleartext(scan: SastScan): boolean {
  return scan.findings.some((f) => f.ruleId === 'manifest.nsc_cleartext');
}

/** Plain HTTP is blocked by default from API 28 (target SDK) unless the manifest or the config says otherwise. */
export function cleartextState(scan: SastScan): { tone: Tone; state: string; detail: string } | undefined {
  const x = scan.artifact.android;
  if (!x) return undefined;
  const target = Number(scan.artifact.targetSdk);
  if (x.cleartextTraffic === true) {
    return { tone: 'bad', state: 'allowed', detail: 'android:usesCleartextTraffic is true: the app may use plain HTTP.' };
  }
  if (nscPermitsCleartext(scan)) {
    return { tone: 'bad', state: 'config permits', detail: 'The manifest blocks cleartext, but the network security config permits it for some or all domains.' };
  }
  if (x.cleartextTraffic === false) {
    return { tone: 'good', state: 'blocked', detail: 'android:usesCleartextTraffic is false: plain HTTP is blocked.' };
  }
  return Number.isNaN(target) || target >= 28
    ? { tone: 'good', state: 'default off', detail: 'The manifest is silent; apps targeting API 28+ block plain HTTP by default.' }
    : { tone: 'warn', state: 'default on', detail: `The manifest is silent and the app targets API ${target}, where plain HTTP is allowed by default.` };
}

/* ---------------------------------------------------------------------- signals */

/** The at-a-glance strip under the hero: each is a yes/no a reviewer asks first. */
export function deriveSignals(scan: SastScan): Signal[] {
  const a = scan.artifact;
  const x = a.android;
  const out: Signal[] = [];

  if (x) {
    out.push({
      key: 'debuggable', label: 'Debuggable', tone: x.debuggable ? 'bad' : 'good',
      state: x.debuggable ? 'yes' : 'no',
      detail: x.debuggable
        ? 'android:debuggable is true: a debugger can attach and read app data on any device.'
        : 'android:debuggable is not set, so a debugger cannot attach on a user device.',
    });
    if (x.testOnly) {
      out.push({ key: 'testOnly', label: 'Test-only', tone: 'bad', state: 'yes', detail: 'android:testOnly is set: this build installs only over adb.' });
    }
    out.push({
      key: 'backup', label: 'Backup', tone: x.allowBackup ? 'warn' : 'good',
      state: x.allowBackup ? 'allowed' : 'off',
      detail: x.allowBackup
        ? 'android:allowBackup is true: app data can be pulled with adb backup or cloud backup.'
        : 'android:allowBackup is false: app data is excluded from backups.',
    });
    const ct = cleartextState(scan);
    if (ct) out.push({ key: 'cleartext', label: 'Cleartext HTTP', ...ct });
    out.push({
      key: 'nsc', label: 'Network security config', tone: x.networkSecurityConfig ? 'info' : 'muted',
      state: x.networkSecurityConfig ? 'custom' : 'default',
      detail: x.networkSecurityConfig
        ? 'The app ships its own network security config, which can relax or tighten TLS trust per domain.'
        : 'No custom network security config: the platform defaults apply.',
    });
  }

  const schemes = schemesOf(scan);
  if (a.signatureSchemes.length > 0 || a.signers.length > 0) {
    const debugKey = isDebugCert(a.signers);
    const v1only = schemes.has('v1') && !schemes.has('v2') && !schemes.has('v3');
    out.push({
      key: 'signing', label: 'Signing',
      tone: debugKey ? 'bad' : v1only ? 'warn' : schemes.size ? 'good' : 'muted',
      state: debugKey ? 'debug key' : v1only ? 'v1 only' : schemes.size ? [...schemes].sort().join(' + ') : 'unknown',
      detail: debugKey
        ? 'Signed with the Android debug certificate, which anyone can use to sign an update.'
        : v1only
          ? 'Only the legacy v1 scheme: forgeable on its own from Android 7 onward.'
          : 'Signature scheme(s) read from the APK signing block.',
    });
  }

  if (a.nativeLibraryDetail.length > 0) {
    const weak = weakNative(a.nativeLibraryDetail).length;
    out.push({
      key: 'native', label: 'Native hardening', tone: weak === 0 ? 'good' : 'warn',
      state: weak === 0 ? 'all libs' : `${weak} of ${a.nativeLibraryDetail.length} weak`,
      detail: weak === 0
        ? 'Every native library has NX, PIE, a stack canary and full RELRO.'
        : `${weak} native ${weak === 1 ? 'library lacks' : 'libraries lack'} NX, PIE, a stack canary or full RELRO.`,
    });
  }

  const cs = componentStats(scan);
  out.push({
    key: 'exported', label: 'Exported components',
    tone: cs.openNonActivity > 0 ? 'bad' : cs.open > 0 ? 'warn' : 'good',
    state: cs.known && cs.open > 0 ? `${cs.exported} (${cs.open} unguarded)` : `${cs.exported}`,
    detail: cs.known
      ? `${cs.exported} component${cs.exported === 1 ? ' is' : 's are'} reachable from other apps; ${cs.open} of them ${cs.open === 1 ? 'has' : 'have'} no guard permission (the launcher activity is not counted).`
      : `${cs.exported} exported component${cs.exported === 1 ? '' : 's'}. This scan predates per-component facts, so guards are not shown.`,
  });

  const dangerous = a.permissionDetail.filter((p) => permLevel(p.level) === 'dangerous').length;
  if (a.permissionDetail.length > 0) {
    out.push({
      key: 'perms', label: 'Dangerous permissions', tone: dangerous > 6 ? 'warn' : dangerous > 0 ? 'info' : 'good',
      state: String(dangerous),
      detail: `${dangerous} of ${a.permissionDetail.length} requested permissions prompt the user at runtime.`,
    });
  }

  if (a.dependencies.length > 0) {
    const adv = advisoryCount(scan);
    out.push({
      key: 'deps', label: 'Library advisories', tone: adv > 0 ? 'bad' : 'good',
      state: adv > 0 ? `${adv} librar${adv === 1 ? 'y' : 'ies'}` : 'none',
      detail: adv > 0
        ? `${adv} of ${a.dependencies.length} versioned libraries match a known advisory.`
        : `None of the ${a.dependencies.length} versioned libraries matched a known advisory.`,
    });
  }
  return out;
}

/* -------------------------------------------------------------------- surface */

export type SurfaceKey =
  | 'components' | 'open' | 'providers' | 'links' | 'permissions' | 'cleartext' | 'nsc' | 'features';

export type SurfaceItem = {
  key: SurfaceKey;
  label: string;
  /** A number, or a word for the yes/no tiles. */
  value: number | string;
  tone: Tone;
  summary: string;
};

/** A deep link with a custom scheme can be claimed by any app; an https one can be verified. */
export function linkKind(schemes: string[]): 'custom' | 'web' | 'mixed' {
  const web = schemes.filter((s) => /^https?$/i.test(s)).length;
  return web === 0 ? 'custom' : web === schemes.length ? 'web' : 'mixed';
}

export function surfaceOf(scan: SastScan): SurfaceItem[] {
  const a = scan.artifact;
  const x = a.android;
  const cs = componentStats(scan);
  const links = a.components.browsable;
  const customLinks = links.filter((l) => linkKind(l.schemes) !== 'web').length;
  const cleartext = cleartextEndpoints(scan).length;
  const custom = x?.customPermissions ?? [];
  const weakCustom = custom.filter((p) => p.protection !== 'signature' && !p.protection.startsWith('signature')).length;
  const ct = cleartextState(scan);

  return [
    {
      key: 'components', label: 'Exported components', value: cs.exported,
      tone: cs.exported ? 'info' : 'good',
      summary: cs.exported ? `Reachable by other apps, of ${cs.total} declared` : 'Nothing reachable from other apps',
    },
    {
      key: 'open', label: 'Unguarded exports', value: cs.known ? cs.open : '—',
      tone: !cs.known ? 'muted' : cs.openNonActivity ? 'bad' : cs.open ? 'warn' : 'good',
      summary: !cs.known ? 'Not recorded in this scan' : cs.open ? 'Exported with no permission guard' : 'Every export is guarded or the launcher',
    },
    {
      key: 'providers', label: 'Exported providers', value: cs.known ? cs.exportedProviders : '—',
      tone: !cs.known ? 'muted' : cs.exportedProviders ? 'bad' : 'good',
      summary: !cs.known ? 'Not recorded in this scan' : cs.exportedProviders ? 'Other apps can query these' : 'No content provider is exported',
    },
    {
      key: 'links', label: 'Deep links', value: links.length,
      tone: customLinks ? 'warn' : links.length ? 'info' : 'muted',
      summary: !links.length ? 'None declared' : customLinks ? `${customLinks} use a scheme any app can claim` : 'Web links that open the app',
    },
    {
      key: 'permissions', label: 'Custom permissions', value: x ? custom.length : '—',
      tone: !x ? 'muted' : weakCustom ? 'warn' : custom.length ? 'info' : 'muted',
      summary: !x ? 'Not recorded in this scan' : weakCustom ? `${weakCustom} not signature-protected` : custom.length ? 'Declared for other apps to request' : 'None declared',
    },
    {
      key: 'cleartext', label: 'Cleartext endpoints', value: cleartext,
      tone: ct?.tone === 'bad' ? 'bad' : cleartext ? 'warn' : 'good',
      summary: cleartext ? 'http:// URLs found in the build' : 'No plain http:// URLs found',
    },
    {
      key: 'nsc', label: 'Network config', value: !x ? '—' : x.networkSecurityConfig ? 'Custom' : 'Default',
      tone: !x ? 'muted' : nscPermitsCleartext(scan) ? 'bad' : x.networkSecurityConfig ? 'info' : 'good',
      summary: !x ? 'Not recorded in this scan' : nscPermitsCleartext(scan) ? 'Permits cleartext' : x.networkSecurityConfig ? 'App ships its own trust rules' : 'Platform TLS defaults apply',
    },
    {
      key: 'features', label: 'Hardware features', value: x ? x.usesFeatures.length : '—',
      tone: !x ? 'muted' : x.usesFeatures.length ? 'info' : 'muted',
      summary: !x ? 'Not recorded in this scan' : x.usesFeatures.length ? 'Declared with uses-feature' : 'None declared',
    },
  ];
}
