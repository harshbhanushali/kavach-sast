/**
 * What the iOS views derive from a scan, kept out of the components.
 * Platform-neutral pieces (tones, verdict, formatting) live in `../sast/model`.
 *
 * Every function here takes possibly-missing facts and returns something a
 * component can render without a guard: the views never do arithmetic on
 * `undefined`, so a build that lacks a profile or an ATS block shows a
 * "not present" state rather than NaN or a blank.
 */
import type { IosFacts, IosRisk, SastScan } from '../../sastTypes';
import type { Signal, Tone } from '../sast/model';

/* ---------------------------------------------------------------- distribution */

export type DistributionInfo = {
  label: string;
  tone: Tone;
  /** What this signing configuration means for someone judging the build. */
  meaning: string;
  /** Who can install it, and how it reaches them. */
  installsOn: string;
  channel: string;
};

export function distributionInfo(d: IosFacts['distribution'] | undefined): DistributionInfo {
  switch (d) {
    case 'development':
      return {
        label: 'Development', tone: 'bad', installsOn: 'Devices registered in the profile', channel: 'Xcode or a local install',
        meaning: 'Signed with a development profile: debuggable, attachable by Xcode, and not a build meant to reach users.',
      };
    case 'ad-hoc':
      return {
        label: 'Ad hoc', tone: 'warn', installsOn: 'Devices registered in the profile (max 100)', channel: 'Direct download, MDM or a test-distribution service',
        meaning: 'Installable only on devices registered in the profile. Fine for testers; not what the App Store ships.',
      };
    case 'enterprise':
      return {
        label: 'Enterprise', tone: 'warn', installsOn: 'Any device that trusts the company certificate', channel: 'In-house download or MDM, no App Store review',
        meaning: 'In-house distribution: installs on any device that trusts the company certificate, outside App Store review.',
      };
    case 'app-store':
      return {
        label: 'App Store', tone: 'good', installsOn: 'Any device, through Apple only', channel: 'App Store or TestFlight',
        meaning: 'Distribution-signed for the App Store: no debugger attach, and installs only through Apple’s channel.',
      };
    default:
      return {
        label: 'Unknown', tone: 'muted', installsOn: 'Not readable from this build', channel: 'Not readable from this build',
        meaning: 'No embedded provisioning profile was found, so how this build is distributed cannot be read from it. Store-delivered builds are re-signed by Apple and often look like this.',
      };
  }
}

/* -------------------------------------------------------------------- profile */

export type ProfileStatus = {
  state: 'valid' | 'expiring' | 'expired' | 'unknown';
  /** Whole days until expiry; negative once expired. */
  days?: number;
  /** 0..1 position of "now" between created and expires, when both are known. */
  progress?: number;
  headline: string;
  tone: Tone;
};

const DAY = 86_400_000;

export function profileStatus(profile: IosFacts['profile'], now: number): ProfileStatus {
  if (!profile) return { state: 'unknown', headline: 'No provisioning profile embedded', tone: 'muted' };
  const expires = profile.expires ? Date.parse(profile.expires) : NaN;
  const created = profile.created ? Date.parse(profile.created) : NaN;
  if (Number.isNaN(expires)) {
    return profile.expired
      ? { state: 'expired', headline: 'Profile has expired', tone: 'bad' }
      : { state: 'unknown', headline: 'Profile expiry not readable', tone: 'muted' };
  }
  const days = Math.round((expires - now) / DAY);
  const progress = Number.isNaN(created) || expires <= created
    ? undefined
    : Math.min(1, Math.max(0, (now - created) / (expires - created)));
  if (profile.expired || days < 0) {
    return { state: 'expired', days, progress, tone: 'bad', headline: `Expired ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago` };
  }
  if (days <= 30) {
    return { state: 'expiring', days, progress, tone: 'warn', headline: `Expires in ${days} day${days === 1 ? '' : 's'}` };
  }
  return { state: 'valid', days, progress, tone: 'good', headline: `Valid for ${days} more days` };
}

/* -------------------------------------------------------------------- binaries */

export type IosBinary = IosFacts['binaries'][number];

/** The four protections a binary can carry. Swift/ObjC is identity, not hardening. */
export const PROTECTIONS = [
  { key: 'arc', label: 'ARC', hint: 'Automatic Reference Counting: compiler-managed memory, fewer use-after-free bugs' },
  { key: 'stackCanary', label: 'Canary', hint: 'Stack canary: a smashed stack is detected before the function returns' },
  { key: 'stripped', label: 'Stripped', hint: 'Local symbols removed: harder to read the binary and to find useful names' },
  { key: 'signed', label: 'Signed', hint: 'Carries a code signature; an unsigned binary will not load on a device' },
] as const;

export type ProtectionKey = (typeof PROTECTIONS)[number]['key'];

export function hardeningScore(b: IosBinary): number {
  return PROTECTIONS.reduce((n, p) => n + (b[p.key] ? 1 : 0), 0);
}

export function missingOf(b: IosBinary): string[] {
  return PROTECTIONS.filter((p) => !b[p.key]).map((p) => p.label);
}

/* ---------------------------------------------------------------------- signals */

/**
 * The at-a-glance strip under the hero: each is a yes/no a reviewer asks first.
 *
 * `state` is the word shown beside the glyph so the chip never relies on colour.
 */
export function deriveSignals(scan: SastScan): Signal[] {
  const ios = scan.artifact.ios;
  const bp = scan.artifact.binaryProtections;
  const out: Signal[] = [];

  if (ios) {
    const relaxed = ios.ats.arbitraryLoads;
    const exceptions = ios.ats.domains.filter((d) => d.allowsHttp).length;
    out.push({
      key: 'ats', label: 'Transport security',
      tone: relaxed ? 'bad' : exceptions > 0 ? 'warn' : 'good',
      state: relaxed ? 'ATS off' : exceptions > 0 ? `${exceptions} exception${exceptions === 1 ? '' : 's'}` : 'ATS strict',
      detail: relaxed
        ? 'NSAllowsArbitraryLoads is set: every connection may use plain HTTP.'
        : exceptions > 0
          ? 'ATS is on, but some domains are allowed to use plain HTTP.'
          : 'App Transport Security is enforced with no HTTP exceptions.',
    });
  }

  if (bp) {
    const add = (key: string, label: string, ok: boolean, yes: string, no: string, detail: string) =>
      out.push({ key, label, tone: ok ? 'good' : 'bad', state: ok ? yes : no, detail });
    add('pie', 'PIE / ASLR', bp.pie, 'on', 'off', 'Position-independent executable, so the image loads at a random address.');
    add('arc', 'ARC', bp.arc, 'on', 'off', 'Automatic Reference Counting in the main binary.');
    add('canary', 'Stack canary', bp.stackCanary, 'on', 'off', 'Stack smashing is detected before a function returns.');
  }

  if (ios) {
    out.push({
      key: 'stripped', label: 'Symbols',
      tone: ios.main.stripped ? 'good' : 'warn',
      state: ios.main.stripped ? 'stripped' : 'present',
      detail: ios.main.stripped
        ? 'Local symbols are removed from the main binary.'
        : `The main binary keeps ${ios.main.localSymbols.toLocaleString()} local symbols, which make reverse engineering easier.`,
    });
    out.push({
      key: 'privacy', label: 'Privacy manifest',
      tone: ios.privacyManifest ? 'good' : 'warn',
      state: ios.privacyManifest ? 'present' : 'missing',
      detail: ios.privacyManifest
        ? 'PrivacyInfo.xcprivacy is bundled.'
        : 'No PrivacyInfo.xcprivacy found. App Store submissions that use required-reason APIs need one.',
    });
    const debuggable = ios.entitlements.some((e) => e.key === 'get-task-allow' && /^(true|1|yes)$/i.test(e.value.trim()));
    out.push({
      key: 'debug', label: 'Debugger attach',
      tone: debuggable ? 'bad' : 'good',
      state: debuggable ? 'allowed' : 'blocked',
      detail: debuggable
        ? 'get-task-allow is true: a debugger can attach to this build on a device.'
        : 'get-task-allow is not granted, so a debugger cannot attach on a user device.',
    });
  }
  return out;
}

/* -------------------------------------------------------------- humanised names */

const EXTENSION_POINTS: Record<string, string> = {
  'com.apple.share-services': 'Share sheet',
  'com.apple.widget-extension': 'Widget',
  'com.apple.widgetkit-extension': 'Widget (WidgetKit)',
  'com.apple.usernotifications.service': 'Notification service',
  'com.apple.usernotifications.content-extension': 'Notification content',
  'com.apple.intents-service': 'Siri intents',
  'com.apple.intents-ui-service': 'Siri intents UI',
  'com.apple.keyboard-service': 'Custom keyboard',
  'com.apple.message-payload-provider': 'iMessage app',
  'com.apple.Safari.web-extension': 'Safari web extension',
  'com.apple.Safari.content-blocker': 'Content blocker',
  'com.apple.networkextension.packet-tunnel': 'VPN packet tunnel',
  'com.apple.broadcast-services': 'Screen broadcast',
  'com.apple.fileprovider-nonui': 'File provider',
  'com.apple.fileprovider-actionsui': 'File provider actions',
  'com.apple.identitylookup.message-filter': 'SMS filter',
  'com.apple.callkit.call-directory': 'Call directory',
  'com.apple.photo-editing': 'Photo editing',
  'com.apple.ui-services': 'Action extension',
  'com.apple.authentication-services-credential-provider-ui': 'Credential provider',
  'com.apple.spotlight.index': 'Spotlight index',
  'com.apple.quicklook.preview': 'Quick Look preview',
  'com.apple.appintents-extension': 'App Intents',
  'com.apple.watchkit': 'Watch app',
  'com.apple.dt.instruments.deviceio': 'Instruments',
};

export function extensionKind(point: string | undefined): string {
  if (!point) return 'Extension';
  return EXTENSION_POINTS[point] ?? point.replace(/^com\.apple\./, '');
}

/** Background modes with a tracking or always-listening implication. */
const SENSITIVE_MODES = new Set(['location', 'voip', 'audio', 'bluetooth-central', 'bluetooth-peripheral', 'external-accessory', 'nearby-interaction']);

const MODE_LABEL: Record<string, string> = {
  audio: 'Audio playback',
  location: 'Location updates',
  voip: 'Voice over IP',
  fetch: 'Background fetch',
  'remote-notification': 'Silent push',
  processing: 'Background processing',
  'bluetooth-central': 'Bluetooth central',
  'bluetooth-peripheral': 'Bluetooth peripheral',
  'external-accessory': 'External accessory',
  'newsstand-content': 'Newsstand',
  'nearby-interaction': 'Nearby interaction',
  'push-to-talk': 'Push to talk',
};

export function backgroundMode(mode: string): { label: string; sensitive: boolean } {
  return { label: MODE_LABEL[mode] ?? mode, sensitive: SENSITIVE_MODES.has(mode) };
}

/** `applinks:example.com?mode=developer` -> service, domain, developer-mode flag. */
export function parseAssociatedDomain(raw: string): { service: string; host: string; developer: boolean } {
  const i = raw.indexOf(':');
  const service = i > 0 ? raw.slice(0, i) : 'unknown';
  const rest = i > 0 ? raw.slice(i + 1) : raw;
  const [host, query = ''] = rest.split('?');
  return { service, host, developer: /mode=(developer|managed)/.test(query) };
}

export const SERVICE_LABEL: Record<string, string> = {
  applinks: 'Universal links',
  webcredentials: 'Password AutoFill',
  activitycontinuation: 'Handoff',
  appclips: 'App Clips',
  'applinks+': 'Universal links',
};

/* ------------------------------------------------------------------- entitlements */

export const RISK_ORDER: Record<IosRisk, number> = { high: 0, medium: 1, low: 2, info: 3 };

export const RISK_TONE: Record<IosRisk, Tone> = { high: 'bad', medium: 'warn', low: 'info', info: 'muted' };

export function riskyEntitlements(ios: IosFacts | undefined) {
  return (ios?.entitlements ?? []).filter((e) => e.risk === 'high' || e.risk === 'medium');
}

/* -------------------------------------------------------------------- surface */

export type SurfaceItem = {
  key: 'schemes' | 'links' | 'ats' | 'extensions' | 'background' | 'queried' | 'entitlements' | 'privacy';
  label: string;
  count: number;
  tone: Tone;
  /** One line for the tile: what the count means. */
  summary: string;
};

export function surfaceOf(ios: IosFacts): SurfaceItem[] {
  const schemes = ios.urlSchemes.flatMap((u) => u.schemes);
  const links = ios.associatedDomains.filter((d) => /^applinks/.test(d));
  const exceptions = ios.ats.domains.filter((d) => d.allowsHttp).length;
  const relaxed = ios.ats.arbitraryLoads;
  const sensitiveModes = ios.backgroundModes.filter((m) => SENSITIVE_MODES.has(m)).length;
  const risky = riskyEntitlements(ios);
  const worstRisk = risky.some((e) => e.risk === 'high') ? 'bad' : risky.length ? 'warn' : 'good';

  return [
    {
      key: 'schemes', label: 'URL schemes', count: schemes.length,
      tone: schemes.length ? 'warn' : 'good',
      summary: schemes.length ? 'Any installed app can open these' : 'No custom schemes',
    },
    {
      key: 'links', label: 'Universal links', count: links.length,
      tone: links.length ? 'info' : 'muted',
      summary: links.length ? 'Web domains that open the app' : 'None declared',
    },
    {
      key: 'ats', label: 'ATS exceptions', count: relaxed ? Math.max(1, exceptions) : exceptions,
      tone: relaxed ? 'bad' : exceptions ? 'warn' : 'good',
      summary: relaxed ? 'Arbitrary loads allowed' : exceptions ? 'Domains allowed over HTTP' : 'HTTPS enforced',
    },
    {
      key: 'extensions', label: 'Extensions', count: ios.extensions.length,
      tone: ios.extensions.length ? 'info' : 'muted',
      summary: ios.extensions.length ? 'Extra entry points into the app' : 'No app extensions',
    },
    {
      key: 'background', label: 'Background modes', count: ios.backgroundModes.length,
      tone: sensitiveModes ? 'warn' : ios.backgroundModes.length ? 'info' : 'muted',
      summary: sensitiveModes ? `${sensitiveModes} with tracking or listening implications` : ios.backgroundModes.length ? 'Runs while not in use' : 'Suspends when backgrounded',
    },
    {
      key: 'queried', label: 'Queried schemes', count: ios.queriedSchemes.length,
      tone: ios.queriedSchemes.length > 10 ? 'warn' : ios.queriedSchemes.length ? 'info' : 'muted',
      summary: ios.queriedSchemes.length ? 'Can probe which apps are installed' : 'Does not probe other apps',
    },
    {
      key: 'entitlements', label: 'Risky entitlements', count: risky.length,
      tone: worstRisk,
      summary: risky.length ? 'Capabilities beyond the sandbox default' : 'Nothing above low risk',
    },
  ];
}
