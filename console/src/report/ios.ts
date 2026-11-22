/**
 * The iOS half of the App dossier: what the app *is*, as opposed to what is
 * wrong with it. Every field of `IosFacts` is treated as possibly missing
 * (older scans, partial decodes), and a page with nothing to show is dropped
 * rather than rendered empty.
 */
import type { IosFacts, IosRisk, SastScan } from '../sastTypes';
import { BAD, GOOD, NEUTRAL, SEV, WARN, appIcon, bytes, callout, chips, esc, facts, fmtDate, h3, meter, opener, packSections, plural, safeBlock, state, tiles, val } from './kit';
import type { Block, SevKey } from './kit';
import type { Signal } from './signals';

const RISK_TO_SEV: Record<IosRisk, SevKey> = { high: 'high', medium: 'medium', low: 'low', info: 'info' };
const RISK_RANK: Record<IosRisk, number> = { high: 0, medium: 1, low: 2, info: 3 };

const DISTRIBUTION: Record<IosFacts['distribution'], { label: string; tone: string; meaning: string; installsOn: string; channel: string }> = {
  'app-store': {
    label: 'App Store',
    tone: GOOD,
    meaning: 'Store distribution build. Apple re-signs and reviews the binary, and entitlements are constrained to what the store allows.',
    installsOn: 'Any device, through Apple only',
    channel: 'App Store or TestFlight',
  },
  'ad-hoc': {
    label: 'Ad hoc',
    tone: WARN,
    meaning: 'Installable only on the devices registered in the provisioning profile. Bypasses App Store review; expected for internal testing, not for release.',
    installsOn: 'Devices registered in the profile (max 100)',
    channel: 'Direct download, MDM or a test-distribution service',
  },
  enterprise: {
    label: 'Enterprise',
    tone: SEV.high.text,
    meaning: 'In-house distribution outside the App Store. Bypasses review and is signed with a certificate Apple can revoke; confirm this is intended.',
    installsOn: 'Any device that trusts the company certificate',
    channel: 'In-house download or MDM, no App Store review',
  },
  development: {
    label: 'Development',
    tone: SEV.high.text,
    meaning: 'Signed for developer devices. Development builds are typically debuggable and must never reach end users.',
    installsOn: 'Devices registered in the profile',
    channel: 'Xcode or a local install',
  },
  unknown: {
    label: 'Unknown',
    tone: NEUTRAL,
    meaning: 'The distribution type could not be determined from the embedded provisioning profile.',
    installsOn: 'Not readable from this build',
    channel: 'Not readable from this build',
  },
};

const DEVICE_FAMILY: Record<string, string> = { '1': 'iPhone / iPod touch', '2': 'iPad', '3': 'Apple TV', '4': 'Apple Watch', '6': 'Mac (Catalyst)', '7': 'Apple Vision' };

const BACKGROUND_MODES: Record<string, string> = {
  audio: 'Plays audio while in the background',
  location: 'Receives location updates while in the background',
  voip: 'Keeps a VoIP connection alive and can wake on incoming calls',
  fetch: 'Periodically fetches new content',
  'remote-notification': 'Wakes silently on a push notification',
  processing: 'Runs long deferred tasks',
  'bluetooth-central': 'Talks to Bluetooth peripherals in the background',
  'bluetooth-peripheral': 'Advertises as a Bluetooth peripheral in the background',
  'external-accessory': 'Communicates with a connected accessory',
  'nearby-interaction': 'Ultra-wideband ranging',
  'newsstand-content': 'Downloads periodical content',
  'push-to-talk': 'Push-to-talk audio',
};

/** Modes that can track or listen while the app is not visible; flagged in the console too. */
const SENSITIVE_MODES = new Set(['location', 'voip', 'audio', 'bluetooth-central', 'bluetooth-peripheral', 'external-accessory', 'nearby-interaction']);

const ASSOC_KIND: Record<string, string> = {
  applinks: 'Universal links',
  webcredentials: 'Password AutoFill',
  activitycontinuation: 'Handoff',
  appclips: 'App Clips',
  'authsrv': 'Authentication services',
};

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
};

function pips(passed: number, total: number): string {
  let out = '';
  for (let i = 0; i < total; i++) out += `<i class="${i < passed ? 'on' : ''}"></i>`;
  return `<span class="pips" aria-label="${passed} of ${total}">${out}</span>`;
}

function riskChip(risk: IosRisk): string {
  const t = SEV[RISK_TO_SEV[risk]];
  return `<span class="chip sevchip" style="color:${t.text};border-color:${t.fill};background:${t.tint}"><span class="g">${t.glyph}</span>${esc(risk)}${meter(t.level, t.fill)}</span>`;
}

function daysBetween(iso: string | undefined): number | undefined {
  if (!iso) return undefined;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return undefined;
  return Math.round((t - Date.now()) / 86_400_000);
}

/** Rows for the main-binary protection checklist; also used as the pre-iOS-facts fallback. */
export function protectionRows(scan: SastScan): { name: string; why: string; ok: boolean | undefined; neutral?: boolean }[] {
  const p = scan.artifact.binaryProtections;
  const main = scan.artifact.ios?.main;
  const rows: { name: string; why: string; ok: boolean | undefined; neutral?: boolean }[] = [];
  if (p) {
    rows.push(
      { name: 'Position independent (PIE)', why: 'Address space layout randomisation applies to the binary.', ok: p.pie },
      { name: 'Stack canary', why: 'Stack overflows are detected before the function returns.', ok: p.stackCanary },
      { name: 'Automatic Reference Counting', why: 'Memory is managed by the compiler, closing most use-after-free bugs.', ok: p.arc },
      { name: 'Non-executable stack', why: 'Stack pages cannot be executed.', ok: p.nonExecutableStack },
    );
  }
  if (main) {
    rows.push({ name: 'Symbols stripped', why: `${plural(main.localSymbols ?? 0, 'local symbol')} remain${(main.localSymbols ?? 0) === 1 ? 's' : ''} in the binary. Stripped binaries give a reverse engineer far less to read.`, ok: main.stripped });
  }
  const signing = scan.artifact.ios?.signing;
  if (signing) rows.push({ name: 'Code signature', why: 'The main binary carries an LC_CODE_SIGNATURE; an unsigned binary will not load on a device.', ok: signing.signed });
  if (p || main) {
    const enc = p?.encrypted ?? main?.encrypted;
    if (enc !== undefined) {
      rows.push({
        name: 'FairPlay encrypted',
        neutral: true,
        why: enc
          ? 'Store-encrypted; strings and code are not readable from this copy.'
          : 'Not encrypted, so strings and code were readable in full (expected outside the App Store).',
        ok: enc,
      });
    }
  }
  return rows;
}

function protectionTable(scan: SastScan): string {
  const rows = protectionRows(scan);
  if (rows.length === 0) return '';
  const p = scan.artifact.binaryProtections;
  return `${h3('Main binary protections', p && p.archCount > 1 ? `read from the first of ${p.archCount} architecture slices` : 'read from the Mach-O load commands')}
    <table class="tbl"><thead><tr><th style="width:38%">Protection</th><th>What it does</th><th class="r" style="width:74px">State</th></tr></thead>
    <tbody>${rows
      .map(
        (r) => `<tr class="${r.ok === false && !r.neutral ? 'flag' : ''}"><td><strong>${esc(r.name)}</strong></td>
        <td class="muted">${esc(r.why)}</td><td class="r">${r.ok === undefined ? val(undefined) : state(r.ok, { neutral: r.neutral })}</td></tr>`,
      )
      .join('')}</tbody></table>`;
}

function profilePage(scan: SastScan, ios: IosFacts, num: string): Block {
  const a = scan.artifact;
  const dist = DISTRIBUTION[ios.distribution] ?? DISTRIBUTION.unknown;
  const p = ios.profile;
  const days = daysBetween(p?.expires);

  let expiry = '';
  if (p) {
    if (p.expired) {
      expiry = `<div class="exp-banner bad"><span>✕</span>PROVISIONING PROFILE EXPIRED${
        days !== undefined ? ` ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago` : ''
      }. This build will not install or launch on devices until it is re-signed.</div>`;
    } else if (days !== undefined && days <= 30) {
      expiry = `<div class="exp-banner warn"><span>▲</span>PROFILE EXPIRES IN ${days} DAY${days === 1 ? '' : 'S'}. Re-sign before then.</div>`;
    } else {
      expiry = `<div class="exp-banner ok"><span>✓</span>Provisioning profile is valid${days !== undefined ? ` for another ${days} days` : ''}.</div>`;
    }
  }

  const family = ios.deviceFamily.map((f) => DEVICE_FAMILY[f] ?? `Family ${f}`);
  const debuggable = ios.entitlements.some((e) => e.key === 'get-task-allow' && /^(true|1|yes)$/i.test(e.value.trim()));

  const html = `
    ${opener('dossier', num, 'App dossier', 'What the app is: identity, toolchain, how it was distributed and how it is provisioned.')}
    <div class="app-id">
      ${appIcon(a.iconDataUrl, ios.displayName ?? a.fileName, ios.bundleId ?? a.packageName ?? a.fileName, 'ico-page')}
      <div class="app-id-t"><div class="nm">${esc(ios.displayName ?? a.packageName ?? a.fileName)}</div>
        <div class="bid">${esc(ios.bundleId ?? a.packageName ?? 'unknown bundle id')}</div>
        <div class="app-id-c">${chips([
          a.versionName ? `v${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : '',
          `iOS ${a.minimumOsVersion ?? ios.main.minOs ?? '?'}+`,
          ...family,
          ios.profile?.teamName ?? ios.signing.teamId ?? '',
          bytes(a.sizeBytes),
        ].filter(Boolean), 'cap')}</div></div>
    </div>
    <div class="dist-hero" style="margin-top:9px">
      <div class="dist-badge" style="color:${dist.tone};border-color:${dist.tone}">${esc(dist.label)}</div>
      <div><div class="verdict-line">Distribution type</div><p class="small muted" style="margin-top:2px">${esc(dist.meaning)}</p></div>
    </div>
    ${facts([
      ['Installs on', dist.installsOn],
      ['Reaches users via', dist.channel],
      ['Debugger attach', state(!debuggable, { yes: 'blocked', no: 'allowed (get-task-allow)' }), { raw: true }],
    ])}

    ${h3('Identity')}
    ${facts([
      ['Display name', ios.displayName],
      ['Bundle ID', ios.bundleId ?? a.packageName],
      ['Executable', ios.executable],
      ['Version', a.versionName ? `${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : undefined],
      ['Minimum iOS', a.minimumOsVersion ?? ios.main.minOs],
      ['Device family', family.join(', ') || undefined],
      ['Platforms', ios.supportedPlatforms.join(', ') || undefined],
      ['Info.plist keys', String(ios.plistKeys)],
      ['Privacy manifest', ios.privacyManifest ? '✓ PrivacyInfo.xcprivacy present' : '✕ not found'],
    ])}

    ${h3('Build toolchain')}
    ${facts([
      ['SDK', ios.sdkName],
      ['Platform version', ios.platformVersion],
      ['Xcode', ios.xcode],
      ['Build machine OS', ios.buildOs],
    ], 4)}

    ${
      ios.requiredCapabilities.length > 0
        ? `${h3('Required device capabilities')}<div class="caps">${chips(ios.requiredCapabilities, 'cap')}</div>`
        : ''
    }

    ${h3('Provisioning profile', p ? esc(p.platform ?? '') : '')}
    ${
      p
        ? `${expiry}<table class="kv"><tbody>
            <tr><td>Profile name</td><td>${val(p.name)}</td></tr>
            <tr><td>Team</td><td>${val(p.teamName)}${p.teamId ? ` <code>${esc(p.teamId)}</code>` : ''}</td></tr>
            <tr><td>Created</td><td>${fmtDate(p.created)}</td></tr>
            <tr><td>Expires</td><td>${fmtDate(p.expires)}</td></tr>
            <tr><td>Registered devices</td><td>${p.deviceCount === undefined ? val(undefined) : `${p.deviceCount}${
              ios.distribution === 'ad-hoc' || ios.distribution === 'development' ? ' (build only runs on these)' : ''
            }`}</td></tr>
            <tr><td>UUID</td><td><code>${val(p.uuid)}</code></td></tr>
          </tbody></table>`
        : `<p class="small muted">No embedded provisioning profile. That is normal for an App Store build, where Apple re-signs the app on delivery.</p>`
    }

    ${h3('Artifact')}
    ${facts([
      ['File', a.fileName],
      ['Size', bytes(a.sizeBytes)],
      ['Files inside', plural(ios.fileCount || a.fileCount, 'file')],
      ...(a.signers.length ? ([['Signing certificate', a.signers.join(' · '), { wide: true }]] as [string, string, { wide: boolean }][]) : []),
    ])}
  `;
  return { id: 'ios-profile', html, cost: 999 };
}

function signingPage(ios: IosFacts, num: string): Block {
  const s = ios.signing;
  const source =
    s.entitlementsSource === 'binary'
      ? 'Read from the signed binary: these are the entitlements the app actually claims at runtime.'
      : s.entitlementsSource === 'profile'
        ? 'The binary carries no embedded entitlements, so these come from the provisioning profile: the ceiling of what the app may claim, not proof it uses them.'
        : 'No entitlements could be read from the binary or from a profile.';
  const ents = [...ios.entitlements].sort((x, y) => RISK_RANK[x.risk] - RISK_RANK[y.risk] || x.key.localeCompare(y.key));
  const by = (r: IosRisk) => ents.filter((e) => e.risk === r).length;

  const html = `
    ${opener('dossier-signing', num, 'Signing & entitlements', 'Who signed the app, and which privileged capabilities it asks the system for.')}
    ${h3('Code signature')}
    ${facts([
      ['Code signature', state(s.signed, { yes: 'present', no: 'missing' }), { raw: true }],
      ['Signing type', s.signed ? (s.adhoc ? 'Ad-hoc (no identity)' : 'Identity-signed') : undefined],
      ['Team ID', s.teamId],
      ['Signing identifier', s.identifier],
      ['Hash type', s.hashType],
      ['Entitlements source', s.entitlementsSource, {}],
    ])}
    ${callout('note', `Entitlements: ${s.entitlementsSource}`, `<p class="small">${esc(source)}</p>`)}

    ${h3('Entitlements', `${plural(ents.length, 'entry', 'entries')}`)}
    ${
      ents.length === 0
        ? '<p class="small muted">No entitlements are declared.</p>'
        : `${tiles([
            { n: by('high'), label: 'High risk', tone: by('high') ? SEV.high.text : undefined },
            { n: by('medium'), label: 'Medium', tone: by('medium') ? WARN : undefined },
            { n: by('low'), label: 'Low' },
            { n: by('info'), label: 'Informational' },
          ])}
          <div style="height:8px"></div>
          <table class="tbl"><thead><tr><th style="width:34%">Entitlement</th><th style="width:17%">Value</th><th style="width:74px">Risk</th><th>What it means</th></tr></thead>
          <tbody>${ents
            .map(
              (e) => `<tr class="${e.risk === 'high' ? 'flag' : e.risk === 'medium' ? 'warn' : ''}">
                <td><code>${esc(e.key)}</code></td>
                <td class="mono small">${esc(e.value)}</td>
                <td>${riskChip(e.risk)}</td>
                <td class="small">${esc(e.note)}</td></tr>`,
            )
            .join('')}</tbody></table>`
    }
  `;
  return { id: 'ios-signing', html, cost: 108 + 10 * ents.length };
}

function networkPage(ios: IosFacts, num: string): Block {
  const ats = ios.ats;
  const httpDomains = ats.domains.filter((d) => d.allowsHttp);
  let tone = GOOD;
  let head: string;
  let sub: string;
  if (ats.arbitraryLoads) {
    tone = BAD;
    head = 'ATS DISABLED GLOBALLY';
    sub = 'NSAllowsArbitraryLoads is on: every connection may use plain HTTP or weak TLS, which removes the platform’s transport protection.';
  } else if (httpDomains.length > 0) {
    tone = WARN;
    head = `ATS ENFORCED, ${plural(httpDomains.length, 'HTTP exception')}`;
    sub = 'Most traffic must use TLS, but the domains below are allowed over plain HTTP.';
  } else if (ats.configured) {
    head = 'ATS ENFORCED, CUSTOM TLS RULES';
    sub = 'App Transport Security is configured with per-domain settings but no cleartext exceptions.';
  } else {
    head = 'ATS AT PLATFORM DEFAULT';
    sub = 'No exceptions are declared: all connections must use TLS 1.2+ with forward secrecy.';
  }

  const flags: [string, boolean, string][] = [
    ['NSAllowsArbitraryLoads', ats.arbitraryLoads, 'Turns ATS off for all network loads.'],
    ['NSAllowsArbitraryLoadsInWebContent', ats.arbitraryLoadsInWebContent, 'Turns ATS off inside web views.'],
    ['NSAllowsArbitraryLoadsForMedia', ats.arbitraryLoadsForMedia, 'Turns ATS off for AV media loads.'],
    ['NSAllowsLocalNetworking', ats.localNetworking, 'Permits loads to local, unqualified hosts.'],
  ];

  const html = `
    ${opener('dossier-network', num, 'Network security', 'App Transport Security posture and the domains that opt out of it.')}
    <div class="dist-hero">
      <div class="dist-badge" style="color:${tone};border-color:${tone};font-size:9.5pt;max-width:62mm">${esc(head)}</div>
      <p class="small muted">${esc(sub)}</p>
    </div>

    ${h3('ATS switches')}
    <table class="tbl"><thead><tr><th style="width:44%">Key</th><th>Effect</th><th class="r" style="width:80px">State</th></tr></thead><tbody>${flags
      .map(
        ([k, on, note]) => `<tr class="${on && k !== 'NSAllowsLocalNetworking' ? 'flag' : ''}"><td><code>${k}</code></td><td class="muted">${note}</td>
          <td class="r">${state(on, { goodWhen: false, yes: 'on', no: 'off' })}</td></tr>`,
      )
      .join('')}</tbody></table>

    ${h3('Per-domain exceptions', plural(ats.domains.length, 'domain'))}
    ${
      ats.domains.length === 0
        ? '<p class="small muted">No per-domain ATS exceptions are declared.</p>'
        : `<table class="tbl"><thead><tr><th>Domain</th><th style="width:76px">HTTP</th><th style="width:72px">Subdomains</th><th style="width:56px">Min TLS</th><th style="width:70px">Fwd secrecy</th><th style="width:62px">Party</th></tr></thead>
          <tbody>${ats.domains
            .map(
              (d) => `<tr class="${d.allowsHttp ? 'flag' : ''}"><td><code>${esc(d.domain)}</code></td>
              <td>${state(d.allowsHttp, { goodWhen: false, yes: 'allowed', no: 'blocked' })}</td>
              <td class="small">${d.includesSubdomains ? 'included' : 'exact'}</td>
              <td class="small">${val(d.minTls)}</td>
              <td class="small">${d.forwardSecrecy === undefined ? val(undefined) : d.forwardSecrecy ? 'required' : 'not required'}</td>
              <td class="small">${d.thirdParty ? 'third' : 'first'}</td></tr>`,
            )
            .join('')}</tbody></table>`
    }
  `;
  return { id: 'ios-network', html, cost: 107 + 8 * ats.domains.length };
}

function attackSurfacePage(ios: IosFacts, num: string): Block {
  const schemeCount = ios.urlSchemes.reduce((n, u) => n + u.schemes.length, 0);
  const assoc = ios.associatedDomains.map((raw) => {
    const i = raw.indexOf(':');
    const kind = i > 0 ? raw.slice(0, i) : '';
    const rest = i > 0 ? raw.slice(i + 1) : raw;
    // `applinks:example.com?mode=developer` bypasses Apple's CDN: testing only.
    return { kind, domain: rest.split('?')[0], developer: /mode=(developer|managed)/.test(rest) };
  });

  // Only surfaces that exist get a section. The ones that do not are listed once,
  // as checked-and-absent, instead of each spending a heading on "none".
  const absent: string[] = [];
  const parts: string[] = [];
  let cost = 22 + 18 + 12;

  if (ios.urlSchemes.length > 0) {
    cost += 18 + 9 * ios.urlSchemes.length + 8;
    parts.push(`${h3('Custom URL schemes', 'any app on the device can invoke these')}
      <table class="tbl"><thead><tr><th style="width:38%">Scheme</th><th>Name</th><th style="width:80px">Role</th></tr></thead><tbody>${ios.urlSchemes
        .map(
          (u) => `<tr><td>${u.schemes.length ? u.schemes.map((s) => `<code>${esc(s)}://</code>`).join(' ') : val(undefined)}</td>
          <td class="small">${val(u.name)}</td><td class="small">${val(u.role)}</td></tr>`,
        )
        .join('')}</tbody></table>
      <p class="small muted" style="margin-top:5px">Custom schemes are not owned: another app can register the same name and intercept links. Universal links are the verified alternative.</p>`);
  } else absent.push('custom URL schemes');

  if (assoc.length > 0) {
    cost += 18 + 8 * assoc.length;
    parts.push(`${h3('Universal links & associated domains', plural(assoc.length, 'entry', 'entries'))}
      <table class="tbl"><thead><tr><th style="width:36%">Service</th><th>Domain</th></tr></thead><tbody>${assoc
        .map((d) => `<tr><td class="small">${esc(ASSOC_KIND[d.kind] ?? (d.kind || 'Other'))}</td><td><code>${esc(d.domain)}</code>${d.developer ? ' <span class="chip sevchip" style="color:'+WARN+';border-color:'+SEV.medium.fill+';background:'+SEV.medium.tint+'" title="?mode=developer bypasses Apple\u2019s CDN and is meant for testing only">developer mode</span>' : ''}</td></tr>`)
        .join('')}</tbody></table>`);
  } else absent.push('associated domains');

  if (ios.queriedSchemes.length > 0) {
    cost += 30 + 5 * Math.ceil(ios.queriedSchemes.length / 6);
    parts.push(`${h3('Queried schemes', 'apps this app probes for')}
      <div class="caps">${chips(ios.queriedSchemes, 'mono')}</div>
      <p class="small muted" style="margin-top:5px">${plural(ios.queriedSchemes.length, 'scheme')} declared in LSApplicationQueriesSchemes. Each one lets the app learn whether that app is installed.</p>`);
  } else absent.push('queried schemes');

  if (ios.extensions.length > 0) {
    cost += 18 + 9 * ios.extensions.length;
    parts.push(`${h3('App extensions', plural(ios.extensions.length, 'extension'))}
      <table class="tbl"><thead><tr><th>Name</th><th>Extension point</th><th>Bundle ID</th></tr></thead><tbody>${ios.extensions
        .map((e) => `<tr><td><strong>${esc(e.name)}</strong></td><td>${e.point ? `${esc(EXTENSION_POINTS[e.point] ?? e.point.replace(/^com\.apple\./, ''))}<br><code>${esc(e.point)}</code>` : val(undefined)}</td><td><code>${val(e.bundleId)}</code></td></tr>`)
        .join('')}</tbody></table>`);
  } else absent.push('app extensions');

  if (ios.backgroundModes.length > 0) {
    cost += 18 + 8 * ios.backgroundModes.length;
    parts.push(`${h3('Background modes')}
      <table class="tbl"><tbody>${ios.backgroundModes
        .map((m) => `<tr><td style="width:34%"><code>${esc(m)}</code></td><td class="small muted">${esc(BACKGROUND_MODES[m] ?? 'Custom background capability')}${
          SENSITIVE_MODES.has(m) ? ` <strong style="color:${WARN}">\u25b2 can track or listen while the app is not visible</strong>` : ''
        }</td></tr>`)
        .join('')}</tbody></table>`);
  } else absent.push('background modes');

  const html = `
    ${opener('dossier-surface', num, 'Attack surface', 'Every way another app, a web page or the system can reach into this one.')}
    ${tiles([
      { n: schemeCount, label: 'URL schemes' },
      { n: assoc.length, label: 'Associated domains' },
      { n: ios.queriedSchemes.length, label: 'Queried schemes' },
      { n: ios.extensions.length, label: 'Extensions' },
      { n: ios.backgroundModes.length, label: 'Background modes' },
    ])}
    ${parts.join('')}
    ${
      absent.length > 0
        ? `<p class="small muted" style="margin-top:12px"><span class="st good">\u25cb Checked, none declared:</span> ${absent.join(', ')}.</p>`
        : ''
    }
  `;
  return { id: 'ios-surface', html, cost };
}

function hardeningPage(scan: SastScan, ios: IosFacts, num: string): Block {
  const m = ios.main;
  const langs = [m.swift ? 'Swift' : '', m.objc ? 'Objective-C' : ''].filter(Boolean).join(' + ');

  // A gap is a missing protection. ARC only counts where there is managed code to protect.
  const rows = ios.binaries.map((b) => {
    const managed = b.objc || b.swift;
    const checks = [
      { ok: b.stackCanary, applies: true },
      { ok: b.stripped, applies: true },
      { ok: b.signed, applies: true },
      { ok: b.arc, applies: managed },
    ];
    const applicable = checks.filter((c) => c.applies);
    const passed = applicable.filter((c) => c.ok).length;
    return { b, managed, gaps: applicable.length - passed, passed, total: applicable.length };
  });
  rows.sort((x, y) => y.gaps - x.gaps || x.b.name.localeCompare(y.b.name));
  const worst = rows.length ? rows[0].gaps : 0;
  const weakestIds = new Set(worst > 0 ? rows.filter((r) => r.gaps === worst).slice(0, 3).map((r) => r.b.path) : []);

  const count = (f: (b: IosFacts['binaries'][number]) => boolean) => ios.binaries.filter(f).length;
  // Bundled libraries resolve through @rpath or the app directory; the rest are the OS's.
  const bundled = m.linkedLibraries.filter((l) => /^@(rpath|executable_path|loader_path)/.test(l));
  const system = m.linkedLibraries.filter((l) => !bundled.includes(l));
  const weakOnly = m.weakLibraries.filter((l) => !m.linkedLibraries.includes(l));
  /** Every library, in full path form, in balanced columns: nothing is trimmed to "+N more". */
  const libList = (title: string, list: string[]) =>
    list.length === 0
      ? ''
      : `<p class="small keepnext" style="margin:6px 0 2px"><strong>${esc(title)}</strong> <span class="muted">(${list.length})</span></p>
         <ul class="libcols">${list
           .map((l) => `<li>${esc(l)}${m.weakLibraries.includes(l) ? ' <span class="wk">weak</span>' : ''}</li>`)
           .join('')}</ul>`;
  const kindLabel: Record<string, string> = { framework: 'Framework', dylib: 'Dylib', extension: 'Extension', watch: 'Watch' };

  const html = `
    ${opener('dossier-hardening', num, 'Binary hardening', 'Compiler and linker protections on the main executable and on every embedded binary.')}
    ${h3('Main executable', esc(ios.executable ?? ''))}
    ${facts([
      ['Architecture', [m.arch, m.cpu, m.is64Bit ? '64-bit' : '32-bit'].filter(Boolean).join(' \u00b7 ') || undefined],
      ['File type', m.fileType],
      ['Language', langs || undefined],
      ['Size', bytes(m.sizeBytes)],
      ['Built for OS', [m.minOs ? `min ${m.minOs}` : '', m.sdk ? `SDK ${m.sdk}` : ''].filter(Boolean).join(' \u00b7 ') || undefined],
      ['Mach-O UUID', m.uuid, { mono: true }],
    ])}

    ${protectionTable(scan)}

    ${h3('Embedded binaries', plural(ios.binaries.length, 'Mach-O binary', 'Mach-O binaries'))}
    ${
      ios.binaries.length === 0
        ? '<p class="small muted">The app embeds no frameworks, dylibs or extensions.</p>'
        : `<div class="stick">${tiles([
            { n: ios.binaries.length, label: 'Binaries' },
            ...([
              ['Stack canary', (b: IosFacts['binaries'][number]) => b.stackCanary],
              ['ARC', (b: IosFacts['binaries'][number]) => b.arc],
              ['Stripped', (b: IosFacts['binaries'][number]) => b.stripped],
              ['Signed', (b: IosFacts['binaries'][number]) => b.signed],
            ] as const).map(([label, ok]) => {
              const have = count(ok);
              return { n: `${have}/${ios.binaries.length}`, label, tone: have === ios.binaries.length ? GOOD : label === 'Signed' ? BAD : WARN };
            }),
          ])}
          <p class="small muted" style="margin:6px 0 6px">Coverage is binaries carrying each protection. Weakest first. Dots count protections present; ARC is scored only where there is Objective-C or Swift code. Per-binary PIE is not recorded.</p></div>
          <table class="tbl mx"><thead><tr>
            <th>Binary</th><th style="width:66px">Kind</th><th style="width:52px">Version</th><th class="r" style="width:54px">Size</th>
            <th class="gap" style="width:56px">Lang</th><th class="gap" style="width:34px">ARC</th><th class="gap" style="width:40px">Canary</th>
            <th class="gap" style="width:46px">Stripped</th><th class="gap" style="width:44px">Signed</th><th class="gap" style="width:46px">Score</th></tr></thead>
          <tbody>${rows
            .map(({ b, managed, gaps, passed, total }) => {
              const weak = weakestIds.has(b.path);
              const cls = weak ? 'flag' : gaps >= 2 ? 'warn' : '';
              const lang = [b.swift ? 'Swift' : '', b.objc ? 'ObjC' : ''].filter(Boolean).join('+') || 'C';
              const glyph = (ok: boolean, applies = true) =>
                applies ? `<span class="st ${ok ? 'good' : 'bad'}">${ok ? '✓' : '✕'}</span>` : '<span class="na">–</span>';
              return `<tr class="${cls}">
                <td class="who">${esc(b.name)}${weak ? '<span class="weak-tag">weakest</span>' : ''}<small>${esc(b.path)}</small>${b.bundleId ? `<small>${esc(b.bundleId)}</small>` : ''}</td>
                <td class="small nw">${esc(kindLabel[b.kind] ?? b.kind)}</td>
                <td class="small">${val(b.version)}</td>
                <td class="r small">${bytes(b.sizeBytes)}</td>
                <td class="gap small nw">${esc(lang)}</td>
                <td class="gap">${glyph(b.arc, managed)}</td>
                <td class="gap">${glyph(b.stackCanary)}</td>
                <td class="gap">${glyph(b.stripped)}</td>
                <td class="gap">${glyph(b.signed)}</td>
                <td class="gap">${pips(passed, total)}</td></tr>`;
            })
            .join('')}</tbody></table>`
    }

    ${
      m.linkedLibraries.length + m.weakLibraries.length + m.rpaths.length > 0
        ? `${h3('Linking', `${plural(m.linkedLibraries.length, 'library', 'libraries')} linked \u00b7 ${bundled.length} bundled \u00b7 ${system.length} system${m.weakLibraries.length ? ` \u00b7 ${m.weakLibraries.length} weak` : ''}`)}
           ${libList('Bundled with the app (resolved through @rpath or the app directory)', bundled)}
           ${libList('System', system)}
           ${weakOnly.length ? libList('Weak-linked, not in the lists above (optional at run time)', weakOnly) : ''}
           ${m.weakLibraries.length ? '<p class="small muted" style="margin-top:4px">Libraries marked <strong>weak</strong> are optional at run time: the app still launches when they are absent.</p>' : ''}
           ${m.rpaths.length ? `<p class="small" style="margin-top:6px"><strong>Runpaths</strong> ${m.rpaths.map((r) => `<code>${esc(r)}</code>`).join(' ')}</p>` : ''}`
        : ''
    }
  `;
  return { id: 'ios-hardening', html, cost: 190 + 12 * ios.binaries.length + 3.4 * Math.ceil((m.linkedLibraries.length + weakOnly.length) / 2) + 24 };
}

/** Fills every field a partial record may lack, so page builders can assume the shape. */
function normalise(raw: IosFacts): IosFacts {
  const r = raw as Partial<IosFacts>;
  return {
    ...raw,
    supportedPlatforms: r.supportedPlatforms ?? [],
    deviceFamily: r.deviceFamily ?? [],
    requiredCapabilities: r.requiredCapabilities ?? [],
    distribution: r.distribution ?? 'unknown',
    signing: { signed: false, adhoc: false, entitlementsSource: 'none', ...(r.signing ?? {}) },
    entitlements: r.entitlements ?? [],
    ats: {
      arbitraryLoads: false, arbitraryLoadsInWebContent: false, arbitraryLoadsForMedia: false,
      localNetworking: false, configured: false, ...(r.ats ?? {}), domains: r.ats?.domains ?? [],
    },
    urlSchemes: (r.urlSchemes ?? []).map((u) => ({ ...u, schemes: u.schemes ?? [] })),
    queriedSchemes: r.queriedSchemes ?? [],
    associatedDomains: r.associatedDomains ?? [],
    backgroundModes: r.backgroundModes ?? [],
    privacyManifest: r.privacyManifest ?? false,
    extensions: r.extensions ?? [],
    binaries: r.binaries ?? [],
    main: {
      is64Bit: true, swift: false, objc: false, stripped: false, localSymbols: 0, sizeBytes: 0,
      hardenedRuntime: false, encrypted: false, ...(r.main ?? {}),
      linkedLibraries: r.main?.linkedLibraries ?? [],
      weakLibraries: r.main?.weakLibraries ?? [],
      rpaths: r.main?.rpaths ?? [],
    },
    plistKeys: r.plistKeys ?? 0,
    fileCount: r.fileCount ?? 0,
  };
}

/**
 * The iOS dossier, or '' when the scan carries no iOS facts.
 *
 * Sections are packed onto sheets by estimated height: a small section joins
 * the sheet before it (kept whole), a large one starts a fresh sheet. That keeps
 * a nearly empty ATS page from costing a whole sheet, while long lists still
 * break across pages cleanly.
 */
export function iosDossier(scan: SastScan, sectionNum: number): string {
  if (scan.artifact.platform !== 'ios' || !scan.artifact.ios) return '';
  const ios = normalise(scan.artifact.ios);
  const n = (i: number) => `${sectionNum}.${i}`;
  return packSections([
    safeBlock('ios-profile', 'profile', () => profilePage(scan, ios, String(sectionNum).padStart(2, '0'))),
    safeBlock('ios-signing', 'signing', () => signingPage(ios, n(2))),
    safeBlock('ios-network', 'network', () => networkPage(ios, n(3))),
    safeBlock('ios-surface', 'surface', () => attackSurfacePage(ios, n(4))),
    safeBlock('ios-hardening', 'hardening', () => hardeningPage(scan, ios, n(5))),
  ]);
}

/**
 * The at-a-glance strip the console shows under its hero: each is a yes/no a
 * reviewer asks first. `state` is the word beside the glyph, so the chip never
 * relies on colour.
 */
export function iosSignals(scan: SastScan): Signal[] {
  if (!scan.artifact.ios) return [];
  const ios = normalise(scan.artifact.ios);
  const bp = scan.artifact.binaryProtections;
  const out: Signal[] = [];
  const relaxed = ios.ats.arbitraryLoads;
  const exceptions = ios.ats.domains.filter((d) => d.allowsHttp).length;
  out.push({
    label: 'Transport security',
    tone: relaxed ? 'bad' : exceptions > 0 ? 'warn' : 'good',
    state: relaxed ? 'ATS off' : exceptions > 0 ? `${exceptions} exception${exceptions === 1 ? '' : 's'}` : 'ATS strict',
  });
  if (bp) {
    out.push(
      { label: 'PIE / ASLR', tone: bp.pie ? 'good' : 'bad', state: bp.pie ? 'on' : 'off' },
      { label: 'ARC', tone: bp.arc ? 'good' : 'bad', state: bp.arc ? 'on' : 'off' },
      { label: 'Stack canary', tone: bp.stackCanary ? 'good' : 'bad', state: bp.stackCanary ? 'on' : 'off' },
    );
  }
  out.push(
    { label: 'Symbols', tone: ios.main.stripped ? 'good' : 'warn', state: ios.main.stripped ? 'stripped' : 'present' },
    { label: 'Privacy manifest', tone: ios.privacyManifest ? 'good' : 'warn', state: ios.privacyManifest ? 'present' : 'missing' },
  );
  const debuggable = ios.entitlements.some((e) => e.key === 'get-task-allow' && /^(true|1|yes)$/i.test(e.value.trim()));
  out.push({ label: 'Debugger attach', tone: debuggable ? 'bad' : 'good', state: debuggable ? 'allowed' : 'blocked' });
  return out;
}
