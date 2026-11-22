/**
 * The Android half of the App dossier: what the app *is*, read from the
 * manifest and the archive, as opposed to what is wrong with it. The
 * counterpart of `ios.ts`.
 *
 * Every field of `AndroidFacts` is optional in practice (older scans predate
 * it), so nothing here assumes a shape: `normalise` fills the gaps, and a scan
 * with no Android facts at all falls back to the generic dossier page.
 */
import type { AndroidFacts, SastScan } from '../sastTypes';
import {
  BAD, GOOD, SEV, WARN, appIcon, bytes, chips, esc, facts, h3, opener, packSections, plural, safeBlock, state, tiles, val,
} from './kit';
import type { Block } from './kit';
import { nativeBlock, permissionTable } from './reference';
import type { Signal } from './signals';

/** API level -> the release it names, so "26 → 34" reads as software a person has heard of. */
const RELEASE: Record<number, string> = {
  19: '4.4', 21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1', 26: '8.0', 27: '8.1', 28: '9', 29: '10', 30: '11',
  31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16',
};

function sdk(level: string | undefined): string | undefined {
  if (!level) return undefined;
  const r = RELEASE[Number(level)];
  return r ? `API ${level} (Android ${r})` : `API ${level}`;
}

const KIND_LABEL: Record<string, string> = { activity: 'Activity', service: 'Service', receiver: 'Receiver', provider: 'Provider' };
const KIND_ORDER = ['activity', 'service', 'receiver', 'provider'];

const SCHEME_HINT: [string, string, string][] = [
  ['v1', 'v1 (JAR signature)', 'Legacy; forgeable on its own from Android 7 onward.'],
  ['v2', 'v2 (APK Signature Scheme)', 'Signs the whole archive: the minimum for a modern build.'],
  ['v3', 'v3 (key rotation)', 'Allows the signing key to be rotated without reinstalling.'],
];

function normalise(raw: AndroidFacts): AndroidFacts {
  const r = raw as Partial<AndroidFacts>;
  return {
    ...raw,
    debuggable: r.debuggable ?? false,
    allowBackup: r.allowBackup ?? false,
    testOnly: r.testOnly ?? false,
    networkSecurityConfig: r.networkSecurityConfig ?? false,
    usesFeatures: r.usesFeatures ?? [],
    customPermissions: r.customPermissions ?? [],
    components: (r.components ?? []).map((c) => ({ ...c, actions: c.actions ?? [], schemes: c.schemes ?? [] })),
    nativeAbis: r.nativeAbis ?? [],
  };
}

/** Exposed without a permission guard: the components another app can start with no credentials. */
function unguarded(c: AndroidFacts['components'][number]): boolean {
  return c.exported && !c.permission;
}

/* ----------------------------------------------------------------------------
 * Blocks
 * ------------------------------------------------------------------------- */

function profileBlock(scan: SastScan, and: AndroidFacts, num: string): Block {
  const a = scan.artifact;
  const target = Number(a.targetSdk);
  const flag = (
    name: string, attr: string, on: boolean, goodWhen: boolean, yes: string, no: string, note: string,
  ) => ({ name, attr, note, cell: state(on, { goodWhen, yes, no }), bad: on !== goodWhen });

  const cleartextRow =
    and.cleartextTraffic === undefined
      ? {
          name: 'Cleartext traffic', attr: 'android:usesCleartextTraffic',
          cell: '<span class="st neutral">○ not set</span>', bad: false,
          note: `The manifest is silent, so the platform default applies: ${
            target >= 28 ? 'plain HTTP is blocked for apps that target API 28 or later' : 'plain HTTP is permitted for apps that target below API 28'
          }.`,
        }
      : flag('Cleartext traffic', 'android:usesCleartextTraffic', and.cleartextTraffic, false, 'permitted', 'blocked',
          'When on, the app may use plain HTTP for any connection, which can be read or altered on the network.');

  const rows = [
    flag('Debuggable', 'android:debuggable', and.debuggable, false, 'enabled', 'off',
      'A debuggable build lets anyone attach a debugger and read the app’s memory and private data.'),
    flag('Backups', 'android:allowBackup', and.allowBackup, false, 'allowed', 'disabled',
      'Lets adb and cloud backup copy the app’s data off the device. Disable it, or exclude sensitive files.'),
    cleartextRow,
    flag('Test only', 'android:testOnly', and.testOnly, false, 'set', 'off',
      'A test-only build cannot be published to a store and is installed with special flags.'),
    {
      name: 'Network security config', attr: 'android:networkSecurityConfig', bad: false,
      cell: `<span class="st neutral">${and.networkSecurityConfig ? '● declared' : '○ none'}</span>`,
      note: and.networkSecurityConfig
        ? 'Custom trust anchors, pinning or cleartext rules apply. Read them in res/xml.'
        : 'No custom network rules: platform defaults apply.',
    },
  ];

  const schemes = a.signatureSchemes ?? [];
  const otherSchemes = schemes.filter((s) => !SCHEME_HINT.some(([k]) => k === s));
  const signers = a.signers ?? [];
  const name = and.label ?? a.packageName ?? a.fileName;

  const html = `
    ${opener('dossier', num, 'App dossier', 'What the app is: identity, manifest configuration, signing and the footprint it carries.')}
    <div class="app-id">
      ${appIcon(a.iconDataUrl, name, a.packageName ?? a.fileName, 'ico-page')}
      <div class="app-id-t"><div class="nm">${esc(name)}</div>
        <div class="bid">${esc(a.packageName ?? 'unknown package')}</div>
        <div class="app-id-c">${[
          a.versionName ? `v${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : '',
          `Android ${RELEASE[Number(a.minSdk)] ?? a.minSdk ?? '?'}+`,
          bytes(a.sizeBytes),
        ].filter(Boolean).map((t) => `<span class="chip cap">${esc(t)}</span>`).join(' ')}</div></div>
    </div>

    ${h3('Identity')}
    ${facts([
      ['App label', and.label],
      ['Package', a.packageName],
      ['Version', a.versionName ? `${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : undefined],
      ['Minimum SDK', sdk(a.minSdk)],
      ['Target SDK', sdk(a.targetSdk)],
      ['Size', bytes(a.sizeBytes)],
      ['Launcher activity', and.launcherActivity, { wide: true, mono: true }],
      ['Application class', and.applicationClass, { wide: true, mono: true }],
      ['Files inside', String(a.fileCount)],
      ['Native ABIs', and.nativeAbis.join(', ') || undefined],
      ['Libraries detected', (a.detectedLibraries ?? []).length ? String(a.detectedLibraries.length) : undefined],
    ])}

    ${h3('Manifest configuration', 'plain-language state of each flag')}
    <table class="tbl"><thead><tr><th style="width:24%">Setting</th><th style="width:26%">Manifest attribute</th><th style="width:88px">State</th><th>What it means</th></tr></thead>
    <tbody>${rows
      .map((r) => `<tr class="${r.bad ? 'flag' : ''}"><td><strong>${esc(r.name)}</strong></td><td><code>${esc(r.attr)}</code></td><td>${r.cell}</td><td class="small muted">${esc(r.note)}</td></tr>`)
      .join('')}</tbody></table>

    ${h3('Signing and certificates', schemes.length ? `schemes: ${esc(schemes.join(', '))}` : 'unknown')}
    <table class="tbl"><tbody>${SCHEME_HINT.map(
      ([key, label, hint]) =>
        `<tr><td style="width:32%"><strong>${esc(label)}</strong></td><td class="small muted">${esc(hint)}</td><td class="r" style="width:84px">${state(schemes.includes(key), { yes: 'present', no: 'absent' })}</td></tr>`,
    ).join('')}${otherSchemes
      .map((s) => `<tr><td><strong>${esc(s)}</strong></td><td class="small muted">Additional signature scheme.</td><td class="r">${state(true, { yes: 'present' })}</td></tr>`)
      .join('')}</tbody></table>
    ${
      signers.length
        ? `<p class="small keepnext" style="margin:8px 0 3px"><strong>Certificate${signers.length === 1 ? '' : 's'}</strong></p><ul class="urls">${signers.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>`
        : '<p class="small muted" style="margin-top:6px">No signing certificate could be read.</p>'
    }
  `;
  return { id: 'android-profile', html, cost: 999 };
}

function componentsBlock(scan: SastScan, and: AndroidFacts, num: string): Block {
  const comps = and.components;
  const count = (k: string) => comps.filter((c) => c.kind === k).length;
  const exported = comps.filter((c) => c.exported);
  const open = comps.filter(unguarded);
  const groups: { title: string; note: string; list: typeof comps }[] = [
    { title: 'Exported, no permission guard', note: 'Another app can start these with no credentials: each is an entry point whose inputs are untrusted.', list: open },
    { title: 'Exported, permission-guarded', note: 'Reachable only by callers holding the named permission.', list: comps.filter((c) => c.exported && c.permission) },
  ];
  const sortKey = (c: (typeof comps)[number]) => `${KIND_ORDER.indexOf(c.kind)}${c.name}`;
  const internal = comps.length - exported.length;
  const internalText = internal > 0 ? `${plural(internal, 'component')} ${internal === 1 ? 'is' : 'are'} internal to the app (not exported) and not listed.` : '';
  const browsable = scan.artifact.components?.browsable ?? [];

  const html = `
    ${opener('dossier-components', num, 'Component inventory', 'Every component the manifest declares, most exposed first.')}
    ${tiles([
      { n: count('activity'), label: 'Activities' },
      { n: count('service'), label: 'Services' },
      { n: count('receiver'), label: 'Receivers' },
      { n: count('provider'), label: 'Providers' },
      { n: exported.length, label: 'Exported', tone: exported.length ? WARN : undefined },
      { n: open.length, label: 'Unguarded', tone: open.length ? BAD : undefined, sub: 'exported, no permission' },
    ])}
    ${
      comps.length === 0
        ? '<p class="small muted" style="margin-top:8px">No component list was recorded for this scan.</p>'
        : exported.length === 0
          ? `<p class="small muted" style="margin-top:8px">No component is exported. ${internalText}</p>`
          : `<table class="tbl comp"><thead><tr><th>Component</th><th style="width:52px">Kind</th><th style="width:74px">Exported</th><th style="width:26%">Guard</th><th style="width:30%">Intent filters</th></tr></thead>
          ${groups
            .filter((g) => g.list.length > 0)
            .map(
              (g) => `<tbody><tr class="grp"><td colspan="5"><strong>${esc(g.title)}</strong> <span class="muted small">${g.list.length} · ${esc(g.note)}</span></td></tr>
              ${[...g.list]
                .sort((x, y) => sortKey(x).localeCompare(sortKey(y)))
                .map(
                  (c) => `<tr class="${unguarded(c) ? 'flag' : c.exported ? 'warn' : ''}">
                  <td><code>${esc(c.name)}</code></td>
                  <td class="small">${esc(KIND_LABEL[c.kind] ?? c.kind)}</td>
                  <td>${state(c.exported, { goodWhen: false, yes: 'yes', no: 'no' })}</td>
                  <td class="small">${c.permission ? `<code>${esc(c.permission)}</code>` : c.exported ? `<strong style="color:${BAD}">none</strong>` : '<span class="na">—</span>'}</td>
                  <td class="small">${
                    c.actions.length || c.schemes.length || c.browsable
                      ? `${c.browsable ? `<span class="chip sevchip" style="color:${SEV.high.text};border-color:${SEV.high.fill};background:${SEV.high.tint}">browsable</span> ` : ''}${
                          c.schemes.length ? `<span class="muted">schemes</span> ${c.schemes.map((s) => `<code>${esc(s)}://</code>`).join(' ')}<br>` : ''
                        }${c.actions.map((x) => `<code>${esc(x)}</code>`).join('<br>')}`
                      : '<span class="na">—</span>'
                  }</td></tr>`,
                )
                .join('')}</tbody>`,
            )
            .join('')}</table>
        ${internalText ? `<p class="small muted" style="margin-top:6px">${internalText}</p>` : ''}`
    }
    ${
      browsable.length > 0
        ? `${h3('Reachable from a web link', String(browsable.length))}
           <table class="tbl"><thead><tr><th>Component</th><th>Schemes / hosts</th></tr></thead><tbody>${browsable
             .map((b) => `<tr><td><code>${esc(b.component)}</code></td><td class="small">${esc((b.schemes ?? []).join(', '))}${(b.hosts ?? []).length ? ` @ ${esc(b.hosts.join(', '))}` : ''}</td></tr>`)
             .join('')}</tbody></table>`
        : ''
    }
  `;
  return { id: 'android-components', html, cost: 40 + 11 * comps.length + 8 * browsable.length };
}

function permissionsBlock(scan: SastScan, and: AndroidFacts, num: string): Block {
  const perms = scan.artifact.permissionDetail ?? [];
  const html = `
    ${opener('dossier-permissions', num, 'Permissions', 'What the app asks the system for, and what it offers other apps.')}
    ${
      and.customPermissions.length > 0
        ? `${h3('Custom permissions declared', plural(and.customPermissions.length, 'permission'))}
           <p class="lead">Permissions this app defines for other apps to request. A weak protection level lets any app obtain them.</p>
           <table class="tbl"><thead><tr><th>Name</th><th style="width:120px">Protection</th></tr></thead><tbody>${and.customPermissions
             .map((p) => `<tr class="${/^normal$|^dangerous$/.test(p.protection) ? 'warn' : ''}"><td><code>${esc(p.name)}</code></td><td class="small">${val(p.protection)}</td></tr>`)
             .join('')}</tbody></table>`
        : '<p class="small muted" style="margin-top:10px"><span class="st good">○ Checked, none declared:</span> custom permissions.</p>'
    }
    ${
      and.usesFeatures.length > 0
        ? `${h3('Hardware and software features', plural(and.usesFeatures.length, 'feature'))}
           <div class="caps">${chips(and.usesFeatures.map((f) => `${f.name}${f.required ? '' : ' (optional)'}`), 'cap')}</div>`
        : ''
    }
    ${h3(`Requested permissions (${perms.length || (scan.artifact.permissions ?? []).length})`)}
    ${permissionTable(scan)}
  `;
  return { id: 'android-permissions', html, cost: 40 + 8 * perms.length + 8 * and.customPermissions.length + 3 * and.usesFeatures.length };
}

function networkBlock(scan: SastScan, and: AndroidFacts, num: string): Block {
  const a = scan.artifact;
  const endpoints = scan.recon?.endpoints ?? [];
  const cleartextEndpoints = endpoints.filter((e) => e.cleartext);
  const domains = scan.domains ?? [];
  const cleartextHosts = domains.filter((d) => d.cleartext);
  const nonProd = domains.filter((d) => d.environment === 'non-production' || d.environment === 'local');
  const target = Number(a.targetSdk);

  let tone = GOOD;
  let head: string;
  let sub: string;
  if (and.cleartextTraffic === true) {
    tone = BAD;
    head = 'CLEARTEXT PERMITTED';
    sub = 'usesCleartextTraffic is on: any connection may use plain HTTP, which removes the platform’s transport protection.';
  } else if (cleartextEndpoints.length > 0 || cleartextHosts.length > 0) {
    tone = WARN;
    head = `HTTPS DEFAULT, ${plural(cleartextHosts.length || cleartextEndpoints.length, 'plain-http host')}`;
    sub = 'The platform blocks cleartext by default, but the artifact contains http:// URLs. They fail at run time unless a network security config allows them.';
  } else if (and.cleartextTraffic === undefined && target > 0 && target < 28) {
    tone = WARN;
    head = 'CLEARTEXT ALLOWED BY DEFAULT';
    sub = `The manifest is silent and the app targets API ${target}: below API 28 plain HTTP is permitted unless configured otherwise.`;
  } else {
    head = and.networkSecurityConfig ? 'HTTPS, CUSTOM NETWORK RULES' : 'HTTPS ONLY';
    sub = and.networkSecurityConfig
      ? 'Cleartext is not permitted and a network security config adds custom trust rules.'
      : 'Cleartext is not permitted and no plain-http URLs were found.';
  }

  const html = `
    ${opener('dossier-network', num, 'Network and native code', 'Transport posture and the compiled libraries bundled with the app.')}
    <div class="dist-hero">
      <div class="dist-badge" style="color:${tone};border-color:${tone};font-size:9.5pt;max-width:62mm">${esc(head)}</div>
      <p class="small muted">${esc(sub)}</p>
    </div>
    <div style="height:8px"></div>
    ${tiles([
      { n: (scan.recon?.hosts ?? []).length, label: 'Hosts contacted' },
      { n: cleartextHosts.length, label: 'Plain-http hosts', tone: cleartextHosts.length ? BAD : undefined },
      { n: cleartextEndpoints.length, label: 'Cleartext URLs', tone: cleartextEndpoints.length ? BAD : undefined },
      { n: nonProd.length, label: 'Non-production', tone: nonProd.length ? WARN : undefined, sub: 'or local hosts' },
    ])}
    ${
      cleartextHosts.length > 0
        ? `<p class="small keepnext" style="margin:10px 0 3px"><strong style="color:${BAD}">Hosts reached over plain http</strong></p><p class="hosts">${cleartextHosts.map((d) => `<code>${esc(d.host)}</code>`).join(' ')}</p>`
        : ''
    }
    <p class="small muted" style="margin-top:6px">Every host, URL and file is listed in the appendix Domains table.</p>
    ${nativeBlock(scan, and.nativeAbis)}
  `;
  return { id: 'android-network', html, cost: 90 + 8 * (a.nativeLibraryDetail ?? []).length };
}

/** True when the dossier carries the tables the appendix would otherwise repeat. */
export function androidCoversPermissionsAndNative(scan: SastScan): boolean {
  return scan.artifact.platform === 'android' && !!scan.artifact.android;
}

/** The Android dossier, or '' when the scan carries no Android facts. */
export function androidDossier(scan: SastScan, sectionNum: number): string {
  if (scan.artifact.platform !== 'android' || !scan.artifact.android) return '';
  const and = normalise(scan.artifact.android);
  const n = (i: number) => `${sectionNum}.${i}`;
  return packSections([
    safeBlock('android-profile', 'profile', () => profileBlock(scan, and, String(sectionNum).padStart(2, '0'))),
    safeBlock('android-components', 'components', () => componentsBlock(scan, and, n(2))),
    safeBlock('android-permissions', 'permissions', () => permissionsBlock(scan, and, n(3))),
    safeBlock('android-network', 'network', () => networkBlock(scan, and, n(4))),
  ]);
}

/** The at-a-glance strip: the manifest questions a reviewer asks first. */
export function androidSignals(scan: SastScan): Signal[] {
  if (!scan.artifact.android) return [];
  const and = normalise(scan.artifact.android);
  const a = scan.artifact;
  const target = Number(a.targetSdk);
  const out: Signal[] = [
    { label: 'Debuggable', tone: and.debuggable ? 'bad' : 'good', state: and.debuggable ? 'enabled' : 'off' },
    { label: 'Backups', tone: and.allowBackup ? 'warn' : 'good', state: and.allowBackup ? 'allowed' : 'disabled' },
    and.cleartextTraffic === undefined
      ? { label: 'Cleartext traffic', tone: target >= 28 ? 'good' : 'warn', state: target >= 28 ? 'default: blocked' : 'default: allowed' }
      : { label: 'Cleartext traffic', tone: and.cleartextTraffic ? 'bad' : 'good', state: and.cleartextTraffic ? 'permitted' : 'blocked' },
  ];
  const schemes = a.signatureSchemes ?? [];
  out.push(
    schemes.length === 0
      ? { label: 'Signing', tone: 'muted', state: 'unknown' }
      : schemes.includes('v2') || schemes.includes('v3')
        ? { label: 'Signing', tone: 'good', state: schemes.includes('v3') ? 'v2 + v3' : 'v2' }
        : { label: 'Signing', tone: 'warn', state: 'v1 only' },
  );
  out.push({ label: 'Network security config', tone: 'muted', state: and.networkSecurityConfig ? 'declared' : 'none' });
  const open = and.components.filter(unguarded).length;
  out.push({ label: 'Unguarded exported components', tone: open ? 'warn' : 'good', state: String(open) });
  if (and.testOnly) out.push({ label: 'Test only', tone: 'bad', state: 'set' });
  const weakNative = (a.nativeLibraryDetail ?? []).filter((l) => !(l.nx && l.pie && l.stackCanary)).length;
  if ((a.nativeLibraryDetail ?? []).length > 0) {
    out.push({ label: 'Native hardening', tone: weakNative ? 'warn' : 'good', state: weakNative ? `${weakNative} weak` : 'all hardened' });
  }
  return out;
}
