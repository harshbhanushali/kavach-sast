/**
 * "Scope & methodology": what was examined, with what, how severity is decided
 * and what this assessment cannot say. Written for a reader who has to decide
 * how far to trust the numbers.
 *
 * Degrades gracefully: scans from before `method` was recorded get generic
 * text derived from the platform, and say that the exact tool run was not kept.
 */
import type { SastScan } from '../sastTypes';
import { esc, facts, fmtDateTime, h3, opener, plural } from './kit';
import { triageScopeText } from './triageView';
import type { TriageView } from './triageView';

const li = (items: string[], cls = '') => `<ul class="plain${cls ? ` ${cls}` : ''}">${items.map((x) => `<li>${x}</li>`).join('')}</ul>`;

/** The tool list as text, plus a decompiler sentence that says plainly which route the code took. */
function toolsBlock(scan: SastScan): string {
  const a = scan.artifact;
  const ios = a.platform === 'ios';
  const m = scan.method;

  if (!m) {
    const generic = ios
      ? [
          'Mach-O reader for the main executable and embedded binaries (headers, load commands, symbols).',
          'Code-signature, entitlement and provisioning-profile parsers; Info.plist parser.',
          'Pattern rules over the binary’s string table and the bundled resources.',
        ]
      : [
          'Manifest and resource decoding; signature verification; ELF reader for native libraries.',
          'Pattern rules, entropy checks and advisory matching over the decoded files and, where available, decompiled code.',
        ];
    return `${li(generic.map(esc), 'cols2')}
      <p class="small muted" style="margin-top:4px">This scan predates the record of exactly which tools ran, so the list above is the standard toolchain for ${
        ios ? 'iOS' : 'Android'
      } artifacts rather than a log of this run.${ios ? '' : ' Whether the code was read as Java or as Dalvik assembly was not recorded.'}</p>`;
  }

  const tools = (m.tools ?? []).map(esc);
  let route: string;
  if (ios) {
    route =
      'iOS apps ship as compiled machine code, so nothing was decompiled. Code-level rules ran over the binary’s string table and the bundled resources instead. They cannot see call sites, so patterns that depend on how a value is used are matched with less confidence than they are on Android.';
  } else if (m.decompiler === 'java') {
    route = `<strong>Decompiled to Java.</strong> The bytecode was decompiled to ${plural(m.javaFileCount, 'Java source file')}, and code rules ran on that source with class and method context. This is the preferred route: findings quote readable code.`;
  } else if (m.decompiler === 'smali') {
    route = `<strong>Read as Dalvik assembly (no Java source was produced).</strong> Code rules ran on the Dalvik assembly rather than on Java. It is accurate but harder to read, and call-site patterns are matched with less context, so some code-level findings may be missed and those reported quote bytecode instead of source.`;
  } else {
    route =
      '<strong>No decompiler ran.</strong> Code-level rules were not evaluated on source; only the manifest, resources, signatures and native libraries could be examined. Treat the absence of code-level findings as not assessed rather than clean.';
  }
  return `${tools.length ? li(tools, 'cols2') : ''}<p class="small" style="margin-top:4px">${route}</p>`;
}

export function scopeLists(scan: SastScan): { inScope: string[]; outScope: string[] } {
  const a = scan.artifact;
  if (a.platform === 'ios') {
    const enc = a.ios?.main?.encrypted;
    return {
      inScope: [
        'Info.plist: App Transport Security, URL schemes, permission purpose strings, background modes',
        'Entitlements and the embedded provisioning profile',
        'Code signature and distribution type',
        'Embedded frameworks, dynamic libraries and app extensions: inventory, version, binary hardening',
        'Main binary protections (PIE, ARC, stack canary, symbols) and its string table',
        'Bundled files: plists, configuration, certificates, resources',
      ],
      outScope: [
        'Backend and server APIs the app talks to',
        'Runtime behaviour: no code was run, hooked or debugged; no traffic was intercepted',
        'Business logic and authorisation flows',
        'Known vulnerabilities in third-party frameworks by version: no advisory database is applied on iOS',
        enc === true
          ? 'Encrypted code: the main binary is FairPlay-encrypted, so only what is readable without decrypting was seen'
          : 'Encrypted code: an App Store download is FairPlay-encrypted and would reveal less than this build did',
        'The device, the operating system and other apps installed alongside',
      ],
    };
  }
  return {
    inScope: [
      'AndroidManifest.xml: flags, components, exported surface, permissions, link handlers',
      'Network security configuration and other decoded resources',
      'Signing certificates and signature schemes',
      'Native libraries: compiler and linker hardening (ELF headers)',
      'Application code, as decompiled Java or smali (see tools)',
      'Bundled assets and resources; declared library versions matched against a curated advisory set',
    ],
    outScope: [
      'Backend and server APIs the app talks to',
      'Runtime behaviour: no code was run, hooked or debugged; no traffic was intercepted',
      'Business logic and authorisation flows',
      'Library vulnerabilities beyond the curated advisory set; this is not a live CVE feed',
      'Code that is packed, encrypted or loaded only at runtime',
      'The device, the operating system and other apps installed alongside',
    ],
  };
}

export function scopePage(scan: SastScan, num: string, tri?: TriageView, sections?: string): string {
  const a = scan.artifact;
  const ios = a.platform === 'ios';
  const cov = scan.coverageSummary;
  const lists = scopeLists(scan);
  const name = ios ? (a.ios?.displayName ?? a.fileName) : (a.android?.label ?? a.fileName);

  return `
  <section class="pg newpage${tri?.on ? ' tri' : ''}" id="scope">
    ${opener('scope-top', num, 'Scope & methodology', 'What was examined, with what, and what this assessment cannot tell you.')}
    ${facts([
      ['Target', `${name} \u00b7 ${a.fileName}`],
      ['Platform and package', `${ios ? 'iOS' : 'Android'} \u00b7 ${(ios ? (a.ios?.bundleId ?? a.packageName) : a.packageName) ?? 'unknown package'}`],
      ['Version and size', `${a.versionName ? `${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''} \u00b7 ` : ''}${(a.sizeBytes / 1024 / 1024).toFixed(2)} MB`],
      ['Application SHA-256', `${a.sha256.slice(0, 20)}\u2026`, { mono: true }],
      ['Scan type', 'Static analysis. The artifact was read; nothing was executed, no network was contacted and nothing was uploaded.', { wide: true }],
      ['Date and duration', `${fmtDateTime(scan.createdAt)} \u00b7 ${(scan.durationMs / 1000).toFixed(1)} s`],
      ['Engine', 'Kavach static analyser'],
      ['Rules evaluated', cov ? `${cov.total} (${cov.flagged} flagged, ${cov.clear} clear)` : 'not recorded'],
      ['Authentication', 'Not applicable: no accounts or test credentials'],
    ], 4)}

    ${h3('Tools used')}
    ${toolsBlock(scan)}

    <div class="two eq">
      <div>${h3('In scope')}${li(lists.inScope.map(esc))}</div>
      <div>${h3('Not in scope')}${li(lists.outScope.map(esc))}</div>
    </div>

    ${sections ? `${h3('In this report')}${sections}` : ''}

    ${tri?.on ? `${h3('Triage decisions', 'recorded after the scan')}${triageScopeText(tri)}` : ''}
  </section>`;
}
