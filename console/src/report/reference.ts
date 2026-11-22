/**
 * The reference tables: everything the console shows on its Permissions,
 * Dependencies, Domains, Secrets, Binary and How-to-verify tabs.
 *
 * These are long by nature and are never trimmed. A list too long for one sheet
 * flows onto the next with its header row repeated; where the data would be
 * unwieldy as a table (hosts, libraries) it is set in compact columns instead.
 * Every function returns '' when its data is absent, so an older scan simply
 * has fewer sections rather than empty ones.
 */
import { commandsFor } from '../components/HowToVerify';
import type { DomainRow, SastFinding, SastScan } from '../sastTypes';
import { BAD, GOOD, NEUTRAL, SEV, WARN, callout, esc, h3, opener, plural, sevChip, state } from './kit';
import { protectionRows } from './ios';

const LEVEL_TONE: Record<string, string> = {
  dangerous: BAD, signature: SEV.high.text, unknown: NEUTRAL, normal: GOOD,
};

const LEVEL_ORDER = ['dangerous', 'signature', 'unknown', 'normal'];

/* ----------------------------------------------------------------------------
 * Permissions
 * ------------------------------------------------------------------------- */

/** Every requested permission (or iOS purpose string) with its level and what it allows. */
export function permissionTable(scan: SastScan): string {
  const rows = scan.artifact.permissionDetail ?? [];
  if (rows.length === 0) {
    const names = scan.artifact.permissions ?? [];
    return names.length > 0
      ? `<p class="hosts">${names.map((n) => `<code>${esc(n)}</code>`).join(' ')}</p>`
      : '<p class="muted small">No permissions are requested.</p>';
  }
  const tally = LEVEL_ORDER.map((l) => [l, rows.filter((p) => p.level === l).length] as const).filter(([, n]) => n > 0);
  const other = rows.filter((p) => !LEVEL_ORDER.includes(p.level)).length;
  return `<p class="small muted" style="margin-bottom:5px">${tally
    .map(([l, n]) => `<strong style="color:${LEVEL_TONE[l]}">${n} ${esc(l)}</strong>`)
    .concat(other ? [`${other} other`] : [])
    .join(' · ')}. Dangerous permissions prompt the user; normal ones are granted silently at install.</p>
    <table class="tbl"><thead><tr><th style="width:36%">Permission</th><th style="width:84px">Level</th><th>What it allows</th></tr></thead>
    <tbody>${rows
      .map(
        (p) => `<tr class="${p.level === 'dangerous' ? 'warn' : ''}"><td><code>${esc(p.name.replace('android.permission.', ''))}</code></td>
        <td><strong style="color:${LEVEL_TONE[p.level] ?? NEUTRAL};font-size:7.4pt;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap">${esc(p.level)}</strong></td>
        <td class="small">${esc(p.description)}</td></tr>`,
      )
      .join('')}</tbody></table>`;
}

/* ----------------------------------------------------------------------------
 * Dependencies
 * ------------------------------------------------------------------------- */

export function dependencyBlock(scan: SastScan): string {
  const deps = scan.artifact.dependencies ?? [];
  if (deps.length === 0) return '';
  const vulnerable = deps.filter((d) => d.advisoryCount > 0).length;
  return `${h3(`Dependencies (${deps.length})`, `<strong style="color:${vulnerable ? BAD : GOOD}">${vulnerable ? '●' : '○'} ${vulnerable} with advisories</strong> · ${deps.length - vulnerable} clear`)}
    <p class="lead">Versions read from <code>META-INF/*.version</code> and <code>pom.properties</code>: what the build wrote into the artifact, not inferred from package names. Matched against a curated advisory set, not a live CVE feed.</p>
    <table class="tbl"><thead><tr><th style="width:14px"></th><th>Coordinate</th><th style="width:76px">Version</th><th style="width:70px">Advisories</th><th>Read from</th></tr></thead>
    <tbody>${deps
      .map(
        (d) => `<tr class="${d.advisoryCount > 0 ? 'flag' : ''}"><td style="color:${d.advisoryCount > 0 ? BAD : GOOD}">${d.advisoryCount > 0 ? '●' : '○'}</td>
        <td><code>${esc(d.coordinate)}</code></td><td class="small">${esc(d.version)}</td>
        <td class="small">${d.advisoryCount > 0 ? `<strong style="color:${BAD}">${d.advisoryCount}</strong>` : '<span class="ok">clear</span>'}</td>
        <td class="small muted"><code>${esc(d.source)}</code></td></tr>`,
      )
      .join('')}</tbody></table>`;
}

/* ----------------------------------------------------------------------------
 * Domains
 * ------------------------------------------------------------------------- */

const ENVIRONMENT: Record<string, { label: string; color: string; tint: string }> = {
  'non-production': { label: 'non-production', color: WARN, tint: SEV.medium.tint },
  local: { label: 'local', color: SEV.low.text, tint: SEV.low.tint },
  production: { label: 'production', color: NEUTRAL, tint: '#fff' },
  unknown: { label: '—', color: NEUTRAL, tint: '#fff' },
};

/**
 * Every host the artifact mentions, worst first as the console sorts them,
 * with every URL and every file it was found in (the console's per-host
 * "URLs" and "Found in" panels, opened).
 */
export function domainsBlock(scan: SastScan): string {
  const domains: DomainRow[] = scan.domains ?? [];
  if (domains.length === 0) return '';
  const cleartext = domains.filter((d) => d.cleartext).length;
  const nonProd = domains.filter((d) => d.environment === 'non-production' || d.environment === 'local').length;
  return `${h3(`Domains (${domains.length})`, `${cleartext} cleartext · ${nonProd} non-production or local`)}
    <p class="lead">Every host the artifact mentions, grouped and classified: who the app talks to, a different question from what is wrong with it. Extracted by reading the artifact; none of these hosts was contacted, resolved or looked up. <em>non-production</em>: the name says development, QA, staging or demo. <em>local</em>: loopback or the emulator host. A dash: no environment marker in the name.</p>
    <table class="tbl dom"><thead><tr><th>Host and URLs</th><th style="width:54px">Scheme</th><th style="width:74px">Environment</th><th style="width:38%">Found in</th></tr></thead>
    <tbody>${domains
      .map((d) => {
        const env = ENVIRONMENT[d.environment] ?? ENVIRONMENT.unknown;
        const urls = d.urls ?? [];
        const files = d.files ?? [];
        return `<tr class="${d.cleartext ? 'flag' : ''}">
          <td><strong class="mono">${esc(d.host)}</strong> <span class="muted small">${plural(d.urlCount ?? urls.length, 'URL')} · ${plural(d.fileCount ?? files.length, 'file')}</span>
            <ul class="urls">${urls.map((u) => `<li>${u.startsWith('http://') ? `<span class="bad">http://</span>${esc(u.slice(7))}` : esc(u)}</li>`).join('')}</ul>
            ${(d.urlCount ?? 0) > urls.length ? `<p class="small muted">${(d.urlCount ?? 0) - urls.length} more URLs counted, not itemised by the scan.</p>` : ''}</td>
          <td class="small">${(d.schemes ?? []).map((s) => `<strong style="color:${s === 'http' ? BAD : GOOD}">${esc(s)}</strong>`).join('<br>') || '<span class="na">—</span>'}</td>
          <td class="small"><span style="color:${env.color};font-weight:${d.environment === 'non-production' || d.environment === 'local' ? 700 : 400}">${esc(env.label)}</span></td>
          <td><ul class="urls">${files.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
            ${(d.fileCount ?? 0) > files.length ? `<p class="small muted">${(d.fileCount ?? 0) - files.length} more files counted, not itemised by the scan.</p>` : ''}</td></tr>`;
      })
      .join('')}</tbody></table>`;
}

/* ----------------------------------------------------------------------------
 * Reconnaissance
 * ------------------------------------------------------------------------- */

export function reconBlock(scan: SastScan): string {
  const r = scan.recon;
  if (!r) return '';
  const endpoints = r.endpoints ?? [];
  const trackers = r.trackers ?? [];
  const hosts = r.hosts ?? [];
  const emails = r.emails ?? [];
  const keyFiles = r.keyFiles ?? [];
  if (endpoints.length + trackers.length + hosts.length + emails.length + keyFiles.length === 0) return '';
  const cleartext = endpoints.filter((e) => e.cleartext);
  return `${h3('Reconnaissance')}
    <p class="lead">Extracted from the artifact only. None of these hosts was contacted, resolved or looked up.</p>
    ${
      trackers.length > 0
        ? `<p class="small" style="margin:8px 0 3px"><strong>Privacy trackers (${trackers.length})</strong></p>
           <table class="tbl"><thead><tr><th>Tracker</th><th style="width:120px">Category</th><th>Signature</th></tr></thead><tbody>${trackers
             .map((t) => `<tr><td>${esc(t.name)}</td><td class="small">${esc(t.category)}</td><td><code>${esc(t.signature)}</code></td></tr>`)
             .join('')}</tbody></table>`
        : '<p class="small muted" style="margin:8px 0 3px">No privacy trackers detected.</p>'
    }
    ${
      hosts.length > 0
        ? `<p class="small keepnext" style="margin:12px 0 3px"><strong>Hosts contacted (${hosts.length})</strong>${
            cleartext.length ? ` <span class="chip sevchip" style="color:${SEV.critical.text};border-color:${SEV.critical.fill};background:${SEV.critical.tint}">${new Set(cleartext.map((e) => e.host)).size} over http</span>` : ''
          }</p><p class="hosts">${hosts.map((h) => `<code>${esc(h)}</code>`).join(' ')}</p>`
        : ''
    }
    ${
      cleartext.length > 0
        ? `<p class="small keepnext" style="margin:12px 0 3px"><strong style="color:${BAD}">Cleartext endpoints (${cleartext.length})</strong></p>
           <table class="tbl"><thead><tr><th style="width:52%">URL</th><th>Found in</th></tr></thead><tbody>${cleartext
             .map((e) => `<tr><td><code>${esc(e.url)}</code></td><td class="small mono">${(e.files ?? []).map(esc).join('<br>') || '<span class="na">—</span>'}</td></tr>`)
             .join('')}</tbody></table>`
        : ''
    }
    ${
      emails.length > 0
        ? `<p class="small keepnext" style="margin:12px 0 3px"><strong>Email addresses (${emails.length})</strong></p>
           <table class="tbl"><thead><tr><th style="width:44%">Address</th><th>Found in</th></tr></thead><tbody>${emails
             .map((e) => `<tr><td><code>${esc(e.address)}</code></td><td class="small mono">${(e.files ?? []).map(esc).join('<br>') || '<span class="na">—</span>'}</td></tr>`)
             .join('')}</tbody></table>`
        : ''
    }
    ${
      keyFiles.length > 0
        ? `<p class="small keepnext" style="margin:12px 0 3px"><strong>Certificate and key files (${keyFiles.length})</strong> <span class="muted">shipped inside the artifact</span></p>
           <ul class="urls">${keyFiles.map((k) => `<li>${esc(k)}</li>`).join('')}</ul>`
        : ''
    }`;
}

/* ----------------------------------------------------------------------------
 * Secrets index
 * ------------------------------------------------------------------------- */

/** The value a location matched: its excerpt, else the marked line of its code window. */
function secretValue(l: SastFinding['locations'][number]): string {
  if (l.excerpt) return l.excerpt;
  return l.snippet?.find((s) => s.vulnerable)?.text.trim() ?? '';
}

/**
 * The console's Secrets tab: every credential-shaped literal, drawn from both
 * lists (a matched format is a defect, an entropy match is a hotspot), values
 * printed in full. `refs` maps a finding to its "F03" / "R2" label and anchor.
 */
export function secretsBlock(scan: SastScan, refs: Map<SastFinding, { label: string; href: string }>): string {
  const list = [...scan.findings, ...scan.hotspots].filter((f) => f.category === 'secrets');
  if (list.length === 0) return '';
  const total = list.reduce((n, f) => n + f.locations.length, 0);
  return `${h3(`Hardcoded secrets (${list.length})`, `${plural(total, 'location')}`)}
    <p class="lead">Credentials compiled into the artifact, where anyone who downloads it can read them. Values are printed in full: a redacted report cannot be acted on. Each block links to the page holding the full evidence.</p>
    <table class="tbl sec"><thead><tr><th style="width:44%">Where</th><th>Value</th></tr></thead>
    ${list
      .map((f) => {
        const ref = refs.get(f);
        const head = f.kind === 'hotspot' ? '<span class="chip sevchip" style="color:' + WARN + ';border-color:' + SEV.medium.fill + ';background:' + SEV.medium.tint + '">review</span>' : sevChip(f.severity);
        return `<tbody><tr class="grp"><td colspan="2">${head} <strong>${ref ? `<a class="lnk" href="${ref.href}">${esc(ref.label)}</a> · ` : ''}${esc(f.title)}</strong>
          <span class="muted small">${plural(Math.max(f.occurrences, f.locations.length), 'occurrence')}</span></td></tr>
          ${f.locations
            .map((l) => `<tr><td><code>${esc(l.file)}${l.line ? `:${l.line}` : ''}</code></td><td><code class="snip">${esc(secretValue(l))}</code></td></tr>`)
            .join('')}</tbody>`;
      })
      .join('')}</table>`;
}

/* ----------------------------------------------------------------------------
 * Native libraries and legacy binary protections
 * ------------------------------------------------------------------------- */

export function nativeBlock(scan: SastScan, abis: string[] = []): string {
  const rows = scan.artifact.nativeLibraryDetail ?? [];
  if (rows.length === 0 && abis.length === 0) return '';
  const cell = (ok: boolean) => `<td class="c">${state(ok, { yes: '', no: '' })}</td>`;
  return `${h3(`Native libraries (${rows.length})`, abis.length ? `ABIs: ${abis.map(esc).join(', ')}` : '')}
    ${rows.length ? '<p class="lead">Compiler and linker hardening, read from the ELF headers of one ABI.</p>' : ''}
    ${
      rows.length
        ? `<table class="tbl"><thead><tr><th>Library</th><th class="c">NX</th><th class="c">PIE</th><th class="c">Canary</th><th class="c">RELRO</th><th class="c">Stripped</th><th class="c">Fortify</th></tr></thead>
    <tbody>${rows
      .map(
        (l) => `<tr class="${[l.nx, l.pie, l.stackCanary].every(Boolean) ? '' : 'warn'}"><td><code>${esc(l.name)}</code></td>${cell(l.nx)}${cell(l.pie)}${cell(l.stackCanary)}
        <td class="c"><strong style="color:${l.relro === 'full' ? GOOD : l.relro === 'partial' ? WARN : BAD}">${l.relro === 'full' ? '✓' : l.relro === 'partial' ? '◐' : '✕'} ${esc(l.relro)}</strong></td>
        ${cell(l.symbolsStripped)}${cell(l.fortified)}</tr>`,
      )
      .join('')}</tbody></table>`
        : ''
    }`;
}

/** iOS protections for scans that predate (or lack) the iOS facts pages. */
export function legacyBinaryBlock(scan: SastScan): string {
  if (scan.artifact.platform !== 'ios' || scan.artifact.ios) return '';
  const rows = protectionRows(scan);
  if (rows.length === 0) return '';
  return `${h3('Binary protections')}
    <table class="tbl"><tbody>${rows
      .map((r) => `<tr class="${r.ok === false && !r.neutral ? 'flag' : ''}"><td style="width:34%"><strong>${esc(r.name)}</strong></td><td class="small muted">${esc(r.why)}</td><td class="r">${r.ok === undefined ? '' : state(r.ok, { neutral: r.neutral })}</td></tr>`)
      .join('')}</tbody></table>`;
}

/* ----------------------------------------------------------------------------
 * Source explorer note
 * ------------------------------------------------------------------------- */

/** The Explorer tab cannot be printed wholesale: say what it holds and where. */
export function explorerNote(scan: SastScan): string {
  const kept = scan.retainedFiles ?? 0;
  if (kept === 0) return '';
  const ios = scan.artifact.platform === 'ios';
  return `${h3('Where the full source lives')}
    ${callout(
      'note',
      'Code Explorer',
      `<p class="small">${ios ? 'Info.plist, entitlements and the binary’s extracted string table' : 'The decompiled Java and XML'} — ${plural(kept, 'file')} retained${
        scan.filesFound && scan.filesFound > kept ? ` of ${scan.filesFound} found${scan.filesTruncated ? ' (a size cap stopped retention short of the whole tree)' : ''}` : ''
      } — is browsable in the console’s Explorer tab, with every flagged line marked. It is too large to print. The code windows on each finding page reproduce the lines a finding landed on, with surrounding context, so this document stands alone for review; the Explorer is for reading further.</p>`,
    )}`;
}

/* ----------------------------------------------------------------------------
 * How to verify
 * ------------------------------------------------------------------------- */

/**
 * The console's How-to-verify tab: the digest check, then the exact commands
 * for every finding and hotspot. The commands come from the console's own
 * builder, so the printed text is what the tab would copy.
 */
export function verifySection(
  scan: SastScan,
  findings: SastFinding[],
  num: string,
  refs: Map<SastFinding, { label: string; href: string }>,
): string {
  const a = scan.artifact;
  const platform = a.platform === 'ios' ? 'ios' : 'android';
  // The ones that decide whether a build ships. The rest are reproduced the same way: open the file at the line the finding names.
  const list = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const tools =
    platform === 'ios'
      ? 'unzip, plutil, codesign, security, otool, nm, strings — the OWASP MASTG static-analysis toolchain, all shipped with the Xcode command line tools.'
      : 'apktool, jadx, apksigner, dexdump, unzip, readelf. All are standard; none is specific to this console.';
  const cmd = (why: string, c: string) => `<div class="vc"><p class="why">${esc(why)}</p><pre class="cmd">${esc(c)}</pre></div>`;
  return `
  <section class="pg newpage" id="verify">
    ${opener('verify-top', num, 'How to verify', 'Reproduce each finding yourself, with the tools everyone already has.')}
    ${h3('Start from the same file')}
    <p class="lead">Every command below assumes the artifact this report describes. Check the digest first: if it does not match, you are looking at a different build and the line numbers will not line up.</p>
    ${cmd('Confirm you have the same artifact.', `shasum -a 256 ${a.fileName}`)}
    <div class="vc"><p class="why">Expected</p><pre class="cmd">${esc(a.sha256)}</pre></div>
    <p class="small muted" style="margin-top:6px">Tools used: ${esc(tools)}</p>

    ${h3('Reproduce the critical and high findings', list.length ? String(list.length) : '')}
    <p class="lead">Commands are built from each finding’s own path, line and DEX, so they run as written. Medium, low and info findings are checked the same way: open the file at the line shown on the finding’s page.</p>
    ${
      list.length === 0
        ? '<p class="small muted">There are no critical or high findings to reproduce.</p>'
        : list
            .map((f, i) => {
              const ref = refs.get(f) ?? { label: `F${i + 1}`, href: '#' };
              const loc = f.locations[0];
              return `<div class="vf"><div class="vf-h"><a class="ref" href="${ref.href}">${esc(ref.label)}</a><span class="vt">${esc(f.title)}</span>
                <span class="vl">${esc(loc?.file ?? f.title)}${loc?.line ? `:${loc.line}` : ''}</span></div>
                ${commandsFor(f, a.fileName, platform).map((c) => cmd(c.why, c.cmd)).join('')}</div>`;
            })
            .join('')
    }
  </section>`;
}
