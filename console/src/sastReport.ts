/**
 * A printable static-analysis dossier. Print dialog -> "Save as PDF".
 *
 * Two editions share the same pages and the same numbering rules:
 *
 *   full       Cover -> Executive summary -> Scope & methodology -> Contents &
 *              findings index -> Remediation roadmap -> App dossier ->
 *              Findings, ONE PER PAGE -> To review & verified -> How to read
 *              this report -> Appendix -> How to verify.
 *   executive  For management, about ten pages: Cover -> Executive summary ->
 *              Scope & methodology -> Contents & findings
 *              index -> Remediation roadmap -> App profile (one page) ->
 *              How to read.
 *              No per-finding pages, hotspot pages, dossier detail or appendix.
 *
 * Section numbers are assigned from the list of sections an edition actually
 * contains, so every number, map entry and cross-reference follows from it.
 * A link whose target page is not in the edition is rendered as plain text
 * (`danglingToText`), so the executive edition never carries a dead link.
 *
 * Completeness rule (full edition): everything the console shows for a scan is
 * in the report, in full. Nothing is silently capped; long lists flow across
 * sheets. The one thing that cannot be printed is the code Explorer, which the
 * report points to.
 *
 * No PDF library: the browser already paginates HTML. The rules that shape it:
 *
 * - **A finding is a page.** Each defect is its own `.pg.newpage` with a severity
 *   banner, so it can be torn out, filed or assigned without dragging its
 *   neighbours along. Long evidence flows onto continuation sheets between
 *   windows and rows, with the finding's name repeated at the top of each; the
 *   next finding still starts on its own fresh sheet.
 * - **Colour is never the only encoding.** Severity is always word + shape glyph
 *   + five-step meter; pass/fail is glyph + word.
 * - **"Not assessed" is not "pass"**, and "done right" is not "no findings":
 *   a reader must be able to tell a checked-and-clean result from an unchecked one.
 * - **Nothing here is written by a model.** The assessment, the risk themes and
 *   the roadmap are templates filled from the scan's own numbers.
 *
 * Helpers live in `./report/` to keep this file about the document's structure.
 */
import { BRAND, markSvg } from './brand';
import { reportScan } from './triage';
import type { SastFinding, SastScan } from './sastTypes';
import { androidCoversPermissionsAndNative, androidDossier, androidSignals } from './report/android';
import { overallAssessment } from './report/assessment';
import { scoreRing, sevDistribution, sevStripe } from './report/charts';
import type { Edition } from './report/edition';
import { locationsBlock } from './report/evidence';
import { howToReadPage } from './report/howto';
import { iosDossier, iosSignals } from './report/ios';
import {
  BAD, GOOD, GRADE_TEXT, SEV, SEVERITY_ORDER, WARN, appIcon, bytes, callout, chip, esc, facts, fmtDateTime, h3, meter,
  opener, plural, rich, safeIcon, sev, sevChip, sevRank, tiles,
} from './report/kit';
import { scopePage } from './report/method';
import { appProfilePage } from './report/profile';
import {
  dependencyBlock, domainsBlock, explorerNote, legacyBinaryBlock, nativeBlock, permissionTable, reconBlock,
  secretsBlock, verifySection,
} from './report/reference';
import { roadmapPage } from './report/roadmap';
import { signalStrip } from './report/signals';
import { reportCss } from './report/styles';
import {
  chipFor, excludedItems, hotspotNote, scoreText, statusBand, triageFingerprint, triageSection, triageView,
} from './report/triageView';
import type { TriageView } from './report/triageView';
import {
  affectedComponent, componentHtml, fLabel, fref, owaspLabel, riskThemes, themeTitle,
} from './report/themes';
import type { Numbered, Theme } from './report/themes';

export type { Edition } from './report/edition';

/** Where a finding or hotspot lives in the document: its short label and anchor. */
type Ref = { label: string; href: string };

/** Findings, worst first and stable, so the index and the pages always agree on numbering. */
function ordered(list: SastFinding[]): SastFinding[] {
  return list.map((f, i) => ({ f, i })).sort((a, b) => sevRank(a.f.severity) - sevRank(b.f.severity) || a.i - b.i).map((x) => x.f);
}

function hasSecrets(scan: SastScan): boolean {
  return scan.findings.some((f) => f.category === 'secrets') || scan.hotspots.some((f) => f.category === 'secrets');
}

/**
 * How the findings split between the app's own code and its dependencies.
 * Stated up front because it reframes the whole number: "30 findings" and "30
 * findings, 7 of them yours" ask for very different responses.
 */
function attributionLine(findings: SastFinding[]): string {
  const mine = findings.filter((f) => f.origin === 'first-party').length;
  const theirs = findings.filter((f) => f.origin === 'third-party').length;
  const both = findings.filter((f) => f.origin === 'mixed').length;
  if (mine === 0 || theirs + both === 0) return '';
  const parts = [`${mine} in the app’s own code`];
  if (theirs > 0) parts.push(`${theirs} in bundled libraries`);
  if (both > 0) parts.push(`${both} in both`);
  return `<p class="small muted">Of ${findings.length} findings: ${parts.join(', ')}.</p>`;
}

function originLabel(f: SastFinding): string {
  if (!f.origin || f.origin === 'unknown') return '';
  if (f.origin === 'first-party') return 'your code';
  if (f.origin === 'mixed') return 'your code + library';
  if (f.libraries && f.libraries.length > 0) {
    return f.libraries.length === 1 ? f.libraries[0] : `${f.libraries[0]} +${f.libraries.length - 1}`;
  }
  return 'library';
}

/* ----------------------------------------------------------------------------
 * Verdict
 * ------------------------------------------------------------------------- */

function verdict(scan: SastScan, tri?: TriageView): { tag: string; fill: string; ink: string; headline: string } {
  const c = scan.counts;
  if (c.critical > 0) {
    return {
      tag: 'Do not ship', fill: SEV.critical.fill, ink: SEV.critical.ink,
      headline: `${plural(c.critical, 'critical issue')} must be fixed before this build ships.`,
    };
  }
  if (c.high > 0) {
    return {
      tag: 'Fix before release', fill: SEV.high.fill, ink: SEV.high.ink,
      headline: `No critical issues, but ${c.high} high-severity ${c.high === 1 ? 'finding needs' : 'findings need'} attention.`,
    };
  }
  if (scan.findings.length === 0 && tri?.on && tri.scan.findings.length > 0) {
    return {
      tag: 'No active defects', fill: '#1f9d2f', ink: '#ffffff',
      headline: `No active defects after triage: ${tri.scan.findings.length === 1 ? 'the one finding was' : `all ${tri.scan.findings.length} findings were`} excluded by reviewers and stay${tri.scan.findings.length === 1 ? 's' : ''} listed.`,
    };
  }
  if (scan.findings.length === 0) {
    return {
      tag: 'No defects found', fill: '#1f9d2f', ink: '#ffffff',
      headline: 'No defects found.',
    };
  }
  return {
    tag: 'Schedule fixes', fill: SEV.medium.fill, ink: SEV.medium.ink,
    headline: 'Nothing critical or high. The remaining findings are worth scheduling, not blocking on.',
  };
}

/* ----------------------------------------------------------------------------
 * Cover
 * ------------------------------------------------------------------------- */

const SHIELD_SVG = markSvg('rpt', { width: 38, height: 43 });

function coverPage(raw: SastScan, edition: Edition, tri: TriageView): string {
  // Headline numbers are the active ones when reviewers have made decisions; the scan's own stay as a secondary line.
  const scan = tri.eff;
  const a = scan.artifact;
  const ios = a.platform === 'ios' ? a.ios : undefined;
  const v = verdict(scan, tri);
  const title = ios?.displayName ?? (a.platform === 'android' ? a.android?.label : undefined) ?? a.fileName;
  const isIos = a.platform === 'ios';
  const dist = ios?.distribution && ios.distribution !== 'unknown' ? ios.distribution : undefined;

  return `
  <section class="pg cover" id="cover">
    <div class="cover-band">
      <div class="cover-top">
        <div class="brandmark">${SHIELD_SVG}<span>KAVACH</span><span class="deva" lang="sa">${BRAND.devanagari}</span></div>
        <div class="classif-row">${edition === 'executive' ? '<div class="classif ed">Executive edition</div>' : ''}<div class="classif">Confidential · Security assessment</div></div>
      </div>
      <div class="cover-id">
        ${appIcon(a.iconDataUrl, title, ios?.bundleId ?? a.packageName ?? a.fileName, 'ico-cover')}
        <div class="cover-id-t">
          <div class="cover-kicker">Static application security assessment</div>
          <h1 class="cover-title${title.length > 26 ? ' long' : ''}">${esc(title)}</h1>
          <div class="cover-sub">
            <span class="plat">${isIos ? 'iOS' : 'Android'}</span>
            <span class="id">${esc(ios?.bundleId ?? a.packageName ?? 'unknown package')}</span>
            ${a.versionName ? `<span>version ${esc(a.versionName)}${a.versionCode ? ` (${esc(a.versionCode)})` : ''}</span>` : ''}
            ${dist ? `<span>${esc(dist)} build</span>` : ''}
          </div>
        </div>
      </div>
      ${sevStripe(scan.counts, 9)}
    </div>

    <div class="cover-main">
      <div class="cover-hero">
        ${scoreRing(scan.score, scan.grade, 236)}
        <div>
          <span class="verdict-tag" style="background:${v.fill};color:${v.ink}">${esc(v.tag)}</span>
          <div class="verdict">${esc(v.headline)}</div>
          <p class="verdict-sub">${plural(scan.findings.length, tri.on ? 'active finding' : 'finding')} to fix,
            ${plural(scan.secure.length, 'control')} verified. Grade <strong style="color:${GRADE_TEXT[scan.grade]}">${esc(scan.grade)}</strong>
            from a ${scan.score}/100 score${tri.on ? ' after triage' : ''}.</p>${
            tri.on
              ? `<p class="verdict-asis"><b>As scanned:</b> ${esc(scoreText(raw.score, raw.grade))} \u00b7 <b>after triage:</b> ${esc(scoreText(tri.adj.score, tri.adj.grade))}${tri.adj.score === raw.score ? ' (unchanged)' : ''}${
                  excludedItems(tri) ? `<span>${esc(excludedItems(tri))} triaged out${tri.summary.expiredAcceptances ? ` \u00b7 ${plural(tri.summary.expiredAcceptances, 'expired acceptance')} counts again` : ''}</span>` : ''
                }</p>`
              : ''
          }
        </div>
      </div>

      <div class="cover-sev">
        ${SEVERITY_ORDER.map((s) => {
          const t = SEV[s];
          const n = scan.counts[s] ?? 0;
          return `<div class="csev" style="border-top-color:${n ? t.fill : '#d9dde1'}">
            <div class="csev-n" style="color:${n ? t.text : '#8a929b'}">${n}</div>
            <div class="csev-l" style="color:${n ? t.text : '#8a929b'}"><span>${t.glyph}</span>${t.label}</div></div>`;
        }).join('')}
      </div>

      <div class="cover-meta">${facts([
        ['File', a.fileName],
        ['Size', bytes(a.sizeBytes)],
        [isIos ? 'Minimum iOS' : 'SDK range', isIos ? (a.minimumOsVersion ?? ios?.main.minOs) : `${a.minSdk ?? '?'} → ${a.targetSdk ?? '?'}`],
        ['Scanned', fmtDateTime(scan.createdAt)],
        ['Scan time', `${(scan.durationMs / 1000).toFixed(1)} s`],
        ['Scan ID', scan.scanId, { mono: true }],
      ])}</div>

      <div class="cover-hash">
        <div class="hash-row"><span class="hash-k">Application SHA-256</span><span class="hash-v strong">${esc(a.sha256)}</span></div>
        <div class="hash-row"><span class="hash-k">Report digest</span><span class="hash-v">${esc(scan.reportHash)}</span></div>
        ${tri.on ? `<div class="hash-row"><span class="hash-k">Triage fingerprint</span><span class="hash-v">${esc(triageFingerprint(raw))}</span></div>` : ''}
        <p class="small muted" style="margin-top:4px">Run <code>shasum -a 256 ${esc(a.fileName)}</code> to confirm this report describes the file in front of you.</p>
      </div>
    </div>
    <div class="cover-foot"><span>Generated locally. Nothing was uploaded.</span><span>Static analysis reads the artifact; it does not run it.</span></div>
  </section>`;
}

/* ----------------------------------------------------------------------------
 * 01 Executive summary
 * ------------------------------------------------------------------------- */

/** One risk theme: worst-severity chip, OWASP name, the business risk in a sentence, and the findings behind it. */
function themeRow(t: Theme): string {
  const MAX_REFS = 6;
  const refs = t.items.slice(0, MAX_REFS).map((x) => fref(x.n)).join(' ');
  const more = t.items.length > MAX_REFS ? ` <span class="muted">+${t.items.length - MAX_REFS} more</span>` : '';
  return `<li class="theme"><div class="th-s">${sevChip(t.worst)}</div>
    <div class="th-b"><div class="th-t">${esc(themeTitle(t))}</div>
      <div class="th-r">${esc(t.risk)}</div></div>
    <div class="th-n"><div class="th-c"><b>${t.items.length}</b> ${t.items.length === 1 ? 'finding' : 'findings'} <span>\u00d7${t.hits}</span></div>
      <div class="th-f">${refs}${more}</div></div></li>`;
}

const TOP_THEMES = 3;

function executiveSummary(raw: SastScan, items: Numbered[], themes: Theme[], controlsNum: string, tri: TriageView): string {
  // `items` and `themes` are the active findings; `scan` carries the active counts, score and hotspots.
  const scan = tri.eff;
  const findings = items.map((x) => x.f);
  const v = verdict(scan, tri);
  const signals = scan.artifact.platform === 'ios' ? iosSignals(scan) : androidSignals(scan);
  const shown = themes.slice(0, TOP_THEMES);
  const secrets = hasSecrets(raw);
  const outF = tri.on ? tri.excluded.findings.total : 0;

  return `
  <section class="pg newpage" id="summary">
    ${opener('summary-top', '01', 'Executive summary', 'The verdict, where the risk sits and what was checked.')}
    <div class="verdict-panel">
      <div><span class="verdict-tag" style="background:${v.fill};color:${v.ink};margin:0">${esc(v.tag)}</span></div>
      <div class="vhead">${esc(v.headline)}</div>
      ${attributionLine(findings)}
    </div>

    ${h3('Overall assessment', 'written from this scan\u2019s numbers')}
    <div class="assess">${overallAssessment(scan, items, themes, v.tag, secrets, controlsNum, tri)}</div>

    <div class="two">
      <div>${h3('Severity distribution', tri.on ? `${findings.length} active` : plural(findings.length, 'finding'))}${sevDistribution(scan.counts)}${
        tri.on ? `<p class="small muted" style="margin-top:4px">After triage; ${raw.findings.length} as scanned.</p>` : ''
      }</div>
      <div>${h3(tri.on ? 'To do, after triage' : 'Triage')}
        <div class="tri-list">
          <div class="tri-row"><div class="n" style="color:${findings.length ? BAD : GOOD}">${findings.length}</div>
            <div><div class="t">To fix</div><div class="d">Defects with a known remedy${outF ? ` \u00b7 ${outF} excluded by triage` : ''}</div></div></div>
          <div class="tri-row"><div class="n" style="color:${GOOD}">${scan.secure.length}</div>
            <div><div class="t">Done right</div><div class="d">Verified good practice</div></div></div>
        </div>
      </div>
    </div>

    ${
      secrets
        ? `<div class="secret-strip"><strong>\u25c6 This document contains live credentials.</strong> Secret values are printed in full so they can be identified and revoked; a masked value cannot be told from a placeholder. All of it is already readable by anyone who downloads the app. Revoke first, then circulate.</div>`
        : ''
    }

    ${signals.length ? `${h3('Key build signals', 'the yes/no questions asked first')}${signalStrip(signals)}` : ''}

    ${h3('Top risk themes', shown.length ? `${shown.length === themes.length ? `${themes.length}` : `${shown.length} of ${themes.length}; every finding is in What to fix`}, by OWASP Mobile Top 10 category` : '')}
    ${
      shown.length === 0
        ? `<p class="small muted">${
            tri.on && tri.excluded.findings.total > 0
              ? 'No active defects remain: every finding was excluded by triage and stays listed.'
              : 'No defects were produced.'
          }</p>`
        : `<ol class="themes">${shown.map(themeRow).join('')}</ol>`
    }
  </section>`;
}

type MapEntry = { num: string; title: string; desc: string; href: string };

/** The sections of this report, as a short linked list. */
function sectionMap(map: MapEntry[]): string {
  return `<div class="map">${map
    .map((m) => `<a href="${m.href}"><span class="mn">${esc(m.num)}</span><span class="mt">${esc(m.title)}<span class="md">${esc(m.desc)}</span></span></a>`)
    .join('')}</div>`;
}

/* ----------------------------------------------------------------------------
 * 03 App dossier (generic; iOS has its own pages)
 * ------------------------------------------------------------------------- */

function artifactPage(scan: SastScan, num: string): string {
  const a = scan.artifact;
  const c = a.components;
  const isAndroid = a.platform === 'android';
  return `
  <section class="pg newpage" id="dossier-page">
    ${opener('dossier', num, 'App dossier', 'What the artifact is: identity, signing and, on Android, its component surface.')}
    <div class="app-id">
      ${appIcon(a.iconDataUrl, a.packageName ?? a.fileName, a.packageName ?? a.fileName, 'ico-page')}
      <div class="app-id-t"><div class="nm">${esc(a.packageName ?? a.fileName)}</div>
        <div class="bid">${esc(a.fileName)}</div>
        <div class="app-id-c">${[
          a.versionName ? `v${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : '',
          isAndroid ? 'Android' : 'iOS',
          bytes(a.sizeBytes),
        ].filter(Boolean).map((t) => `<span class="chip cap">${esc(t)}</span>`).join(' ')}</div></div>
    </div>
    ${h3('Identity')}
    ${facts([
      ['Package', a.packageName],
      ['Version', a.versionName ? `${a.versionName}${a.versionCode ? ` (${a.versionCode})` : ''}` : undefined],
      ['Size', bytes(a.sizeBytes)],
      [isAndroid ? 'SDK range' : 'Minimum iOS', isAndroid ? `${a.minSdk ?? '?'} → ${a.targetSdk ?? '?'}` : a.minimumOsVersion],
      ['Signature schemes', a.signatureSchemes.join(', ') || undefined],
      ['Files inside', String(a.fileCount)],
      ['SHA-256', a.sha256, { wide: true, mono: true }],
      ...(a.signers.length ? ([['Certificate', a.signers.join(' · '), { wide: true }]] as [string, string, { wide: boolean }][]) : []),
      ...(a.detectedLibraries.length ? ([['Libraries detected', a.detectedLibraries.join(', '), { wide: true }]] as [string, string, { wide: boolean }][]) : []),
    ])}
    ${
      isAndroid && c
        ? `${h3('Application components')}
           ${tiles([
             { n: c.activities, label: 'Activities' },
             { n: c.services, label: 'Services' },
             { n: c.receivers, label: 'Receivers' },
             { n: c.providers, label: 'Providers' },
             { n: c.exported, label: 'Exported', tone: c.exported > 0 ? WARN : undefined },
           ])}
           ${
             c.browsable && c.browsable.length > 0
               ? `${h3('Reachable from a web link', String(c.browsable.length))}
                  <table class="tbl"><thead><tr><th>Component</th><th>Schemes / hosts</th></tr></thead><tbody>${c.browsable
                    .map(
                      (b) => `<tr><td><code>${esc(b.component)}</code></td><td class="small">${esc(b.schemes.join(', '))}${
                        b.hosts.length ? ` @ ${esc(b.hosts.join(', '))}` : ''
                      }</td></tr>`,
                    )
                    .join('')}</tbody></table>`
               : ''
           }`
        : ''
    }
  </section>`;
}

/* ----------------------------------------------------------------------------
 * 04 Findings — one per page
 * ------------------------------------------------------------------------- */

function findingPage(f: SastFinding, index: number, total: number, tri: TriageView): string {
  const t = sev(f.severity);
  const n = index + 1;
  const num = String(n).padStart(2, '0');
  const olabel = originLabel(f);
  const ctx = `Finding ${num} \u00b7 ${f.title}`;
  // How much evidence earns its space: the worse the finding, and the more it is the app's own code, the more is shown.
  const major = f.severity === 'critical' || f.severity === 'high';
  const library = f.origin === 'third-party';
  const caps = { windows: library ? (major ? 1 : 0) : major ? 3 : f.severity === 'medium' ? 2 : 1, rows: library ? 3 : 6 };
  const evidence = locationsBlock(f.locations, ctx, f.occurrences, caps);

  const originNote =
    f.origin === 'third-party' || f.origin === 'mixed'
      ? `<div class="f-note">${
          f.origin === 'third-party' ? 'Sits entirely in bundled library code' : 'Appears in both the app\u2019s own packages and bundled library code'
        }${f.libraries && f.libraries.length > 0 ? ` (${esc(f.libraries.join(', '))})` : ''}. ${
          f.origin === 'third-party'
            ? 'The remedy is a dependency upgrade rather than a source change.'
            : 'The matches in the app\u2019s own packages are the actionable ones.'
        }</div>`
      : '';

  // Numbered dynamically because exploitation steps are optional.
  let k = 0;
  const sec = (title: string, body: string) => `<div class="f-sec"><h4 role="presentation"><span class="k">${String(++k).padStart(2, '0')}</span>${title}</h4>${body}</div>`;

  return `
  <article class="pg newpage finding sev-${esc(f.severity)}" id="finding-${n}">
    <div class="f-band" style="background:${t.fill};color:${t.ink}">
      <div class="f-lvl"><span class="gl">${t.glyph}</span>${esc(t.label)}${meter(t.level, t.ink)}</div>
      <div class="f-of">Finding<b>${num}</b> / ${String(total).padStart(2, '0')}</div>
    </div>
    <div class="f-titlebox" style="background:${t.tint};border-color:${t.fill}">
      <h2 class="f-title">${esc(f.title)}</h2>
      <div class="f-comp"><span class="lab">Affected component</span><span class="val">${componentHtml(affectedComponent(f))}</span></div>
      <div class="f-chips">
        ${f.cwe ? chip(f.cwe) : ''}${f.masvs ? chip(f.masvs) : ''}${f.owasp ? `<span class="chip owasp">${esc(owaspLabel(f.owasp))}</span>` : ''}
        ${chip(f.category, 'cap')}
        ${olabel ? chip(olabel, 'cap') : ''}
        ${chip(plural(f.occurrences, 'occurrence'), 'cap')}
      </div>
      ${originNote}
    </div>
    ${statusBand(tri, f)}

    ${sec('What this is', `<p>${rich(f.description)}</p>`)}
    ${sec('Risk if left', callout('risk', 'Impact', `<p>${rich(f.impact)}</p>`))}
    ${f.exploitation && f.exploitation.length > 0 ? sec('How this gets exploited', `<ol class="steps">${f.exploitation.map((x) => `<li>${rich(x)}</li>`).join('')}</ol>`) : ''}
    ${sec('What to change', callout('fix', 'Remediation', `<p>${rich(f.remediation)}</p>`))}
    ${sec('Evidence', evidence)}

  </article>`;
}

/**
 * A medium, low or informational finding as a card that never splits across
 * sheets: what it is, why it matters and the fix side by side, one window of
 * evidence, and every other location named. These are the findings that fill
 * a report, so each takes a third of a page rather than a sheet of its own.
 */
function findingCard(f: SastFinding, index: number, total: number, tri: TriageView): string {
  const t = sev(f.severity);
  const n = index + 1;
  const num = String(n).padStart(2, '0');
  const library = f.origin === 'third-party';
  const caps = { windows: library ? 0 : f.severity === 'medium' ? 1 : 1, rows: library ? 3 : 4 };
  const evidence = locationsBlock(f.locations, `Finding ${num} \u00b7 ${f.title}`, f.occurrences, caps);
  const olabel = originLabel(f);
  return `
  <article class="fc sev-${esc(f.severity)}" id="finding-${n}" style="border-left-color:${t.fill}">
    <div class="fc-h">
      <span class="fc-sev" style="color:${t.text}"><span class="gl">${t.glyph}</span>${esc(t.label)}</span>
      <span class="fc-t">${esc(f.title)}</span>
      <span class="fc-n">${num} / ${String(total).padStart(2, '0')}</span>
    </div>
    <div class="fc-meta">${componentHtml(affectedComponent(f))}${
      [f.cwe, f.masvs, f.owasp ? owaspLabel(f.owasp) : '', olabel, plural(f.occurrences, 'occurrence')].filter(Boolean).map((x) => ` <span class="dot">\u00b7</span> ${esc(String(x))}`).join('')
    }</div>
    ${statusBand(tri, f)}
    <div class="fc-cols">
      <div><h5>What this is, and the risk</h5><p>${rich(f.description)}</p><p class="fc-risk">${rich(f.impact)}</p></div>
      <div><h5>What to change</h5><p>${rich(f.remediation)}</p></div>
    </div>
    <div class="fc-ev">${evidence}</div>
  </article>`;
}

/** The report's findings: a page each for critical and high, then the rest as cards under one heading. */
function findingsSection(findings: SastFinding[], tri: TriageView): string {
  const total = findings.length;
  const major = (f: SastFinding) => f.severity === 'critical' || f.severity === 'high';
  const pages = findings.map((f, i) => (major(f) ? findingPage(f, i, total, tri) : '')).join('');
  const cards = findings.map((f, i) => (major(f) ? '' : findingCard(f, i, total, tri))).join('');
  return `${pages}${
    cards
      ? `<section class="pg newpage" id="finding-lower">
    <div class="fc-title"><span>Medium, low and informational findings</span><span class="muted small">${findings.filter((f) => !major(f)).length} findings, worst first</span></div>
    ${cards}
  </section>`
      : ''
  }`;
}

/* ----------------------------------------------------------------------------
 * 05 To review & verified controls
 * ------------------------------------------------------------------------- */

function hotspotBlock(f: SastFinding, i: number, tri: TriageView): string {
  // A hotspot with code windows or many locations is allowed to run onto the
  // next sheet; a short one is kept whole.
  const small = f.locations.length <= 4 && !f.locations.some((l) => l.snippet && l.snippet.length > 0);
  const decided = tri.on && !!tri.entry(f);
  return `<article class="hs${small ? ' keep' : ''}${decided && !tri.active(f) ? ' xm' : ''}" id="hotspot-${i + 1}">
    <div class="hs-h"><span class="hs-n">R${i + 1}</span><span class="hs-t">${esc(f.title)}</span>${decided ? chipFor(tri, f, false) : ''}
      <span class="chip sevchip" style="color:${SEV.medium.text};border-color:${SEV.medium.fill};background:${SEV.medium.tint}"><span class="g">?</span>review</span></div>
    <div class="hs-id">${esc(f.category)}${f.cwe ? ` \u00b7 ${esc(f.cwe)}` : ''}${f.masvs ? ` \u00b7 ${esc(f.masvs)}` : ''}${f.owasp ? ` \u00b7 ${esc(owaspLabel(f.owasp))}` : ''}${
      f.origin && f.origin !== 'unknown' ? ` \u00b7 ${esc(originLabel(f))}` : ''
    } \u00b7 ${plural(Math.max(f.occurrences, f.locations.length), 'occurrence')}</div>
    ${decided ? hotspotNote(tri, f) : ''}
    <p>${rich(f.description)}</p>
    ${f.impact ? `<p class="muted">${rich(f.impact)}</p>` : ''}
    ${
      f.exploitation && f.exploitation.length > 0
        ? `<ol class="steps hs-steps">${f.exploitation.map((x) => `<li>${rich(x)}</li>`).join('')}</ol>`
        : ''
    }
    <p class="ask"><strong>Ask:</strong> ${rich(f.remediation)}</p>
    ${f.locations.length ? `<div class="hs-ev">${locationsBlock(f.locations, `Review R${i + 1} \u00b7 ${f.title}`, f.occurrences)}</div>` : ''}
  </article>`;
}

function reviewPages(scan: SastScan, num: string, tri: TriageView): string {
  if (scan.hotspots.length === 0 && scan.secure.length === 0) return '';
  return `
  <section class="pg newpage" id="review">
    ${opener('review-top', num, 'What the app does right', 'Good practice the scan verified in the artifact.')}
    ${
      scan.hotspots.length > 0
        ? `${h3('To review', tri.on && tri.excluded.hotspots.total > 0 ? `${scan.hotspots.length} \u00b7 ${tri.eff.hotspots.length} active, ${tri.excluded.hotspots.total} excluded by triage` : `${scan.hotspots.length}`)}
           <p class="lead">None of these is a defect on its own. Each is a decision the app has made that someone who knows the product should confirm was deliberate.</p>
           <div class="hsi">${scan.hotspots
             .map(
               (h, i) => `<a${tri.on && !tri.active(h) ? ' class="xm"' : ''} href="#hotspot-${i + 1}"><span class="rn">R${i + 1}</span><span class="rt">${esc(h.title)}${
                 tri.on && tri.entry(h) ? ` ${chipFor(tri, h)}` : ''
               }</span><span class="rh">${h.locations.length ? Math.max(h.occurrences, h.locations.length) : ''}</span></a>`,
             )
             .join('')}</div>
           ${scan.hotspots.map((h, i) => hotspotBlock(h, i, tri)).join('')}`
        : ''
    }
    ${
      scan.secure.length > 0
        ? `${h3('What this app does right', `${scan.secure.length}`)}
           <p class="lead">Listed so a hardened app is distinguishable from one that simply has a short finding list.</p>
           <div class="secure">${scan.secure.map((f) => `<div class="sec-item"><div class="t">${esc(f.title)}</div><div class="d">${esc(f.description)}</div></div>`).join('')}</div>`
        : ''
    }
  </section>`;
}

/* ----------------------------------------------------------------------------
 * 06 Appendix
 * ------------------------------------------------------------------------- */

function appendix(scan: SastScan, num: string, refs: Map<SastFinding, Ref>): string {
  const a = scan.artifact;
  const permRows = a.permissionDetail ?? [];
  // On Android with manifest facts the dossier already carries these two tables.
  const inDossier = androidCoversPermissionsAndNative(scan);
  return `
  <section class="pg newpage" id="appendix">
    ${opener('appendix-top', num, 'Appendix', 'Reference tables, in full: permissions, dependencies, domains, reconnaissance, secrets and native code.')}
    ${inDossier ? '' : `${h3(`Permissions (${permRows.length || (a.permissions ?? []).length})`)}${permissionTable(scan)}`}
    ${dependencyBlock(scan)}
    ${domainsBlock(scan)}
    ${reconBlock(scan)}
    ${secretsBlock(scan, refs)}
    ${inDossier ? '' : nativeBlock(scan)}
    ${legacyBinaryBlock(scan)}

    ${explorerNote(scan)}
  </section>`;
}

/* ----------------------------------------------------------------------------
 * Assembly
 * ------------------------------------------------------------------------- */

/**
 * Turns every in-document link whose target is not in this document into plain
 * text. The executive edition has no finding pages, hotspot pages or control
 * cards, and a link that goes nowhere is worse than none.
 */
export function danglingToText(html: string): string {
  const ids = new Set<string>();
  for (const m of html.matchAll(/\bid="([^"]+)"/g)) ids.add(m[1]);
  const converted: boolean[] = [];
  return html.replace(/<a\b([^>]*)>|<\/a>/g, (tag, attrs: string | undefined) => {
    if (tag === '</a>') return converted.pop() ? '</span>' : tag;
    const m = /\bhref="#([^"]+)"/.exec(attrs ?? '');
    if (m && !ids.has(m[1])) {
      converted.push(true);
      return `<span${(attrs ?? '').replace(/\s*href="[^"]*"/, '').replace(/\blnk\b/, '')}>`;
    }
    converted.push(false);
    return tag;
  });
}

type SectionKey =
  | 'summary' | 'scope' | 'roadmap' | 'triage' | 'dossier' | 'profile'
  | 'findings' | 'review' | 'howto' | 'appendix' | 'verify';

export function buildSastReportHtml(raw: SastScan, options: { edition?: Edition } = {}): string {
  // One list, with false positives left out entirely (see `reportScan`).
  const scan = reportScan(raw);
  const edition: Edition = options.edition === 'executive' ? 'executive' : 'full';
  const full = edition === 'full';
  const a = scan.artifact;
  const findings = ordered(scan.findings);
  const items: Numbered[] = findings.map((f, i) => ({ f, n: i + 1 }));
  // Decisions recorded by reviewers. Without any, `tri.on` is false and the document is exactly what it was before triage existed.
  const tri = triageView(scan);
  // The headline pieces (summary, themes, roadmap) read the active findings, numbered as on their pages.
  const activeItems = tri.on ? items.filter((x) => tri.active(x.f)) : items;
  const themes = riskThemes(activeItems);
  const hasFacts = (a.platform === 'ios' && !!a.ios) || (a.platform === 'android' && !!a.android);
  const hasReview = scan.hotspots.length > 0 || scan.secure.length > 0;

  // Every finding and hotspot's short label and anchor, so the secrets index
  // and the verification section can point at the page that holds the evidence.
  const refs = new Map<SastFinding, Ref>();
  findings.forEach((f, i) => refs.set(f, { label: fLabel(i + 1), href: `#finding-${i + 1}` }));
  scan.hotspots.forEach((f, i) => refs.set(f, { label: `R${i + 1}`, href: `#hotspot-${i + 1}` }));

  const dossierDesc =
    a.platform === 'ios'
      ? a.ios ? 'Profile, signing, network, attack surface, hardening' : 'Identity, signing'
      : a.android ? 'Profile, components, permissions, network, native code' : 'Identity, signing, components';

  // The sections this edition contains, in reading order. Numbers follow from the list.
  const plan: { key: SectionKey; title: string; desc: string; href: string }[] = [
    { key: 'summary', title: 'Executive summary', desc: 'Verdict, overall assessment, distribution, top risk themes', href: '#summary' },
    ...(full ? [{ key: 'scope' as const, title: 'Scope & methodology', desc: 'Target, tools, and what was and was not examined', href: '#scope' }] : []),
    { key: 'roadmap', title: 'What to fix, and when', desc: tri.on ? 'Active findings by timeline, with the one-line fix for each' : 'Every finding by timeline, with the one-line fix for each', href: '#roadmap' },
    ...(tri.on
      ? [{
          key: 'triage' as const, title: 'Triage summary',
          desc: `${plural(tri.summary.decided, 'reviewer decision')}, in full, with the effect on the score and a fingerprint`, href: '#triage',
        }]
      : []),
    full
      ? { key: 'dossier', title: 'App dossier', desc: dossierDesc, href: '#dossier' }
      : { key: 'profile', title: 'App profile', desc: 'Identity, signing, build signals and footprint on one page', href: '#profile' },
    ...(full
      ? [{
          key: 'findings' as const, title: 'Findings',
          desc: findings.length ? `${plural(findings.length, 'defect')}${tri.on && tri.excluded.findings.total ? ` (${tri.excluded.findings.total} excluded by triage)` : ''}, one per page` : 'No defects produced',
          href: findings.length ? '#finding-1' : '#roadmap',
        }]
      : []),
    ...(full && hasReview
      ? [{ key: 'review' as const, title: 'What the app does right', desc: `${scan.secure.length} controls done right`, href: '#review' }]
      : []),
    { key: 'howto', title: 'About this report', desc: 'What the severities mean, how the score works, what this can and cannot tell you', href: '#howto' },
    ...(full
      ? [
          { key: 'appendix' as const, title: 'Appendix', desc: 'Permissions, dependencies, domains, recon, secrets', href: '#appendix' },
          { key: 'verify' as const, title: 'How to verify', desc: 'Digest check and the commands to reproduce each finding', href: '#verify' },
        ]
      : []),
  ];
  const num = {} as Record<SectionKey, string>;
  const map: MapEntry[] = plan.map((p, i) => {
    num[p.key] = String(i + 1).padStart(2, '0');
    return { num: num[p.key], title: p.title, desc: p.desc, href: p.href };
  });
  const ref = (key: SectionKey, href: string) => (num[key] ? { num: num[key], href } : undefined);

  const dossier = !full
    ? ''
    : a.platform === 'ios' && hasFacts
      ? iosDossier(scan, Number(num.dossier))
      : a.platform === 'android' && hasFacts
        ? androidDossier(scan, Number(num.dossier))
        : artifactPage(scan, num.dossier);

  const body = [
    coverPage(scan, edition, tri),
    executiveSummary(scan, activeItems, themes, '', tri),
    full ? scopePage(scan, num.scope, tri, sectionMap(map)) : '',
    roadmapPage(scan, activeItems, num.roadmap, edition, full && hasReview ? { num: num.review } : undefined, tri.on ? { view: tri, num: num.triage } : undefined),
    tri.on ? triageSection(tri, refs, num.triage, undefined) : '',
    full ? dossier : appProfilePage(scan, num.profile),
    full ? findingsSection(findings, tri) : '',
    full && hasReview ? reviewPages(scan, num.review, tri) : '',
    howToReadPage(scan, num.howto, edition, {
      verify: ref('verify', '#verify'),
      scope: ref('scope', '#scope'),
    }),
    full ? appendix(scan, num.appendix, refs) : '',
    full ? verifySection(scan, findings, num.verify, refs) : '',
  ].join('\n');

  const title = `Kavach \u2014 ${a.fileName} \u2014 static analysis${full ? '' : ' (executive edition)'}`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${reportCss({ title: a.fileName, digest: scan.reportHash, icon: safeIcon(a.iconDataUrl), edition: full ? undefined : 'EXECUTIVE EDITION' })}</style></head>
<body>
<div class="preview-note">Preview on A4 pages. Dividers show roughly where pages end; the exported PDF paginates exactly, never splitting a table row or a card.</div>
${danglingToText(body)}
<script>
  // Preview only: round each sheet up to whole A4 pages so the on-screen view
  // reads as standard pages. The print stylesheet ignores --sheet-h.
  (function () {
    if (window.matchMedia && window.matchMedia('print').matches) return;
    var page = 297 * 96 / 25.4;
    Array.prototype.forEach.call(document.querySelectorAll('.pg:not(.cont):not(.cover)'), function (el) {
      var pages = Math.max(1, Math.ceil((el.getBoundingClientRect().height - 2) / page));
      el.style.setProperty('--sheet-h', pages * 297 + 'mm');
    });
  })();
</script>
</body></html>`;
}

/** Opens the report in a new tab and raises the print dialog. */
export function openSastReport(scan: SastScan, edition: Edition = 'full'): void {
  const win = window.open('', '_blank');
  if (!win) return;
  win.document.write(buildSastReportHtml(scan, { edition }));
  win.document.close();
  // A tick for layout, or Safari prints a blank first page.
  win.setTimeout(() => win.print(), 350);
}
