/**
 * "Remediation roadmap": the findings regrouped by when they should be fixed,
 * one compact table per timeline bucket, then the human decisions and the
 * controls worth adding. This is the page a manager turns into tickets.
 *
 * Tables flow across sheets with their header row repeated, so a long bucket
 * never strands a heading or leaves a near-empty page.
 */
import type { SastScan } from '../sastTypes';
import { controlsToAdd, effortMeterHtml, groupName, lowValueMissing } from './controls';
import type { Edition } from './edition';
import { esc, h3, opener, plural, rich, sevChip } from './kit';
import { BUCKETS } from './policy';
import { affectedComponent, componentHtml, firstSentence, fref } from './themes';
import type { Numbered } from './themes';
import { excludedItems } from './triageView';
import type { TriageView } from './triageView';

function bucketTable(items: Numbered[], showSev: boolean): string {
  return `<table class="tbl rm"><thead><tr>
      <th style="width:11mm">Ref</th><th style="width:46mm">Finding</th><th style="width:48mm">Where</th><th>Fix</th></tr></thead>
    <tbody>${items
      .map(
        ({ f, n }) => `<tr><td class="n">${fref(n)}</td>
        <td class="t">${showSev ? sevChip(f.severity) : ''}<span class="tt">${esc(f.title)}</span></td>
        <td class="small comp">${componentHtml(affectedComponent(f))}</td>
        <td class="small">${rich(firstSentence(f.remediation)) || '<span class="na">—</span>'}</td></tr>`,
      )
      .join('')}</tbody></table>`;
}

/** The backlog as a plain list: what it is and where, without a fix per line. */
function compactList(items: Numbered[]): string {
  return `<ul class="cl">${items
    .map(({ f, n }) => `<li>${fref(n)} <span class="tt">${esc(f.title)}</span> <span class="muted small">${componentHtml(affectedComponent(f))}</span></li>`)
    .join('')}</ul>`;
}

export function roadmapPage(
  scan: SastScan,
  items: Numbered[],
  num: string,
  edition: Edition,
  _review: { num: string } | undefined,
  /** With decisions recorded: the roadmap is the active findings only, and says what was left out and where to read why. */
  tri?: { view: TriageView; num: string },
): string {
  const on = !!tri?.view.on;
  const leftOut = on ? tri!.view.excluded.findings.total + tri!.view.excluded.hotspots.total : 0;
  const buckets = BUCKETS.map((b) => {
    const mine = items.filter((x) => b.sevs.includes(x.f.severity));
    const chips = b.sevs.map((s) => sevChip(s)).join(' ');
    return `<div class="rm-b">
      <div class="rm-h"><div class="rm-t">${chips}<span class="rm-w">${esc(b.when)}</span></div><div class="rm-c">${
        mine.length ? plural(mine.length, 'finding') : 'none'
      }</div></div>
      ${mine.length ? (edition === 'executive' && (b.key === 'low' || b.key === 'medium') ? compactList(mine) : bucketTable(mine, b.sevs.length > 1)) : `<p class="small muted rm-none">No ${b.sevs.length > 1 ? 'low or info' : b.label.toLowerCase()} findings.</p>`}
    </div>`;
  }).join('');

  // The scanner's review items are listed with the findings, so there is no separate review block.
  const reviewBlock = '';

  const add = controlsToAdd(scan);
  const cheap = lowValueMissing(scan);
  const hasControlData = (scan.controls ?? []).length > 0;
  const controlsBlock = hasControlData
    ? `<div class="stick rm-sec">${h3('Controls to add', add.length ? `${add.length}, highest value first` : '')}
      ${
        add.length === 0
          ? `<p class="small muted">No missing control would offer more than low bypass resistance once added.${cheap ? ` ${plural(cheap, 'control')} not detected but cheap to defeat; ${cheap === 1 ? 'it is' : 'they are'} listed in the console’s Controls tab.` : ''}</p>`
          : `<table class="tbl rm"><thead><tr><th style="width:50mm">Control</th><th style="width:26mm">Group</th><th style="width:30mm">Bypass effort once added</th><th>Why it matters</th></tr></thead>
            <tbody>${add
              .map(
                (c) => `<tr><td class="t"><span class="tt">${esc(c.title)}</span></td><td class="small">${esc(groupName(c.group))}</td>
                <td class="nw">${effortMeterHtml(c, false)}</td><td class="small">${rich(firstSentence(c.what, 170))}</td></tr>`,
              )
              .join('')}</tbody></table>
            <p class="small muted" style="margin-top:4px">Not detected: no reference found in the binary or code.${
              cheap ? ` ${plural(cheap, 'further control')} not detected would be cheap to bypass even once added, so ${cheap === 1 ? 'it is' : 'they are'} not listed.` : ''
            } Client-side controls raise the cost of an attack; they do not replace server-side checks.</p>`
      }</div>`
    : '';

  return `
  <section class="pg newpage${on ? ' tri' : ''}" id="roadmap">
    ${opener('roadmap-top', num, 'What to fix, and when', 'Every finding, worst first, with the one-line fix.')}
    <p class="lead">${on ? 'Active findings' : 'Findings'} grouped by timeline. The full remediation, impact and evidence are ${
      edition === 'full' ? 'on each finding’s own page' : 'in the full technical report'
    }.</p>
    ${
      items.length === 0
        ? `<p class="small muted" style="margin-top:8px">${
            on && tri!.view.excluded.findings.total > 0
              ? 'No active findings to schedule: every finding was excluded by triage.'
              : 'No findings to schedule: nothing is bucketed by timeline.'
          }</p>`
        : buckets
    }
    ${
      leftOut > 0
        ? `<p class="rm-tri"><strong>${esc(excludedItems(tri!.view))} excluded by triage</strong> ${leftOut === 1 ? 'is' : 'are'} not scheduled here \u2014 see <a class="lnk" href="#triage">section ${esc(tri!.num)}</a>. ${
            tri!.view.summary.expiredAcceptances > 0
              ? `${plural(tri!.view.summary.expiredAcceptances, 'expired acceptance')} ${tri!.view.summary.expiredAcceptances === 1 ? 'is' : 'are'} active again and included above.`
              : ''
          }</p>`
        : ''
    }
    ${reviewBlock}
    ${controlsBlock}
    <p class="rm-close"><strong>Close the loop.</strong> Re-scan the rebuilt artifact after fixing to confirm closure: a finding is closed when it no longer appears, and the score and report digest change to match.${
      items.length || leftOut ? ' Finding numbers (F01, F02, ...) belong to this report; they follow severity and will change after a re-scan.' : ''
    }</p>
  </section>`;
}
