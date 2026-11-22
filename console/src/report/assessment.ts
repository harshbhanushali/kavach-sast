/**
 * The executive summary's "Overall assessment": a short paragraph assembled
 * from the scan's own numbers. Deterministic, no model: the same scan always
 * produces the same words, and every clause is traceable to a count on the
 * page.
 */
import type { SastScan } from '../sastTypes';
import { SEV, SEVERITY_ORDER, esc, plural } from './kit';
import { themeTitle } from './themes';
import type { Numbered, Theme } from './themes';
import { triageSentences } from './triageView';
import type { TriageView } from './triageView';

/** "1 high, 4 medium and 2 low" */
function severityList(counts: SastScan['counts']): string {
  const parts = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => `${counts[s]} ${SEV[s].label.toLowerCase()}`);
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

function joinAnd(list: string[]): string {
  if (list.length <= 1) return list.join('');
  return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

export function overallAssessment(
  scan: SastScan,
  items: Numbered[],
  themes: Theme[],
  tag: string,
  secrets: boolean,
  controlsNum = '',
  tri?: TriageView,
): string {
  const c = scan.counts;
  const total = items.length;
  const rules = scan.coverageSummary?.total ?? 0;
  const assessed = (scan.categories ?? []).filter((x) => x.applicable);
  const failing = assessed.filter((x) => !x.pass);

  const found: string[] = [];
  if (total === 0 && tri?.on && tri.scan.findings.length > 0) {
    found.push(
      `<strong>${esc(tag)}.</strong> Every finding was excluded by triage, so no active defect remains, giving ${scan.score}/100 (grade ${esc(scan.grade)}).`,
    );
  } else if (total === 0) {
    found.push(
      `<strong>${esc(tag)}.</strong> ${rules ? `The ${rules} rules evaluated` : 'The rules evaluated'} produced no defects, giving ${scan.score}/100 (grade ${esc(scan.grade)}).`,
    );
  } else {
    found.push(
      `<strong>${esc(tag)}.</strong> The app scores ${scan.score}/100 (grade ${esc(scan.grade)}) with ${plural(total, tri?.on ? 'active defect' : 'defect')}: ${esc(severityList(c))}.`,
    );
  }
  // With decisions recorded, say so up front: what was set aside, that the score is after triage, and any lapsed acceptance.
  if (tri?.on) found.push(...triageSentences(tri));

  if (assessed.length > 0) {
    if (failing.length === 0) {
      found.push(`All ${assessed.length} assessed categories pass.`);
    } else {
      const names = failing.slice(0, 4).map((x) => esc(x.title));
      found.push(
        `${failing.length} of ${assessed.length} assessed categories fail: ${joinAnd(names)}${failing.length > 4 ? ` and ${failing.length - 4} more` : ''}.`,
      );
    }
  }

  const named = themes.filter((t) => t.code !== 'Other').slice(0, 3);
  if (named.length > 0) {
    found.push(
      `The strongest risk themes are ${joinAnd(named.map((t) => `${esc(themeTitle(t))} (worst ${SEV[t.worst].label.toLowerCase()}, ${plural(t.items.length, 'finding')})`))}.`,
    );
  }

  const mine = items.filter((x) => x.f.origin === 'first-party').length;
  const theirs = items.filter((x) => x.f.origin === 'third-party').length;
  if (mine > 0 && theirs > 0) {
    found.push(`${mine} of the ${total} findings sit in the app’s own code and ${theirs} in bundled libraries, where the remedy is usually an upgrade.`);
  }

  const controls = scan.controls ?? [];
  if (controls.length > 0) {
    const det = controls.filter((x) => x.status === 'detected');
    const weak = det.filter((x) => x.bypassEffort === 'trivial' || x.bypassEffort === 'low').length;
    const miss = controls.filter((x) => x.status === 'not-detected');
    const lead = controlsNum ? `<a class="lnk" href="#controls">security controls (section ${esc(controlsNum)})</a>` : 'security controls';
    let s = `${det.length} of ${controls.length} ${lead} were detected`;
    if (weak > 0) s += `, ${weak} of them easy to bypass`;
    if (miss.length > 0) s += `; not detected: ${joinAnd(miss.slice(0, 3).map((x) => esc(x.title.toLowerCase())))}${miss.length > 3 ? ` and ${miss.length - 3} more` : ''}`;
    found.push(`${s}.`);
  }

  const extras: string[] = [];
  if (scan.hotspots.length > 0) extras.push(`${plural(scan.hotspots.length, 'hotspot')} ${scan.hotspots.length === 1 ? 'needs' : 'need'} a human decision`);
  if (scan.secure.length > 0) extras.push(`${plural(scan.secure.length, 'good practice')} ${scan.secure.length === 1 ? 'was' : 'were'} verified`);
  if (extras.length) found.push(`${extras.join(' and ')}.`);

  // What to do first.
  const first = items[0]?.f;
  const q = (t: string) => `“${esc(t)}”`;
  let todo: string;
  if (c.critical > 0 && first) {
    todo = `Fix the ${plural(c.critical, 'critical issue')} before release, starting with ${q(first.title)}.`;
  } else if (c.high > 0 && first) {
    todo = `Start with the ${plural(c.high, 'high-severity finding')}, beginning with ${q(first.title)}, and close ${c.high === 1 ? 'it' : 'them'} this sprint.`;
  } else if (c.medium > 0 && first) {
    todo = `Nothing blocks release. Schedule the ${plural(c.medium, 'medium finding')} for the next release, beginning with ${q(first.title)}.`;
  } else if (total > 0) {
    todo = 'Everything found is low or informational. Fold it into the backlog.';
  } else {
    todo = 'Re-scan every build; a clean result is not assurance on its own.';
  }
  if (secrets) todo = `Revoke the credentials exposed in this artifact first. ${todo}`;

  return `<p class="assess-a">${found.join(' ')}</p><p class="assess-b"><strong>What to do first.</strong> ${todo}</p>`;
}
