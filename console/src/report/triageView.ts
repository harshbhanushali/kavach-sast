/**
 * Triage in the report: reviewers' decisions about findings and hotspots, and
 * what they do to the document.
 *
 * The rules (which statuses count, what the adjusted score is) live in
 * `../triage.ts`, shared with the dashboard; this file only decides how a
 * decision is *shown*. The one switch that matters is `on`: with no decision
 * recorded the view is inert and every page renders exactly as it did before
 * triage existed (no Status column, no banners, no section). With one or more,
 * the headline numbers are computed on the **active** findings, the as-scanned
 * figures stay visible beside them, and excluded items remain in the report,
 * marked, so a reader can always see what was set aside and why.
 *
 * `eff` is the whole trick for the pages that already read counts from a scan:
 * a copy of the scan whose findings, hotspots, counts, score, grade and
 * scorecard are the active ones, so the verdict, the assessment and the
 * summary need no second code path.
 */
import type { SastFinding, SastScan, SastSeverity, TriageEntry, TriageStatus } from '../sastTypes';
import { TRIAGE_META, adjustedScore, isActive, isExpired, mergeReview, triageSummary } from '../triage';
import type { TriageSummary } from '../triage';
import { BAD, esc, h3, opener, plural, tiles } from './kit';
import { sha256Hex } from './sha256';

const GLYPH: Record<TriageStatus, string> = {
  open: '○',
  confirmed: '◉',
  false_positive: '⊘',
  accepted_risk: '◐',
  fixed: '✓',
};

const DECIDED: TriageStatus[] = ['confirmed', 'false_positive', 'accepted_risk', 'fixed'];

/** One tally of what triage did to a list of items. */
export type Tally = { total: number; confirmed: number; falsePositive: number; acceptedRisk: number; expired: number; fixed: number };

export type TriageView = {
  /** At least one decision on a finding or hotspot in this scan. */
  on: boolean;
  scan: SastScan;
  now: Date;
  summary: TriageSummary;
  adj: ReturnType<typeof adjustedScore>;
  /** The scan as the headline numbers see it: active findings and hotspots, adjusted score and counts. */
  eff: SastScan;
  entry(f: SastFinding): TriageEntry | undefined;
  status(f: SastFinding): TriageStatus;
  active(f: SastFinding): boolean;
  expired(f: SastFinding): boolean;
  /** Items set aside by triage (excluded, so not counting). */
  excluded: { findings: Tally; hotspots: Tally };
};

const FAILING: SastSeverity[] = ['critical', 'high', 'medium'];

function validEntry(e: TriageEntry | undefined): TriageEntry | undefined {
  return e && DECIDED.includes(e.status) ? e : undefined;
}

function tally(list: SastFinding[], view: Pick<TriageView, 'entry' | 'active' | 'expired'>): Tally {
  const t: Tally = { total: 0, confirmed: 0, falsePositive: 0, acceptedRisk: 0, expired: 0, fixed: 0 };
  for (const f of list) {
    const e = view.entry(f);
    if (!e) continue;
    if (e.status === 'confirmed') t.confirmed += 1;
    else if (e.status === 'false_positive') t.falsePositive += 1;
    else if (e.status === 'fixed') t.fixed += 1;
    else if (view.expired(f)) t.expired += 1;
    else t.acceptedRisk += 1;
    if (!view.active(f)) t.total += 1;
  }
  return t;
}

export function triageView(raw: SastScan, now: Date = new Date()): TriageView {
  const scan = mergeReview(raw);
  const summary = triageSummary(scan);
  const on = summary.decided > 0;
  const adj = adjustedScore(scan, now);
  const entry = (f: SastFinding) => validEntry(scan.triage?.[f.ruleId]);
  const active = (f: SastFinding) => (entry(f) ? isActive(scan, f.ruleId, now) : true);
  const expired = (f: SastFinding) => isExpired(entry(f), now);
  const base = { entry, active, expired };

  let eff = scan;
  if (on) {
    const findings = scan.findings.filter(active);
    eff = {
      ...scan,
      findings,
      hotspots: scan.hotspots.filter(active),
      counts: adj.counts,
      score: adj.score,
      grade: adj.grade,
      categories: scan.categories.map((c) => {
        // A review item the scanner did not call a defect only counts against a category once a person confirms it.
        const own = findings.filter((f) => f.category === c.category && (!f.fromReview || scan.triage?.[f.ruleId]?.status === 'confirmed'));
        return { ...c, findings: own.length, pass: !own.some((f) => FAILING.includes(f.severity)) };
      }),
    };
  }

  return {
    on, scan, now, summary, adj, eff,
    ...base,
    status: (f) => entry(f)?.status ?? 'open',
    excluded: { findings: tally(scan.findings, base), hotspots: tally(scan.hotspots, base) },
  };
}

/* ----------------------------------------------------------------------------
 * Words
 * ------------------------------------------------------------------------- */

/** "31 Dec 2025", always read in UTC so a decision keeps the date it was made on, wherever it is printed. */
export function fmtDay(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

export function fmtStamp(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC`;
}

/** The status word. `Accepted` is the short form used where a column is narrow. */
export function statusWord(status: TriageStatus, short = false): string {
  return short && status === 'accepted_risk' ? 'Accepted' : TRIAGE_META[status].label;
}

/** "1 false positive, 2 accepted risks and 1 fixed"; '' when the tally is empty. */
export function excludedBreakdown(t: Tally): string {
  const parts: string[] = [];
  if (t.falsePositive) parts.push(`${t.falsePositive} false ${t.falsePositive === 1 ? 'positive' : 'positives'}`);
  if (t.acceptedRisk) parts.push(plural(t.acceptedRisk, 'accepted risk'));
  if (t.fixed) parts.push(`${t.fixed} fixed`);
  return parts.length <= 1 ? parts.join('') : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

function sumTally(a: Tally, b: Tally): Tally {
  return {
    total: a.total + b.total, confirmed: a.confirmed + b.confirmed, falsePositive: a.falsePositive + b.falsePositive,
    acceptedRisk: a.acceptedRisk + b.acceptedRisk, expired: a.expired + b.expired, fixed: a.fixed + b.fixed,
  };
}

/** How many findings and hotspots triage set aside: "3 findings and 1 hotspot". */
export function excludedItems(v: TriageView): string {
  const f = v.excluded.findings.total;
  const h = v.excluded.hotspots.total;
  return [f ? plural(f, 'finding') : '', h ? plural(h, 'hotspot') : ''].filter(Boolean).join(' and ');
}

/** The score before and after, e.g. `54/100 (D)`. */
export const scoreText = (score: number, grade: string) => `${score}/100 (${grade})`;

/**
 * The sentences the overall assessment adds when decisions exist: what was set
 * aside, that the score is after triage, and any acceptance that has lapsed.
 * Plain HTML-safe text; deterministic like the rest of the assessment.
 */
export function triageSentences(v: TriageView): string[] {
  if (!v.on) return [];
  const all = sumTally(v.excluded.findings, v.excluded.hotspots);
  const out: string[] = [];
  const before = scoreText(v.scan.score, v.scan.grade);
  const after = scoreText(v.adj.score, v.adj.grade);
  if (all.total > 0) {
    const n = all.total;
    out.push(
      `${esc(excludedItems(v))} ${n === 1 ? 'was' : 'were'} triaged out${excludedBreakdown(all) ? `: ${esc(excludedBreakdown(all))}` : ''}.`,
    );
    out.push(
      v.adj.score === v.scan.score
        ? `The score is after triage and is unchanged at ${esc(before)}.`
        : `The score is after triage: ${esc(after)}, against ${esc(before)} as scanned.`,
    );
  } else {
    out.push(`Reviewers recorded ${plural(v.summary.decided, 'decision')}, but none excludes anything, so the numbers are the scan’s own.`);
  }
  if (all.expired > 0) {
    out.push(
      `${plural(all.expired, 'accepted risk')} ${all.expired === 1 ? 'has' : 'have'} expired and ${all.expired === 1 ? 'counts' : 'count'} again.`,
    );
  }
  if (all.confirmed > 0) out.push(`${plural(all.confirmed, 'item')} ${all.confirmed === 1 ? 'was' : 'were'} confirmed by a reviewer.`);
  return out;
}

/* ----------------------------------------------------------------------------
 * Chips, bands and notes
 * ------------------------------------------------------------------------- */

/**
 * The status chip: glyph + word (never colour alone). A lapsed acceptance gets
 * a second line, "expired", because it is the one status that changes a number
 * back.
 */
export function statusChip(status: TriageStatus, opts: { expired?: boolean; short?: boolean } = {}): string {
  const chip = `<span class="stc s-${status}"><span class="g">${GLYPH[status]}</span>${esc(statusWord(status, opts.short))}</span>`;
  return opts.expired ? `<span class="stw">${chip}<span class="stx">! expired</span></span>` : chip;
}

/** A status chip for a finding or hotspot as the view sees it. */
export function chipFor(v: TriageView, f: SastFinding, short = true): string {
  return statusChip(v.status(f), { expired: v.expired(f), short });
}

function byline(e: TriageEntry): string {
  return `by ${esc(e.updatedBy)} · ${esc(fmtDay(e.updatedAt))}`;
}

function reasonHtml(e: TriageEntry): string {
  return e.reason && e.reason.trim() ? esc(e.reason.trim()) : '<span class="muted">No reason recorded.</span>';
}

/**
 * The band under a finding's banner: what was decided, what it does to the
 * numbers, the reason in full, who and when, and any expiry. Empty for an open
 * finding.
 */
export function statusBand(v: TriageView, f: SastFinding): string {
  const e = v.entry(f);
  if (!e || !v.on) return '';
  const expired = v.expired(f);
  let head: string;
  if (e.status === 'false_positive') head = 'False positive · excluded from counts and score';
  else if (e.status === 'fixed') head = 'Fixed · excluded (rescan to confirm)';
  else if (e.status === 'confirmed') head = 'Confirmed · a real issue; counts toward the score';
  else if (expired) head = `Accepted risk — expired ${fmtDay(e.expiresAt)} · counts again`;
  else head = 'Accepted risk · excluded from counts and score';
  const expiry =
    e.status !== 'accepted_risk'
      ? ''
      : expired
        ? ''
        : `<span>${e.expiresAt ? `Accepted until ${esc(fmtDay(e.expiresAt))}` : 'No expiry date'}</span>`;
  const showReason = e.reason?.trim() || e.status === 'false_positive' || e.status === 'accepted_risk';
  return `<div class="f-status s-${e.status}${expired ? ' lapsed' : ''}">
    <div class="fs-h"><span class="fs-t"><span class="g">${expired ? '!' : GLYPH[e.status]}</span>${esc(head)}</span><span class="fs-m"><span>${byline(e)}</span>${expiry}</span></div>
    ${showReason ? `<div class="fs-r"><span class="lab">Reason</span>${reasonHtml(e)}</div>` : ''}
  </div>`;
}

/** The compact status line on a hotspot card: the reason in full, who, when, expiry. */
export function hotspotNote(v: TriageView, f: SastFinding): string {
  const e = v.entry(f);
  if (!e || !v.on) return '';
  const expired = v.expired(f);
  const bits = [
    byline(e),
    e.status === 'accepted_risk' ? (expired ? `lapsed ${esc(fmtDay(e.expiresAt))}, counts again` : e.expiresAt ? `until ${esc(fmtDay(e.expiresAt))}` : 'no expiry') : '',
  ].filter(Boolean);
  const effect = expired
    ? 'counts again'
    : v.active(f)
      ? 'counts'
      : 'excluded from the counts';
  return `<div class="hs-tri s-${e.status}${expired ? ' lapsed' : ''}"><span class="hs-tri-h"><span class="eff">${effect}</span></span>
    ${e.reason?.trim() || e.status === 'false_positive' || e.status === 'accepted_risk' ? `<span class="hs-tri-r">${reasonHtml(e)}</span>` : ''}
    <span class="hs-tri-m">${bits.join(' · ')}</span></div>`;
}

/** Which of the finding page's checkboxes matches a status, so the printed form agrees with the decision. */
export function tickedBox(status: TriageStatus): 'fix' | 'accept' | 'fp' | undefined {
  return status === 'fixed' ? 'fix' : status === 'accepted_risk' ? 'accept' : status === 'false_positive' ? 'fp' : undefined;
}

/* ----------------------------------------------------------------------------
 * Fingerprint
 * ------------------------------------------------------------------------- */

/**
 * The decisions in their canonical form: every decision on a finding or
 * hotspot of this scan, sorted by rule id (code-point order, not locale),
 * fields in a fixed order, `expiresAt` null when absent, no whitespace.
 * Anyone with the decisions can recompute the fingerprint from this.
 */
export function canonicalDecisions(scan: SastScan): string {
  const known = new Set([...scan.findings, ...scan.hotspots].map((f) => f.ruleId));
  const rows = Object.entries(scan.triage ?? {})
    .filter(([ruleId, e]) => known.has(ruleId) && validEntry(e))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([ruleId, e]) => ({
      ruleId, status: e.status, reason: e.reason ?? '', expiresAt: e.expiresAt ?? null, updatedBy: e.updatedBy, updatedAt: e.updatedAt,
    }));
  return JSON.stringify(rows);
}

/** First 16 hex characters of the SHA-256 over `canonicalDecisions`. */
export function triageFingerprint(scan: SastScan): string {
  return sha256Hex(canonicalDecisions(scan)).slice(0, 16);
}

/* ----------------------------------------------------------------------------
 * Legend (How to read)
 * ------------------------------------------------------------------------- */

/** What each status means and what it does to the numbers, in a compact two-column grid. Always printed: it is how-to-read content. */
export function triageLegend(): string {
  const text: Record<TriageStatus, string> = {
    open: 'Not reviewed yet. Counts.',
    confirmed: 'A person checked it and it is real. Counts.',
    false_positive: 'The scanner matched something that is not a problem. Excluded from the counts and score.',
    accepted_risk: 'A real issue the team lives with, for now. Excluded until its expiry date, then counts again.',
    fixed: 'Resolved in the code. Excluded; a rescan confirms it.',
  };
  const order: TriageStatus[] = ['open', 'confirmed', 'false_positive', 'accepted_risk', 'fixed'];
  return `<div class="tleg">${order.map((st) => `<p>${statusChip(st)} ${esc(text[st])}</p>`).join('')}<p class="tn">Excluded items stay listed, marked, with the reviewer\u2019s reason. With decisions recorded, every headline count and the score are those of the active items; the as-scanned figures stay beside them.</p></div>`;
}

/* ----------------------------------------------------------------------------
 * Scope paragraph
 * ------------------------------------------------------------------------- */

/** The paragraph for Scope & methodology; only called when decisions exist. */
export function triageScopeText(v: TriageView): string {
  const s = v.summary;
  return `<p class="small">This report carries ${plural(s.decided, 'reviewer decision')} recorded after the scan. They do not change what the scanner found: excluded items stay listed, marked, but the counts and the score are those of the active items, with the as-scanned figures beside them; ${
    s.expiredAcceptances ? `${plural(s.expiredAcceptances, 'expired acceptance')} ${s.expiredAcceptances === 1 ? 'counts' : 'count'} again` : 'an acceptance counts again once it expires'
  }. Statuses are defined in <a class="lnk" href="#howto">How to read this report</a>; every decision is listed in <a class="lnk" href="#triage">the triage summary</a>.</p>`;
}

/* ----------------------------------------------------------------------------
 * Triage summary section
 * ------------------------------------------------------------------------- */

export type DecisionRow = {
  f: SastFinding;
  ref: { label: string; href: string };
  kind: 'finding' | 'hotspot';
  entry: TriageEntry;
};

/** Every decided item, findings first (in report order) then hotspots. */
export function decisionRows(v: TriageView, refs: Map<SastFinding, { label: string; href: string }>): DecisionRow[] {
  const rows: DecisionRow[] = [];
  const hot = new Set(v.scan.hotspots);
  for (const [f, ref] of refs) {
    const entry = v.entry(f);
    if (entry) rows.push({ f, ref, kind: hot.has(f) ? 'hotspot' : 'finding', entry });
  }
  return rows;
}

export function triageSection(
  v: TriageView,
  refs: Map<SastFinding, { label: string; href: string }>,
  num: string,
  scoreRef?: { num: string; href: string },
): string {
  const rows = decisionRows(v, refs);
  const s = v.summary;
  const users = [...new Set(rows.map((r) => r.entry.updatedBy))].sort();
  const latest = rows.map((r) => r.entry.updatedAt).sort().pop();
  const openF = v.scan.findings.filter((f) => !v.entry(f)).length;
  const openH = v.scan.hotspots.filter((f) => !v.entry(f)).length;
  const c = v.adj.counts;
  const before = v.scan.counts;

  const mix = (k: Record<SastSeverity, number>) => (['critical', 'high', 'medium', 'low', 'info'] as const).map((x) => k[x] ?? 0).join(' \u00b7 ');
  const effect = `<table class="tbl tri-fx"><thead><tr><th>Measure</th><th class="r" style="width:24mm">As scanned</th><th class="r" style="width:24mm">After triage</th></tr></thead><tbody>
    <tr><td>Score and grade</td><td class="r">${esc(scoreText(v.scan.score, v.scan.grade))}</td><td class="r"><strong>${esc(scoreText(v.adj.score, v.adj.grade))}</strong></td></tr>
    <tr><td>Defects (findings)</td><td class="r">${v.scan.findings.length}</td><td class="r"><strong>${v.eff.findings.length}</strong></td></tr>
    <tr><td>Critical \u00b7 high \u00b7 medium \u00b7 low \u00b7 info</td><td class="r">${mix(before)}</td><td class="r"><strong>${mix(c)}</strong></td></tr>
  </tbody></table>`;

  const integrity = `<div class="callout note tri-int">
    <p class="small"><strong>Triage as of ${esc(fmtStamp(latest))}</strong></p>
    <p class="small">${plural(rows.length, 'decision')} by ${esc(users.join(', '))}</p>
    <p class="tri-fp"><span class="k">Fingerprint</span><code>${esc(triageFingerprint(v.scan))}</code></p>
  </div>`;

  const table = `<table class="tbl tri-t"><thead><tr>
      <th style="width:12mm">Item</th><th style="width:44mm">Title</th><th style="width:27mm">Status</th><th>Reason</th>
      <th style="width:30mm">Decided</th><th style="width:25mm">Expiry</th></tr></thead><tbody>${rows
    .map((r) => {
      const expired = v.expired(r.f);
      const e = r.entry;
      const expiry =
        e.status !== 'accepted_risk'
          ? '<span class="na">—</span>'
          : e.expiresAt
            ? `${esc(fmtDay(e.expiresAt))}${expired ? '<span class="exp-flag">Expired — counts as active</span>' : ''}`
            : '<span class="muted">No expiry</span>';
      return `<tr class="${expired ? 'warn' : ''}"><td class="n"><a class="fref" href="${r.ref.href}">${esc(r.ref.label)}</a></td>
        <td class="t"><span class="tt">${esc(r.f.title)}</span></td>
        <td>${statusChip(e.status, { expired })}</td>
        <td class="small reason">${reasonHtml(e)}</td>
        <td class="small">${esc(e.updatedBy)}<span class="rid">${esc(fmtDay(e.updatedAt))}</span></td>
        <td class="small">${expiry}</td></tr>`;
    })
    .join('')}</tbody></table>`;

  const open =
    openF + openH === 0
      ? 'Every finding and hotspot has a decision.'
      : `${[openF ? plural(openF, 'finding') : '', openH ? plural(openH, 'hotspot') : ''].filter(Boolean).join(' and ')} ${openF + openH === 1 ? 'has' : 'have'} no decision (open) and ${openF + openH === 1 ? 'counts' : 'count'} in full.`;

  return `
  <section class="pg newpage" id="triage">
    ${opener('triage-top', num, 'Triage summary', 'What reviewers decided about each finding and hotspot, and what that did to the numbers.')}
    <p class="lead">Decisions were recorded after the scan, by people. Excluded items stay in this report, marked; the headline counts and the score${
      scoreRef ? ` (<a class="lnk" href="${scoreRef.href}">section ${esc(scoreRef.num)}</a>)` : ''
    } are computed on the active ones. ${esc(open)}</p>
    ${tiles([
      { n: s.decided, label: 'Decisions', sub: `${v.scan.findings.length + v.scan.hotspots.length} items` },
      { n: s.confirmed, label: 'Confirmed', sub: 'counts' },
      { n: s.falsePositive, label: 'False positive', sub: 'excluded' },
      { n: s.acceptedRisk, label: 'Accepted risk', sub: 'excluded' },
      { n: s.expiredAcceptances, label: 'Expired', sub: 'counts again', tone: s.expiredAcceptances ? BAD : undefined },
      { n: s.fixed, label: 'Fixed', sub: 'excluded' },
    ])}
    <div class="two tri-two">
      <div>${h3('What triage did to the numbers')}${effect}</div>
      <div>${h3('Integrity')}${integrity}</div>
    </div>
    <p class="small muted tri-dg">Two digests, two jobs. The scan\u2019s <strong>report digest</strong> (<code>${esc(v.scan.reportHash.slice(0, 16))}</code>, in every page footer) covers the raw scan: the application hash, the score as scanned and every finding. It does not cover these decisions. The <strong>triage fingerprint</strong> covers the decisions only: the first 16 hex characters of the SHA-256 of a JSON array holding one object per decision, sorted by rule id, with the fields <code>ruleId</code>, <code>status</code>, <code>reason</code>, <code>expiresAt</code> (null when there is none), <code>updatedBy</code> and <code>updatedAt</code>, and no whitespace. Change a decision and the fingerprint changes; the report digest does not.</p>
    ${h3('Every decision', `${rows.length}, findings first`)}
    ${table}
  </section>`;
}
