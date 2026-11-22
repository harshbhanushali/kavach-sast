/**
 * The findings list, shared by both platforms: grouped by severity, filterable,
 * one line per finding.
 *
 * A scan can hold dozens of findings, most of which are not what the reader is
 * looking for. Each row therefore carries what is needed to decide whether to
 * open it (severity, title, where, standards, how many places) and expands into
 * the shared `FindingBody`, so the detail reads the same as everywhere else.
 */
import { useContext, useMemo, useState } from 'react';
import { ORIGIN_MEANING, OWASP_MOBILE_2024, matchesOrigin } from '../../sastTypes';
import type { OriginFilter, SastFinding, SastScan, SastSeverity } from '../../sastTypes';
import { FindingBody, OriginTag } from '../FindingDetail';
import { Empty, Panel } from '../ui';
import { isActive, triageSummary } from '../../triage';
import { SEVERITIES } from './model';
import type { StatusFilter } from './model';
import { STATUS_FILTERS, TriageChip, TriageContext, TriagePanel, countLabel, matchesStatus } from './triageUi';
import { FilterChip, SEV, SevChip, SevGlyph, Tag } from './ui';

type Filters = {
  severities: Set<SastSeverity>; category: string; query: string; origin: OriginFilter; status: StatusFilter;
};

const NO_FILTERS = (): Filters => ({ severities: new Set(), category: 'all', query: '', origin: 'all', status: 'all' });

const CATEGORY_TITLE = (scan: SastScan, key: string) =>
  scan.categories.find((c) => c.category === key)?.title ?? key;

function matches(scan: SastScan, f: SastFinding, flt: Filters): boolean {
  if (!matchesOrigin(f, flt.origin)) return false;
  if (!matchesStatus(scan, f.ruleId, flt.status)) return false;
  if (flt.severities.size > 0 && !flt.severities.has(f.severity)) return false;
  if (flt.category !== 'all' && f.category !== flt.category) return false;
  const q = flt.query.trim().toLowerCase();
  if (!q) return true;
  return [f.title, f.cwe, f.masvs, f.owasp, f.owasp ? OWASP_MOBILE_2024[f.owasp] : undefined, f.description, ...(f.locations.slice(0, 5).map((l) => l.file))]
    .some((s) => s?.toLowerCase().includes(q));
}

/**
 * One finding as a row. Exported because the Secrets tab lists findings too and
 * should look like the Findings tab, not like a different product.
 */
export function FindingRow({
  finding, open, onToggle, tone, category,
}: {
  finding: SastFinding; open: boolean; onToggle: () => void; tone: 'defect' | 'hotspot'; category?: string;
}) {
  const s = SEV[finding.severity];
  const loc = finding.locations[0];
  const id = `finding-${finding.ruleId}`;
  const triage = useContext(TriageContext);
  const entry = triage?.scan.triage?.[finding.ruleId];
  // Excluded rows stay in the list, quieter: the decision is part of the record.
  // The header content dims; the status chip and the opened body do not.
  const dim = entry && !isActive(triage!.scan, finding.ruleId) ? 'opacity-55' : '';
  return (
    <li className={`scroll-mt-4 rounded-lg border border-l-[3px] border-slate-800 bg-slate-900/30 transition-colors hover:bg-slate-900/60 ${s.stripe}`}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={id}
        className="flex w-full flex-wrap items-start gap-x-3 gap-y-2 px-3.5 py-3 text-left"
      >
        <span className={`w-[5.75rem] shrink-0 pt-px ${dim}`}>
          <SevChip severity={finding.severity} />
        </span>
        <span className="min-w-0 flex-1 basis-64">
          <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className={`text-sm font-medium leading-snug text-slate-100 ${dim}`}>{finding.title}</span>
            {entry && <TriageChip entry={entry} />}
          </span>
          <span className={`mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-500 ${dim}`}>
            {category && <span className="text-slate-400">{category}</span>}
            {loc && (
              <span className="min-w-0 max-w-full truncate font-mono text-ember-300/80">
                {loc.file}{loc.line ? `:${loc.line}` : ''}
                {loc.dex && <span className="ml-2 text-amber-200/70">in {loc.dex}</span>}
              </span>
            )}
            <OriginTag origin={finding.origin} libraries={finding.libraries} />
          </span>
        </span>
        <span className={`ml-auto flex shrink-0 items-center gap-1.5 ${dim}`}>
          {finding.cwe && <Tag title="Common Weakness Enumeration">{finding.cwe}</Tag>}
          {finding.masvs && <Tag title="OWASP MASVS control">{finding.masvs}</Tag>}
          {finding.owasp && (
            <Tag title={`OWASP Mobile Top 10 (2024): ${OWASP_MOBILE_2024[finding.owasp] ?? finding.owasp}`}>{finding.owasp}</Tag>
          )}
          <span
            title={`${finding.occurrences} occurrence${finding.occurrences === 1 ? '' : 's'}`}
            className="inline-flex min-w-[2.6rem] items-center justify-center rounded border border-slate-700 bg-slate-950/60 px-1.5 py-px text-[11px] font-semibold tabular-nums text-slate-300"
          >
            {'×'}{finding.occurrences}
          </span>
          <span aria-hidden className={`text-slate-500 transition-transform ${open ? 'rotate-90' : ''}`}>{'›'}</span>
        </span>
      </button>
      {open && (
        <div id={id} className="space-y-3 border-t border-slate-800/80 px-4 pb-4 pt-3 @3xl:pl-[6.5rem]">
          {/* Keyed by scan so loading another scan never carries a half-typed draft over. */}
          {triage && <TriagePanel key={`${triage.scan.scanId}:${finding.ruleId}`} ruleId={finding.ruleId} />}
          <FindingBody finding={finding} tone={tone} />
        </div>
      )}
    </li>
  );
}

export function SastFindings({
  scan, open, onToggle, initialStatus = 'all',
}: {
  scan: SastScan; open: Set<string>; onToggle: (id: string) => void;
  /** Opens the list already narrowed by status, e.g. from the overview's "excluded by triage" link. */
  initialStatus?: StatusFilter;
}) {
  const [flt, setFlt] = useState<Filters>(() => ({ ...NO_FILTERS(), status: initialStatus }));
  const [showSecure, setShowSecure] = useState(false);

  const categories = useMemo(() => {
    const n = new Map<string, number>();
    for (const f of scan.findings) n.set(f.category, (n.get(f.category) ?? 0) + 1);
    return [...n.entries()].sort((a, b) => b[1] - a[1]);
  }, [scan]);

  // Shown only when the split is real: on an app whose findings all sit in one
  // place the control would be three chips where two do nothing.
  const origin: Record<OriginFilter, number> = {
    all: scan.findings.length,
    'first-party': scan.findings.filter((f) => matchesOrigin(f, 'first-party')).length,
    'third-party': scan.findings.filter((f) => matchesOrigin(f, 'third-party')).length,
  };

  const defects = scan.findings.filter((f) => matches(scan, f, flt));
  const filtering = flt.severities.size > 0 || flt.category !== 'all' || flt.query.trim() !== '' || flt.origin !== 'all' || flt.status !== 'all';

  // Counts for the status row are over everything triageable, whatever the
  // other filters say, so a chip's number is what it would show on its own.
  const triageable = useMemo(() => scan.findings, [scan]);
  const decisions = triageSummary(scan);
  const statusCount = (key: StatusFilter) => triageable.filter((f) => matchesStatus(scan, f.ruleId, key)).length;
  const excludedCount = statusCount('excluded');
  const excludedIn = (list: SastFinding[]) => list.filter((f) => !isActive(scan, f.ruleId)).length;

  const sevCount = (s: SastSeverity) => scan.findings.filter((f) => f.severity === s).length;
  const toggleSeverity = (s: SastSeverity) =>
    setFlt((p) => {
      const next = new Set(p.severities);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return { ...p, severities: next };
    });

  return (
    <div className="@container space-y-5">
      {/* filters */}
      <div className="panel space-y-3 px-4 py-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative min-w-[14rem] flex-1">
            <span className="sr-only">Search findings</span>
            <input
              type="text"
              value={flt.query}
              onChange={(e) => setFlt((p) => ({ ...p, query: e.target.value }))}
              placeholder="Search title, CWE, MASVS, OWASP or file"
              className="w-full !rounded-lg !py-1.5 !pl-8"
            />
            <span aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">{'⌕'}</span>
          </label>
          {filtering && (
            <button
              type="button"
              onClick={() => setFlt(NO_FILTERS())}
              className="rounded-md px-2.5 py-1.5 text-xs font-medium text-ember-300 hover:bg-slate-800"
            >
              Clear filters
            </button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by severity">
          <span className="eyebrow mr-1">Severity</span>
          {SEVERITIES.filter((s) => sevCount(s) > 0).map((s) => (
            <FilterChip key={s} active={flt.severities.has(s)} onClick={() => toggleSeverity(s)}>
              <span className={SEV[s].text}><SevGlyph severity={s} /></span>
              {SEV[s].label}
              <span className="tabular-nums text-slate-500">{sevCount(s)}</span>
            </FilterChip>
          ))}
        </div>
        {(decisions.decided > 0 || flt.status !== 'all') && (
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by triage status">
              <span className="eyebrow mr-1">Status</span>
              {STATUS_FILTERS.filter((x) => x.key === 'all' || x.key === 'active' || flt.status === x.key || statusCount(x.key) > 0).map((x) => (
                <FilterChip key={x.key} active={flt.status === x.key} title={x.hint} onClick={() => setFlt((p) => ({ ...p, status: x.key }))}>
                  {x.label}
                  <span className="tabular-nums text-slate-500">{statusCount(x.key)}</span>
                </FilterChip>
              ))}
            </div>
            {(excludedCount > 0 || decisions.expiredAcceptances > 0) && (
              <p className="text-xs leading-relaxed text-slate-400">
                {excludedCount > 0 && (
                  <>
                    <span aria-hidden className="mr-1.5 text-slate-500">{'\u2298'}</span>
                    {excludedCount} excluded by triage: listed dimmed, not counted in the score.
                  </>
                )}
                {decisions.expiredAcceptances > 0 && (
                  <span className="ml-2 text-amber-300">
                    <span aria-hidden className="mr-1">{'\u25b2'}</span>
                    {decisions.expiredAcceptances} accepted risk{decisions.expiredAcceptances === 1 ? ' has' : 's have'} expired and count{decisions.expiredAcceptances === 1 ? 's' : ''} again.
                  </span>
                )}
              </p>
            )}
          </div>
        )}
        {origin['first-party'] > 0 && origin['third-party'] > 0 && (
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by whose code it is">
            <span className="eyebrow mr-1">Code</span>
            {([
              ['all', 'All', 'Every finding'],
              ['first-party', 'Your code', ORIGIN_MEANING['first-party']],
              ['third-party', 'Libraries', ORIGIN_MEANING['third-party']],
            ] as const).map(([key, label, hint]) => (
              <FilterChip key={key} active={flt.origin === key} title={hint} onClick={() => setFlt((p) => ({ ...p, origin: key }))}>
                {label}
                <span className="tabular-nums text-slate-500">{origin[key]}</span>
              </FilterChip>
            ))}
          </div>
        )}
        {categories.length > 1 && (
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by category">
            <span className="eyebrow mr-1">Category</span>
            <FilterChip active={flt.category === 'all'} onClick={() => setFlt((p) => ({ ...p, category: 'all' }))}>
              All
            </FilterChip>
            {categories.map(([key, n]) => (
              <FilterChip
                key={key}
                active={flt.category === key}
                onClick={() => setFlt((p) => ({ ...p, category: p.category === key ? 'all' : key }))}
              >
                {CATEGORY_TITLE(scan, key)}
                <span className="tabular-nums text-slate-500">{n}</span>
              </FilterChip>
            ))}
          </div>
        )}
      </div>

      {/* defects, one group per severity */}
      <Panel
        title={`Vulnerabilities (${countLabel(defects.length, excludedIn(defects))}${filtering ? ` of ${scan.findings.length}` : ''})`}
        subtitle="Worst first, one row per rule. Open a row to see where it is, decide whether it is real (a false positive drops out of the score and the report), and how to fix it."
      >
        {scan.findings.length === 0 ? (
          <Empty>No defects found.</Empty>
        ) : defects.length === 0 ? (
          <Empty>Nothing matches these filters.</Empty>
        ) : (
          <div className="space-y-5">
            {SEVERITIES.map((sev) => {
              const group = defects.filter((f) => f.severity === sev);
              if (group.length === 0) return null;
              return (
                <section key={sev} aria-label={`${SEV[sev].label} findings`}>
                  <h3 className={`mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider ${SEV[sev].text}`}>
                    <SevGlyph severity={sev} />
                    {SEV[sev].label}
                    <span className="rounded-full bg-slate-800 px-1.5 py-px text-[10px] tabular-nums text-slate-300">{group.length}</span>
                    <span className="h-px flex-1 bg-slate-800" />
                  </h3>
                  <ul className="space-y-2">
                    {group.map((f) => (
                      <FindingRow
                        key={f.ruleId}
                        finding={f}
                        tone={f.fromReview ? 'hotspot' : 'defect'}
                        category={CATEGORY_TITLE(scan, f.category)}
                        open={open.has(f.ruleId)}
                        onToggle={() => onToggle(f.ruleId)}
                      />
                    ))}
                  </ul>
                </section>
              );
            })}
          </div>
        )}
      </Panel>

      {scan.secure.length > 0 && (
        <Panel
          title={`Done right (${scan.secure.length})`}
          subtitle="Listed so a hardened app is distinguishable from one that simply has a short finding list."
          actions={
            <button
              type="button"
              onClick={() => setShowSecure((v) => !v)}
              aria-expanded={showSecure}
              className="rounded-md border border-slate-700 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              {showSecure ? 'Hide' : 'Show all'}
            </button>
          }
        >
          <ul className="grid gap-2.5 @3xl:grid-cols-2">
            {(showSecure ? scan.secure : scan.secure.slice(0, 4)).map((f) => (
              <li key={f.ruleId} className="flex gap-2.5 rounded-lg border border-emerald-500/20 bg-emerald-500/[0.04] px-3 py-2.5">
                <span aria-hidden className="mt-px text-sm leading-none text-emerald-400">{'✓'}</span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-slate-100">{f.title}</span>
                  <span className="block text-xs leading-relaxed text-slate-400">{f.description}</span>
                </span>
              </li>
            ))}
          </ul>
          {!showSecure && scan.secure.length > 4 && (
            <p className="mt-2.5 text-xs text-slate-500">{scan.secure.length - 4} more hidden.</p>
          )}
        </Panel>
      )}
    </div>
  );
}
