/**
 * What both platforms' views derive from a scan, kept out of the components.
 *
 * The iOS and Android dashboards are one product with two data sources, so the
 * pieces that do not care about the platform live here: tones, severity order,
 * number formatting, the verdict sentence and the tab keys. Platform models
 * (`ios/iosModel.ts`, `android/androidModel.ts`) build on these.
 */
import type { ControlGroup, SastFinding, SastScan, SastSeverity, SecurityControl } from '../../sastTypes';
import { activeFindings, adjustedScore, mergeReview, triageSummary } from '../../triage';
import type { TriageSummary } from '../../triage';

/** Which tab a card or tile sends the reader to. */
export type SastTabKey = 'findings' | 'surface' | 'trust' | 'binary' | 'controls' | 'explorer';

/**
 * Which findings-list status filter a link opens with. `excluded` is every
 * decision that stops a finding counting; the rest are a single status.
 */
export type StatusFilter = 'all' | 'active' | 'excluded' | 'open' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'fixed';

/** Navigation from a card or tile; the Findings tab can also be opened already filtered. */
export type Navigate = (t: SastTabKey, opts?: { status?: StatusFilter }) => void;

export type Tone = 'good' | 'warn' | 'bad' | 'info' | 'muted';

export const SEVERITIES: SastSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function formatBytes(n: number | undefined): string {
  if (!n || n < 0) return '—';
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(n >= 10 * 1024 * 1024 ? 1 : 2)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Grade letter -> text colour and the glow the hero paints behind the dial. */
export const GRADE: Record<string, { text: string; chip: string; glow: string }> = {
  A: { text: 'text-emerald-300', chip: 'border-emerald-500/45 bg-emerald-500/10', glow: 'rgb(52 211 153 / 0.16)' },
  B: { text: 'text-lime-300', chip: 'border-lime-500/45 bg-lime-500/10', glow: 'rgb(163 230 53 / 0.14)' },
  C: { text: 'text-amber-300', chip: 'border-amber-500/45 bg-amber-500/10', glow: 'rgb(252 211 77 / 0.14)' },
  D: { text: 'text-orange-300', chip: 'border-orange-500/45 bg-orange-500/10', glow: 'rgb(253 186 116 / 0.15)' },
  F: { text: 'text-rose-300', chip: 'border-rose-500/45 bg-rose-500/10', glow: 'rgb(253 164 175 / 0.16)' },
};

/** The at-a-glance chips under the hero. `state` is the word beside the glyph, so a chip never relies on colour. */
export type Signal = { key: string; label: string; tone: Tone; detail: string; state: string };

/* ---------------------------------------------------------------------- triage */

/**
 * The numbers the overview shows once reviewers' decisions are applied.
 *
 * With no decisions this is the scan exactly as scanned, so an untriaged scan
 * looks the same as before. With decisions, the lists, severity counts and
 * score are over the *active* findings (see `triage.ts`), and `scanned` keeps
 * the original score for the "as scanned" comparison.
 */
export type Effective = {
  findings: SastFinding[];
  hotspots: SastFinding[];
  counts: Record<SastSeverity, number>;
  score: number;
  grade: SastScan['grade'];
  /** The scanner's own score, before any decision. */
  scanned: { score: number; grade: SastScan['grade'] };
  /** Findings and hotspots that no longer count. */
  excluded: number;
  excludedFindings: number;
  excludedHotspots: number;
  summary: TriageSummary;
};

export function effectiveOf(raw: SastScan): Effective {
  // One list: the scanner's review items sit with the defects (see `mergeReview`), so `hotspots` is always empty here.
  const scan = mergeReview(raw);
  const summary = triageSummary(scan);
  const scanned = { score: raw.score, grade: raw.grade };
  const adj = adjustedScore(scan);
  const findings = activeFindings(scan);
  return {
    findings, hotspots: [], counts: adj.counts,
    // With no decisions the score is the scanner's own, to the digit.
    score: summary.decided === 0 ? raw.score : adj.score,
    grade: summary.decided === 0 ? raw.grade : adj.grade,
    scanned,
    excludedFindings: scan.findings.length - findings.length,
    excludedHotspots: 0,
    excluded: scan.findings.length - findings.length,
    summary,
  };
}

/* --------------------------------------------------------------------- verdict */

export type Verdict = { tone: Tone; headline: string; detail: string };

/**
 * The one sentence under the app name.
 *
 * `buildNote` is appended when the build itself is not a release build
 * (development-signed on iOS, debuggable on Android): a clean result on a
 * debug build says little about what ships.
 */
export function verdictOf(scan: SastScan, buildNote?: string): Verdict {
  // Over the active findings: a false positive or a fixed finding is not
  // something to fix before this ships.
  const eff = effectiveOf(scan);
  const { critical, high, medium } = eff.counts;
  const severe = critical + high;
  const n = eff.findings.length;

  let base: Verdict;
  if (severe > 0) {
    const parts = [critical && `${critical} critical`, high && `${high} high`].filter(Boolean).join(' and ');
    base = {
      tone: 'bad',
      headline: `Fix ${parts} before this ships`,
      detail: `${n} finding${n === 1 ? '' : 's'} to fix.`,
    };
  } else if (medium > 0 || n > 0) {
    base = {
      tone: 'warn',
      headline: 'No critical issues, but there is work to do',
      detail: `${n} finding${n === 1 ? '' : 's'} to fix, none above medium severity.`,
    };
  } else if (eff.excludedFindings > 0) {
    base = {
      tone: 'good',
      headline: 'No open defects after triage',
      detail: `${eff.excludedFindings} defect${eff.excludedFindings === 1 ? ' was' : 's were'} excluded by a reviewer's decision. Triage records a judgement, not a rescan.`,
    };
  } else {
    base = {
      tone: 'good',
      headline: 'No defects found in what could be read',
      detail: scan.artifact.platform === 'ios'
        ? 'A static scan of an IPA cannot see decompiled logic.'
        : 'A static scan reads what the build declares and what decompiles cleanly; it cannot see runtime behaviour.',
    };
  }
  return buildNote ? { ...base, detail: `${base.detail} ${buildNote}` } : base;
}

/* -------------------------------------------------------------------- identity */

/** The app's display name and stable identifier, from whichever platform facts exist. */
export function identityOf(scan: SastScan): { name: string; id: string | undefined } {
  const a = scan.artifact;
  const name = a.ios?.displayName ?? a.android?.label ?? a.packageName ?? a.fileName;
  return { name, id: a.ios?.bundleId ?? a.packageName };
}

/** Deterministic hue from the bundle id, so each app gets a stable monogram. */
export function hueOf(seed: string): number {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) % 360;
  return h;
}

/* ------------------------------------------------------------------- controls */

/** Groups in the order a reviewer reads them: the wire first, then the device, then the code itself. */
export const CONTROL_GROUPS: { key: ControlGroup; label: string }[] = [
  { key: 'network', label: 'Network' },
  { key: 'device-integrity', label: 'Device integrity' },
  { key: 'tamper', label: 'Tamper resistance' },
  { key: 'authentication', label: 'Authentication' },
  { key: 'storage', label: 'Storage' },
  { key: 'platform', label: 'Platform' },
  { key: 'build', label: 'Build' },
];

export const CONTROL_GROUP_LABEL = (g: ControlGroup): string =>
  CONTROL_GROUPS.find((x) => x.key === g)?.label ?? g;

/**
 * How hard a control is to defeat for someone who owns the device. `steps` is
 * how many of the four meter segments are lit; the colour runs from rose (a
 * one-line hook) to emerald (needs real reverse engineering).
 */
export const BYPASS_EFFORT: Record<SecurityControl['bypassEffort'], {
  label: string; steps: number; text: string; chip: string; solid: string;
}> = {
  trivial: { label: 'Trivial', steps: 1, text: 'text-rose-300', solid: 'bg-rose-400', chip: 'border-rose-500/45 bg-rose-500/10 text-rose-200' },
  low: { label: 'Low', steps: 2, text: 'text-amber-300', solid: 'bg-amber-400', chip: 'border-amber-500/45 bg-amber-500/10 text-amber-200' },
  moderate: { label: 'Moderate', steps: 3, text: 'text-sky-300', solid: 'bg-sky-400', chip: 'border-sky-500/40 bg-sky-500/10 text-sky-200' },
  high: { label: 'High', steps: 4, text: 'text-emerald-300', solid: 'bg-emerald-400', chip: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' },
};

/** The controls a scan carries, or undefined for a scan taken before the backend emitted them. */
export function controlsOf(scan: SastScan): SecurityControl[] | undefined {
  return scan.controls && scan.controls.length > 0 ? scan.controls : undefined;
}

/** A detected control that takes little effort to remove: it adds friction, not a boundary. */
export const isWeakControl = (c: SecurityControl): boolean =>
  c.status === 'detected' && (c.bypassEffort === 'trivial' || c.bypassEffort === 'low');

export type ControlsSummary = {
  detected: number;
  notDetected: number;
  notAssessed: number;
  /** Controls the scanner could judge either way: the denominator for "N of M detected". */
  assessed: number;
  weak: SecurityControl[];
};

export function summariseControls(controls: SecurityControl[]): ControlsSummary {
  const detected = controls.filter((c) => c.status === 'detected').length;
  const notDetected = controls.filter((c) => c.status === 'not-detected').length;
  return {
    detected,
    notDetected,
    notAssessed: controls.length - detected - notDetected,
    assessed: detected + notDetected,
    // Easiest to defeat first, so the line leads with the worst.
    weak: controls
      .filter(isWeakControl)
      .sort((x, y) => BYPASS_EFFORT[x.bypassEffort].steps - BYPASS_EFFORT[y.bypassEffort].steps),
  };
}
