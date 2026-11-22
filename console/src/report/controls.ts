/**
 * What the remediation roadmap needs from the scan's security controls: which missing protections are
 * worth adding, and how hard each is to bypass.
 *
 * The report no longer carries a section of its own for controls; the console's Controls tab shows them
 * in full. Detection is by reference in the binary or code, so "present" is not "strong": the effort
 * meter, not the status, carries strength, and "not assessed" is never counted as a gap.
 */
import type { SecurityControl } from '../sastTypes';
import { GOOD, GOOD_FILL, SEV, esc, meter } from './kit';

type Effort = SecurityControl['bypassEffort'];

const GROUP_LABEL: Record<string, string> = {
  network: 'Network',
  'device-integrity': 'Device integrity',
  tamper: 'Tamper resistance',
  authentication: 'Authentication',
  storage: 'Storage',
  platform: 'Platform',
  build: 'Build',
};

/** Level on the four-step meter, the word shown, and the colours (fill for the bars, text for type). */
const EFFORT: Record<Effort, { level: number; label: string; fill: string; text: string }> = {
  trivial: { level: 1, label: 'Trivial', fill: SEV.critical.fill, text: SEV.critical.text },
  low: { level: 2, label: 'Low', fill: SEV.high.fill, text: SEV.high.text },
  moderate: { level: 3, label: 'Moderate', fill: SEV.medium.fill, text: SEV.medium.text },
  high: { level: 4, label: 'High', fill: GOOD_FILL, text: GOOD },
};

function effortOf(c: SecurityControl) {
  return EFFORT[c.bypassEffort] ?? EFFORT.moderate;
}

export function groupName(g: string): string {
  if (GROUP_LABEL[g]) return GROUP_LABEL[g];
  const s = String(g).replace(/[-_]+/g, ' ').trim();
  return s ? s[0].toUpperCase() + s.slice(1) : 'Other';
}

/** The four-step bypass-effort meter with its word. `dim` greys it for a control that is not present. */
export function effortMeterHtml(c: SecurityControl, dim = false): string {
  const e = effortOf(c);
  const ink = dim ? '#8a929b' : e.text;
  const fill = dim ? '#8a929b' : e.fill;
  return `<span class="eff" style="color:${ink}">${meter(e.level, fill, 4)}<b>${esc(e.label)}</b></span>`;
}

/**
 * Controls the scan looked for and did not find, worth adding, highest value
 * first: those that would take real effort to bypass once present (high, then
 * moderate). Controls that are trivial to bypass are friction, not a priority,
 * and "not assessed" is never a gap.
 */
export function controlsToAdd(scan: { controls?: SecurityControl[] }): SecurityControl[] {
  return (scan.controls ?? [])
    .map((c, i) => ({ c, i }))
    .filter(({ c }) => c.status === 'not-detected' && (c.bypassEffort === 'high' || c.bypassEffort === 'moderate'))
    .sort((a, b) => effortOf(b.c).level - effortOf(a.c).level || a.i - b.i)
    .map((x) => x.c);
}

/** Not-detected controls that are cheap to bypass even once added: counted, not recommended first. */
export function lowValueMissing(scan: { controls?: SecurityControl[] }): number {
  return (scan.controls ?? []).filter((c) => c.status === 'not-detected' && !(c.bypassEffort === 'high' || c.bypassEffort === 'moderate')).length;
}
