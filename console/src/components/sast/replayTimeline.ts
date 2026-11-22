/**
 * A finished scan as the steps of a live one.
 *
 * The live view is fed three kinds of step by the running scan: a file appears, a file is read, a rule
 * matches in a file. A replay needs the same steps for a scan that is over, and the report holds enough to
 * make them: the files the scan kept, and the file each finding sits in. So the replay is the live view
 * played back, not a second picture of it.
 *
 * It is a re-enactment, not a recording: the scan did not keep the order it read files in, so the walk goes
 * folder by folder. The files and the places findings sit are real; the order and the pace are not.
 *
 * No browser or React imports, so it can be exercised from node.
 */
import type { SastFinding } from '../../sastTypes';
import { clusterKey, type MapItem } from './liveModel.ts';

export type FileRef = { path: string; bytes: number };
export type Step = { at: number; item: MapItem };

export type Timeline = {
  /** Every file to draw before the walk starts, flagged ones first so a cap never drops them. */
  files: string[];
  steps: Step[];
  /** Seconds at 1x. */
  duration: number;
  /** Files the tree has, and files drawn. */
  filesTotal: number;
  filesShown: number;
  /** Findings with a file the map can show; the rest have none (they are not part of the walk). */
  placed: number;
  /** Findings, by severity, that the walk will flag: what the severity bars fill toward. */
  totals: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
};

/** The most files the map holds (the live model's own cap). */
export const MAX_FILES = 20000;
/** How much longer the walk stays on a file with a finding than on one without. */
const DWELL = 14;

const keyOf = (path: string) => clusterKey(path, path.startsWith('sources/') ? 5 : 3);

export function buildTimeline(files: FileRef[], findings: SastFinding[]): Timeline {
  // The first file of each finding the tree (or the finding itself) can name. A finding whose files are
  // all unknown to the tree still gets a place: the file is added as its own entry.
  const flaggedAt = new Map<string, number[]>();
  findings.forEach((f, index) => {
    const file = f.locations[0]?.file;
    if (!file) return;
    flaggedAt.set(file, [...(flaggedAt.get(file) ?? []), index]);
  });

  const inTree = new Set(files.map((f) => f.path));
  const flagged = [...flaggedAt.keys()];
  const rest = files.filter((f) => !flaggedAt.has(f.path)).map((f) => f.path);

  // Thin the unflagged files evenly when the map cannot hold them all.
  const room = Math.max(0, MAX_FILES - flagged.length);
  const stride = rest.length > room ? rest.length / room : 1;
  const kept: string[] = [];
  for (let i = 0; i < rest.length && kept.length < room; i += stride) kept.push(rest[Math.floor(i)]);

  // Folder by folder, files in path order.
  const walk = [...flagged, ...kept].sort((a, b) => keyOf(a).localeCompare(keyOf(b)) || a.localeCompare(b));

  const weights = walk.map((p) => (flaggedAt.has(p) ? DWELL : 1));
  const sum = weights.reduce((a, b) => a + b, 0) || 1;
  const duration = Math.min(60, Math.max(12, 8 + Math.sqrt(walk.length) * 0.35));

  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const steps: Step[] = [];
  let elapsed = 0;
  walk.forEach((path, k) => {
    const at = (elapsed / sum) * duration;
    steps.push({ at, item: { k: 'visit', path } });
    for (const ref of flaggedAt.get(path) ?? []) {
      const f = findings[ref];
      totals[f.severity] += 1;
      steps.push({ at: at + 0.001, item: { k: 'hit', file: path, title: f.title, severity: f.severity, ref } });
    }
    elapsed += weights[k];
  });

  return {
    files: [...flagged, ...kept],
    steps,
    duration,
    filesTotal: files.length + flagged.filter((p) => !inTree.has(p)).length,
    filesShown: flagged.length + kept.length,
    placed: totals.critical + totals.high + totals.medium + totals.low + totals.info,
    totals,
  };
}

/** Index of the first step that starts after `t`: everything before it has happened by then. */
export function stepsDoneBy(steps: Step[], t: number): number {
  let lo = 0;
  let hi = steps.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (steps[mid].at <= t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
