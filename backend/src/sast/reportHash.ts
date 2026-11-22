import { createHash } from 'node:crypto';
import type { SastFinding } from './types.ts';

/**
 * A stable digest over the verdict.
 *
 * The artifact hash is the first input, so the same findings on a different
 * binary produce a different report hash. Findings are sorted and reduced to
 * their identifying fields so that re-running a scan on the same file produces
 * the same hash — a digest that changed with the timestamp would be useless for
 * comparing two releases.
 */
export function hashReport(artifactSha256: string, findings: SastFinding[], hotspots: SastFinding[], score: number): string {
  const canonical = [
    artifactSha256,
    `score=${score}`,
    ...[...findings, ...hotspots]
      .map((f) => `${f.ruleId}|${f.severity}|${f.occurrences}`)
      .sort(),
  ].join('\n');
  return createHash('sha256').update(canonical).digest('hex');
}
