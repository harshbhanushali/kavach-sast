/**
 * The report's rules, in one place, so the pages that state them never drift:
 * the score arithmetic, what each severity means and the timeline each one
 * carries. The score page, the roadmap, the methodology page and the
 * "how to read" page all quote from here.
 */
import type { SevKey } from './kit';

/**
 * How the score is worked out (model 2). Mirrors `scoreOf` in backend/src/sast/types.ts, which explains why
 * it is built this way; a test keeps the two in step. Duplicated because the console builds standalone.
 */
export const SCORE_MODEL = 2;
export const SCORE_LOSS: Record<string, { weight: number; cap: number }> = {
  critical: { weight: 25, cap: 50 },
  high: { weight: 5, cap: 25 },
  medium: { weight: 1.2, cap: 12 },
  low: { weight: 0.4, cap: 3 },
  info: { weight: 0, cap: 0 },
};
export const LIBRARY_SHARE = 0.25;
export const SCORE_CEILING = { critical: 74, high: 89 };
export const HOTSPOT_PENALTY_CAP = 4;
export const SECURE_CREDIT_CAP = 6;

/** Highest score each severity of defect lets an app keep, in the words the report uses. */
export const SCORE_SUMMARY =
  'Each severity costs points with diminishing returns up to a ceiling of its own (critical up to ' +
  `${SCORE_LOSS.critical.cap}, high ${SCORE_LOSS.high.cap}, medium ${SCORE_LOSS.medium.cap}, low ${SCORE_LOSS.low.cap}); ` +
  `a finding in a bundled library counts a quarter as much as one in the app's own code. A critical defect in ` +
  `the app's own code caps the score at ${SCORE_CEILING.critical} and a high one at ${SCORE_CEILING.high}.`;

/** What each severity means, in the words used on the "how to read" page. */
export const SEVERITY_MEANING: Record<SevKey, string> = {
  critical:
    'Works for anyone who holds the app, with nothing else needed, and the damage is severe. In practice a leaked credential: a key or token that already opens a cloud account, a payment account or a code repository. A build with one should not ship.',
  high:
    'A serious weakness an attacker can reach with one realistic step: a network position, another app on the device, or input they control. Also a leaked key whose reach is narrower than an account takeover.',
  medium:
    'A real weakness that raises risk, a setting that permits one, or a hardening gap. It becomes serious only in combination with another flaw, or with the device or the network in hand.',
  low: 'A hardening gap or a weakness with limited reach or impact. Worth closing; unlikely to be the way in on its own.',
  info: 'An observation with no direct risk, recorded so a reviewer knows it was seen.',
};

/** The remediation timeline, one bucket per row of the roadmap. */
export type Bucket = { key: 'critical' | 'high' | 'medium' | 'low'; label: string; sevs: SevKey[]; when: string; short: string };

export const BUCKETS: Bucket[] = [
  { key: 'critical', label: 'Critical', sevs: ['critical'], when: 'Fix before release (immediately)', short: 'Immediately' },
  { key: 'high', label: 'High', sevs: ['high'], when: 'This sprint', short: 'This sprint' },
  { key: 'medium', label: 'Medium', sevs: ['medium'], when: 'Next release', short: 'Next release' },
  { key: 'low', label: 'Low and info', sevs: ['low', 'info'], when: 'Backlog', short: 'Backlog' },
];

/** The timeline a severity falls under. */
export function timelineOf(s: SevKey): string {
  const b = BUCKETS.find((x) => x.sevs.includes(s));
  return b ? b.when : 'Backlog';
}
