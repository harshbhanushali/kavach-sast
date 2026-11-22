/**
 * OWASP Mobile Top 10 (2024) category for a finding.
 *
 * Findings already carry a CWE and a MASVS control. The Top 10 is the list most
 * readers know and the one other reports lead with, so each finding is mapped
 * onto it. The mapping is derived, not authoritative: it follows the MASVS area
 * first, then the weakness class, then the category the rule lives in, and a
 * finding with no usable signal gets no category rather than a guessed one.
 */
import type { SastFinding } from './types.ts';

export const OWASP_MOBILE_2024: Record<string, string> = {
  M1: 'Improper Credential Usage',
  M2: 'Inadequate Supply Chain Security',
  M3: 'Insecure Authentication/Authorization',
  M4: 'Insufficient Input/Output Validation',
  M5: 'Insecure Communication',
  M6: 'Inadequate Privacy Controls',
  M7: 'Insufficient Binary Protections',
  M8: 'Security Misconfiguration',
  M9: 'Insecure Data Storage',
  M10: 'Insufficient Cryptography',
};

/** Weakness classes that are credential problems whatever the rule's MASVS area says. */
const CREDENTIAL_CWES = new Set([798, 259, 256, 321, 522, 257]);
/** Weakness classes that are input/output validation problems. */
const INPUT_CWES = new Set([20, 22, 78, 79, 88, 89, 94, 95, 117, 502, 601, 749, 939, 918]);

export function owaspMobileFor(f: Pick<SastFinding, 'ruleId' | 'category' | 'masvs' | 'cwe'>): string | undefined {
  const cwe = Number((f.cwe ?? '').replace(/\D/g, '')) || 0;
  const masvs = f.masvs ?? '';
  const rule = f.ruleId;

  if (f.category === 'secrets' || CREDENTIAL_CWES.has(cwe)) return 'M1';
  if (rule === 'recon.trackers') return 'M6';
  if (f.category === 'dependencies' || rule.startsWith('dependency.')) return 'M2';

  if (masvs.startsWith('MASVS-NETWORK')) return 'M5';
  if (masvs.startsWith('MASVS-CRYPTO')) return 'M10';
  if (masvs.startsWith('MASVS-STORAGE')) return 'M9';
  if (masvs.startsWith('MASVS-PRIVACY')) return 'M6';
  if (masvs.startsWith('MASVS-RESILIENCE')) return 'M7';
  if (masvs.startsWith('MASVS-AUTH')) return 'M3';

  if (/exported|permission|provider_grant|normal_permission/.test(rule)) return 'M3';
  if (INPUT_CWES.has(cwe) || /webview|deeplink|url_scheme|sql/.test(rule)) return 'M4';

  if (masvs.startsWith('MASVS-CODE')) {
    const n = masvs.match(/MASVS-CODE-(\d)/)?.[1];
    if (n === '3') return 'M2';
    if (n === '4') return 'M4';
    return 'M8';
  }
  if (masvs.startsWith('MASVS-PLATFORM')) return 'M8';

  const byCategory: Record<string, string> = {
    network: 'M5', crypto: 'M10', storage: 'M9', binary: 'M7', signing: 'M7', manifest: 'M8', code: 'M4',
  };
  return byCategory[f.category];
}
