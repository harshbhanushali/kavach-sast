/**
 * SARIF 2.1.0 export.
 *
 * The PDF is for people; SARIF is for the tools around them — GitHub code
 * scanning, Azure DevOps, IDE viewers, a CI gate. One result per location, so
 * each lands on its own line in those tools. Defects and hotspots are
 * exported; the "done right" list is not a finding and stays out.
 *
 * Triage travels with the results. A false positive or a live accepted risk
 * becomes a SARIF suppression with the reviewer's reason, so a consumer that
 * honours suppressions hides exactly what the report hides. Confirmed and
 * fixed decisions are not suppressions; they ride along in `properties`.
 */
import { createHash } from 'node:crypto';
import type { TriageEntry } from './triage.ts';
import type { SastFinding, SastScan, SastSeverity } from './types.ts';

const LEVEL: Record<SastSeverity, 'error' | 'warning' | 'note'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
};

/** GitHub's `security-severity` is a CVSS-like 0-10 string; these sit in its bands. */
const SECURITY_SEVERITY: Record<SastSeverity, string> = {
  critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.5',
};

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

/** A decision that hides the finding: a false positive, or an accepted risk that has not lapsed. */
function suppresses(entry: TriageEntry | undefined, now: Date): entry is TriageEntry {
  if (!entry) return false;
  if (entry.status === 'false_positive') return true;
  return entry.status === 'accepted_risk' && (!entry.expiresAt || entry.expiresAt >= now.toISOString().slice(0, 10));
}

function levelOf(f: SastFinding): 'error' | 'warning' | 'note' {
  return f.kind === 'hotspot' ? 'note' : LEVEL[f.severity];
}

export function toSarif(scan: SastScan, triage: Record<string, TriageEntry> = {}, now = new Date()) {
  const reported = [...scan.findings, ...scan.hotspots];

  const rules = reported.map((f) => ({
    id: f.ruleId,
    name: f.title,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    help: { text: f.remediation },
    defaultConfiguration: { level: levelOf(f) },
    properties: {
      tags: ['security', f.category, ...[f.masvs, f.cwe, f.owasp].filter((t): t is string => Boolean(t))],
      'security-severity': SECURITY_SEVERITY[f.severity],
    },
  }));

  const results = reported.flatMap((f) => {
    const entry = triage[f.ruleId];
    // A finding with no location still has to be reported; point at the artifact itself.
    const locations = f.locations.length > 0 ? f.locations : [{ file: scan.artifact.fileName }];
    return locations.map((loc, i) => ({
      ruleId: f.ruleId,
      level: levelOf(f),
      message: {
        text: f.occurrences > 1 ? `${f.description} (${f.occurrences} occurrences in total)` : f.description,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: loc.file },
            ...('line' in loc && loc.line
              ? {
                  region: {
                    startLine: loc.line,
                    ...(loc.excerpt ? { snippet: { text: loc.excerpt } } : {}),
                  },
                }
              : {}),
          },
        },
      ],
      partialFingerprints: { 'kavachFinding/v1': sha(`${f.ruleId}|${loc.file}|${i}`) },
      ...(suppresses(entry, now)
        ? { suppressions: [{ kind: 'external', status: 'accepted', justification: entry.reason }] }
        : {}),
      properties: {
        severity: f.severity,
        kind: f.kind ?? 'defect',
        ...(entry ? { triage: { status: entry.status, reason: entry.reason, by: entry.updatedBy, at: entry.updatedAt } } : {}),
      },
    }));
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Kavach SAST', rules } },
        results,
        properties: {
          scanId: scan.scanId,
          reportHash: scan.reportHash,
          score: scan.score,
          grade: scan.grade,
          platform: scan.artifact.platform,
          fileName: scan.artifact.fileName,
          sha256: scan.artifact.sha256,
          ...(scan.artifact.packageName ? { packageName: scan.artifact.packageName } : {}),
        },
      },
    ],
  };
}
