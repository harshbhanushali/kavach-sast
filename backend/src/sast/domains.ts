/**
 * Every host the artifact mentions, in one table.
 *
 * The findings answer "what is wrong"; this answers "who does this app talk
 * to", which is a different question and often the first one a reviewer asks.
 * An app that reaches four hosts is a different proposition from one that
 * reaches forty, and neither fact shows up in a finding list.
 *
 * Built from the URLs reconnaissance already extracts, grouped by host, and
 * classified on two axes that decide what a reader does next:
 *
 *   - **cleartext** — is any reference to this host plain HTTP?
 *   - **environment** — does the name say development, QA, staging or demo?
 *     A production build carrying those is worth a conversation; the hosts
 *     themselves are usually softer targets than production.
 *
 * Nothing here is resolved or contacted. Every row comes from reading the
 * artifact, which is the same promise the rest of the scan makes.
 */
import type { Endpoint } from './recon.ts';

export type DomainEnvironment = 'production' | 'non-production' | 'local' | 'unknown';

export type DomainRow = {
  host: string;
  /** Schemes seen for this host across the artifact. */
  schemes: string[];
  cleartext: boolean;
  environment: DomainEnvironment;
  /** Distinct URLs on this host, capped for display. */
  urls: string[];
  urlCount: number;
  /** Files it appears in, capped. */
  files: string[];
  fileCount: number;
};

const NON_PRODUCTION =
  /\b(dev|development|qa|uat|staging|stage|stg|test|sandbox|demo|preprod|pre-prod|nonprod|mock)\b/i;

const LOCAL = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2|10\.0\.3\.2|\[::1\])$/i;

/**
 * Hosts that are part of the platform rather than the app's own traffic.
 *
 * Reporting `schemas.android.com` as a domain the app contacts would be wrong:
 * it is an XML namespace, and it is never fetched. Keeping them out is what
 * makes the remaining list short enough to read.
 */
const NOT_TRAFFIC =
  /^(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|xmlpull\.org|java\.sun\.com|www\.android\.com|.*\.apache\.org|xml\.org|purl\.org|json-schema\.org)$/i;

function environmentOf(host: string): DomainEnvironment {
  if (LOCAL.test(host)) return 'local';
  if (NON_PRODUCTION.test(host)) return 'non-production';
  // Deliberately not "production": a host with no environment marker in its
  // name is most likely production, but saying so would be a guess dressed as
  // a fact. `unknown` is the honest label and sorts alongside production.
  return 'unknown';
}

/** Group extracted URLs into one row per host. */
export function inventoryDomains(endpoints: Endpoint[]): DomainRow[] {
  const byHost = new Map<
    string,
    { schemes: Set<string>; cleartext: boolean; urls: Set<string>; files: Set<string> }
  >();

  for (const endpoint of endpoints) {
    const host = endpoint.host.toLowerCase().replace(/:\d+$/, '');
    if (!host || NOT_TRAFFIC.test(host)) continue;

    let row = byHost.get(host);
    if (!row) {
      row = { schemes: new Set(), cleartext: false, urls: new Set(), files: new Set() };
      byHost.set(host, row);
    }
    row.schemes.add(endpoint.cleartext ? 'http' : 'https');
    // Cleartext is sticky: one plain-HTTP reference is enough to matter, even
    // if the same host is also reached over TLS elsewhere.
    if (endpoint.cleartext) row.cleartext = true;
    row.urls.add(endpoint.url);
    for (const file of endpoint.files) row.files.add(file);
  }

  return [...byHost.entries()]
    .map(([host, row]) => ({
      host,
      schemes: [...row.schemes].sort(),
      cleartext: row.cleartext,
      environment: environmentOf(host),
      urls: [...row.urls].sort().slice(0, 12),
      urlCount: row.urls.size,
      files: [...row.files].sort().slice(0, 8),
      fileCount: row.files.size,
    }))
    // Worst first: cleartext, then non-production, then the rest alphabetically.
    .sort((a, b) => {
      const rank = (d: DomainRow) =>
        d.cleartext ? 0 : d.environment === 'local' ? 1 : d.environment === 'non-production' ? 2 : 3;
      return rank(a) - rank(b) || a.host.localeCompare(b.host);
    });
}
