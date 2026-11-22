/**
 * Reconnaissance: what the artifact reveals about where it talks and who it
 * reports to.
 *
 * Reconnaissance earns its place: a list of
 * every endpoint an app contacts is often the single most useful page of a
 * report, because it answers "where does our data actually go" without running
 * the app.
 *
 * Nothing here contacts any of the hosts it finds. Resolving them, checking
 * reputation or geolocating them would send a customer's endpoint list to a
 * third party, which is not a decision a scanner should make on its own.
 */
import { readText } from './fileCache.ts';
import { TRACKER_SIGNATURES } from './trackerData.ts';
import type { WalkedFile } from './scanner.ts';

/**
 * Hosts that belong to the toolchain rather than to the app.
 *
 * XML namespaces and documentation URLs only: they are never fetched and
 * listing them would bury the app's own traffic.
 *
 * Loopback and the emulator host are deliberately *not* excluded any more.
 * They are not traffic that leaves the device, but they are in the artifact,
 * and a shipped `http://10.0.2.2:3000` is direct evidence that a developer
 * build's configuration reached production. The domain inventory labels them
 * `local` rather than hiding them.
 */
const INFRASTRUCTURE =
  /^(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|xmlpull\.org|java\.sun\.com|www\.apache\.org|apache\.org|goo\.gl\/[a-z]|developer\.android\.com|android\.googlesource\.com|json-schema\.org|www\.example\.com|example\.com)$/i;

const URL_RE = /\bhttps?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{4,180}/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,63}\.[A-Za-z]{2,12}\b/g;

/** Files worth reading for endpoints. */
const SCANNABLE = /\.(smali|xml|json|js|html?|txt|properties|kt|java|plist|strings|swift|m|h)$/i;

export type Endpoint = { url: string; host: string; cleartext: boolean; files: string[] };
export type TrackerHit = { name: string; category: string; signature: string };

export type ReconReport = {
  endpoints: Endpoint[];
  hosts: string[];
  emails: { address: string; files: string[] }[];
  trackers: TrackerHit[];
  /** Files that look like bundled key material. */
  keyFiles: string[];
};

function hostOf(url: string): string {
  const match = url.match(/^https?:\/\/([^/?#:]+)/i);
  return match ? match[1].toLowerCase() : '';
}

/**
 * Detects trackers by package path.
 *
 * Exodus publishes several signatures per tracker separated by `|`, and they are
 * written in dotted package form; a decompiled tree uses slashes, so both forms
 * are matched.
 */
export function detectTrackers(files: WalkedFile[]): TrackerHit[] {
  const paths = files.map((f) => f.relative).join('\n');
  const slashed = paths.replace(/\//g, '.');
  const hits: TrackerHit[] = [];

  for (const tracker of TRACKER_SIGNATURES) {
    const alternatives = tracker.signature.split('|').map((s) => s.trim()).filter(Boolean);
    const matched = alternatives.find((alt) => slashed.includes(alt));
    if (matched) hits.push({ name: tracker.name, category: tracker.category, signature: matched });
  }

  // A tracker can match on more than one alternative; keep one row per name.
  const byName = new Map<string, TrackerHit>();
  for (const hit of hits) if (!byName.has(hit.name)) byName.set(hit.name, hit);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function runRecon(root: string, files: WalkedFile[]): ReconReport {
  const endpoints = new Map<string, Endpoint>();
  const emails = new Map<string, Set<string>>();
  const keyFiles: string[] = [];

  for (const file of files) {
    if (/\.(pem|cer|crt|der|key|p12|pfx|jks|keystore|bks)$/i.test(file.relative)) {
      keyFiles.push(file.relative);
    }
    if (!SCANNABLE.test(file.relative) || file.size > 3 * 1024 * 1024) continue;

    let content: string;
    try {
      content = readText(file.absolute);
    } catch {
      continue;
    }

    for (const raw of content.match(URL_RE) ?? []) {
      // Trailing punctuation is almost always the surrounding syntax, not URL.
      const url = raw.replace(/[).,;'"\]}>]+$/, '');
      const host = hostOf(url);
      if (!host || INFRASTRUCTURE.test(host)) continue;
      // A host with no dot is a placeholder or a format string.
      if (!host.includes('.')) continue;

      const existing = endpoints.get(url);
      if (existing) {
        if (existing.files.length < 5 && !existing.files.includes(file.relative)) {
          existing.files.push(file.relative);
        }
      } else if (endpoints.size < 400) {
        endpoints.set(url, {
          url,
          host,
          cleartext: url.toLowerCase().startsWith('http://'),
          files: [file.relative],
        });
      }
    }

    for (const address of content.match(EMAIL_RE) ?? []) {
      const lower = address.toLowerCase();
      // Version strings and resource ids produce a lot of @-shaped noise.
      if (/^[0-9.]+@/.test(lower) || lower.endsWith('.png') || lower.endsWith('.xml')) continue;
      const set = emails.get(lower) ?? new Set<string>();
      if (set.size < 5) set.add(file.relative);
      emails.set(lower, set);
    }
  }

  const endpointList = [...endpoints.values()].sort(
    (a, b) => Number(b.cleartext) - Number(a.cleartext) || a.host.localeCompare(b.host),
  );

  return {
    endpoints: endpointList,
    hosts: [...new Set(endpointList.map((e) => e.host))].sort(),
    emails: [...emails.entries()]
      .slice(0, 100)
      .map(([address, files]) => ({ address, files: [...files] }))
      .sort((a, b) => a.address.localeCompare(b.address)),
    trackers: detectTrackers(files),
    keyFiles: keyFiles.slice(0, 50),
  };
}
