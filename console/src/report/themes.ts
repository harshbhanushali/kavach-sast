/**
 * Cross-cutting views of the findings: which OWASP Mobile Top 10 category each
 * falls under, where it lives, and the risk themes the executive summary and
 * the overall assessment are written from.
 *
 * Everything is deterministic text built from the scan: no model writes any of
 * it, so the same scan always yields the same words.
 */
import { OWASP_MOBILE_2024 } from '../sastTypes';
import type { SastFinding, SastLocation } from '../sastTypes';
import { SEVERITY_ORDER, esc, sevRank } from './kit';
import type { SevKey } from './kit';

/** A finding with its position in the ordered list (the number on its page). */
export type Numbered = { f: SastFinding; n: number };

/* ----------------------------------------------------------------------------
 * OWASP Mobile Top 10 (2024)
 * ------------------------------------------------------------------------- */

/** Short names, for table cells where the full name would wrap to three lines. */
export const OWASP_SHORT: Record<string, string> = {
  M1: 'Credential Usage',
  M2: 'Supply Chain',
  M3: 'Authn / Authz',
  M4: 'Input / Output Validation',
  M5: 'Insecure Communication',
  M6: 'Privacy Controls',
  M7: 'Binary Protections',
  M8: 'Security Misconfiguration',
  M9: 'Insecure Data Storage',
  M10: 'Cryptography',
};

/** One plain-language sentence of business risk per category. */
export const OWASP_RISK: Record<string, string> = {
  M1: 'Credentials or API keys shipped inside the app can be extracted by anyone who downloads it and used against your accounts and services.',
  M2: 'Code or build components that were not vetted can bring third-party vulnerabilities, or tampering, into the product.',
  M3: 'Weak or missing checks on who the user is or what they may do can let someone act as another user or reach functions they should not.',
  M4: 'Input the app accepts is not checked well enough, so crafted links, web content or files can make it misbehave or hand over data.',
  M5: 'Traffic can be read or modified by anyone on the same network, exposing user data and sessions.',
  M6: 'Personal data may be collected, kept or shared beyond what users expect, which carries regulatory and reputational cost.',
  M7: 'The app is easier to reverse-engineer, tamper with or repackage, which makes every other weakness cheaper to find and exploit.',
  M8: 'Insecure settings or defaults widen what an attacker, or another app on the device, can reach.',
  M9: 'Data stored on the device can be read by other apps, by backups or by anyone holding the phone.',
  M10: 'Weak or misused cryptography means protected data and tokens can be guessed, forged or decrypted.',
};

const OTHER_RISK = 'Findings the scanner did not map to an OWASP category. Read them individually.';

/** `M5` from `M5`, `m5`, `M5:2024`; the raw text when it has no recognisable code; '' when absent. */
export function owaspCode(raw: string | undefined): string {
  const t = (raw ?? '').trim();
  if (!t) return '';
  const m = /\bM(\d{1,2})\b/i.exec(t);
  return m ? `M${Number(m[1])}` : t;
}

export function owaspName(code: string): string | undefined {
  return OWASP_MOBILE_2024[code];
}

/** `M5 · Insecure Communication` (full name), or just the code when it is not a known category. */
export function owaspLabel(raw: string | undefined, short = false): string {
  const code = owaspCode(raw);
  if (!code) return '';
  const name = short ? (OWASP_SHORT[code] ?? owaspName(code)) : owaspName(code);
  return name ? `${code} · ${name}` : code;
}

/** Table cell: bold code over the short name, or an em dash. */
export function owaspCell(raw: string | undefined): string {
  const code = owaspCode(raw);
  if (!code) return '<span class="na">—</span>';
  const name = OWASP_SHORT[code] ?? owaspName(code);
  return `<span class="ow-c">${esc(code)}</span>${name ? `<span class="ow-n">${esc(name)}</span>` : ''}`;
}

/* ----------------------------------------------------------------------------
 * Affected component
 * ------------------------------------------------------------------------- */

/** `Lcom/foo/Bar$Baz;` -> `com.foo.Bar$Baz` */
function dexToDotted(cls: string): string {
  return cls.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
}

/** The component a single location belongs to: a class, a manifest component or a file. */
function locationKey(l: SastLocation): string {
  if (l.className) return dexToDotted(l.className);
  const file = l.file ?? '';
  if (/(^|\/)AndroidManifest\.xml$/i.test(file)) {
    const m = /android:name\s*=\s*"([^"]+)"/.exec(l.excerpt ?? '');
    return m ? m[1] : 'AndroidManifest.xml';
  }
  const strings = /^_strings\/(.+)\.strings\.txt$/.exec(file);
  if (strings) return `${strings[1]} (binary strings)`;
  return file || 'whole artifact';
}

/**
 * Where a finding lives, in a few words: the dominant location (most hits;
 * the first one wins a tie) as a dex class, a file path or a manifest
 * component name. When several distinct places are involved it reads
 * `<dominant> +N more`.
 */
export function affectedComponent(f: SastFinding): string {
  const counts = new Map<string, number>();
  for (const l of f.locations ?? []) {
    const k = locationKey(l);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  if (counts.size === 0) return 'Whole application';
  let best = '';
  let bestN = -1;
  for (const [k, n] of counts) {
    if (n > bestN) {
      best = k;
      bestN = n;
    }
  }
  const more = counts.size - 1;
  return more > 0 ? `${best} +${more} more` : best;
}

/** HTML for a component string with soft break points after `/` and `.`, so long paths wrap cleanly. */
export function componentHtml(text: string): string {
  return esc(text).replace(/([/.])(?=[^\s])/g, '$1<wbr>');
}

/* ----------------------------------------------------------------------------
 * Sentences
 * ------------------------------------------------------------------------- */

const ABBREV = /(?:e\.g|i\.e|vs|etc|approx|cf|no)$/i;

/** The first sentence of a paragraph, for one-line summaries. Full text always lives on the finding page. */
export function firstSentence(text: string, max = 190): string {
  const t = (text ?? '').replace(/\s+/g, ' ').trim();
  if (!t) return '';
  let inCode = false;
  let end = t.length;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '`') inCode = !inCode;
    // A sentence ends at a terminator followed by a space and a capital, digit, quote or backtick (or the end),
    // so "pass ? placeholders" and "e.g. foo" do not cut a sentence short.
    if (!inCode && (c === '.' || c === '!' || c === '?') && (i === t.length - 1 || (/\s/.test(t[i + 1]) && /[A-Z0-9`"'\u201c(<]/.test(t[i + 2] ?? 'A')))) {
      if (c === '.' && ABBREV.test(t.slice(0, i))) continue;
      end = i + 1;
      break;
    }
  }
  const s = t.slice(0, end);
  if (s.length <= max) return s;
  const cut = s.slice(0, max - 1);
  const sp = cut.lastIndexOf(' ');
  // Never leave an unbalanced backtick behind.
  let out = (sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:]+$/, '');
  if ((out.match(/`/g) ?? []).length % 2 === 1) out = out.replace(/`[^`]*$/, '').trim();
  return `${out}…`;
}

/* ----------------------------------------------------------------------------
 * Risk themes
 * ------------------------------------------------------------------------- */

export type Theme = {
  /** `M5`, or `Other` for findings with no OWASP category. */
  code: string;
  name: string;
  risk: string;
  worst: SevKey;
  items: Numbered[];
  /** Total occurrences across the theme's findings. */
  hits: number;
};

const codeNum = (c: string) => (/^M(\d+)$/.test(c) ? Number(c.slice(1)) : 99);

/**
 * Findings grouped by OWASP category, strongest first: worst severity, then
 * how many findings, then how many hits, then the category number. Findings with
 * no category form a final "Other" theme, whatever its weight, so the named
 * categories always read first.
 */
export function riskThemes(items: Numbered[]): Theme[] {
  const byCode = new Map<string, Numbered[]>();
  for (const it of items) {
    const code = owaspCode(it.f.owasp) || 'Other';
    byCode.set(code, [...(byCode.get(code) ?? []), it]);
  }
  const themes: Theme[] = [...byCode.entries()].map(([code, list]) => {
    const known = code !== 'Other' ? owaspName(code) : undefined;
    const worst = [...list].sort((a, b) => sevRank(a.f.severity) - sevRank(b.f.severity))[0].f.severity as SevKey;
    return {
      code,
      name: code === 'Other' ? 'Other findings' : (known ?? 'Uncategorised'),
      risk: code === 'Other' ? OTHER_RISK : (OWASP_RISK[code] ?? OTHER_RISK),
      worst: SEVERITY_ORDER.includes(worst) ? worst : 'info',
      items: list,
      hits: list.reduce((n, x) => n + Math.max(x.f.occurrences, x.f.locations.length), 0),
    };
  });
  return themes.sort((a, b) => {
    if ((a.code === 'Other') !== (b.code === 'Other')) return a.code === 'Other' ? 1 : -1;
    return sevRank(a.worst) - sevRank(b.worst) || b.items.length - a.items.length || b.hits - a.hits || codeNum(a.code) - codeNum(b.code);
  });
}

export function themeTitle(t: Theme): string {
  return t.code === 'Other' ? t.name : t.name === 'Uncategorised' ? t.code : `${t.code} · ${t.name}`;
}

/** "F03" */
export const fLabel = (n: number) => `F${String(n).padStart(2, '0')}`;

/** A finding reference as a link; the document-level pass turns it into plain text where the target page does not exist. */
export function fref(n: number): string {
  return `<a class="fref" href="#finding-${n}">${fLabel(n)}</a>`;
}
