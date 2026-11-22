/**
 * "About this report": what the severities mean, how the score is worked out,
 * which standards the references come from, and (in the executive edition,
 * which has no scope page of its own) what was and was not examined. One page:
 * a reader who wants more finds it in the finding itself.
 *
 * The severity timelines and the score arithmetic are quoted from `policy.ts`,
 * the same constants the roadmap and the score page use.
 */
import { OWASP_MOBILE_2024 } from '../sastTypes';
import type { SastScan } from '../sastTypes';
import type { Edition } from './edition';
import { SEV, SEVERITY_ORDER, esc, h3, meter, opener } from './kit';
import { scopeLists } from './method';
import { HOTSPOT_PENALTY_CAP, SCORE_SUMMARY, SECURE_CREDIT_CAP, SEVERITY_MEANING, timelineOf } from './policy';

type Ref = { num: string; href: string } | undefined;

const link = (r: Ref, text: string) => (r ? `<a class="lnk" href="${r.href}">${esc(text)} (section ${esc(r.num)})</a>` : esc(text));

function severityTable(): string {
  return `<table class="tbl hr-sev"><thead><tr><th style="width:27mm">Severity</th><th>Meaning</th><th style="width:34mm">Timeline</th></tr></thead><tbody>${SEVERITY_ORDER.map(
    (s) => `<tr><td><span class="chip sevchip" style="color:${SEV[s].text};border-color:${SEV[s].fill};background:${SEV[s].tint}"><span class="g">${SEV[s].glyph}</span>${SEV[s].label}${meter(SEV[s].level, SEV[s].fill)}</span></td>
      <td class="small">${esc(SEVERITY_MEANING[s])}</td><td class="small"><strong>${esc(timelineOf(s))}</strong></td></tr>`,
  ).join('')}</tbody></table>`;
}

export function howToReadPage(
  scan: SastScan,
  num: string,
  edition: Edition,
  refs: { verify?: Ref; scope?: Ref },
): string {
  const full = edition === 'full';
  const lists = scopeLists(scan);
  // Only the categories this report actually cites: a table of all ten, most of them empty, is noise.
  const used = new Set([...scan.findings].map((f) => f.owasp).filter((c): c is string => !!c));
  const owaspRows = Object.entries(OWASP_MOBILE_2024)
    .filter(([c]) => used.has(c))
    .map(([c, n]) => `<b>${esc(c)}</b> ${esc(n)}`)
    .join(' &nbsp;·&nbsp; ');

  return `
  <section class="pg newpage" id="howto">
    ${opener('howto-top', num, 'About this report', 'What the severities mean, how the score works, and what this assessment can and cannot tell you.')}

    ${h3('Severity and timelines')}
    ${severityTable()}

    <div class="two eq">
      <div>${h3('How the score is computed')}
        <p class="small">Start at 100. ${SCORE_SUMMARY} Subtract 1 per finding that is a judgement call not yet confirmed (at most ${HOTSPOT_PENALTY_CAP}). Add 2 per verified good practice (at most ${SECURE_CREDIT_CAP}), but not while a critical defect in the app’s own code is open. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.</p></div>
      <div>${h3('What this can and cannot tell you')}
        <p class="small">This is static analysis: the artifact was read, nothing was run, and nothing was uploaded. A short or empty list means the rules that ran found nothing, not that the app is secure${
          full && refs.scope ? `; ${link(refs.scope, 'Scope & methodology')} says what could not be seen` : ''
        }. The <strong>application SHA-256</strong> on the cover identifies the exact file scanned (<code>shasum -a 256 ${esc(scan.artifact.fileName)}</code>); if yours differs, this describes a different build.${
          full && refs.verify ? ` Commands to reproduce each finding are in ${link(refs.verify, 'How to verify')}.` : ''
        }</p></div>
    </div>

    ${
      full
        ? ''
        : `<div class="two eq">
      <div>${h3('In scope')}<ul class="plain">${lists.inScope.slice(0, 4).map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>
      <div>${h3('Not in scope')}<ul class="plain">${lists.outScope.slice(0, 4).map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>
    </div>`
    }

    ${
      owaspRows
        ? `${h3('Standards cited')}
    <p class="small" style="max-width:165mm"><strong>CWE</strong> is the weakness class and <strong>OWASP MASVS</strong> the control it breaks. <strong>OWASP Mobile Top 10 (2024)</strong> is derived from the two, so it groups findings by familiar category; it is a way to sort findings, not a compliance result. The categories this report uses:</p>
    <p class="small" style="max-width:170mm;margin-top:3px">${owaspRows}</p>`
        : ''
    }

  </section>`;
}
