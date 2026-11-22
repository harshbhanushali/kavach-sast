/**
 * Inline-SVG / CSS charts for the report.
 *
 * Form choices (from the dataviz method): the score is one headline number, so
 * it is a ring with the grade set in the middle rather than a dial with a scale;
 * severity is a part-to-whole of five ordered categories, so it is one stacked
 * bar (2px gaps between fills) with the counts printed underneath, not a pie.
 * Every mark is labelled with text, so nothing depends on colour alone.
 */
import { GRADE_COLOR, GRADE_TEXT, SEV, SEVERITY_ORDER, esc, meter } from './kit';
import type { SevKey } from './kit';

/** Score ring: track + arc, grade letter centred, numeric score beneath. */
export function scoreRing(score: number, grade: string, size = 190): string {
  const r = 42;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = GRADE_COLOR[grade] ?? '#66707c';
  const text = GRADE_TEXT[grade] ?? '#4b5563';
  // Tick marks every 10 points, so the arc reads as a scale even when printed small.
  const ticks = Array.from({ length: 20 }, (_, i) => {
    const a = (i / 20) * 2 * Math.PI - Math.PI / 2;
    const x1 = 50 + Math.cos(a) * 49;
    const y1 = 50 + Math.sin(a) * 49;
    const x2 = 50 + Math.cos(a) * (i % 5 === 0 ? 45.5 : 47);
    const y2 = 50 + Math.sin(a) * (i % 5 === 0 ? 45.5 : 47);
    return `<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}" stroke="#aeb5bd" stroke-width="${i % 5 === 0 ? 0.7 : 0.4}"/>`;
  }).join('');
  return `<svg class="ring" width="${size}" height="${size}" viewBox="0 0 100 100" role="img"
      aria-label="Security score ${score} out of 100, grade ${esc(grade)}">
    ${ticks}
    <circle cx="50" cy="50" r="${r}" fill="none" stroke="#e6e9ec" stroke-width="7"/>
    <circle cx="50" cy="50" r="${r}" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round"
      stroke-dasharray="${(c * pct).toFixed(2)} ${c.toFixed(2)}" transform="rotate(-90 50 50)"/>
    <text x="50" y="52" text-anchor="middle" font-size="34" font-weight="800" fill="${text}"
      font-family="-apple-system, 'Segoe UI', Roboto, Helvetica, sans-serif" letter-spacing="-1">${esc(grade)}</text>
    <text x="50" y="65" text-anchor="middle" font-size="7.2" font-weight="700" fill="#3a424c"
      font-family="-apple-system, 'Segoe UI', Roboto, Helvetica, sans-serif">${score} / 100</text>
  </svg>`;
}

/** A thin segmented bar, one segment per severity, widths proportional to counts. */
export function sevStripe(counts: Record<string, number>, height = 8): string {
  const total = SEVERITY_ORDER.reduce((n, s) => n + (counts[s] ?? 0), 0);
  if (total === 0) {
    return `<div class="stripe" style="height:${height}px"><span style="flex:1;background:#d9dde1"></span></div>`;
  }
  return `<div class="stripe" style="height:${height}px">${SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0)
    .map((s) => `<span style="flex:${counts[s]};background:${SEV[s].fill}"></span>`)
    .join('')}</div>`;
}

/**
 * Severity distribution: stacked bar, then one row per severity with its
 * shape glyph, word, count, share and level meter. Zero rows stay listed so a
 * reader sees "0 critical" as a fact rather than an omission.
 */
export function sevDistribution(counts: Record<string, number>): string {
  const total = SEVERITY_ORDER.reduce((n, s) => n + (counts[s] ?? 0), 0);
  return `
    <div class="dist">
      ${sevStripe(counts, 16)}
      <table class="dist-rows">
        ${SEVERITY_ORDER.map((s: SevKey) => {
          const n = counts[s] ?? 0;
          const t = SEV[s];
          const share = total ? Math.round((n / total) * 100) : 0;
          return `<tr class="${n === 0 ? 'zero' : ''}">
            <td class="dr-g" style="color:${t.text}">${t.glyph}</td>
            <td class="dr-l">${t.label}</td>
            <td class="dr-m">${meter(t.level, t.fill)}</td>
            <td class="dr-n">${n}</td>
            <td class="dr-p">${total ? `${share}%` : ''}</td>
          </tr>`;
        }).join('')}
      </table>
    </div>`;
}
