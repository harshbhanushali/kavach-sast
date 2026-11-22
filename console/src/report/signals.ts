/**
 * The "key build signals" strip: a handful of yes/no questions a reviewer asks
 * before reading anything else (is it debuggable, is transport strict, ...).
 * Each platform derives its own list; this only draws it.
 */
import { BAD, GOOD, NEUTRAL, WARN, esc } from './kit';

export type SignalTone = 'good' | 'warn' | 'bad' | 'muted';
export type Signal = { label: string; tone: SignalTone; state: string };

const TONE: Record<SignalTone, { color: string; glyph: string }> = {
  good: { color: GOOD, glyph: '✓' },
  warn: { color: WARN, glyph: '▲' },
  bad: { color: BAD, glyph: '✕' },
  muted: { color: NEUTRAL, glyph: '○' },
};

/** Glyph + label + word per signal: colour is never the only cue. */
export function signalStrip(signals: Signal[]): string {
  if (signals.length === 0) return '';
  return `<ul class="signals">${signals
    .map((s) => {
      const t = TONE[s.tone];
      return `<li style="border-color:${t.color}"><span class="sg" style="color:${t.color}">${t.glyph}</span><span class="sl">${esc(s.label)}</span><strong style="color:${t.color}">${esc(s.state)}</strong></li>`;
    })
    .join('')}</ul>`;
}
