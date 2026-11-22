/**
 * The Guide's hero: the name, the promise, and the journey a scan makes.
 *
 * Ported from the Kavach console, with this product's four stages (scan,
 * review, decide, report). Each shows where things actually stand and jumps to
 * the screen that does the work, so the hero is a working map rather than an
 * illustration. The mark sits inside slowly turning rings. Motion is decorative
 * and switched off under prefers-reduced-motion (see index.css).
 */
import { BRAND } from '../brand';
import { KavachMark } from './KavachMark';

export type HeroStage = {
  id: 'scan' | 'review' | 'triage' | 'report';
  title: string;
  /** What this app's state is, in a few words. */
  detail: string;
  state: 'done' | 'current' | 'todo' | 'blocked';
};

const STATE_LABEL: Record<HeroStage['state'], string> = {
  done: 'Done',
  current: 'Next',
  todo: 'Open',
  blocked: 'Blocked',
};

const GLYPH: Record<HeroStage['id'], string> = {
  scan: 'M11 4a7 7 0 1 0 4.2 12.6l4.6 4.6 1.4-1.4-4.6-4.6A7 7 0 0 0 11 4Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Z',
  review: 'M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm0 2.1 6 2.2V11c0 3.9-2.5 7.2-6 8.8-3.5-1.6-6-4.9-6-8.8V6.3l6-2.2Z',
  triage: 'M9.6 16.2 5.4 12l-1.4 1.4 5.6 5.6L21 7.6 19.6 6.2 9.6 16.2Z',
  report: 'M6 2h9l5 5v15H6V2Zm8 1.5V8h4.5L14 3.5ZM8 12h8v1.6H8V12Zm0 3.4h8V17H8v-1.6Z',
};

export function KavachHero({ stages, onGoTo }: { stages: HeroStage[]; onGoTo: () => void }) {
  return (
    <section className="k-hero" aria-label={`${BRAND.name}: ${BRAND.tagline}`}>
      <div className="k-hero-grid">
        <div className="k-orbit" aria-hidden="true">
          <svg viewBox="0 0 260 260">
            <circle className="k-ring k-ring-1" cx="130" cy="130" r="122" />
            <circle className="k-ring k-ring-2" cx="130" cy="130" r="98" />
            <circle className="k-ring k-ring-3" cx="130" cy="130" r="76" />
            <g className="k-sat k-sat-1"><circle cx="130" cy="8" r="3.4" /></g>
            <g className="k-sat k-sat-2"><circle cx="130" cy="32" r="2.6" /></g>
          </svg>
          <KavachMark size={150} className="k-mark" />
        </div>

        <div className="min-w-0">
          <p className="k-eyebrow">
            <span lang="sa">{BRAND.devanagari}</span>
            <span aria-hidden="true">·</span>
            <span>{BRAND.name.toUpperCase()}</span>
          </p>
          <h2 className="k-title">
            Know what is wrong with your app,<br />
            <span className="k-title-accent">before anyone else does.</span>
          </h2>
          <p className="k-lede">
            Scan an Android or iOS build, read what was found and why it matters, decide what each finding means,
            then hand over a report that can be verified.
          </p>
        </div>
      </div>

      <ol className="k-journey" aria-label="From scan to report">
        {stages.map((s, i) => (
          <li key={s.id} className={`k-stage k-${s.state}`}>
            <button type="button" onClick={onGoTo} className="k-stage-btn">
              <span className="k-stage-top">
                <span className="k-stage-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="18" height="18"><path d={GLYPH[s.id]} fill="currentColor" /></svg>
                </span>
                <span className="k-stage-n">0{i + 1}</span>
                <span className="k-stage-tag">{STATE_LABEL[s.state]}</span>
              </span>
              <span className="k-stage-title">{s.title}</span>
              <span className="k-stage-detail">{s.detail}</span>
            </button>
            {i < stages.length - 1 && <span className="k-link" aria-hidden="true" />}
          </li>
        ))}
      </ol>
    </section>
  );
}
