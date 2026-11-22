import { useTheme } from '../theme';
import { useShell } from './shell';
import type { ThemeChoice } from '../theme';

const ICON: Record<ThemeChoice, string> = {
  light: 'M12 4V2m0 20v-2m8-8h2M2 12h2m13.66-5.66 1.41-1.41M4.93 19.07l1.41-1.41m0-11.32L4.93 4.93m14.14 14.14-1.41-1.41M12 8a4 4 0 100 8 4 4 0 000-8z',
  medium: 'M12 3a9 9 0 100 18 9 9 0 000-18z',
  dark: 'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z',
};
const LABEL: Record<ThemeChoice, string> = { light: 'Light', medium: 'Medium', dark: 'Dark' };

const ORDER = ['light', 'medium', 'dark'] as const;

function ThemeIcon({ t }: { t: ThemeChoice }) {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICON[t]} />
      {/* Medium is a circle filled on one side: halfway between sun and moon. */}
      {t === 'medium' && <path d="M12 3a9 9 0 010 18z" fill="currentColor" />}
    </svg>
  );
}

/** Three buttons so the current choice is always visible; one cycling button when `compact`. */
export function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const [choice, setChoice] = useTheme();
  const { tip } = useShell();

  if (compact) {
    const next = ORDER[(ORDER.indexOf(choice) + 1) % ORDER.length];
    return (
      <button
        type="button"
        onClick={() => setChoice(next)}
        aria-label={`Theme: ${LABEL[choice]}. Switch to ${LABEL[next]}`}
        {...tip(`${LABEL[choice]} theme`)}
        className="mx-auto grid size-10 place-items-center rounded-lg border border-slate-700 bg-slate-900 text-slate-300 transition hover:border-slate-600 hover:text-slate-50"
      >
        <ThemeIcon t={choice} />
      </button>
    );
  }

  return (
    <div role="radiogroup" aria-label="Colour theme" className="flex items-center rounded-lg border border-slate-700 bg-slate-900 p-0.5">
      {ORDER.map((t) => (
        <button
          key={t}
          type="button"
          role="radio"
          aria-checked={choice === t}
          aria-label={LABEL[t]}
          title={`${LABEL[t]} theme`}
          onClick={() => setChoice(t)}
          className={`flex h-7 flex-1 items-center justify-center gap-1.5 rounded-md px-1.5 text-xs font-medium transition ${
            choice === t ? 'bg-slate-700 text-slate-100' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ThemeIcon t={t} />
          <span>{LABEL[t]}</span>
        </button>
      ))}
    </div>
  );
}
