/**
 * Light, medium or dark.
 *
 * Until the user picks one, the console follows the operating system (light or
 * dark). A pick is kept in localStorage and written to `<html data-theme>`,
 * which the stylesheet keys off. index.html carries a copy of the startup logic
 * so the right theme is on the page before the first paint.
 */
import { useEffect, useState } from 'react';

export type ThemeChoice = 'light' | 'medium' | 'dark';

const KEY = 'kavach.theme';
const COLORS: Record<ThemeChoice, string> = { light: '#f7f3f3', medium: '#2a2125', dark: '#0c0709' };

function stored(): ThemeChoice | null {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'light' || v === 'medium' || v === 'dark') return v;
  } catch {
    // Storage can be blocked; the system setting is a fine default.
  }
  return null;
}

const systemTheme = (): ThemeChoice => (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');

function apply(theme: ThemeChoice) {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', COLORS[theme]);
}

export function useTheme(): [ThemeChoice, (next: ThemeChoice) => void] {
  const [choice, setChoice] = useState<ThemeChoice>(() => stored() ?? systemTheme());

  useEffect(() => {
    apply(choice);
    if (stored()) return;
    // Nothing picked yet: keep following the operating system.
    const query = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => setChoice(systemTheme());
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, [choice]);

  const set = (next: ThemeChoice) => {
    try {
      localStorage.setItem(KEY, next);
    } catch {
      // Not persisted; still applies for this visit.
    }
    setChoice(next);
  };
  return [choice, set];
}
