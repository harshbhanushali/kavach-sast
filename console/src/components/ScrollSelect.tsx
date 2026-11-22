/**
 * A select whose list scrolls after ten rows.
 *
 * A native <select> opens a list as tall as the screen allows and cannot be
 * styled, so an instance with many apps gets a wall of them. This one keeps the
 * list to ten rows and scrolls the rest, with the keyboard behaviour people
 * expect of a select (arrows, Home/End, Enter, Escape, type-ahead on the label).
 */
import { useEffect, useId, useRef, useState } from 'react';

export type ScrollOption = {
  value: string;
  label: string;
  /** Secondary text, shown muted after the label. */
  hint?: string;
  disabled?: boolean;
};

const VISIBLE_ROWS = 10;
const ROW_REM = 2.25;

export function ScrollSelect({ value, options, onChange, label, className = '', menuClassName = '', align = 'left' }: {
  value: string;
  options: ScrollOption[];
  onChange: (value: string) => void;
  /** Accessible name. */
  label: string;
  className?: string;
  menuClassName?: string;
  /** Which edge of the button the list lines up with. `right` for a control at the right of the page, so a wide list opens leftwards. */
  align?: 'left' | 'right';
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const id = useId();

  const selected = options.find((o) => o.value === value);
  const enabled = (i: number) => i >= 0 && i < options.length && !options[i].disabled;

  function openMenu() {
    setActive(Math.max(0, options.findIndex((o) => o.value === value)));
    setOpen(true);
  }

  function choose(i: number) {
    if (!enabled(i)) return;
    onChange(options[i].value);
    setOpen(false);
  }

  function step(from: number, direction: 1 | -1): number {
    let i = from + direction;
    while (i >= 0 && i < options.length && options[i].disabled) i += direction;
    return enabled(i) ? i : from;
  }

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', away);
    return () => document.removeEventListener('mousedown', away);
  }, [open]);

  // Keep the highlighted row in view as the arrows move it.
  useEffect(() => {
    if (open) list.current?.children[active]?.scrollIntoView({ block: 'nearest' });
  }, [open, active]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (!open) {
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    if (e.key === 'Escape') setOpen(false);
    else if (e.key === 'ArrowDown') setActive((a) => step(a, 1));
    else if (e.key === 'ArrowUp') setActive((a) => step(a, -1));
    else if (e.key === 'Home') setActive(step(-1, 1));
    else if (e.key === 'End') setActive(step(options.length, -1));
    else if (e.key === 'Enter' || e.key === ' ') choose(active);
    else if (e.key === 'Tab') setOpen(false);
    else if (e.key.length === 1) {
      const typed = e.key.toLowerCase();
      const from = (active + 1) % options.length;
      for (let n = 0; n < options.length; n++) {
        const i = (from + n) % options.length;
        if (!options[i].disabled && options[i].label.toLowerCase().startsWith(typed)) {
          setActive(i);
          break;
        }
      }
      return;
    } else return;
    e.preventDefault();
  }

  return (
    <div ref={root} className={`relative ${className}`}>
      <button
        type="button"
        role="combobox"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={`${id}-list`}
        aria-activedescendant={open && active >= 0 ? `${id}-${active}` : undefined}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={onKeyDown}
        className="flex w-full items-center justify-between gap-2 rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-left text-sm text-slate-200 transition hover:border-slate-600"
      >
        <span className="truncate">{selected?.label ?? ''}</span>
        <svg viewBox="0 0 12 12" className="h-3 w-3 shrink-0 text-slate-400" aria-hidden="true">
          <path d="M2 4l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <ul
          ref={list}
          id={`${id}-list`}
          role="listbox"
          aria-label={label}
          style={{ maxHeight: `${VISIBLE_ROWS * ROW_REM}rem` }}
          className={`absolute ${align === 'right' ? 'right-0' : 'left-0'} z-50 mt-1 min-w-full overflow-y-auto rounded-md border border-slate-700 bg-slate-900 py-1 shadow-xl shadow-black/50 ${menuClassName}`}
        >
          {options.map((o, i) => (
            <li
              key={`${o.value}-${i}`}
              id={`${id}-${i}`}
              role="option"
              aria-selected={o.value === value}
              aria-disabled={o.disabled || undefined}
              onMouseEnter={() => enabled(i) && setActive(i)}
              onClick={() => choose(i)}
              style={{ height: `${ROW_REM}rem` }}
              className={`flex items-center gap-2 whitespace-nowrap px-3 text-sm ${
                o.disabled ? 'cursor-not-allowed text-slate-600' : 'cursor-pointer text-slate-200'
              } ${i === active && !o.disabled ? 'bg-slate-800' : ''}`}
            >
              <span className={`w-3 shrink-0 text-ember-400 ${o.value === value ? '' : 'invisible'}`}>✓</span>
              <span>{o.label}</span>
              {o.hint && <span className="text-xs text-slate-500">{o.hint}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
