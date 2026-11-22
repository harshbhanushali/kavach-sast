/**
 * State and pieces shared by the sidebar and the report sections that sit in it.
 *
 * The sidebar belongs to the app shell, but the report's own pages (Findings,
 * Attack surface, ...) are known only to the scan screen. That screen renders
 * them into a slot the sidebar provides, so there is one rail and not two.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

const KEY = 'kavach.sidebar';

type Tip = { label: string; top: number; left: number } | null;

type Shell = {
  collapsed: boolean;
  toggle: () => void;
  expand: () => void;
  /** Where the scan screen puts the report's pages. */
  sections: HTMLElement | null;
  setSections: (el: HTMLElement | null) => void;
  /** Hover and focus handlers that show `label` beside a collapsed item. Empty when the rail is expanded. */
  tip: (label: string) => Record<string, unknown>;
};

// Outside the shell (the sign-in page) nothing is collapsed and nothing has a tooltip.
const NO_SHELL: Shell = { collapsed: false, toggle: () => {}, expand: () => {}, sections: null, setSections: () => {}, tip: () => ({}) };

const ShellContext = createContext<Shell>(NO_SHELL);

export const useShell = (): Shell => useContext(ShellContext);

function storedCollapsed(): boolean {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'collapsed') return true;
    if (v === 'open') return false;
  } catch {
    // Storage can be blocked; fall through to the default.
  }
  // A phone gets the slim rail until it is opened.
  return window.matchMedia('(max-width: 767px)').matches;
}

export function ShellProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(storedCollapsed);
  const [sections, setSections] = useState<HTMLElement | null>(null);
  const [tipState, setTip] = useState<Tip>(null);

  const set = useCallback((next: boolean) => {
    setCollapsed(next);
    setTip(null);
    try {
      localStorage.setItem(KEY, next ? 'collapsed' : 'open');
    } catch {
      // Not persisted; still applies for this visit.
    }
  }, []);

  const tip = useCallback(
    (label: string) => {
      if (!collapsed) return {};
      const show = (e: { currentTarget: Element }) => {
        const r = e.currentTarget.getBoundingClientRect();
        // Anchor to the rail's edge, not the button's, so the tip clears the border.
        const edge = e.currentTarget.closest('aside')?.getBoundingClientRect().right ?? r.right;
        setTip({ label, top: r.top + r.height / 2, left: edge + 8 });
      };
      const hide = () => setTip(null);
      return { onMouseEnter: show, onFocus: show, onMouseLeave: hide, onBlur: hide };
    },
    [collapsed],
  );

  const value = useMemo<Shell>(
    () => ({ collapsed, toggle: () => set(!collapsed), expand: () => set(false), sections, setSections, tip }),
    [collapsed, set, sections, tip],
  );

  // A tooltip left behind by an item that unmounted would hang there for good.
  useEffect(() => {
    if (!collapsed) setTip(null);
  }, [collapsed]);

  return (
    <ShellContext.Provider value={value}>
      {children}
      {tipState &&
        createPortal(
          <div
            role="tooltip"
            style={{ top: tipState.top, left: tipState.left }}
            className="pointer-events-none fixed z-[60] -translate-y-1/2 whitespace-nowrap rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-100 shadow-lg shadow-black/30"
          >
            {tipState.label}
          </div>,
          document.body,
        )}
    </ShellContext.Provider>
  );
}

/** 24px stroke icons, one path each. */
export const ICON = {
  guide: 'M4 19.5A2.5 2.5 0 016.5 17H20V3H6.5A2.5 2.5 0 004 5.5zM4 19.5V22h16',
  scan: 'M3 7V5a2 2 0 012-2h2m10 0h2a2 2 0 012 2v2m0 10v2a2 2 0 01-2 2h-2M7 21H5a2 2 0 01-2-2v-2M7 12h10',
  audit: 'M9 5h6M9 9h6M9 13h4M6 3h12a1 1 0 011 1v16a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z',
  plus: 'M12 5v14M5 12h14',
  panel: 'M3 4h18v16H3zM9 4v16',
  chevronsRight: 'M13 17l5-5-5-5M6 17l5-5-5-5',
  chevron: 'M9 6l6 6-6 6',
} as const;

export function Icon({ d, size = 18, className = '' }: { d: string; size?: number; className?: string }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={`shrink-0 ${className}`}
    >
      <path d={d} />
    </svg>
  );
}

/** One row of the sidebar: icon, label and an optional count. Shrinks to just the icon when the rail is collapsed. */
export function NavButton({ icon, label, active, count, tone, onClick, strong, tooltip = true }: {
  icon: string;
  label: string;
  active: boolean;
  count?: number;
  tone?: 'alert';
  onClick: () => void;
  /** Reads as the current section without the filled highlight, for a parent whose child is the highlighted one. */
  strong?: boolean;
  /** Set false when something else (a flyout) already names this item. */
  tooltip?: boolean;
}) {
  const { collapsed, tip } = useShell();
  const shown = count !== undefined && count > 0;
  const badge = tone === 'alert' ? 'bg-rose-500/20 text-rose-200' : 'bg-slate-700/80 text-slate-300';
  return (
    <button
      type="button"
      aria-current={active ? 'page' : undefined}
      aria-label={collapsed ? (shown ? `${label}, ${count}` : label) : undefined}
      onClick={onClick}
      {...(tooltip ? tip(shown ? `${label} · ${count}` : label) : {})}
      className={`group relative flex items-center rounded-lg text-left text-sm font-medium transition ${
        collapsed ? 'mx-auto size-10 justify-center' : 'w-full gap-3 py-2 pl-3 pr-2.5'
      } ${
        active
          ? 'bg-ember-500/12 text-slate-50 ring-1 ring-inset ring-ember-500/30'
          : strong
            ? 'text-slate-50 hover:bg-slate-800/60'
            : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
      }`}
    >
      <span
        aria-hidden="true"
        className={`absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-ember-500 transition-opacity ${active ? 'opacity-100' : 'opacity-0'}`}
      />
      <Icon d={icon} className={`transition ${active || strong ? 'text-ember-400' : 'text-slate-500 group-hover:text-slate-300'}`} />
      {!collapsed && <span className="min-w-0 flex-1 truncate">{label}</span>}
      {shown &&
        (collapsed ? (
          <span className={`absolute -right-0.5 -top-0.5 min-w-4 rounded-full px-1 text-center text-[9px] font-bold leading-4 tabular-nums ${badge}`}>
            {count! > 999 ? '999+' : count}
          </span>
        ) : (
          <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold tabular-nums ${badge}`}>{count}</span>
        ))}
    </button>
  );
}

/** A heading in the expanded sidebar; a thin rule when collapsed. */
export function NavGroup({ title, first, children }: { title: string; first?: boolean; children: ReactNode }) {
  const { collapsed } = useShell();
  return (
    <div className="flex flex-col gap-0.5">
      {collapsed ? (
        !first && <hr className="mx-3 my-2 border-slate-800" />
      ) : (
        <p className={`eyebrow px-3 pb-1 ${first ? 'pt-0.5' : 'pt-3'}`}>{title}</p>
      )}
      {children}
    </div>
  );
}
