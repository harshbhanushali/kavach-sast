/**
 * The app's left rail: brand, which app is selected, the three screens, the
 * report's own pages while a scan is open, and the account and theme controls.
 * It collapses to an icon rail, with the name of each item on hover.
 */
import { useState } from 'react';
import { BRAND } from '../brand';
import { KavachMark } from './KavachMark';
import { AccountMenu } from './AccountMenu';
import type { CurrentUser } from './AccountMenu';
import { ScrollSelect } from './ScrollSelect';
import { ThemeToggle } from './ThemeToggle';
import { ICON, Icon, NavButton, NavGroup, useShell } from './shell';
import type { App } from '../api';

export type Screen = 'guide' | 'scan' | 'audit';

/** The pages inside the Scan section. */
export type ScanView = 'scan' | 'report' | 'history' | 'compare';

/** 'report' is not listed: it is the open scan's own page, reached by scanning or from the history. */
const SCAN_VIEWS: { id: ScanView; label: string }[] = [
  { id: 'scan', label: 'Scan an app' },
  { id: 'history', label: 'Scan history' },
  { id: 'compare', label: 'Compare scans' },
];

const SCREENS: { id: Screen; label: string; icon: string }[] = [
  { id: 'guide', label: 'Guide', icon: ICON.guide },
  { id: 'scan', label: 'Scan', icon: ICON.scan },
  { id: 'audit', label: 'Audit', icon: ICON.audit },
];

/**
 * Scan has pages of its own. Expanded, they open in place under it (the arrow
 * folds them away); collapsed, they come out beside the icon on hover or focus,
 * so nothing is hidden behind a gesture that touch and keyboard cannot make.
 */
function ScanMenu({ screen, onScreen, view, onView }: {
  screen: Screen;
  onScreen: (s: Screen) => void;
  view: ScanView;
  onView: (v: ScanView) => void;
}) {
  const { collapsed } = useShell();
  const [open, setOpen] = useState(true);
  const here = screen === 'scan';
  const go = (v: ScanView) => {
    onScreen('scan');
    onView(v);
  };

  if (collapsed) {
    return (
      <div className="group/menu relative">
        <NavButton icon={ICON.scan} label="Scan" active={here} tooltip={false} onClick={() => go(view)} />
        <div className="invisible absolute left-full top-0 z-40 pl-3 opacity-0 transition group-focus-within/menu:visible group-focus-within/menu:opacity-100 group-hover/menu:visible group-hover/menu:opacity-100">
          <div className="w-48 rounded-xl border border-slate-700 bg-slate-900 p-1.5 shadow-xl shadow-black/30">
            <p className="eyebrow px-2.5 pb-1 pt-1">Scan</p>
            {SCAN_VIEWS.map((v) => (
              <SubItem key={v.id} label={v.label} active={here && view === v.id} onClick={() => go(v.id)} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  const showing = open;
  return (
    <div>
      <div className="relative">
        <NavButton icon={ICON.scan} label="Scan" active={here && !showing} strong={here && showing} onClick={() => { go(view); setOpen(true); }} />
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          aria-label={open ? 'Hide the scan pages' : 'Show the scan pages'}
          className="absolute right-1.5 top-1/2 grid size-6 -translate-y-1/2 place-items-center rounded-md text-slate-500 transition hover:bg-slate-700/60 hover:text-slate-100"
        >
          <Icon d={ICON.chevron} size={15} className={`transition-transform ${open ? 'rotate-90' : ''}`} />
        </button>
      </div>
      {showing && (
        <div className="ml-[1.4rem] mt-0.5 flex flex-col gap-0.5 border-l border-slate-800 pl-2">
          {SCAN_VIEWS.map((v) => (
            <SubItem key={v.id} label={v.label} active={here && view === v.id} onClick={() => go(v.id)} />
          ))}
        </div>
      )}
    </div>
  );
}

function SubItem({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
      className={`w-full rounded-md px-2.5 py-1.5 text-left text-sm font-medium transition ${
        active
          ? 'bg-ember-500/12 text-slate-50 ring-1 ring-inset ring-ember-500/30'
          : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
      }`}
    >
      {label}
    </button>
  );
}

export function Sidebar({ screen, onScreen, scanView, onScanView, apps, appId, onApp, onNewApp, user, onSignedOut }: {
  screen: Screen;
  onScreen: (s: Screen) => void;
  scanView: ScanView;
  onScanView: (v: ScanView) => void;
  apps: App[] | null;
  appId: string;
  onApp: (id: string) => void;
  onNewApp: () => void;
  user: CurrentUser;
  onSignedOut: () => void;
}) {
  const { collapsed, toggle, expand, setSections, tip } = useShell();
  const current = apps?.find((a) => a.appId === appId);

  return (
    <aside
      aria-label="Main"
      className={`sticky top-0 z-30 flex h-screen shrink-0 flex-col border-r border-slate-800 bg-slate-900/40 transition-[width] duration-200 ${
        collapsed ? 'w-[4.5rem]' : 'w-64'
      }`}
    >
      {/* Brand and the collapse control */}
      <div className={`flex items-center ${collapsed ? 'flex-col gap-3 px-3 pb-4 pt-4' : 'gap-2.5 px-4 pb-5 pt-4'}`}>
        <KavachMark size={collapsed ? 34 : 30} title={BRAND.name} />
        {!collapsed && (
          <div className="min-w-0 flex-1 leading-tight">
            <p className="truncate text-[0.95rem] font-extrabold uppercase tracking-[0.16em] text-slate-50">{BRAND.name}</p>
            <p lang="sa" className="text-xs font-semibold text-amber-300">{BRAND.devanagari}</p>
          </div>
        )}
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? 'Expand the sidebar' : 'Collapse the sidebar'}
          {...tip('Expand')}
          className="grid size-8 shrink-0 place-items-center rounded-md text-slate-500 transition hover:bg-slate-800 hover:text-slate-200"
        >
          <Icon d={collapsed ? ICON.chevronsRight : ICON.panel} size={17} />
        </button>
      </div>

      {/* Which app the scans are filed under */}
      <div className="px-3 pb-3">
        {collapsed ? (
          <button
            type="button"
            onClick={expand}
            aria-label="Choose an app"
            {...tip(current ? current.displayName : 'App: auto from the scan')}
            className="mx-auto grid size-10 place-items-center rounded-lg border border-slate-700 bg-slate-900 text-sm font-bold uppercase text-slate-200 transition hover:border-slate-600"
          >
            {current ? current.displayName.slice(0, 1) : 'A'}
          </button>
        ) : (
          <>
            <p className="eyebrow px-1 pb-1.5">App</p>
            <div className="flex items-center gap-1.5">
              <ScrollSelect
                label="App"
                className="min-w-0 flex-1"
                value={appId}
                onChange={onApp}
                options={[
                  { value: '', label: 'Auto (from the scan)' },
                  ...(apps ?? []).map((a) => ({ value: a.appId, label: a.displayName, hint: `${a.bundleId} · ${a.platform}` })),
                ]}
              />
              <button
                type="button"
                onClick={onNewApp}
                aria-label="Register a new app"
                title="Register a new app (optional: a scan works without one)"
                className="grid size-9 shrink-0 place-items-center rounded-md border border-slate-700 bg-slate-900 text-slate-300 transition hover:border-ember-500/60 hover:text-slate-50"
              >
                <Icon d={ICON.plus} size={16} />
              </button>
            </div>
          </>
        )}
      </div>

      {/* The three screens */}
      <nav aria-label="Screens" className="flex flex-col gap-0.5 px-3">
        <NavGroup title="Menu" first>
          {SCREENS.map((s) =>
            s.id === 'scan' ? (
              <ScanMenu key={s.id} screen={screen} onScreen={onScreen} view={scanView} onView={onScanView} />
            ) : (
              <NavButton key={s.id} icon={s.icon} label={s.label} active={screen === s.id} onClick={() => onScreen(s.id)} />
            ),
          )}
        </NavGroup>
      </nav>

      {/* The scan screen puts the report's pages here while a scan is open */}
      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden px-3 pb-2">
        <nav
          aria-label="Report sections"
          ref={setSections}
          className="mt-3 flex flex-col gap-0.5 border-t border-slate-800 pt-3 empty:hidden"
        />
      </div>

      {/* Theme and the signed-in account */}
      <div className="space-y-2 border-t border-slate-800 p-3">
        <ThemeToggle compact={collapsed} />
        <AccountMenu user={user} onSignedOut={onSignedOut} />
      </div>
    </aside>
  );
}
