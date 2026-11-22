/**
 * One console, one job: scan an artifact and review what it found.
 *
 * Adapted from the console shell of the author's earlier Kavach project, trimmed to this
 * product's screens: a Guide, the scan screen (SastScreen) and the audit log.
 * Everything about policies, builds, protection and the threat viewer is gone
 * along with the screens it rendered.
 */
import { BRAND } from './brand';
import { KavachMark } from './components/KavachMark';
import { useEffect, useState } from 'react';
import { clearToken, getToken, request, setToken } from './api';
import type { CurrentUser } from './components/AccountMenu';
import { ShellProvider } from './components/shell';
import { Sidebar } from './components/Sidebar';
import type { ScanView } from './components/Sidebar';
import { LoginScreen } from './screens/LoginScreen';
import type { App } from './api';
import { Button, Panel } from './components/ui';
import { NewAppDialog } from './components/NewAppDialog';
import { SastScreen } from './screens/SastScreen';
import { AuditLog } from './screens/AuditLog';
import { GuideScreen } from './screens/GuideScreen';

type Tab = 'guide' | 'scan' | 'audit';

const GUIDE_SEEN_KEY = 'kavach-sast-guide-seen';

/** First visit lands on the Guide; after that, straight to Scan. Storage can be blocked, so it is only a convenience. */
function initialTab(): Tab {
  try {
    if (localStorage.getItem(GUIDE_SEEN_KEY)) return 'scan';
    localStorage.setItem(GUIDE_SEEN_KEY, '1');
  } catch {
    return 'scan';
  }
  return 'guide';
}

export default function App() {
  const [tab, setTab] = useState<Tab>(initialTab);
  const [scanView, setScanView] = useState<ScanView>('scan');
  const [apps, setApps] = useState<App[] | null>(null);
  const [appId, setAppId] = useState<string>('');
  const [toast, setToast] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [token, setTokenState] = useState(getToken());
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [showNewApp, setShowNewApp] = useState(false);

  // Restore a session on load. A token in storage proves nothing on its own —
  // it may have expired, or been revoked by a password change — so the server
  // is asked who it belongs to before anything else renders.
  useEffect(() => {
    if (!token) {
      setUser(null);
      setCheckingSession(false);
      return;
    }
    request<CurrentUser>('/v1/auth/me')
      .then((me) => {
        setUser(me);
        setToast(null);
      })
      .catch(() => {
        clearToken();
        setTokenState('');
        setUser(null);
      })
      .finally(() => setCheckingSession(false));
  }, [token]);

  useEffect(() => {
    // Hooks run before the early return that renders the login screen, so
    // without this guard the app list is requested while signed out.
    if (!user) return;
    request<{ apps: App[] }>('/v1/apps')
      .then((r) => {
        setApps(r.apps);
      })
      .catch((e) => setToast({ kind: 'err', text: e.message }));
  }, [token, user]);

  /** A scan filed itself under an app named from its package. Select it, and list it if it is new. */
  function onAppResolved(resolvedId: string, created: boolean, redirectedFrom?: string | null) {
    if (resolvedId === appId && !redirectedFrom) return;
    request<{ apps: App[] }>('/v1/apps')
      .then((r) => {
        setApps(r.apps);
        setAppId(resolvedId);
        const name = r.apps.find((a) => a.appId === resolvedId)?.displayName ?? resolvedId;
        if (created) {
          setToast({ kind: 'ok', text: `Registered ${name} from the scan (${resolvedId}). Its next scans will be tracked together.` });
        } else if (redirectedFrom) {
          const was = r.apps.find((a) => a.appId === redirectedFrom)?.displayName ?? redirectedFrom;
          setToast({ kind: 'ok', text: `This scan is not ${was}, so it was filed under ${name} (${resolvedId}).` });
        }
      })
      .catch(() => undefined);
  }

  if (checkingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <p className="text-sm text-slate-500">Checking your session…</p>
      </div>
    );
  }

  if (!user) {
    return (
      <LoginScreen
        onSignedIn={(t) => {
          setToken(t);
          setTokenState(t);
          setCheckingSession(true);
        }}
      />
    );
  }

  return (
    <ShellProvider>
    <div className="flex min-h-screen">
      <Sidebar
        screen={tab}
        onScreen={setTab}
        scanView={scanView}
        onScanView={setScanView}
        apps={apps}
        appId={appId}
        onApp={setAppId}
        onNewApp={() => setShowNewApp(true)}
        user={user}
        onSignedOut={() => { setUser(null); setTokenState(''); }}
      />

      <div className="min-w-0 flex-1">
      {showNewApp && (
        <NewAppDialog
          onClose={() => setShowNewApp(false)}
          onCreated={(app) => {
            setShowNewApp(false);
            setApps((current) => [...(current ?? []), app]);
            setAppId(app.appId);
            setToast({ kind: 'ok', text: `Registered ${app.displayName}.` });
          }}
        />
      )}

      {toast && (
        <div
          className={`mx-6 mt-4 max-w-[1512px] rounded-lg border px-4 py-3 text-sm min-[1608px]:mx-auto ${
            toast.kind === 'ok'
              ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200'
              : 'border-rose-800 bg-rose-950/40 text-rose-200'
          }`}
        >
          <div className="flex items-start justify-between gap-4">
            <span>{toast.text}</span>
            <Button variant="ghost" onClick={() => setToast(null)}>dismiss</Button>
          </div>
        </div>
      )}

      <main className="mx-auto max-w-[1560px] px-6 py-6">
        {tab !== 'guide' && apps !== null && apps.length === 0 && (
          <Panel title="No apps registered">
            <p className="text-sm text-slate-400">
              Registering an app is optional: scanning works without one. Use the <strong className="text-slate-200">+</strong> beside the app picker{' '}
              if you want scans grouped under a project.
            </p>
          </Panel>
        )}

        {tab === 'guide' && (
          <GuideScreen appId={appId} apps={apps} onGoTo={setTab} onNewApp={() => setShowNewApp(true)} />
        )}
        {tab === 'scan' && <SastScreen appId={appId} onAppResolved={onAppResolved} view={scanView} onView={setScanView} />}
        {tab === 'audit' && <AuditLog appId={appId} />}
      </main>

      <footer className="mx-auto mt-10 flex max-w-[1560px] flex-wrap items-center justify-between gap-x-6 gap-y-1 border-t border-slate-800 px-6 py-5 text-xs text-slate-500">
        <p className="flex items-center gap-2.5">
          <KavachMark size={30} />
          <span className="text-sm font-semibold tracking-[0.18em] text-slate-300">{BRAND.name.toUpperCase()}</span>
          <span lang="sa" className="text-lg font-semibold text-amber-300">{BRAND.devanagari}</span>
          <span aria-hidden>·</span>
          <span>{BRAND.tagline}</span>
        </p>
      </footer>
      </div>
    </div>
    </ShellProvider>
  );
}
