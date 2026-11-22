import { useState } from 'react';
import { ApiError, request } from '../api';
import type { App } from '../api';
import { Button } from './ui';

/**
 * Registers an app.
 *
 * The package name (Android) or bundle id (iOS) is the app's identity here:
 * scans taken with the app selected are kept together under it, and triage
 * decisions carry forward between them. Carry-over also checks the scan's own
 * package, so a wrong name here costs grouping, not correctness.
 */
export function NewAppDialog({ onCreated, onClose }: {
  onCreated: (app: App) => void;
  onClose: () => void;
}) {
  const [appId, setAppId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [platform, setPlatform] = useState<'android' | 'ios' | 'universal'>('android');
  const [owner, setOwner] = useState('you@example.com');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const body = await request<{ app: App }>('/v1/apps', {
        method: 'POST',
        body: { appId, displayName: displayName || appId, platform, bundleId: appId, owner },
      });
      onCreated(body.app);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-6"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="panel w-full max-w-lg"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <header className="panel-header">
          <h2 className="text-[0.95rem] font-semibold text-slate-50">Register an app</h2>
          <p className="mt-1 text-sm text-slate-400">
            Use the app's package name (Android) or bundle id (iOS). Scans of it are kept together
            when you select it before scanning, and your triage decisions carry over to its next scan.
          </p>
        </header>

        <div className="panel-body space-y-4">
          <label className="block">
            <span className="eyebrow">Package name / bundle id</span>
            <input
              type="text"
              value={appId}
              autoFocus
              placeholder="owasp.sat.agoat"
              onChange={(e) => setAppId(e.target.value.trim())}
              className="mt-1 w-full"
            />
          </label>

          <label className="block">
            <span className="eyebrow">Display name</span>
            <input
              type="text"
              value={displayName}
              placeholder="AndroGoat"
              onChange={(e) => setDisplayName(e.target.value)}
              className="mt-1 w-full"
            />
          </label>

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="eyebrow">Platform</span>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value as 'android' | 'ios' | 'universal')}
                className="mt-1 w-full"
              >
                <option value="android">android</option>
                <option value="ios">ios</option>
                <option value="universal">universal</option>
              </select>
            </label>
            <label className="block">
              <span className="eyebrow">Owner</span>
              <input
                type="text"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                className="mt-1 w-full"
              />
            </label>
          </div>

          {error && (
            <p className="rounded-md border-l-[3px] border-rose-500 border-y border-r border-y-rose-900/60 border-r-rose-900/60 bg-rose-950/40 px-4 py-3 text-sm text-rose-100">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={create} disabled={busy || !appId}>
              {busy ? 'Registering…' : 'Register'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
