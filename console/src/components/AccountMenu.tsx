/**
 * Who is signed in, changing their password, and signing out.
 *
 * Replaces the role dropdown that used to sit in the header. That control let
 * anyone pick their own permissions, which made the RBAC decorative; the role
 * now comes from the account and cannot be chosen in the UI.
 */
import { useEffect, useRef, useState } from 'react';
import { ApiError, clearToken, request } from '../api';
import { useShell } from './shell';

export type CurrentUser = {
  username: string;
  role: string;
  usingDefaultPassword: boolean;
  lastLoginAt: string | null;
  staticToken: boolean;
  accountsOnDefaults?: string[];
};

export function AccountMenu({ user, onSignedOut }: { user: CurrentUser; onSignedOut: () => void }) {
  const [open, setOpen] = useState(false);
  const [changing, setChanging] = useState(false);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const { collapsed, tip } = useShell();

  // Close on an outside click, which is the behaviour a menu is expected to
  // have and its absence is immediately annoying.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  async function signOut() {
    await request('/v1/auth/logout', { method: 'POST' }).catch(() => undefined);
    clearToken();
    onSignedOut();
  }

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError('the two new passwords do not match');
      return;
    }
    try {
      const result = await request<{ message: string }>('/v1/auth/password', {
        method: 'POST',
        body: { currentPassword: current, newPassword: next },
      });
      setDone(result.message);
      // Changing a password revokes every session, including this one, so the
      // only honest next step is to sign in again.
      setTimeout(() => {
        clearToken();
        onSignedOut();
      }, 1800);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={collapsed ? `Account: ${user.username}` : undefined}
        {...tip(`${user.username} · ${user.role}`)}
        className={`flex items-center rounded-lg border text-sm transition ${
          collapsed ? 'mx-auto size-10 justify-center' : 'w-full gap-2.5 px-2.5 py-2'
        } ${
          user.usingDefaultPassword
            ? 'border-amber-500/40 bg-amber-500/10 text-amber-100 hover:bg-amber-500/15'
            : 'border-slate-700 bg-slate-900 text-slate-200 hover:border-slate-600'
        }`}
      >
        <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-slate-700 text-[11px] font-bold uppercase text-slate-100">
          {user.username.slice(0, 1)}
        </span>
        {!collapsed && (
          <>
            <span className="min-w-0 flex-1 truncate text-left font-medium">{user.username}</span>
            <span className="text-xs text-slate-500">{user.role}</span>
            {user.usingDefaultPassword && <span className="text-xs" title="Still using the default password">⚠</span>}
          </>
        )}
      </button>

      {open && (
        <div className="absolute bottom-full left-0 z-40 mb-2 w-80 rounded-xl border border-slate-800 bg-slate-900 p-4 shadow-xl shadow-black/40">
          <p className="text-sm font-medium text-slate-100">{user.username}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            Role: {user.role}
            {user.lastLoginAt && ` · last signed in ${new Date(user.lastLoginAt).toLocaleString()}`}
          </p>

          {user.usingDefaultPassword && (
            <p className="mt-3 rounded-md bg-amber-500/10 px-3 py-2 text-xs leading-relaxed text-amber-100 ring-1 ring-inset ring-amber-500/30">
              This account still uses the published default password. Anyone who can reach this console
              can sign in as you.
            </p>
          )}

          {user.staticToken && (
            <p className="mt-3 rounded-md bg-slate-800/60 px-3 py-2 text-xs leading-relaxed text-slate-400">
              Signed in with a static development token rather than an account, so there is no password
              to change.
            </p>
          )}

          {done ? (
            <p className="mt-3 rounded-md bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200 ring-1 ring-inset ring-emerald-500/30">
              {done}
            </p>
          ) : (
            <>
              {!user.staticToken && !changing && (
                <button
                  type="button"
                  onClick={() => setChanging(true)}
                  className="mt-3 w-full rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 transition hover:bg-slate-800"
                >
                  Change password
                </button>
              )}

              {changing && (
                <form onSubmit={submitPassword} className="mt-3 space-y-2">
                  {[
                    ['Current password', current, setCurrent, 'current-password'] as const,
                    ['New password', next, setNext, 'new-password'] as const,
                    ['Confirm new password', confirm, setConfirm, 'new-password'] as const,
                  ].map(([label, value, set, autoComplete]) => (
                    <label key={label} className="block">
                      <span className="mb-1 block text-[11px] uppercase tracking-wide text-slate-500">
                        {label}
                      </span>
                      <input
                        type="password"
                        value={value}
                        autoComplete={autoComplete}
                        onChange={(e) => set(e.target.value)}
                        className="w-full rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100 outline-none focus:border-ember-500"
                      />
                    </label>
                  ))}
                  <p className="text-[11px] text-slate-500">
                    At least 10 characters, and not one of the published defaults.
                  </p>
                  {error && <p className="text-xs text-rose-300">{error}</p>}
                  <button
                    type="submit"
                    className="w-full rounded-md bg-ember-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ember-500"
                  >
                    Save
                  </button>
                </form>
              )}
            </>
          )}

          <button
            type="button"
            onClick={signOut}
            className="mt-3 w-full rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:border-rose-500/50 hover:bg-rose-500/10 hover:text-rose-200"
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
