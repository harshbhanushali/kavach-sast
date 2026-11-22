/**
 * The login screen.
 *
 * The default credentials are printed on the page, and clicking one fills the
 * form. That is deliberate: they are in the README and in the repository, so
 * showing them here reveals nothing new, and hiding them only locks out the
 * person who has just installed the tool. What the page does instead is make
 * the consequence visible — while an account is still on its default password,
 * a banner says so and does not stop saying so until it is changed.
 */
import { BRAND } from '../brand';
import { KavachMark } from '../components/KavachMark';
import { ThemeToggle } from '../components/ThemeToggle';
import { useCallback, useEffect, useState } from 'react';

type DefaultAccount = { username: string; role: string; password: string };

type AuthInfo = {
  defaultAccounts: DefaultAccount[];
  accountsOnDefaults: string[];
  sessionHours: number;
};

export function LoginScreen({ onSignedIn }: { onSignedIn: (token: string) => void }) {
  const [info, setInfo] = useState<AuthInfo | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Whether the backend is answering at all.
   *
   * This used to be swallowed: a failed fetch set `info` to null and the
   * default-accounts panel simply did not render. A reader saw a login form
   * with no credentials on it and no reason given, which looks like the
   * credentials were removed rather than like the server is down. The state is
   * now explicit so the page can say which it is.
   */
  const [reachable, setReachable] = useState<'checking' | 'ok' | 'down'>('checking');

  const loadInfo = useCallback(() => {
    setReachable('checking');
    fetch('/v1/auth/info')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`http ${r.status}`))))
      .then((body: AuthInfo) => {
        setInfo(body);
        setReachable('ok');
      })
      .catch(() => {
        setInfo(null);
        setReachable('down');
      });
  }, []);

  useEffect(loadInfo, [loadInfo]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!username || !password) return;
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/v1/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const body = await response.json();
      if (!response.ok) setError(body.error ?? 'sign in failed');
      else onSignedIn(body.token);
    } catch (e) {
      setError(
        e instanceof Error && /fetch/i.test(e.message)
          ? 'Could not reach the backend. Is it running on port 8788?'
          : String(e),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10">
      <div className="absolute right-4 top-4"><ThemeToggle /></div>
      <div className="w-full max-w-sm">
        <div className="mb-7 flex items-center gap-3">
          <KavachMark size={60} />
          <div>
            <h1 className="flex items-baseline gap-2 text-2xl font-extrabold uppercase tracking-[0.2em] text-slate-50">
              {BRAND.name}
              <span lang="sa" className="text-sm font-semibold normal-case tracking-normal text-amber-300/90">{BRAND.devanagari}</span>
            </h1>
            <p className="text-sm text-slate-400">{BRAND.tagline}</p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-xl shadow-black/30"
        >
          <label className="block">
            <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-400">
              Username
            </span>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-ember-500 focus:ring-1 focus:ring-ember-500/40"
              placeholder="admin"
            />
          </label>

          <label className="mt-4 block">
            <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-400">
              Password
            </span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-ember-500 focus:ring-1 focus:ring-ember-500/40"
              placeholder="••••••••"
            />
          </label>

          {error && (
            <p
              role="alert"
              className="mt-4 rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-200 ring-1 ring-inset ring-rose-500/30"
            >
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy || !username || !password}
            className="mt-5 w-full rounded-md bg-ember-600 px-3 py-2 text-sm font-semibold text-white transition hover:bg-ember-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>

          {info && info.sessionHours > 0 && (
            <p className="mt-3 text-center text-xs text-slate-600">
              A session lasts {info.sessionHours} hours.
            </p>
          )}
        </form>

        {reachable === 'down' && (
          <div className="mt-5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4">
            <p className="text-sm font-medium text-amber-100">Cannot reach the backend</p>
            <p className="mt-1.5 text-xs leading-relaxed text-amber-200/80">
              The console is running, but nothing is answering on port 8787. The default accounts
              cannot be listed and signing in will fail until it is started:
            </p>
            <code className="mt-2 block rounded-md bg-slate-950/70 px-2.5 py-1.5 font-mono text-xs text-slate-200">
              npm run backend
            </code>
            <button
              type="button"
              onClick={loadInfo}
              className="mt-3 rounded-md border border-amber-500/40 px-3 py-1.5 text-xs font-medium text-amber-100 transition hover:bg-amber-500/15"
            >
              Try again
            </button>
          </div>
        )}

        {reachable === 'ok' && info && info.defaultAccounts.length > 0 && (
          <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Default accounts
            </p>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">
              Created on first run. Click one to fill the form.
            </p>

            {/* Column headers, so there is no guessing which value is which.
                The password used to sit unlabelled beside the username in a
                dimmer grey than everything around it — 4.2:1 against this
                background, under the 4.5:1 floor for text this size. It is the
                one value on the page a reader has to transcribe, so it is now
                the brightest thing in the row rather than the faintest. */}
            <div className="mt-3 grid grid-cols-[1fr_1fr_auto] gap-x-3 px-3 pb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
              <span>Username</span>
              <span>Password</span>
              <span>Role</span>
            </div>

            <div className="space-y-1.5">
              {info.defaultAccounts.map((account) => {
                const stillDefault = info.accountsOnDefaults.includes(account.username);
                return (
                  <button
                    key={account.username}
                    type="button"
                    title={
                      stillDefault
                        ? `Sign in as ${account.username}`
                        : `${account.username} has had its password changed, so ${account.password} will no longer work.`
                    }
                    onClick={() => {
                      setUsername(account.username);
                      setPassword(account.password);
                      setError(null);
                    }}
                    className="grid w-full grid-cols-[1fr_1fr_auto] items-center gap-x-3 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-left transition hover:-translate-y-px hover:border-slate-600 hover:bg-slate-900"
                  >
                    <span className="truncate font-mono text-sm text-slate-100">
                      {account.username}
                    </span>
                    {/* Dimmed and struck through only when it genuinely will
                        not work, which is the one case where being hard to
                        read carries the right meaning. */}
                    <span
                      className={`truncate font-mono text-sm ${
                        stillDefault ? 'text-slate-100' : 'text-slate-600 line-through'
                      }`}
                    >
                      {account.password}
                    </span>
                    <span className="text-[11px] uppercase tracking-wide text-ember-300/80">
                      {stillDefault ? account.role : 'changed'}
                    </span>
                  </button>
                );
              })}
            </div>

            {info.accountsOnDefaults.length > 0 && (
              <p className="mt-3 border-t border-slate-800 pt-3 text-xs leading-relaxed text-amber-200/80">
                {info.accountsOnDefaults.length} account
                {info.accountsOnDefaults.length === 1 ? ' is' : 's are'} still using the published
                password. Anyone who can reach this page can sign in. Change it from the account menu
                before putting this instance on a shared network.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
