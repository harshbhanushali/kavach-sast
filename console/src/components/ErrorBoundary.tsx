/**
 * A screen that throws should say so, not leave a black page. The usual cause in
 * development is a console newer than the backend it talks to (a route or a
 * field that does not exist yet), so the message points at restarting it.
 */
import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

type State = { error: Error | null };

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('console crashed', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="mx-auto mt-24 max-w-xl rounded-xl border border-rose-900/60 bg-rose-950/30 p-6 text-rose-100">
        <p className="text-base font-semibold">The console hit an error and stopped.</p>
        <p className="mt-2 text-sm leading-relaxed">
          If you just updated the code, the backend is probably older than this console. Restart it
          (<code className="text-rose-50">npm run backend</code>) and reload this page.
        </p>
        <pre className="mt-3 overflow-auto rounded-md bg-slate-950/70 p-3 text-xs text-rose-200">{error.message}</pre>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="mt-4 rounded-md border border-rose-700 px-3 py-1.5 text-sm font-medium hover:bg-rose-900/40"
        >
          Reload
        </button>
      </div>
    );
  }
}
