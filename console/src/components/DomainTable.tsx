/**
 * Every host the artifact mentions.
 *
 * The findings answer "what is wrong"; this answers "who does this app talk
 * to". A reviewer usually asks the second question first, and until now the
 * answer was a comma-separated line buried in the reconnaissance panel.
 *
 * Sorted worst first — cleartext, then loopback, then non-production — because
 * that is the order someone works through them.
 */
import { useState } from 'react';
import type { DomainRow } from '../sastTypes';

const ENVIRONMENT: Record<string, { label: string; className: string; hint: string }> = {
  'non-production': {
    label: 'non-production',
    className: 'border-amber-500/50 bg-amber-500/10 text-amber-200',
    hint: 'The hostname says development, QA, staging or demo. Those environments are usually less hardened than production, and shipping their addresses tells an attacker they exist.',
  },
  local: {
    label: 'local',
    className: 'border-ember-500/50 bg-ember-500/10 text-ember-200',
    hint: 'Loopback or the Android emulator host. Harmless in itself — the traffic never leaves the device — but it means a developer build’s configuration reached the shipped artifact.',
  },
  production: {
    label: 'production',
    className: 'border-slate-700 bg-slate-800/60 text-slate-300',
    hint: 'No environment marker in the name.',
  },
  unknown: {
    label: '—',
    className: 'border-slate-700 bg-slate-800/40 text-slate-400',
    hint: 'No environment marker in the hostname. Most likely production, but the scan will not claim that as a fact.',
  },
};

export function DomainTable({ domains }: { domains: DomainRow[] }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [only, setOnly] = useState<'all' | 'cleartext' | 'non-production'>('all');

  const counts = {
    all: domains.length,
    cleartext: domains.filter((d) => d.cleartext).length,
    'non-production': domains.filter((d) => d.environment === 'non-production' || d.environment === 'local').length,
  };

  const shown = domains.filter((d) =>
    only === 'all'
      ? true
      : only === 'cleartext'
        ? d.cleartext
        : d.environment === 'non-production' || d.environment === 'local',
  );

  if (domains.length === 0) {
    return (
      <p className="text-sm text-slate-400">
        No URLs were found in the artifact. That is unusual for a networked app — read the coverage
        note before treating it as a clean result.
      </p>
    );
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        {([
          ['all', 'All hosts', 'border-slate-400 bg-slate-100 text-slate-900'],
          ['cleartext', 'Cleartext', 'border-rose-500/60 bg-rose-500/15 text-rose-200'],
          ['non-production', 'Non-production', 'border-amber-500/60 bg-amber-500/15 text-amber-200'],
        ] as const).map(([key, label, active]) => (
          <button
            key={key}
            type="button"
            disabled={counts[key] === 0}
            onClick={() => setOnly(key)}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition disabled:opacity-40 ${
              only === key ? active : 'border-slate-700 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            {label} <span className="tabular-nums">{counts[key]}</span>
          </button>
        ))}
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/60 text-left text-[11px] uppercase tracking-wide text-slate-400">
              <th className="px-3 py-2 font-semibold">Host</th>
              <th className="px-3 py-2 font-semibold">Scheme</th>
              <th className="px-3 py-2 font-semibold">Environment</th>
              <th className="px-3 py-2 text-right font-semibold">URLs</th>
              <th className="px-3 py-2 text-right font-semibold">Files</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {shown.map((d) => {
              const env = ENVIRONMENT[d.environment] ?? ENVIRONMENT.unknown;
              const isOpen = open.has(d.host);
              return (
                <>
                  <tr
                    key={d.host}
                    className={`transition-colors hover:bg-slate-800/40 ${d.cleartext ? 'bg-rose-500/5' : ''}`}
                  >
                    <td className="px-3 py-2 font-mono text-[13px] text-slate-100">{d.host}</td>
                    <td className="px-3 py-2">
                      {d.schemes.map((s) => (
                        <span
                          key={s}
                          className={`mr-1 rounded px-1.5 py-0.5 text-[11px] font-semibold ${
                            s === 'http'
                              ? 'bg-rose-500/20 text-rose-200 ring-1 ring-inset ring-rose-500/40'
                              : 'bg-emerald-500/15 text-emerald-200 ring-1 ring-inset ring-emerald-500/30'
                          }`}
                        >
                          {s}
                        </span>
                      ))}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        title={env.hint}
                        className={`cursor-help rounded-full border px-2 py-0.5 text-[11px] font-medium ${env.className}`}
                      >
                        {env.label}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-400">{d.urlCount}</td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-400">{d.fileCount}</td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        onClick={() =>
                          setOpen((prev) => {
                            const next = new Set(prev);
                            if (next.has(d.host)) next.delete(d.host);
                            else next.add(d.host);
                            return next;
                          })
                        }
                        className="text-xs text-slate-500 transition-colors hover:text-ember-300"
                      >
                        {isOpen ? 'Hide' : 'URLs'}
                      </button>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr key={`${d.host}-detail`} className="bg-slate-950/50">
                      <td colSpan={6} className="px-3 py-3">
                        <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                          URLs ({d.urlCount})
                        </p>
                        <ul className="mt-1.5 space-y-0.5">
                          {d.urls.map((u) => (
                            <li key={u} className="break-all font-mono text-[12px] text-slate-300">
                              <span className={u.startsWith('http://') ? 'text-rose-300' : 'text-emerald-300'}>
                                {u.startsWith('http://') ? 'http://' : 'https://'}
                              </span>
                              {u.replace(/^https?:\/\//, '')}
                            </li>
                          ))}
                        </ul>
                        <p className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                          Found in ({d.fileCount})
                        </p>
                        <ul className="mt-1.5 space-y-0.5">
                          {d.files.map((f) => (
                            <li key={f} className="break-all font-mono text-[12px] text-ember-300/80">
                              {f}
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-xs leading-relaxed text-slate-500">
        Extracted by reading the artifact. None of these hosts was contacted, resolved or looked up.
      </p>
    </div>
  );
}
