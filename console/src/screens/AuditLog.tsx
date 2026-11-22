import { useEffect, useState } from 'react';
import { request } from '../api';
import { Empty, Panel } from '../components/ui';

type Entry = {
  id: number;
  at: string;
  actor: string;
  role: string;
  action: string;
  appId: string | null;
  subject: string | null;
  detail: string;
};

export function AuditLog({ appId }: { appId: string }) {
  const [entries, setEntries] = useState<Entry[] | null>(null);

  useEffect(() => {
    request<{ entries: Entry[] }>(`/v1/audit?appId=${encodeURIComponent(appId)}`)
      .then((r) => setEntries(r.entries))
      .catch(() => setEntries([]));
  }, [appId]);

  if (!entries) return <Panel title="Audit log"><Empty>Loading…</Empty></Panel>;

  return (
    <Panel title="Audit log" subtitle="Who changed which check, when, and from what value to what.">
      {entries.length === 0 ? (
        <Empty>Nothing recorded yet.</Empty>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-slate-300">
            <tr>
              <th className="py-2 pr-4 font-semibold">When</th>
              <th className="py-2 pr-4 font-semibold">Actor</th>
              <th className="py-2 pr-4 font-semibold">Action</th>
              <th className="py-2 pr-4 font-semibold">Subject</th>
              <th className="py-2 font-semibold">Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="py-2 pr-4 whitespace-nowrap text-slate-400">
                  {new Date(e.at).toLocaleString()}
                </td>
                <td className="py-2 pr-4 text-slate-200">
                  {e.actor} <span className="text-slate-400">({e.role})</span>
                </td>
                <td className="py-2 pr-4 text-slate-300">{e.action}</td>
                <td className="py-1.5 pr-3"><code className="text-xs text-slate-300">{e.subject ?? '—'}</code></td>
                <td className="py-2 text-slate-300">{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
