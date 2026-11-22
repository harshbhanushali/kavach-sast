/**
 * A short guide: five steps, each ticked off from what the backend actually
 * reports, so it says where you are rather than describing a workflow in the
 * abstract.
 */
import { useEffect, useState } from 'react';
import { request } from '../api';
import type { App } from '../api';
import { Panel } from '../components/ui';
import { KavachHero } from '../components/KavachHero';
import type { HeroStage } from '../components/KavachHero';
import type { SastScan, ScanSummary } from '../sastTypes';

type Capability = {
  android: { full: boolean; note: string };
  ios: { available: boolean };
  pdf?: { available: boolean };
};

function Step({ index, done, title, children }: {
  index: number;
  done: boolean;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <li className="flex gap-3.5">
      <span
        aria-hidden
        className={`grid size-7 shrink-0 place-items-center rounded-full border text-sm font-bold ${
          done
            ? 'border-emerald-500 bg-emerald-500/20 text-emerald-200'
            : 'border-slate-600 bg-slate-800 text-slate-400'
        }`}
      >
        {done ? '✓' : index}
      </span>
      <div className="min-w-0 flex-1 pb-4">
        <h3 className="text-[0.95rem] font-semibold text-slate-50">{title}</h3>
        <div className="mt-1 text-sm leading-relaxed text-slate-300">{children}</div>
      </div>
    </li>
  );
}

const Strong = ({ children }: { children: React.ReactNode }) => (
  <strong className="text-slate-100">{children}</strong>
);

export function GuideScreen({ appId, apps, onGoTo, onNewApp }: {
  appId: string;
  apps: App[] | null;
  onGoTo: (tab: 'scan') => void;
  onNewApp: () => void;
}) {
  const [capability, setCapability] = useState<Capability | null>(null);
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  /** How many findings the latest scan has a decision recorded against. */
  const [decisions, setDecisions] = useState(0);

  useEffect(() => {
    request<Capability>('/v1/sast/capability').then(setCapability).catch(() => setCapability(null));
  }, []);

  useEffect(() => {
    const query = appId ? `?appId=${encodeURIComponent(appId)}` : '';
    request<{ scans: ScanSummary[] }>(`/v1/sast/scans${query}`)
      .then((r) => {
        setScans(r.scans);
        if (r.scans.length === 0) return setDecisions(0);
        return request<SastScan>(`/v1/sast/scans/${encodeURIComponent(r.scans[0].scanId)}`)
          .then((scan) => setDecisions(Object.keys(scan.triage ?? {}).length))
          .catch(() => setDecisions(0));
      })
      .catch(() => setScans([]));
  }, [appId]);

  const ready = capability?.android.full === true;
  const hasApp = Boolean(apps?.find((a) => a.appId === appId));
  const scanCount = scans?.length ?? 0;
  const hasScan = scanCount > 0;
  const latest = scans?.[0];
  const pdfReady = capability?.pdf?.available === true;
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

  const stages: HeroStage[] = [
    {
      id: 'scan',
      title: 'Scan',
      detail: !ready && capability
        ? 'Limited: full Android scanning is not available on this server.'
        : hasScan
          ? `${plural(scanCount, 'scan')} taken. Upload another build any time.`
          : 'Upload an APK or IPA, with no source code needed.',
      state: !ready && capability ? 'blocked' : hasScan ? 'done' : 'current',
    },
    {
      id: 'review',
      title: 'Review findings',
      detail: latest
        ? `Latest: ${latest.fileName}, grade ${latest.grade} (${latest.score}), ${plural(latest.findings, 'finding')}.`
        : 'Score, grade and what to fix, once a scan exists.',
      state: decisions > 0 ? 'done' : hasScan ? 'current' : 'todo',
    },
    {
      id: 'triage',
      title: 'Decide',
      detail: decisions > 0
        ? `${plural(decisions, 'decision')} recorded on the latest scan.`
        : 'Mark each finding confirmed, false positive, accepted or fixed.',
      state: decisions > 0 ? 'done' : 'todo',
    },
    {
      id: 'report',
      title: 'Report',
      detail: capability && !pdfReady
        ? 'PDF export is not available on this server. JSON and SARIF still work.'
        : 'Export a PDF to hand over, or JSON and SARIF for tools.',
      state: capability && !pdfReady ? 'blocked' : decisions > 0 ? 'current' : 'todo',
    },
  ];

  return (
    <div className="space-y-5">
    <KavachHero stages={stages} onGoTo={() => onGoTo('scan')} />
    <Panel title="Step by step">
      <ol>
        <Step index={1} done={ready} title="Check the scanner is ready">
          {capability === null ? (
            'Checking…'
          ) : ready ? (
            'Full Android and iOS scanning is available on this server.'
          ) : (
            'Full Android scanning is not available on this server, so Android scans will be limited. Ask whoever runs this server to check its setup.'
          )}
        </Step>

        <Step index={2} done={hasApp} title="Your app is created for you">
          You do not need to set anything up. The first time you scan an app, Kavach registers it from its
          package name and selects it. Scan a new build of the same app and the two are tracked together:
          your decisions carry over, and the Overview shows whether it is getting better. Use{' '}
          <button type="button" className="text-ember-300 underline" onClick={onNewApp}>Register an app</button> only if
          you want to register one by hand.
        </Step>

        <Step index={3} done={hasScan} title="Scan an app">
          On <button type="button" className="text-ember-300 underline" onClick={() => onGoTo('scan')}>Scan</button>,
          choose an <Strong>.apk</Strong> or <Strong>.ipa</Strong> and press <Strong>Run scan</Strong>. It takes
          from a few seconds to a couple of minutes.
        </Step>

        <Step index={4} done={false} title="Review and decide">
          Start at <Strong>Overview</Strong> (score and grade), then <Strong>Findings</Strong>. Open a finding to
          see why it matters and how to fix it, then mark it <Strong>Confirmed</Strong>,{' '}
          <Strong>False positive</Strong>, <Strong>Accepted risk</Strong> or <Strong>Fixed</Strong> with a reason.
        </Step>

        <Step index={5} done={false} title="Export">
          <Strong>Preview &amp; export</Strong> gives a PDF report to hand over. <Strong>Export JSON</Strong> is the raw
          data. <Strong>Export SARIF</Strong> is for developer tools and is optional.
        </Step>
      </ol>
    </Panel>
    </div>
  );
}
