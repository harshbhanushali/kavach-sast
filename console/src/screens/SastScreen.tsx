/**
 * Static analysis screen: upload an APK or IPA, read the scorecard.
 *
 * This is a review tool and the UI says so. Nothing here changes a policy or a
 * build — it reads an artifact and reports what is in it, which is a different
 * question from what the RASP checks answer at runtime.
 *
 * The page is organised the way a reviewer actually works: triage first (what must
 * I fix, what must I decide, what is already right), then the evidence behind each
 * of those.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { NavButton, NavGroup, useShell } from '../components/shell';
import type { ScanView } from '../components/Sidebar';
import { ApiError, getToken, request } from '../api';
import { Button, Empty, Panel } from '../components/ui';
import { ScanCompare } from '../components/ScanCompare';
import { LineFlags, OpenInExplorer, lineFlagIndex } from '../components/FindingDetail';
import { CodeExplorer } from '../components/CodeExplorer';
import { ScanReplay } from '../components/sast/ScanReplay';
import { LiveScanMap } from '../components/sast/LiveScanMap';
import { LiveMap } from '../components/sast/liveModel.ts';
import { HowToVerify } from '../components/HowToVerify';
import { DomainTable } from '../components/DomainTable';
import { IosOverview } from '../components/ios/IosOverview';
import { IosSurface } from '../components/ios/IosSurface';
import { IosTrust } from '../components/ios/IosTrust';
import { IosHardening } from '../components/ios/IosHardening';
import { AndroidOverview } from '../components/android/AndroidOverview';
import { AndroidSurface } from '../components/android/AndroidSurface';
import { AndroidTrust } from '../components/android/AndroidTrust';
import { AndroidHardening } from '../components/android/AndroidHardening';
import { SastChains } from '../components/sast/Chains';
import { splitChains } from '../components/sast/chainModel';
import { SastControls } from '../components/sast/Controls';
import { controlsOf, effectiveOf, summariseControls } from '../components/sast/model';
import type { StatusFilter } from '../components/sast/model';
import { FindingRow, SastFindings } from '../components/sast/Findings';
import { TriageContext, countLabel } from '../components/sast/triageUi';
import type { TriageApi } from '../components/sast/triageUi';
import type { CurrentUser } from '../components/AccountMenu';
import { isActive, mergeReview } from '../triage';
import { IdentityStrip } from '../components/sast/IdentityStrip';
import { ReportPreview } from '../components/sast/ReportPreview';
import type { SastScan, ScanSummary, TriageEntry } from '../sastTypes';
import type { LiveEventIn } from '../components/sast/liveModel.ts';

type Capability = {
  android: { available: boolean; full: boolean; signing: boolean; note: string };
  ios: { available: boolean; full: boolean; note: string };
  maxBytes: number;
};

/** A grade as a chip: the colour says how bad before the number is read. */
const GRADE_CHIP: Record<string, string> = {
  A: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  B: 'border-lime-500/40 bg-lime-500/10 text-lime-300',
  C: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  D: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  F: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

/** "5 minutes ago", for a list where the exact time is a hover away. */
function ago(iso: string): string {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  const units: [number, string][] = [[60, 'minute'], [3600, 'hour'], [86400, 'day'], [2592000, 'month'], [31536000, 'year']];
  let best = units[0];
  for (const u of units) if (seconds >= u[0]) best = u;
  const n = Math.floor(seconds / best[0]);
  return `${n} ${best[1]}${n === 1 ? '' : 's'} ago`;
}

const LEVEL_STYLES: Record<string, string> = {
  dangerous: 'text-rose-300',
  signature: 'text-orange-300',
  unknown: 'text-slate-400',
  normal: 'text-emerald-300',
};

function bytes(n: number): string {
  return n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(2)} MB` : `${(n / 1024).toFixed(0)} KB`;
}

/** A copyable hash row. The value is the point, so it gets the width. */
function HashRow({
  label, value, hint, strong,
}: { label: string; value: string; hint: string; strong?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className={`flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2 ${
        strong ? 'border-ember-500/30 bg-ember-500/5' : 'border-slate-800 bg-slate-950/60'
      }`}
    >
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</span>
      <code
        className={`min-w-0 flex-1 break-all font-mono ${
          strong ? 'text-[13px] font-semibold text-ember-200' : 'text-xs text-slate-400'
        }`}
      >
        {value}
      </code>
      <span className="font-mono text-[11px] text-slate-600">{hint}</span>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1400);
          }).catch(() => undefined);
        }}
        className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

/**
 * The two digests that identify a scan: the artifact's own SHA-256 leads, since
 * it names the thing under test. The report digest describes the verdict, which
 * is only meaningful once you know the binary.
 */
function IntegrityRows({ scan }: { scan: SastScan }) {
  return (
    <div className="mt-5 space-y-2">
      <HashRow
        label="Application SHA-256"
        value={scan.artifact.sha256}
        hint={`shasum -a 256 ${scan.artifact.fileName}`}
        strong
      />
      <HashRow label="Report digest" value={scan.reportHash} hint="artifact + score + findings" />
    </div>
  );
}

/**
 * The report is long — a scorecard, three finding lists, permissions,
 * dependencies and native hardening. As one scroll it buries
 * the thing a reader came for. Tabs put each question on its own page and make
 * the counts visible before you commit to a click.
 */
type Tab =
  | 'overview' | 'findings' | 'chains' | 'secrets' | 'binary' | 'controls' | 'surface' | 'trust'
  | 'permissions' | 'dependencies' | 'domains' | 'replay' | 'explorer' | 'verify';

/** How the report's pages are grouped in the sidebar. */
const TAB_GROUPS: { title: string; keys: Tab[] }[] = [
  { title: 'Results', keys: ['overview', 'findings', 'chains', 'secrets'] },
  { title: 'Inspect', keys: ['surface', 'trust', 'binary', 'controls', 'permissions', 'dependencies', 'domains'] },
  { title: 'Explore', keys: ['replay', 'explorer', 'verify'] },
];

const TAB_ICON: Record<Tab, string> = {
  overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  findings: 'M4 22V4m0 0h12l-2 4 2 4H4',
  chains: 'M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1',
  secrets: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 11-7.8 7.8 5.5 5.5 0 017.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3',
  surface: 'M12 3a9 9 0 100 18 9 9 0 000-18zm0 6a3 3 0 100 6 3 3 0 000-6z',
  trust: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zm-3 9l2 2 4-4',
  binary: 'M7 7h10v10H7zM9 1v3m6-3v3M9 20v3m6-3v3M1 9h3m-3 6h3m16-6h3m-3 6h3',
  controls: 'M4 21v-7m0-4V3m8 18v-9m0-4V3m8 18v-5m0-4V3M1 14h6M9 8h6m2 8h6',
  permissions: 'M5 11h14v10H5zM8 11V7a4 4 0 118 0v4',
  dependencies: 'M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8',
  domains: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  replay: 'M12 3a9 9 0 100 18 9 9 0 000-18zM10 8.5l5.5 3.5-5.5 3.5z',
  explorer: 'M8 8l-4 4 4 4m8-8l4 4-4 4m-5 2l2-12',
  verify: 'M9 11l3 3 8-8M20 12v7a2 2 0 01-2 2H6a2 2 0 01-2-2V7a2 2 0 012-2h9',
};

/**
 * The report's pages, drawn into the app's sidebar (see components/shell.tsx)
 * rather than on this screen, so there is one rail down the left and the
 * report gets the full width.
 */
function TabBar({
  tab, onChange, tabs,
}: {
  tab: Tab;
  onChange: (t: Tab) => void;
  tabs: { key: Tab; label: string; count?: number; tone?: 'alert' }[];
}) {
  const { sections } = useShell();
  if (!sections) return null;
  const byKey = new Map(tabs.map((t) => [t.key, t]));
  return createPortal(
    <>
      {TAB_GROUPS.map((group, gi) => {
        const items = group.keys.map((k) => byKey.get(k)).filter((t): t is NonNullable<typeof t> => Boolean(t));
        if (items.length === 0) return null;
        return (
          <NavGroup key={group.title} title={group.title} first={gi === 0}>
            {items.map((t) => (
              <NavButton
                key={t.key}
                icon={TAB_ICON[t.key]}
                label={t.label}
                count={t.count}
                tone={t.tone}
                active={tab === t.key}
                onClick={() => onChange(t.key)}
              />
            ))}
          </NavGroup>
        );
      })}
    </>,
    sections,
  );
}

/** The whole scan as JSON, for anything this console does not show. */
function exportJson(scan: SastScan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${scan.artifact.fileName.replace(/\.(apk|ipa)$/i, '')}-scan.json`;
  link.click();
  URL.revokeObjectURL(url);
}

/** The scan as SARIF, fetched with the session token (a plain link would not carry it). */
async function exportSarif(scan: SastScan): Promise<void> {
  const response = await fetch(`/v1/sast/scans/${encodeURIComponent(scan.scanId)}/sarif`, {
    headers: { authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) throw new Error(`SARIF export failed (${response.status})`);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = `${scan.artifact.fileName.replace(/\.(apk|ipa)$/i, '')}.sarif`;
  link.click();
  URL.revokeObjectURL(url);
}

export function SastScreen({ appId, onAppResolved, view, onView }: {
  appId: string;
  /** Which page of the Scan section is showing; chosen in the sidebar. */
  view: ScanView;
  onView: (view: ScanView) => void;
  /** Called after a scan files itself under an app, so the shell can select it (and list it, if it was just created). */
  onAppResolved?: (appId: string, created: boolean, redirectedFrom?: string | null) => void;
}) {
  const [capability, setCapability] = useState<Capability | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  // What the server sent. `scan` below is the same scan with its review items listed among the defects, as one list.
  const [rawScan, setScan] = useState<SastScan | null>(null);
  const scan = useMemo(() => (rawScan ? mergeReview(rawScan) : null), [rawScan]);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<
    { stage: 'uploading' | 'analysing'; percent: number; label?: string } | null
  >(null);
  // The live map of a scan in progress; set once the server starts sending events (an Android scan does, an iOS one does not).
  const [live, setLive] = useState<LiveMap | null>(null);
  /** Set by "Show the report" to cut the play-out of a finished scan short. */
  const skip = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  // The report is only a page while one is loaded; without one, "report" is the upload page.
  const mode: ScanView = view === 'report' && !scan ? 'scan' : view;
  const [tab, setTab] = useState<Tab>('overview');
  // A link on the overview can open the Findings tab already narrowed by status.
  const [findingsStatus, setFindingsStatus] = useState<StatusFilter>('all');
  // Who is signed in, to know whether the triage form is offered. Asked of the
  // server (as the console does on load) rather than assumed: unknown means read-only.
  const [role, setRole] = useState<string | null>(null);
  // Set when a finding's "View file" is clicked. The nonce makes repeat clicks
  // on the same location re-trigger the jump.
  const [jumpTo, setJumpTo] = useState<{ path: string; line?: number; nonce: number }>();
  /** Paths the explorer holds, so a location knows whether it can be opened. */
  const [openablePaths, setOpenablePaths] = useState<Set<string>>(new Set());

  useEffect(() => {
    request<CurrentUser>('/v1/auth/me').then((me) => setRole(me.role)).catch(() => setRole(null));
  }, []);

  useEffect(() => {
    request<Capability>('/v1/sast/capability').then(setCapability).catch(() => setCapability(null));
  }, []);

  /** The scans listed under "Scan history": the selected app's, or all of them when none is selected. */
  const history = appId ? scans.filter((s) => s.appId === appId) : scans;

  function refreshHistory() {
    request<{ scans: ScanSummary[] }>('/v1/sast/scans')
      .then((r) => setScans(r.scans))
      .catch(() => setScans([]));
  }
  useEffect(refreshHistory, []);

  /**
   * One finding open at a time. Opening another closes the first, so the list stays a list
   * and not a wall of evidence, and the page does not grow with every row looked at.
   */
  function toggle(id: string) {
    setOpen((prev) => (prev.has(id) ? new Set() : new Set([id])));
    // Closing a row above shifts everything up; bring the one just opened back to where it can be seen.
    requestAnimationFrame(() =>
      requestAnimationFrame(() =>
        document.getElementById(`finding-${id}`)?.closest('li')?.scrollIntoView({ block: 'nearest' }),
      ),
    );
  }

  /**
   * Upload with a real progress bar.
   *
   * `fetch` cannot report upload progress — there is no event for it — so this
   * uses XMLHttpRequest, which can. It matters here because an APK is often
   * hundreds of megabytes: without it the button says "Scanning..." for a
   * minute and a half with no way to tell a slow upload from a hung one.
   *
   * Two phases, because they fail differently and only one of them is
   * measurable. Upload progress is known to the byte; the analysis that follows
   * reports nothing until it finishes, so claiming a percentage for it would be
   * inventing one.
   */
  async function upload() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setScan(null);
    setPhase({ stage: 'uploading', percent: 0 });

    // The server keys its progress on this, so the console can poll while the
    // upload request is still open.
    const progressId = crypto.randomUUID();
    let poll: ReturnType<typeof setInterval> | undefined;
    // The map the scan's events build, and the poll that feeds it. Kept out here so the last of the events can
    // be read, and played out, after the scan itself has finished.
    const feed: { map: LiveMap | null; cursor: number; pulling?: Promise<void>; pull?: () => Promise<void> | undefined } = { map: null, cursor: 0 };
    skip.current = false;

    const form = new FormData();
    form.append('artifact', file);
    form.append('progressId', progressId);
    if (appId) form.append('appId', appId);

    try {
      const result = await new Promise<{ ok: boolean; body: unknown }>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/v1/sast/scan');
        xhr.setRequestHeader('authorization', `Bearer ${getToken()}`);

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            setPhase({ stage: 'uploading', percent: Math.round((e.loaded / e.total) * 100) });
          }
        };
        // The last byte is sent; everything after this is the server working,
        // so from here the percentage comes from the server's own stages
        // rather than from anything the browser can see.
        xhr.upload.onload = () => {
          setPhase({ stage: 'analysing', percent: 0, label: 'Starting' });
          // Events (files found, files read, rule matches) ride on the same poll, from a cursor. A full page
          // means there is more, so it asks again straight away.
          feed.pull = () => {
            if (feed.pulling) return feed.pulling;
            feed.pulling = request<{ stage: string; percent: number; label: string; events?: LiveEventIn[]; next?: number }>(
              `/v1/sast/progress/${progressId}?after=${feed.cursor}`,
            )
              .then((p) => {
                if (p.events && p.events.length > 0) {
                  if (!feed.map) {
                    feed.map = new LiveMap();
                    setLive(feed.map);
                  }
                  feed.map.push(p.events);
                  feed.cursor = p.next ?? feed.cursor + p.events.length;
                }
                // Never let the bar go backwards: a poll that races the next
                // stage would make it stutter.
                setPhase((prev) =>
                  prev && prev.stage === 'analysing'
                    ? { stage: 'analysing', percent: Math.max(prev.percent, p.percent), label: p.label }
                    : prev,
                );
                feed.pulling = undefined;
                return p.events && p.events.length >= 400 ? feed.pull?.() : undefined;
              })
              .catch(() => {
                feed.pulling = undefined;
              });
            return feed.pulling;
          };
          poll = setInterval(() => void feed.pull?.(), 350);
        };

        xhr.onload = () => {
          try {
            resolve({ ok: xhr.status >= 200 && xhr.status < 300, body: JSON.parse(xhr.responseText) });
          } catch {
            reject(new Error(`the server replied with ${xhr.status} and a body that is not JSON`));
          }
        };
        xhr.onerror = () => reject(new Error('Could not reach the backend. Is it running?'));
        xhr.onabort = () => reject(new Error('upload cancelled'));
        xhr.send(form);
      });

      if (!result.ok) setError((result.body as { error?: string }).error ?? 'scan failed');
      else {
        // A short scan (an iOS app takes a couple of seconds) is over before most of it has been drawn. Read what
        // is left of the feed and let the map play it out, for a few seconds at most; "Show the report" skips it.
        if (poll) clearInterval(poll);
        await feed.pull?.();
        const started = Date.now();
        if (feed.map && feed.map.backlog > 0) {
          setPhase({ stage: 'analysing', percent: 100, label: 'Playing back the scan' });
          while (!skip.current && feed.map.backlog > 0 && Date.now() - started < 6000) await new Promise((r) => setTimeout(r, 120));
          if (!skip.current) await new Promise((r) => setTimeout(r, 900));
        }
        const body = result.body as SastScan & { appId?: string | null; appCreated?: boolean; appRedirectedFrom?: string | null };
        setScan(body);
        setTab('overview');
        onView('report');
        refreshHistory();
        if (body.appId) onAppResolved?.(body.appId, body.appCreated === true, body.appRedirectedFrom);
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      if (poll) clearInterval(poll);
      setBusy(false);
      setPhase(null);
      setLive(null);
    }
  }

  async function load(scanId: string) {
    setError(null);
    try {
      setScan(await request<SastScan>(`/v1/sast/scans/${scanId}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }

  async function remove(scanId: string) {
    if (!confirm('Delete this scan? The report will not be recoverable.')) return;
    await request(`/v1/sast/scans/${scanId}`, { method: 'DELETE' }).catch(() => undefined);
    if (scan?.scanId === scanId) setScan(null);
    refreshHistory();
  }

  const a = scan?.artifact;

  // Any signed-in user records decisions. This product has the one `user`
  // role; `null` (not yet loaded, or /auth/me failed) stays read-only.
  const canTriage = role === 'user';
  const [previewOpen, setPreviewOpen] = useState(false);

  /**
   * Record one decision and fold the server's answer into the scan held here.
   * The report export and every tab read `scan.triage` from this state, so
   * updating it is what makes a decision show up everywhere at once. Rejects
   * with the server's own message (reason too short, past expiry, 403...).
   */
  const triageApi = useMemo<TriageApi | null>(() => {
    if (!scan) return null;
    const scanId = scan.scanId;
    return {
      scan,
      canEdit: canTriage,
      save: async (ruleId, body) => {
        const res = await request<{ ruleId: string; entry: TriageEntry | null }>(
          `/v1/sast/scans/${encodeURIComponent(scanId)}/triage/${encodeURIComponent(ruleId)}`,
          { method: 'PUT', body },
        ).catch((error) => {
          // The framework's own 404 means the route is missing: a backend started before triage existed.
          // The route's own 404s say "no such scan" or name the finding, so they pass through untouched.
          if (error instanceof ApiError && error.status === 404 && error.message === 'Not Found') {
            throw new Error('This backend does not support triage yet. Restart the backend to load the latest version, then try again.');
          }
          throw error;
        });
        setScan((prev) => {
          // The reviewer may have opened another scan while this was in flight.
          if (!prev || prev.scanId !== scanId) return prev;
          const triage = { ...(prev.triage ?? {}) };
          if (res.entry) triage[ruleId] = res.entry;
          else delete triage[ruleId];
          return { ...prev, triage };
        });
      },
    };
  }, [scan, canTriage]);

  // What the overview, the tab badges and the hero count once decisions apply.
  const eff = scan ? effectiveOf(scan) : null;
  // Lines more than one finding sits on, so each code window can point at the others.
  const lineFlags = useMemo(() => (scan ? lineFlagIndex([...scan.findings, ...scan.hotspots]) : null), [scan]);

  // Secrets get their own tab, drawn from both lists: an entropy match is a
  // hotspot and a matched credential format is a defect, but someone looking
  // for "what did we leak" wants them in one place.
  const secretFindings = scan
    ? [...scan.findings, ...scan.hotspots].filter((f) => f.category === 'secrets')
    : [];
  const activeSecrets = scan ? secretFindings.filter((f) => isActive(scan, f.ruleId)).length : 0;

  // Which lines of which files a finding landed on, so the explorer can mark
  // them. Built from both lists: a hotspot is still worth seeing in the file.
  const flaggedLines = useMemo(() => {
    const map = new Map<string, Set<number>>();
    for (const f of [...(scan?.findings ?? []), ...(scan?.hotspots ?? [])]) {
      for (const l of f.locations) {
        if (!l.line) continue;
        if (!map.has(l.file)) map.set(l.file, new Set());
        map.get(l.file)!.add(l.line);
      }
    }
    return map;
  }, [scan]);

  // Fetched once per scan: the explorer's own listing, used only to decide
  // which locations get a "View file" button. A scan just uploaded has no
  // `retainedFiles` yet (the server stores the sources after it replies) but is
  // `filesPending`; the listing waits for them, so ask for it then too.
  useEffect(() => {
    if (!scan?.scanId || (!scan.retainedFiles && !scan.filesPending)) {
      setOpenablePaths(new Set());
      return;
    }
    request<{ files: { path: string }[] }>(`/v1/sast/scans/${scan.scanId}/files`)
      .then((r) => setOpenablePaths(new Set(r.files.map((f) => f.path))))
      .catch(() => setOpenablePaths(new Set()));
  }, [scan?.scanId, scan?.retainedFiles, scan?.filesPending]);

  const explorerLink = useMemo(
    () => ({
      open: (path: string, line?: number) => {
        setJumpTo({ path, line, nonce: Date.now() });
        setTab('explorer');
        // Instant, not smooth: a smooth page scroll is still animating when
        // the explorer tries to position the code pane, and the two fight.
        window.scrollTo({ top: 0 });
      },
      canOpen: (path: string) => openablePaths.has(path),
    }),
    [openablePaths],
  );

  // A tab with nothing behind it is not offered. An empty "Dependencies" page
  // says the scan failed; not offering it says the artifact has none to show,
  // which is the truth.
  const tabs: { key: Tab; label: string; count?: number; tone?: 'alert' }[] = scan && a
    ? [
        { key: 'overview', label: 'Overview' },
        {
          key: 'findings',
          label: 'Findings',
          count: eff!.findings.length,
          tone: 'alert' as const,
        },
        // Only when the findings join up into something: a page that says "none" would read as a clean bill
        // of health, which is more than a pattern scanner can claim.
        ...((scan.chains?.length ?? 0) > 0
          ? [
              {
                key: 'chains' as const,
                label: 'Attack chains',
                count: splitChains(scan).standing.length,
                ...(splitChains(scan).standing.length > 0 ? { tone: 'alert' as const } : {}),
              },
            ]
          : []),
        // Attack surface, trust and hardening exist for both platforms and read
        // the same; only the facts behind them differ. A scan taken before the
        // backend recorded `artifact.ios` / `artifact.android` still gets the
        // tabs and shows "not present" states (Android falls back to the
        // counts it does have).
        { key: 'surface' as const, label: 'Attack surface' },
        { key: 'trust' as const, label: 'Trust & signing' },
        {
          key: 'binary' as const,
          label: 'Hardening',
          count: a.ios ? a.ios.binaries.length + 1 : a.nativeLibraryDetail.length,
        },
        // Only for scans that carry controls: an older scan has nothing to list,
        // and a tab that says "rescan" is a worse offer than no tab.
        ...(controlsOf(scan)
          ? [{ key: 'controls' as const, label: 'Controls', count: summariseControls(controlsOf(scan)!).detected }]
          : []),
        ...(secretFindings.length > 0 || scan.recon.keyFiles.length > 0
          ? [{ key: 'secrets' as const, label: 'Secrets', count: activeSecrets }]
          : []),
        // Android's permissions and dependencies live in Trust & signing and
        // Hardening; iOS keeps the standalone tabs.
        ...(a.platform !== 'android' && a.permissionDetail.length > 0
          ? [{ key: 'permissions' as const, label: 'Permissions', count: a.permissionDetail.length }]
          : []),
        ...(a.platform !== 'android' && a.dependencies.length > 0
          ? [{ key: 'dependencies' as const, label: 'Dependencies', count: a.dependencies.length }]
          : []),
        ...((scan.domains?.length ?? 0) > 0
          ? [{ key: 'domains' as const, label: 'Domains', count: scan.domains!.length }]
          : []),
        ...((scan.retainedFiles && scan.retainedFiles > 0) || scan.filesPending
          ? [
              { key: 'replay' as const, label: 'Replay' },
              { key: 'explorer' as const, label: 'Explorer', count: scan.retainedFiles || undefined },
            ]
          : []),
        { key: 'verify', label: 'How to verify' },
      ]
    : [];

  // Loading a different scan can remove the tab that is open — an iOS artifact
  // has no dependency list. Falling back beats rendering a blank page.
  const activeTab: Tab = tabs.some((t) => t.key === tab) ? tab : 'overview';

  /** A card on the iOS overview sending the reader to the tab behind it. */
  function goTo(next: Tab, opts?: { status?: StatusFilter }) {
    setFindingsStatus(opts?.status ?? 'all');
    setTab(next);
    window.scrollTo({ top: 0 });
  }

  return (
    <div className="space-y-5">
      {mode === 'compare' && <ScanCompare scans={history} appSelected={Boolean(appId)} />}

      {mode === 'scan' && scan && a && !busy && (
        <button
          type="button"
          onClick={() => onView('report')}
          className="flex w-full items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-2.5 text-left text-sm text-slate-300 transition hover:border-ember-500/50 hover:text-slate-50"
        >
          <span>The report for <strong className="font-semibold text-slate-100">{scan.artifact.fileName}</strong> is still open.</span>
          <span className="shrink-0 font-medium text-ember-300">Back to the report →</span>
        </button>
      )}

      {mode === 'scan' && (
      <Panel
        title="Scan an app for shipped mistakes"
        subtitle="Upload an APK or IPA. This reads the artifact and reports what is in it — it does not change your policy, your build, or anything on a device."
      >
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="file"
            accept=".apk,.ipa"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setError(null);
            }}
            className="block w-full max-w-md text-sm text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-ember-500/15 file:px-3 file:py-2 file:text-sm file:font-medium file:text-ember-200 hover:file:bg-ember-500/25"
          />
          <Button onClick={upload} disabled={!file || busy} variant="primary">
            {busy ? 'Scanning…' : 'Run scan'}
          </Button>
          {file && <span className="text-sm text-slate-400">{bytes(file.size)}</span>}
        </div>

        {busy && phase && live && (
          <div className="mt-4">
            <LiveScanMap map={live} label={phase.label ?? 'Analysing'} percent={phase.percent} onSkip={phase.percent >= 100 ? () => { skip.current = true; } : undefined} />
          </div>
        )}

        {busy && phase && !live && (
          <div className="mt-4">
            <div className="mb-2 flex items-baseline justify-between gap-4">
              <span className="text-sm font-medium text-slate-100">
                {phase.stage === 'uploading'
                  ? `Uploading ${file ? bytes(file.size) : ''}`
                  : (phase.label ?? 'Analysing')}
              </span>
              <span className="shrink-0 text-lg font-bold tabular-nums text-ember-300">
                {phase.percent}%
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full rounded-full bg-ember-500 transition-[width] duration-500 ease-out"
                style={{ width: `${Math.max(2, phase.percent)}%` }}
              />
            </div>
            <p className="mt-2 text-xs text-slate-500">
              {phase.stage === 'uploading'
                ? 'The artifact is streamed to disk on the server and deleted when the scan finishes.'
                : 'The percentage tracks the stage the scan has reached. Some stages report nothing from inside their own work, so the bar moves in steps rather than smoothly.'}
            </p>
          </div>
        )}

        {capability && (
          <div className="mt-4 grid gap-2 text-sm text-slate-400 sm:grid-cols-2">
            <p><span className="font-medium text-slate-300">Android:</span> {capability.android.note}</p>
            <p><span className="font-medium text-slate-300">iOS:</span> {capability.ios.note}</p>
          </div>
        )}

        {error && (
          <p className="mt-3 rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-200 ring-1 ring-inset ring-rose-500/30">
            {error}
          </p>
        )}
      </Panel>

      )}

      {mode === 'report' && scan && a && (
        <TriageContext.Provider value={triageApi}>
          {previewOpen && <ReportPreview scan={scan} onClose={() => setPreviewOpen(false)} />}
        <OpenInExplorer.Provider value={explorerLink}>
        <LineFlags.Provider value={lineFlags}>
          {/* --- identity: which app this is, on every tab --- */}
          <IdentityStrip
            scan={scan}
            actions={
              <>
                <Button onClick={() => { setScan(null); onView('scan'); }}>New scan</Button>
                <Button onClick={() => exportJson(rawScan ?? scan)}>Export JSON</Button>
                <Button
                  onClick={() => exportSarif(scan).catch((e: Error) => setError(e.message))}
                  title="SARIF 2.1.0 for GitHub code scanning, Azure DevOps and CI. Triage decisions are included as suppressions."
                >
                  Export SARIF
                </Button>
                <Button onClick={() => setPreviewOpen(true)} variant="primary" title="Preview the report, then download it as a PDF">Preview &amp; export</Button>
              </>
            }
          />

          <TabBar tab={activeTab} onChange={(t) => { setFindingsStatus('all'); setTab(t); }} tabs={tabs} />

          {activeTab === 'overview' && (
            <>
              {a.platform === 'ios' ? (
                <IosOverview scan={scan} onNavigate={goTo}>
                  <IntegrityRows scan={scan} />
                </IosOverview>
              ) : (
                <AndroidOverview scan={scan} onNavigate={goTo}>
                  <IntegrityRows scan={scan} />
                </AndroidOverview>
              )}
            </>
          )}

          {activeTab === 'findings' && <SastFindings scan={scan} open={open} onToggle={toggle} initialStatus={findingsStatus} />}

          {activeTab === 'secrets' && (
            <>
          {/* --- secrets ---
              Given a tab of their own because they are the one category where
              the value itself is the finding: a reader needs to see the literal
              to judge whether it is live. Nothing here is masked, deliberately. */}
          <Panel
            title={`Hardcoded secrets (${countLabel(secretFindings.length, secretFindings.length - activeSecrets)})`}
            subtitle="Credentials compiled into the artifact, where anyone who downloads it can read them. Values are shown in full — a redacted report cannot be acted on."
          >
            {secretFindings.length === 0 ? (
              <Empty>No credential-shaped literals matched.</Empty>
            ) : (
              <ul className="space-y-2">
                {secretFindings.map((f) => (
                  <FindingRow
                    key={f.ruleId}
                    finding={f}
                    tone={f.kind === 'hotspot' ? 'hotspot' : 'defect'}
                    open={open.has(f.ruleId)}
                    onToggle={() => toggle(f.ruleId)}
                  />
                ))}
              </ul>
            )}
          </Panel>

          {(scan.recon.keyFiles.length > 0 || scan.recon.emails.length > 0) && (
            <Panel
              title="Bundled key material"
              subtitle="Certificate and key files shipped inside the artifact, and addresses found in it."
            >
              {scan.recon.keyFiles.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Certificate / key files ({scan.recon.keyFiles.length})
                  </p>
                  <ul className="mt-2 space-y-1">
                    {scan.recon.keyFiles.map((k) => (
                      <li key={k} className="font-mono text-xs text-slate-300">{k}</li>
                    ))}
                  </ul>
                </div>
              )}
              {scan.recon.emails.length > 0 && (
                <div className={scan.recon.keyFiles.length > 0 ? 'mt-4 border-t border-slate-800 pt-3' : ''}>
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Email addresses ({scan.recon.emails.length})
                  </p>
                  <p className="mt-1.5 font-mono text-xs leading-relaxed text-slate-400">
                    {scan.recon.emails.slice(0, 20).map((e) => e.address).join(', ')}
                  </p>
                </div>
              )}
            </Panel>
          )}
          {/* --- reconnaissance --- */}
          <Panel
            title="Reconnaissance"
            subtitle="Extracted from the artifact only. None of these hosts was contacted, resolved or looked up."
          >
            <div className="grid gap-5 lg:grid-cols-2">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Privacy trackers ({scan.recon.trackers.length})
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  Signatures from the Exodus Privacy database (ODbL 1.0), exodus-privacy.eu.org.
                </p>
                {scan.recon.trackers.length === 0 ? (
                  <p className="mt-1 text-sm text-emerald-300">None detected.</p>
                ) : (
                  <ul className="mt-2 space-y-1">
                    {scan.recon.trackers.map((t) => (
                      <li key={t.name} className="text-xs text-slate-300">
                        {t.name}
                        <span className="ml-2 text-slate-500">{t.category}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Hosts contacted ({scan.recon.hosts.length})
                </p>
                <p className="mt-2 font-mono text-xs leading-relaxed text-slate-400">
                  {scan.recon.hosts.length > 0 ? scan.recon.hosts.join(', ') : 'none found'}
                </p>
              </div>
            </div>

            {scan.recon.endpoints.some((e) => e.cleartext) && (
              <div className="mt-4 border-t border-slate-800 pt-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-rose-300">
                  Cleartext endpoints ({scan.recon.endpoints.filter((e) => e.cleartext).length})
                </p>
                <ul className="mt-1 space-y-0.5">
                  {scan.recon.endpoints.filter((e) => e.cleartext).slice(0, 15).map((e) => (
                    <li key={e.url} className="font-mono text-xs text-slate-400">{e.url}</li>
                  ))}
                </ul>
              </div>
            )}

            {(scan.recon.keyFiles.length > 0 || scan.recon.emails.length > 0) && (
              <div className="mt-4 grid gap-5 border-t border-slate-800 pt-3 lg:grid-cols-2">
                {scan.recon.keyFiles.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Certificate / key files ({scan.recon.keyFiles.length})
                    </p>
                    <p className="mt-1 font-mono text-xs text-slate-400">{scan.recon.keyFiles.join(', ')}</p>
                  </div>
                )}
                {scan.recon.emails.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Email addresses ({scan.recon.emails.length})
                    </p>
                    <p className="mt-1 font-mono text-xs text-slate-400">
                      {scan.recon.emails.slice(0, 12).map((e) => e.address).join(', ')}
                    </p>
                  </div>
                )}
              </div>
            )}
          </Panel>

            </>
          )}

          {activeTab === 'surface' && (a.platform === 'ios' ? <IosSurface scan={scan} onNavigate={goTo} /> : <AndroidSurface scan={scan} />)}
          {activeTab === 'trust' && (a.platform === 'ios' ? <IosTrust scan={scan} /> : <AndroidTrust scan={scan} />)}
          {activeTab === 'binary' && (a.platform === 'ios' ? <IosHardening scan={scan} /> : <AndroidHardening scan={scan} />)}

          {activeTab === 'chains' && <SastChains scan={scan} />}

          {activeTab === 'controls' && <SastControls scan={scan} />}

          {activeTab === 'permissions' && (
            <>
          {/* --- permissions --- */}
          {a.permissionDetail.length > 0 && (
            <Panel
              title={`Permissions (${a.permissionDetail.length})`}
              subtitle="Dangerous permissions prompt the user; normal ones are granted silently at install."
            >
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="pb-2 font-medium">Permission</th>
                    <th className="pb-2 font-medium">Level</th>
                    <th className="pb-2 font-medium">What it allows</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {a.permissionDetail.map((p) => (
                    <tr key={p.name} className="transition-colors hover:bg-slate-800/40">
                      <td className="py-1.5 pr-3 font-mono text-xs text-slate-300">
                        {p.name.replace('android.permission.', '')}
                      </td>
                      <td className={`py-1.5 pr-3 text-xs font-semibold uppercase ${LEVEL_STYLES[p.level] ?? ''}`}>
                        {p.level}
                      </td>
                      <td className="py-1.5 text-xs text-slate-400">{p.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}

            </>
          )}

          {activeTab === 'dependencies' && (
            <>
          {/* --- dependencies --- */}
          {a.dependencies.length > 0 && (
            <Panel
              title={`Dependencies (${a.dependencies.length})`}
              subtitle="Versions read from META-INF/*.version and pom.properties — what the build actually wrote into the artifact, not inferred from package names."
            >
              <div className="mb-3 flex flex-wrap gap-2 text-xs">
                <span className="rounded bg-rose-500/10 px-2 py-1 text-rose-200 ring-1 ring-inset ring-rose-500/30">
                  {a.dependencies.filter((d) => d.advisoryCount > 0).length} with advisories
                </span>
                <span className="rounded bg-emerald-500/10 px-2 py-1 text-emerald-200 ring-1 ring-inset ring-emerald-500/30">
                  {a.dependencies.filter((d) => d.advisoryCount === 0).length} clear
                </span>
              </div>
              <div className="max-h-96 overflow-y-auto rounded-md border border-slate-800">
                <table className="w-full text-xs">
                  <tbody className="divide-y divide-slate-800/70">
                    {a.dependencies.map((d) => (
                      <tr
                        key={d.coordinate}
                        className={`transition hover:bg-slate-800/40 ${
                          d.advisoryCount > 0 ? 'bg-rose-500/5' : ''
                        }`}
                      >
                        <td className="w-6 py-1.5 pl-2.5">
                          <span className={d.advisoryCount > 0 ? 'text-rose-400' : 'text-emerald-500/70'}>
                            {d.advisoryCount > 0 ? '●' : '○'}
                          </span>
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-slate-300">{d.coordinate}</td>
                        <td className="w-28 py-1.5 pr-3 font-mono tabular-nums text-slate-400">{d.version}</td>
                        <td className="w-24 py-1.5 pr-2.5 text-right">
                          {d.advisoryCount > 0 ? (
                            <span className="rounded bg-rose-500/15 px-1.5 py-0.5 font-semibold text-rose-200">
                              {d.advisoryCount} advisory
                            </span>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

            </>
          )}

          {activeTab === 'domains' && (
            <Panel
              title={`Domains (${scan.domains?.length ?? 0})`}
              subtitle="Every host the artifact mentions, grouped and classified. This answers who the app talks to — a different question from what is wrong with it."
            >
              <DomainTable domains={scan.domains ?? []} />
            </Panel>
          )}

          {activeTab === 'replay' && (
            <Panel
              title="Scan replay"
              subtitle="Watch the scan’s result built up on a map of the app: files grouped by folder, with a flag where each finding sits."
            >
              <ScanReplay scan={scan} findings={eff!.findings} />
            </Panel>
          )}

          {activeTab === 'explorer' && (
            <Panel
              title="Code explorer"
              subtitle={
                a.platform === 'android'
                  ? 'The decompiled source behind the findings, as readable Java and XML. Binary files a finding names (signatures, native libraries, key stores) open at their own path as a readable decoding of the original. Lines a finding landed on are marked.'
                  : 'The bundle’s property lists, and each Mach-O binary at its own path as a readable decoding: what it links and imports, its Objective-C and Swift names, its signed entitlements and its string table, then each function the scan read as pseudo-code: what it calls, with the arguments the scanner could follow, and the literals it holds. It is machine code read back, not the original source. Lines a finding landed on are marked, and each finding quotes them.'
              }
            >
              <CodeExplorer
                jumpTo={jumpTo}
                scanId={scan.scanId}
                retainedFiles={scan.retainedFiles}
                filesFound={scan.filesFound}
                filesTruncated={scan.filesTruncated}
                flagged={flaggedLines}
              />
            </Panel>
          )}

          {activeTab === 'verify' && (
            <HowToVerify
              findings={[...scan.findings, ...scan.hotspots]}
              fileName={a.fileName}
              sha256={a.sha256}
              platform={a.platform}
            />
          )}
        </LineFlags.Provider>
        </OpenInExplorer.Provider>
        </TriageContext.Provider>
      )}

      {mode === 'history' && (
      <Panel
        title={`Scan history${history.length ? ` (${history.length})` : ''}`}
        subtitle={
          <>
            Every scan is saved here, so you can reopen its report any time. The app file you uploaded is deleted
            as soon as the scan finishes; only the results are kept.
            {appId && ' Showing the selected app only. Choose “Auto” in the App menu to see every scan.'}
          </>
        }
      >
        {history.length === 0 ? (
          <Empty>{appId ? 'This app has no scans yet.' : 'No scans yet. Upload an app above to run the first one.'}</Empty>
        ) : (
          <ul className="-my-1 divide-y divide-slate-800/70">
            {history.map((s) => {
              const viewing = scan?.scanId === s.scanId;
              return (
                <li
                  key={s.scanId}
                  className={`relative flex flex-wrap items-center gap-x-4 gap-y-2 py-3 pl-3 pr-1 ${viewing ? 'bg-ember-500/[0.06]' : ''}`}
                >
                  {viewing && <span aria-hidden="true" className="absolute inset-y-2 left-0 w-[3px] rounded-r bg-ember-500" />}

                  {/* What was scanned */}
                  <div className="min-w-0 flex-1 basis-64">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium text-slate-100">{s.fileName}</span>
                      <span className="shrink-0 rounded border border-slate-700 px-1.5 text-[11px] font-medium text-slate-400">
                        {s.platform === 'android' ? 'Android' : 'iOS'}
                      </span>
                      {viewing && (
                        <span className="shrink-0 rounded bg-ember-500/15 px-1.5 text-[11px] font-semibold text-ember-300">Open now</span>
                      )}
                    </div>
                    <p className="mt-0.5 truncate text-xs text-slate-500">
                      {s.packageName ? `${s.packageName} · ` : ''}
                      <time dateTime={s.createdAt} title={new Date(s.createdAt).toLocaleString()}>{ago(s.createdAt)}</time>
                    </p>
                  </div>

                  {/* The result, at a glance */}
                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded-md border px-2 py-0.5 text-sm font-semibold tabular-nums ${GRADE_CHIP[s.grade] ?? GRADE_CHIP.F}`}
                      title={`Score ${s.score} out of 100, grade ${s.grade}`}
                    >
                      {s.grade} · {s.score}
                    </span>
                    <span className="w-20 text-sm tabular-nums text-slate-400">
                      {s.findings} {s.findings === 1 ? 'finding' : 'findings'}
                    </span>
                  </div>

                  {/* What you can do with it */}
                  <div className="flex items-center gap-2">
                    <div className="w-28 [&>button]:w-full">
                    <Button
                      onClick={() => { void load(s.scanId); onView('report'); window.scrollTo({ top: 0 }); }}
                      variant={viewing ? 'default' : 'primary'}
                      title="Show this scan's report"
                    >
                      {viewing ? 'Viewing' : 'Open report'}
                    </Button>
                    </div>
                    <button
                      type="button"
                      onClick={() => remove(s.scanId)}
                      aria-label={`Delete the scan of ${s.fileName}`}
                      title="Delete this scan and its report"
                      className="grid size-8 place-items-center rounded-md text-slate-500 transition hover:bg-rose-500/15 hover:text-rose-300"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M4 7h16M10 11v6m4-6v6M6 7l1 13h10l1-13M9 7V4h6v3" />
                      </svg>
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
      )}
    </div>
  );
}
