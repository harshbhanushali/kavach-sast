/**
 * Preview the report, then export it.
 *
 * A report is a long document and a reviewer should see what they are about to
 * hand over before they hand it over, particularly now that triage decisions
 * change its numbers. The modal shows the real report in a frame, lets the
 * reader switch between the executive and full editions, and exports it as a PDF
 * file directly. The print dialog stays available as the fallback for a server
 * with no browser to render with.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ApiError, getToken, request } from '../../api';
import { buildSastReportHtml, openSastReport } from '../../sastReport';
import type { SastScan } from '../../sastTypes';
import { triageSummary } from '../../triage';

type Edition = 'executive' | 'full';

const EDITIONS: { edition: Edition; title: string; blurb: string }[] = [
  { edition: 'executive', title: 'Executive summary', blurb: 'About ten pages for a decision-maker.' },
  { edition: 'full', title: 'Full technical report', blurb: 'Every finding on its own page, with evidence.' },
];

/** A file name that is safe on every platform: `Acme-Wallet-sast-full-2026-10-03.pdf`. */
function fileNameFor(scan: SastScan, edition: Edition, protectedFile = false): string {
  const base = (scan.artifact.ios?.displayName ?? scan.artifact.android?.label ?? scan.artifact.packageName ?? scan.artifact.fileName)
    .replace(/[^\w.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'report';
  return `${base}-sast-${edition}${protectedFile ? '-protected' : ''}-${new Date().toISOString().slice(0, 10)}.pdf`;
}

/** Mirrors the server's rules (backend/src/sast/pdf.ts) so a bad password is caught before the render. */
const MIN_PASSWORD = 8;
function passwordProblem(password: string): string | undefined {
  if ([...password].length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (new TextEncoder().encode(password).length > 127) return 'That is too long. Use 127 bytes or fewer.';
  if (password.startsWith('-')) return 'The password cannot start with a dash.';
  return undefined;
}

type PdfState = 'unknown' | 'ready' | 'unavailable';

export function ReportPreview({ scan, onClose }: { scan: SastScan; onClose: () => void }) {
  const [edition, setEdition] = useState<Edition>('executive');
  const [pdfSupport, setPdfSupport] = useState<PdfState>('unknown');
  const [pdfNote, setPdfNote] = useState<string | undefined>();
  const [passwordSupport, setPasswordSupport] = useState(false);
  const [passwordNote, setPasswordNote] = useState<string | undefined>();
  const [protect, setProtect] = useState(false);
  const [password, setPassword] = useState('');
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);
  const closeButton = useRef<HTMLButtonElement>(null);

  // Built on demand and again only when the edition or the decisions change.
  const html = useMemo(() => buildSastReportHtml(scan, { edition }), [scan, edition]);
  // A false positive is left out of the report entirely, so it is not a decision the report applies.
  const summary = triageSummary(scan);
  const decided = summary.decided - summary.falsePositive;

  // Whether the server can render a PDF itself.
  useEffect(() => {
    let live = true;
    request<{ pdf?: { available: boolean; note?: string }; pdfPassword?: { available: boolean; note?: string } }>('/v1/sast/capability')
      .then((cap) => {
        if (!live) return;
        setPdfSupport(cap.pdf?.available ? 'ready' : 'unavailable');
        setPdfNote(cap.pdf?.note);
        setPasswordSupport(Boolean(cap.pdfPassword?.available));
        setPasswordNote(cap.pdfPassword?.note);
      })
      // An older backend has no `pdf` entry; treat that as "cannot render".
      .catch(() => live && setPdfSupport('unavailable'));
    return () => { live = false; };
  }, []);

  // Dialog behaviour: focus in, Escape out, focus back, page behind does not scroll.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    closeButton.current?.focus();
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = overflow;
      opener?.focus?.();
    };
  }, [onClose]);

  const passwordError = protect ? passwordProblem(password) : undefined;
  const locked = protect && !passwordError;

  const download = async () => {
    if (protect && passwordError) {
      setMessage({ tone: 'error', text: passwordError });
      return;
    }
    const fileName = fileNameFor(scan, edition, locked);
    setBusy(true);
    setMessage(null);
    try {
      // Not `request`: the answer is a file, not JSON.
      const response = await fetch('/v1/sast/report/pdf', {
        method: 'POST',
        headers: { authorization: `Bearer ${getToken()}`, 'content-type': 'application/json' },
        body: JSON.stringify({ html, fileName, ...(locked ? { password } : {}) }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { error?: string } | null;
        // The generic 404 is a backend that predates this endpoint.
        const text = response.status === 404 && (!body?.error || body.error === 'Not Found')
          ? 'This backend cannot render PDFs yet. Restart it to load the latest version, or use Print.'
          : body?.error ?? `The server answered ${response.status}.`;
        throw new ApiError(response.status, text, body);
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setMessage({ tone: 'ok', text: locked ? `Downloaded ${fileName}. It asks for the password you set; Kavach does not keep it, so there is no way to recover it.` : `Downloaded ${fileName}.` });
    } catch (error) {
      setMessage({ tone: 'error', text: error instanceof Error ? error.message : 'The PDF could not be created.' });
    } finally {
      setBusy(false);
    }
  };

  const canDownload = pdfSupport === 'ready';

  // Rendered on the document body. The dashboard's panels use container queries, and a
  // container establishes the containing block for `position: fixed` descendants, so a
  // fixed modal inside one is laid out against the panel instead of the window.
  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Report preview"
      className="fixed inset-0 z-50 flex flex-col bg-slate-950/95 backdrop-blur-sm"
    >
      <header className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-slate-800 bg-slate-900 px-5 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-slate-100">Report preview</h2>
          <p className="truncate text-xs text-slate-400">
            {scan.artifact.fileName}
            {decided > 0 ? ` · ${decided} triage decision${decided === 1 ? '' : 's'} applied` : ''}
          </p>
        </div>

        <div role="radiogroup" aria-label="Edition" className="flex gap-1 rounded-lg border border-slate-700 bg-slate-950 p-1">
          {EDITIONS.map((option) => {
            const on = edition === option.edition;
            return (
              <button
                key={option.edition}
                type="button"
                role="radio"
                aria-checked={on}
                title={option.blurb}
                onClick={() => { setEdition(option.edition); setMessage(null); }}
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-ember-400 ${
                  on ? 'bg-ember-600 text-white' : 'text-slate-300 hover:bg-slate-800'
                }`}
              >
                {option.title}
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label
            className={`flex items-center gap-2 text-sm ${passwordSupport ? 'text-slate-200' : 'cursor-not-allowed text-slate-500'}`}
            title={passwordSupport ? 'Lock the PDF so it asks for a password to open' : passwordNote ?? 'Checking whether this server can protect PDFs'}
          >
            <input
              type="checkbox"
              checked={protect}
              disabled={!passwordSupport}
              onChange={(event) => { setProtect(event.target.checked); setMessage(null); }}
              className="h-4 w-4 accent-ember-500"
            />
            Password-protect
          </label>
          {protect && (
            <div className="flex items-center gap-1">
              <input
                type={reveal ? 'text' : 'password'}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                placeholder="Password (8+ characters)"
                aria-label="Password for the PDF"
                aria-invalid={Boolean(passwordError && password)}
                className={`w-52 rounded-md border bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-ember-400 ${
                  passwordError && password ? 'border-rose-500' : 'border-slate-700'
                }`}
              />
              <button
                type="button"
                onClick={() => setReveal((value) => !value)}
                aria-pressed={reveal}
                className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                {reveal ? 'Hide' : 'Show'}
              </button>
            </div>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => openSastReport(scan, edition)}
            className={`rounded-md border px-3 py-1.5 text-sm font-medium transition ${
              canDownload ? 'border-slate-600 bg-slate-800 text-slate-100 hover:bg-slate-700' : 'border-ember-400 bg-ember-600 text-white hover:bg-ember-500'
            }`}
            title="Open the browser's print dialog; choose Save as PDF"
          >
            Print
          </button>
          <button
            type="button"
            onClick={download}
            disabled={!canDownload || busy || (protect && Boolean(passwordError))}
            title={!canDownload ? pdfNote ?? 'Checking whether this server can render PDFs' : protect && passwordError ? passwordError : 'Create the PDF and save it'}
            className="inline-flex items-center gap-2 rounded-md border border-ember-400 bg-ember-600 px-3 py-1.5 text-sm font-medium text-white shadow-sm transition hover:bg-ember-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy && <span aria-hidden className="h-3 w-3 animate-spin rounded-full border-2 border-white/40 border-t-white" />}
            {busy ? 'Rendering PDF' : locked ? 'Download protected PDF' : 'Download PDF'}
          </button>
          <button
            ref={closeButton}
            type="button"
            onClick={onClose}
            className="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-sm font-medium text-slate-100 transition hover:bg-slate-700"
          >
            Close
          </button>
        </div>
      </header>

      <div aria-live="polite" className="min-h-0 shrink-0">
        {busy && (
          <p className="border-b border-slate-800 bg-ember-950/40 px-5 py-2 text-xs text-ember-200">
            Rendering the PDF on the server. A long report can take up to a minute.
          </p>
        )}
        {message && (
          <p
            className={`border-b px-5 py-2 text-xs ${
              message.tone === 'ok'
                ? 'border-emerald-900/60 bg-emerald-950/40 text-emerald-200'
                : 'border-rose-900/60 bg-rose-950/40 text-rose-200'
            }`}
          >
            {message.text}
          </p>
        )}
        {pdfSupport === 'unavailable' && !message && (
          <p className="border-b border-amber-900/50 bg-amber-950/30 px-5 py-2 text-xs text-amber-200">
            {pdfNote ?? 'This server cannot create PDFs directly.'} Use <strong>Print</strong> and choose Save as PDF.
          </p>
        )}
      </div>

      {/* Scripts are allowed inside the frame (the preview sizes its sheets with one) but it has no
          access to this page, its storage or its session. */}
      <iframe
        key={edition}
        title={`Report preview, ${edition} edition`}
        sandbox="allow-scripts"
        srcDoc={html}
        className="min-h-0 w-full flex-1 border-0 bg-slate-300"
      />
    </div>,
    document.body,
  );
}
