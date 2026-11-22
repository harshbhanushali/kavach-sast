/**
 * The reviewer's side of a finding: what has been decided about it, and the
 * form to change that.
 *
 * What a decision does to the numbers lives in `triage.ts` (and is shared with
 * the report); this file is only how it is shown and edited. Rows and the panel
 * read the scan and the save function from `TriageContext`, so the Findings tab
 * and the Secrets tab, which both render `FindingRow`, behave the same without
 * threading props through either.
 */
import { createContext, useContext, useEffect, useId, useRef, useState } from 'react';
import { ApiError } from '../../api';
import type { SastScan, TriageEntry, TriageStatus } from '../../sastTypes';
import { MIN_REASON, TRIAGE_META, TRIAGE_STATUSES, adjustedScore, isActive, isExpired, statusOf } from '../../triage';
import { effectiveOf, formatDate } from './model';
import type { StatusFilter } from './model';

export type TriageSave = { status: TriageStatus; reason?: string; expiresAt?: string };

export type TriageApi = {
  scan: SastScan;
  /** Editor or above. Everyone else sees the decision read-only. */
  canEdit: boolean;
  /** Saves one decision and updates the scan held by the screen. Rejects with the server's message. */
  save: (ruleId: string, body: TriageSave) => Promise<void>;
};

export const TriageContext = createContext<TriageApi | null>(null);

/** The server's cap, mirrored so the counter and `maxLength` agree with it. */
const MAX_REASON = 1000;

/** Today as YYYY-MM-DD in UTC: the server compares expiry dates in UTC, so the picker's floor must too. */
const todayUtc = () => new Date().toISOString().slice(0, 10);

/* ----------------------------------------------------------------------- chips */

/**
 * One glyph shape and one word per decision, so a status survives without
 * colour. The shapes are chosen to differ from the severity ramp's (diamond,
 * triangle, square, circle), which sits on the same row.
 */
export const TRIAGE_TONE: Record<Exclude<TriageStatus, 'open'>, { glyph: string; chip: string; word: string }> = {
  confirmed: { glyph: '◉', word: 'Confirmed', chip: 'border-indigo-400/50 bg-indigo-500/10 text-indigo-200' },
  false_positive: { glyph: '⊘', word: 'False positive', chip: 'border-slate-500/60 bg-slate-700/40 text-slate-200' },
  accepted_risk: { glyph: '◐', word: 'Accepted', chip: 'border-teal-500/50 bg-teal-500/10 text-teal-200' },
  fixed: { glyph: '✓', word: 'Fixed', chip: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200' },
};

/** The status chip, plus an "Expired" badge on an acceptance that has lapsed (it counts again). */
export function TriageChip({ entry }: { entry: TriageEntry }) {
  const t = TRIAGE_TONE[entry.status];
  const expired = isExpired(entry);
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className={`pill ${t.chip}`} title={TRIAGE_META[entry.status].blurb}>
        <span aria-hidden className="text-[0.65rem] leading-none">{t.glyph}</span>
        {t.word}
      </span>
      {expired && (
        <span
          className="pill border-amber-500/50 bg-amber-500/10 text-amber-200"
          title={`The acceptance lapsed on ${entry.expiresAt}. This finding counts again until it is decided afresh.`}
        >
          <span aria-hidden className="text-[0.65rem] leading-none">{'▲'}</span>
          Expired
        </span>
      )}
    </span>
  );
}

/* ---------------------------------------------------------------------- filter */

export const STATUS_FILTERS: { key: StatusFilter; label: string; hint: string }[] = [
  { key: 'all', label: 'All', hint: 'Every finding, whatever its status' },
  { key: 'active', label: 'Active', hint: 'Still counts: open, confirmed, or an acceptance that has expired' },
  { key: 'excluded', label: 'Excluded', hint: 'Stopped counting: false positive, fixed, or a current accepted risk' },
  { key: 'open', label: 'Open', hint: TRIAGE_META.open.blurb },
  { key: 'confirmed', label: 'Confirmed', hint: TRIAGE_META.confirmed.blurb },
  { key: 'false_positive', label: 'False positive', hint: TRIAGE_META.false_positive.blurb },
  { key: 'accepted_risk', label: 'Accepted risk', hint: TRIAGE_META.accepted_risk.blurb },
  { key: 'fixed', label: 'Fixed', hint: TRIAGE_META.fixed.blurb },
];

export function matchesStatus(scan: Pick<SastScan, 'triage'>, ruleId: string, filter: StatusFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'active') return isActive(scan, ruleId);
  if (filter === 'excluded') return !isActive(scan, ruleId);
  return statusOf(scan, ruleId) === filter;
}

/** "8 active · 3 excluded" when some of a list no longer counts, otherwise the plain count. */
export function countLabel(total: number, excluded: number): string {
  return excluded > 0 && excluded < total ? `${total - excluded} active · ${excluded} excluded` : String(total);
}

/* ----------------------------------------------------------------------- panel */

type Message = { kind: 'ok' | 'err'; text: string };

/** What a decision is, as one line: who, when, and until when. */
function Decision({ entry }: { entry: TriageEntry }) {
  const expired = isExpired(entry);
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <TriageChip entry={entry} />
        <span className="text-xs text-slate-500">
          by <span className="text-slate-300">{entry.updatedBy}</span> {'·'} {formatDate(entry.updatedAt)}
        </span>
        {entry.carriedFrom && (
          <span
            className="rounded border border-slate-700 px-1.5 py-0.5 text-[0.65rem] text-slate-400"
            title="Copied from an earlier scan of this app because the finding has not changed. Change the decision to make it this scan's own."
          >
            carried forward
          </span>
        )}
        {entry.expiresAt && (
          <span className={`text-xs ${expired ? 'text-amber-300' : 'text-slate-400'}`}>
            {expired ? `expired ${entry.expiresAt}, counts again` : `until ${entry.expiresAt}`}
          </span>
        )}
      </div>
      {entry.reason ? (
        <p className="max-w-[80ch] whitespace-pre-wrap border-l-2 border-slate-700 pl-3 text-sm leading-relaxed text-slate-300">
          {entry.reason}
        </p>
      ) : (
        <p className="text-xs text-slate-500">No reason recorded.</p>
      )}
    </div>
  );
}

/**
 * The triage block at the top of an expanded finding.
 *
 * Everyone sees the current decision. Editors and above also get the form. The
 * message under it is a live region so a screen reader hears "Saved" or the
 * server's refusal without having to find it.
 */
export function TriagePanel({ ruleId }: { ruleId: string }) {
  const api = useContext(TriageContext);
  const [message, setMessage] = useState<Message | null>(null);
  if (!api) return null;

  const entry = api.scan.triage?.[ruleId];

  return (
    <section aria-label="Triage" className="rounded-lg border border-slate-800 bg-slate-950/40 px-3.5 py-3">
      <h4 className="eyebrow mb-2.5">Triage</h4>
      {entry ? (
        <Decision entry={entry} />
      ) : (
        <p className="flex items-center gap-2 text-sm text-slate-300">
          <span aria-hidden className="text-[0.65rem] text-slate-500">{'○'}</span>
          Open <span className="text-xs text-slate-500">{'—'} {TRIAGE_META.open.blurb.toLowerCase()}</span>
        </p>
      )}

      {api.canEdit ? (
        <TriageForm
          ruleId={ruleId}
          entry={entry}
          save={api.save}
          onResult={setMessage}
          scoreEffect={(next, expiresAt) => scoreEffect(api.scan, ruleId, next, expiresAt)}
        />
      ) : (
        <p className="mt-3 text-xs text-slate-500">Sign in to change this decision.</p>
      )}

      {/* Always rendered, so the live region exists before its text changes. */}
      <div aria-live="polite" role="status" className={message ? 'mt-2.5' : ''}>
        {message && (
          <p
            className={`rounded-md px-3 py-2 text-sm ring-1 ring-inset ${
              message.kind === 'ok'
                ? 'bg-emerald-500/10 text-emerald-200 ring-emerald-500/30'
                : 'bg-rose-500/10 text-rose-200 ring-rose-500/30'
            }`}
          >
            {message.text}
          </p>
        )}
      </div>
    </section>
  );
}

/**
 * What a decision does to the score, in words: the number before, the number
 * after, and whether it moved at all. Worked out the same way the overview does
 * (`adjustedScore`), over the scan as it would stand with this one decision.
 */
export function scoreEffect(scan: SastScan, ruleId: string, next: TriageStatus, expiresAt: string): string {
  const before = effectiveOf(scan);
  const triage = { ...(scan.triage ?? {}) };
  if (next === 'open') delete triage[ruleId];
  else triage[ruleId] = { status: next, reason: '', updatedBy: '', updatedAt: '', ...(expiresAt ? { expiresAt } : {}) };
  const after = adjustedScore({ ...scan, triage });
  const show = (n: number, g: string) => `${n} (${g})`;
  if (after.score !== before.score) return `Score ${show(before.score, before.grade)} \u2192 ${show(after.score, after.grade)}.`;
  return `The score stays ${show(before.score, before.grade)}; other findings still weigh on it.`;
}

function TriageForm({
  ruleId, entry, save, onResult, scoreEffect,
}: {
  scoreEffect: (next: TriageStatus, expiresAt: string) => string;
  ruleId: string;
  entry: TriageEntry | undefined;
  save: TriageApi['save'];
  onResult: (m: Message | null) => void;
}) {
  const uid = useId();
  const statusRef = useRef<HTMLSelectElement>(null);
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const [status, setStatus] = useState<TriageStatus>(entry?.status ?? 'open');
  const [reason, setReason] = useState(entry?.reason ?? '');
  const [expiresAt, setExpiresAt] = useState(entry?.expiresAt ?? '');
  const [saving, setSaving] = useState(false);
  // Controls are disabled while a save is in flight, which drops keyboard focus
  // to the page. Where it goes back to waits for them to be enabled again.
  const focusAfter = useRef<'status' | 'trigger' | null>(null);
  const trigger = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (saving || !focusAfter.current) return;
    (focusAfter.current === 'status' ? statusRef.current : trigger.current)?.focus();
    focusAfter.current = null;
  }, [saving]);

  const meta = TRIAGE_META[status];
  const trimmed = reason.trim();
  const short = meta.needsReason && trimmed.length < MIN_REASON;

  // Unchanged is not saved: it would only stamp a new author and date on a
  // decision nobody revisited.
  const dirty = status === 'open'
    ? Boolean(entry)
    : !entry
      || status !== entry.status
      || trimmed !== entry.reason
      || (status === 'accepted_risk' && expiresAt !== (entry.expiresAt ?? ''));

  async function submit(next: TriageStatus) {
    const text = reason.trim();
    if (TRIAGE_META[next].needsReason && text.length < MIN_REASON) {
      onResult({
        kind: 'err',
        text: `A reason of at least ${MIN_REASON} characters is required to mark a finding ${TRIAGE_META[next].label.toLowerCase()}.`,
      });
      reasonRef.current?.focus();
      return;
    }
    trigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    // Worked out before the save, while the scan still shows the old decision.
    const effect = scoreEffect(next, expiresAt);
    setSaving(true);
    onResult(null);
    try {
      await save(
        ruleId,
        next === 'open'
          ? { status: 'open' }
          : {
              status: next,
              ...(text ? { reason: text } : {}),
              ...(next === 'accepted_risk' && expiresAt ? { expiresAt } : {}),
            },
      );
      if (next === 'open') {
        setStatus('open');
        setReason('');
        setExpiresAt('');
        onResult({ kind: 'ok', text: `Reopened. This finding counts again. ${effect}` });
      } else {
        setReason(text);
        onResult({
          kind: 'ok',
          text: `Saved as ${TRIAGE_META[next].label.toLowerCase()}. ${
            next === 'confirmed' ? 'It still counts. ' : ''
          }${effect}${next === 'fixed' ? ' Rescan the fixed build to confirm it.' : ''}`,
        });
      }
      // Save and Reopen both change what the buttons offer, so land on the status.
      focusAfter.current = 'status';
    } catch (e) {
      focusAfter.current = 'trigger';
      onResult({ kind: 'err', text: e instanceof ApiError ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void submit(status);
      }}
      className="mt-3 space-y-3 border-t border-slate-800 pt-3"
    >
      <div className="grid gap-x-4 gap-y-3 @2xl:grid-cols-[minmax(0,15rem)_minmax(0,1fr)]">
        <div className="space-y-1.5">
          <label htmlFor={`${uid}-status`} className="block text-xs font-semibold uppercase tracking-wide text-slate-400">
            Status
          </label>
          <select
            id={`${uid}-status`}
            ref={statusRef}
            value={status}
            aria-describedby={`${uid}-blurb`}
            disabled={saving}
            onChange={(e) => {
              const next = e.target.value as TriageStatus;
              setStatus(next);
              // An expiry only means something on an accepted risk.
              if (next !== 'accepted_risk') setExpiresAt('');
            }}
            className="w-full"
          >
            {TRIAGE_STATUSES.map((s) => (
              <option key={s} value={s}>{TRIAGE_META[s].label}</option>
            ))}
          </select>
          <p id={`${uid}-blurb`} className="text-xs leading-relaxed text-slate-500">{meta.blurb}</p>
        </div>

        <div className="space-y-1.5">
          <label htmlFor={`${uid}-reason`} className="flex flex-wrap items-baseline justify-between gap-x-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
            <span>
              Reason{' '}
              <span className="font-normal normal-case tracking-normal text-slate-500">
                {meta.needsReason ? `(required, at least ${MIN_REASON} characters)` : '(optional)'}
              </span>
            </span>
          </label>
          <textarea
            id={`${uid}-reason`}
            ref={reasonRef}
            rows={3}
            value={reason}
            maxLength={MAX_REASON}
            disabled={saving || status === 'open'}
            aria-describedby={`${uid}-count`}
            aria-invalid={short && reason.length > 0 ? true : undefined}
            onChange={(e) => setReason(e.target.value)}
            placeholder={status === 'open' ? 'Reopening clears the decision and its reason.' : 'Why is this the right call? What did you check?'}
            className="block w-full resize-y"
          />
          <p id={`${uid}-count`} className="flex justify-between gap-3 text-xs tabular-nums text-slate-500">
            <span className={short && reason.length > 0 ? 'text-amber-300' : ''}>
              {status === 'open'
                ? ''
                : short
                  ? `${Math.max(0, MIN_REASON - trimmed.length)} more character${MIN_REASON - trimmed.length === 1 ? '' : 's'} needed`
                  : meta.needsReason ? 'Long enough.' : ''}
            </span>
            <span>{reason.length} / {MAX_REASON}</span>
          </p>
        </div>
      </div>

      {status === 'accepted_risk' && (
        <div className="space-y-1.5">
          <label htmlFor={`${uid}-expires`} className="block text-xs font-semibold uppercase tracking-wide text-slate-400">
            Expires on <span className="font-normal normal-case tracking-normal text-slate-500">(optional)</span>
          </label>
          <input
            id={`${uid}-expires`}
            type="date"
            value={expiresAt}
            min={todayUtc()}
            disabled={saving}
            aria-describedby={`${uid}-expires-hint`}
            onChange={(e) => setExpiresAt(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-sm text-slate-100 [color-scheme:dark]"
          />
          <p id={`${uid}-expires-hint`} className="text-xs text-slate-500">
            After this date the finding counts again. Leave empty to accept it with no end date.
          </p>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="submit"
          disabled={saving || !dirty}
          className="rounded-md border border-ember-400 bg-ember-600 px-3 py-1.5 text-sm font-medium text-white shadow-sm transition hover:bg-ember-500 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        {entry && (
          <button
            type="button"
            disabled={saving}
            onClick={() => void submit('open')}
            title="Clear the decision. The finding counts again."
            className="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-sm font-medium text-slate-100 transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Reopen
          </button>
        )}
      </div>
    </form>
  );
}
