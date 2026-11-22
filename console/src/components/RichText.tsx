/** Prose with its code picked out: commands you can copy, names and attributes in monospace. See richText.ts. */
import { useState } from 'react';
import { pieces } from '../richText';

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1400);
        }).catch(() => undefined);
      }}
      aria-label={`Copy ${text}`}
      title="Copy this command"
      className="ml-1.5 rounded border border-slate-600/70 px-1 py-px align-baseline font-sans text-[10px] font-medium text-slate-400 transition hover:border-slate-500 hover:text-slate-100"
    >
      {done ? 'Copied' : 'Copy'}
    </button>
  );
}

export function RichText({ text }: { text: string }) {
  return (
    <>
      {pieces(text).map((p, i) =>
        p.kind === 'text' ? (
          <span key={i}>{p.value}</span>
        ) : p.kind === 'command' ? (
          <span key={i} className="whitespace-normal">
            <code className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[0.86em] leading-6 text-emerald-200 [overflow-wrap:anywhere]">
              <span aria-hidden className="mr-1 select-none text-emerald-400/70">$</span>
              {p.value}
            </code>
            <CopyButton text={p.value} />
          </span>
        ) : (
          <code key={i} className="rounded bg-slate-800/80 px-1 py-px font-mono text-[0.86em] text-ember-200 ring-1 ring-inset ring-slate-700/70 [overflow-wrap:anywhere]">
            {p.value}
          </code>
        ),
      )}
    </>
  );
}
