/**
 * Attack chains: the findings of a scan, read as the paths an attacker would take.
 *
 * The Findings tab answers "what is wrong". This one answers "which of it is wrong together", so a team can
 * see that closing one door ends several stories. Each chain is drawn as the path it is (how in, the flaw,
 * what makes it worse) with the real finding behind every step, a button that opens the code, and the one
 * change that ends it.
 *
 * Everything shown is derived from the scan's findings and adds nothing to the score. Static analysis cannot
 * prove a path is reachable, so the page says what "likely" means rather than leaving it to be assumed.
 */
import { useState } from 'react';
import type { AttackChain, ChainItem, ChainLink, SastScan } from '../../sastTypes';
import { TRIAGE_META, statusOf } from '../../triage';
import { Empty, Panel } from '../ui';
import { ViewFileButton } from '../FindingDetail';
import { ROLE_LABEL, brokenLinks, itemHolds, linkHolds, splitChains } from './chainModel';
import { SEV, SevChip, SevGlyph, Tag, ToneChip } from './ui';

/** Items a step lists before it says how many more there are. */
const ITEMS_SHOWN = 3;

const CONFIDENCE = {
  likely: {
    tone: 'warn' as const,
    label: 'Likely',
    hint: 'The entry point and the flaw are in the same class, so the component runs the code that is wrong.',
  },
  possible: {
    tone: 'info' as const,
    label: 'Possible',
    hint: 'Every part is in the app, but the scan did not find them in the same class. Worth checking, not proven.',
  },
};

/* ------------------------------------------------------------------- pieces */

function Item({ scan, item }: { scan: SastScan; item: ChainItem }) {
  const holds = itemHolds(scan, item);
  const status = item.ruleId ? statusOf(scan, item.ruleId) : 'open';
  return (
    <li className={`flex flex-wrap items-center gap-x-2 gap-y-1 ${holds ? '' : 'opacity-60'}`}>
      {item.severity ? (
        <span className={SEV[item.severity].text} title={`${SEV[item.severity].label}${item.kind === 'hotspot' ? ' (to review)' : ''}`}>
          <SevGlyph severity={item.severity} />
        </span>
      ) : (
        <span aria-hidden className="size-3 shrink-0 text-center text-[0.7rem] leading-3 text-slate-500">◦</span>
      )}
      <span className={`min-w-0 text-sm ${item.kind === 'fact' ? 'font-mono text-slate-200' : 'text-slate-100'} ${holds ? '' : 'line-through'}`}>
        {item.title}
      </span>
      {item.kind === 'hotspot' && <Tag mono={false} title="Nothing is provably wrong; a person should look.">review</Tag>}
      {!holds && <Tag mono={false}>{TRIAGE_META[status].label}</Tag>}
      {item.location && (
        <>
          <span className="font-mono text-[11px] text-slate-400">
            {item.location.file}
            {item.location.line ? `:${item.location.line}` : ''}
          </span>
          <ViewFileButton path={item.location.file} line={item.location.line} />
        </>
      )}
    </li>
  );
}

function Step({ scan, link, index, last }: { scan: SastScan; link: ChainLink; index: number; last: boolean }) {
  const holds = linkHolds(scan, link);
  const absent = link.absence === true;
  return (
    <li className="relative flex gap-3 pb-4 last:pb-0">
      {/* The path: a numbered node, and the line down to the next one. */}
      <div className="flex flex-col items-center">
        <span
          aria-hidden
          className={`grid size-6 shrink-0 place-items-center rounded-full border text-[11px] font-semibold tabular ${
            !holds
              ? 'border-slate-700 bg-slate-800/60 text-slate-500'
              : absent
                ? 'border-dashed border-amber-500/60 bg-amber-500/10 text-amber-200'
                : 'border-ember-500/50 bg-ember-500/15 text-ember-200'
          }`}
        >
          {index + 1}
        </span>
        {!last && <span aria-hidden className="mt-1 w-px flex-1 bg-slate-700" />}
      </div>
      <div className="min-w-0 flex-1 pt-0.5">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{ROLE_LABEL[link.role]}</span>
          {!link.required && <span className="text-[11px] text-slate-500">· extra</span>}
          {absent && <ToneChip tone="warn" title="The scan looks for this protection and did not find it.">not found</ToneChip>}
        </div>
        <p className={`text-sm font-medium ${holds ? 'text-slate-50' : 'text-slate-400 line-through'}`}>{link.label}</p>
        {link.items.length > 0 && (
          <ul className="mt-1.5 space-y-1.5">
            {link.items.slice(0, ITEMS_SHOWN).map((item, i) => (
              <Item key={`${item.ruleId ?? item.title}:${i}`} scan={scan} item={item} />
            ))}
            {link.total > ITEMS_SHOWN && (
              <li className="text-xs text-slate-400">
                + {link.total - ITEMS_SHOWN} more {link.items.some((i) => i.kind === 'fact') ? 'hosts' : 'like it'}
              </li>
            )}
          </ul>
        )}
      </div>
    </li>
  );
}

function ChainCard({ scan, chain, open, onToggle, broken }: {
  scan: SastScan; chain: AttackChain; open: boolean; onToggle: () => void; broken: boolean;
}) {
  const sev = SEV[chain.severity];
  const confidence = CONFIDENCE[chain.confidence];
  const gone = brokenLinks(scan, chain);
  const id = `chain-${chain.id.replace(/[^a-z0-9]+/gi, '-')}`;
  return (
    <li id={id} className={`panel overflow-hidden border-l-4 ${broken ? 'border-l-slate-600 opacity-80' : sev.stripe}`}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={`${id}-body`}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SevChip severity={chain.severity} />
            <ToneChip tone={confidence.tone} title={confidence.hint}>{confidence.label}</ToneChip>
            <span className="text-xs text-slate-400">{chain.links.filter((l) => !l.absence).length} linked findings</span>
            {broken && <ToneChip tone="good" title="Triage has taken a required link away, so this path no longer counts.">broken by triage</ToneChip>}
          </div>
          <h3 className={`mt-1.5 text-[0.95rem] font-semibold ${broken ? 'text-slate-300' : 'text-slate-50'}`}>{chain.title}</h3>
          <p className="mt-0.5 text-sm leading-relaxed text-slate-400">{chain.summary}</p>
        </div>
        <svg
          viewBox="0 0 16 16"
          aria-hidden
          className={`mt-1 size-4 shrink-0 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
        >
          <path d="M3 6l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <div id={`${id}-body`} className="grid gap-6 border-t border-slate-800 px-4 py-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
          <div>
            <h4 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">What it is made of</h4>
            <ol>
              {chain.links.map((link, i) => (
                <Step key={`${link.role}:${link.label}`} scan={scan} link={link} index={i} last={i === chain.links.length - 1} />
              ))}
            </ol>
          </div>

          <div className="space-y-4">
            <div>
              <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">How it plays out</h4>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm leading-relaxed text-slate-200 marker:text-slate-500">
                {chain.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>

            {broken ? (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm text-slate-300">
                <p className="font-medium text-emerald-200">This path is closed by triage.</p>
                <p className="mt-1 text-slate-400">
                  {gone.map((l) => l.label).join('; ')}: every finding behind {gone.length === 1 ? 'it is' : 'them are'} marked as
                  fixed, a false positive or an accepted risk. Reopen one to bring the chain back.
                </p>
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/[0.07] p-3">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300">Break it here</p>
                <p className="mt-1 text-sm leading-relaxed text-slate-100">{chain.breakpoint}</p>
              </div>
            )}

            {(chain.masvs || chain.cwe) && (
              <div className="flex flex-wrap gap-1.5">
                {chain.cwe?.map((c) => <Tag key={c}>{c}</Tag>)}
                {chain.masvs && <Tag>{chain.masvs}</Tag>}
              </div>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

/* --------------------------------------------------------------------- tab */

export function SastChains({ scan }: { scan: SastScan }) {
  const { standing, broken } = splitChains(scan);
  // The worst chain starts open: the page should answer its question before anything is clicked.
  const [open, setOpen] = useState<string | null>(standing[0]?.id ?? null);
  const toggle = (id: string) => setOpen((cur) => (cur === id ? null : id));

  const likely = standing.filter((c) => c.confidence === 'likely').length;

  return (
    <div className="space-y-5">
      <Panel
        title="Attack chains"
        subtitle={
          <>
            Findings that are wrong <em>together</em>. Each chain is a path an attacker could take, built from findings in this
            scan, with the one change that ends it. It reads the findings you already have and does not change the score. Code in
            bundled libraries is left out, and so is anything triage has closed.
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          {standing.length > 0 ? (
            <>
              <span className="text-sm text-slate-200">
                <strong className="tabular text-slate-50">{standing.length}</strong> {standing.length === 1 ? 'chain' : 'chains'}
              </span>
              {(['critical', 'high', 'medium', 'low'] as const).map((s) => {
                const n = standing.filter((c) => c.severity === s).length;
                return n > 0 ? <SevChip key={s} severity={s} count={n} /> : null;
              })}
              {likely > 0 && (
                <ToneChip tone={CONFIDENCE.likely.tone} title={CONFIDENCE.likely.hint}>{likely} likely</ToneChip>
              )}
            </>
          ) : (
            <span className="text-sm text-slate-300">
              {broken.length > 0 ? 'Every chain has been closed by triage.' : 'No chains found in this scan.'}
            </span>
          )}
        </div>
        <p className="mt-3 text-xs leading-relaxed text-slate-500">
          <strong className="font-medium text-slate-400">Likely</strong> means the entry point and the flaw are in the same class.{' '}
          <strong className="font-medium text-slate-400">Possible</strong> means both are in the app but not shown to be connected.
          Static analysis cannot prove a path can be walked, so treat a chain as a lead to verify.
        </p>
      </Panel>

      {standing.length === 0 && broken.length === 0 && (
        <Panel>
          <Empty>
            None of the findings in this scan join up into a path. That is a statement about these findings, not a clean bill of
            health: a chain is only drawn when every part of it was found.
          </Empty>
        </Panel>
      )}

      {standing.length > 0 && (
        <ul className="space-y-3">
          {standing.map((chain) => (
            <ChainCard
              key={chain.id}
              scan={scan}
              chain={chain}
              open={open === chain.id}
              onToggle={() => toggle(chain.id)}
              broken={false}
            />
          ))}
        </ul>
      )}

      {broken.length > 0 && (
        <section aria-label="Chains closed by triage" className="space-y-3">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Closed by triage ({broken.length})
          </h3>
          <ul className="space-y-3">
            {broken.map((chain) => (
              <ChainCard
                key={chain.id}
                scan={scan}
                chain={chain}
                open={open === chain.id}
                onToggle={() => toggle(chain.id)}
                broken
              />
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
