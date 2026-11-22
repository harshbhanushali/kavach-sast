/**
 * What a triage decision does to an attack chain.
 *
 * A chain is only as real as its required links. When a reviewer marks the finding behind one of them a false
 * positive, fixed, or an accepted risk, that link is gone and so is the path, so the chain stops counting and
 * is listed as broken. A link that rests on several findings stays while any one of them is still active, and
 * a fact the scan read from the artifact (a host) cannot be triaged, so it always holds. A protection the scan
 * looked for and did not find (`absence`) is never what a chain is made of, so it never breaks one.
 */
import type { AttackChain, ChainItem, ChainLink, SastScan } from '../../sastTypes';
import { isActive } from '../../triage';

/** Whether anything a link rests on still counts. */
export function linkHolds(scan: Pick<SastScan, 'triage'>, link: ChainLink): boolean {
  if (link.absence) return true;
  return link.items.some((item) => itemHolds(scan, item));
}

export function itemHolds(scan: Pick<SastScan, 'triage'>, item: ChainItem): boolean {
  return item.ruleId === undefined || isActive(scan, item.ruleId);
}

/** The required links triage has taken away; empty while the chain stands. */
export function brokenLinks(scan: Pick<SastScan, 'triage'>, chain: AttackChain): ChainLink[] {
  return chain.links.filter((l) => l.required && !linkHolds(scan, l));
}

export const chainStands = (scan: Pick<SastScan, 'triage'>, chain: AttackChain) => brokenLinks(scan, chain).length === 0;

/** Chains split into those still standing and those triage has broken, order kept. */
export function splitChains(scan: Pick<SastScan, 'triage' | 'chains'>): { standing: AttackChain[]; broken: AttackChain[] } {
  const standing: AttackChain[] = [];
  const broken: AttackChain[] = [];
  for (const chain of scan.chains ?? []) (chainStands(scan, chain) ? standing : broken).push(chain);
  return { standing, broken };
}

export const ROLE_LABEL: Record<ChainLink['role'], string> = {
  entry: 'How in',
  weakness: 'The flaw',
  amplifier: 'Makes it worse',
  impact: 'What it touches',
};
