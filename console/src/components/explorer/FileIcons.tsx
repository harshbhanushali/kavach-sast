/**
 * Icons and file kinds for the code explorer.
 *
 * A tree of identical grey rows makes you read every name; a tile coloured by
 * file type lets you spot the Java, the manifest and the resources by shape and
 * colour first. The tiles are small SVG, so they stay crisp and cost nothing.
 */
import type { ReactNode } from 'react';

export type FileKind = 'source' | 'resource' | 'smali' | 'native' | 'other';

/** Where a file lives decides how a reviewer thinks of it. */
export function kindOf(path: string): FileKind {
  if (path.startsWith('sources/') || /\.(java|kt)$/.test(path)) return 'source';
  if (path.startsWith('smali')) return 'smali';
  if (path.startsWith('res/') || path === 'AndroidManifest.xml' || path.startsWith('assets/')) return 'resource';
  // iOS: `_binary/` is the readable view of a Mach-O, and the bundle's property lists and strings are its resources.
  if (/\.(so|dylib|a)$/.test(path) || path.startsWith('lib/') || path.startsWith('_binary/')) return 'native';
  if (/\.(plist|strings|xcprivacy|entitlements)$/.test(path)) return 'resource';
  return 'other';
}

export const KIND_LABEL: Record<FileKind, string> = {
  source: 'Source',
  resource: 'Resources',
  smali: 'Assembly',
  native: 'Native',
  other: 'Other',
};

type Tile = { text: string; tone: string };

const EXT: Record<string, Tile> = {
  java: { text: 'JV', tone: 'bg-amber-500/20 text-amber-200 ring-amber-400/40' },
  kt: { text: 'KT', tone: 'bg-violet-500/20 text-violet-200 ring-violet-400/40' },
  xml: { text: '</>', tone: 'bg-sky-500/20 text-sky-200 ring-sky-400/40' },
  smali: { text: 'SM', tone: 'bg-fuchsia-500/20 text-fuchsia-200 ring-fuchsia-400/40' },
  json: { text: '{}', tone: 'bg-emerald-500/20 text-emerald-200 ring-emerald-400/40' },
  yml: { text: 'YML', tone: 'bg-teal-500/20 text-teal-200 ring-teal-400/40' },
  yaml: { text: 'YML', tone: 'bg-teal-500/20 text-teal-200 ring-teal-400/40' },
  properties: { text: 'CFG', tone: 'bg-teal-500/20 text-teal-200 ring-teal-400/40' },
  txt: { text: 'TXT', tone: 'bg-slate-500/25 text-slate-200 ring-slate-400/30' },
  md: { text: 'MD', tone: 'bg-slate-500/25 text-slate-200 ring-slate-400/30' },
  png: { text: 'IMG', tone: 'bg-pink-500/20 text-pink-200 ring-pink-400/40' },
  jpg: { text: 'IMG', tone: 'bg-pink-500/20 text-pink-200 ring-pink-400/40' },
  webp: { text: 'IMG', tone: 'bg-pink-500/20 text-pink-200 ring-pink-400/40' },
  gif: { text: 'IMG', tone: 'bg-pink-500/20 text-pink-200 ring-pink-400/40' },
  svg: { text: 'SVG', tone: 'bg-pink-500/20 text-pink-200 ring-pink-400/40' },
  so: { text: 'SO', tone: 'bg-rose-500/20 text-rose-200 ring-rose-400/40' },
  dex: { text: 'DEX', tone: 'bg-rose-500/20 text-rose-200 ring-rose-400/40' },
  plist: { text: 'PL', tone: 'bg-orange-500/20 text-orange-200 ring-orange-400/40' },
  html: { text: 'HT', tone: 'bg-orange-500/20 text-orange-200 ring-orange-400/40' },
  js: { text: 'JS', tone: 'bg-yellow-500/20 text-yellow-200 ring-yellow-400/40' },
  pem: { text: 'KEY', tone: 'bg-red-500/20 text-red-200 ring-red-400/40' },
  der: { text: 'KEY', tone: 'bg-red-500/20 text-red-200 ring-red-400/40' },
  cer: { text: 'KEY', tone: 'bg-red-500/20 text-red-200 ring-red-400/40' },
};

const FALLBACK: Tile = { text: '·', tone: 'bg-slate-600/25 text-slate-300 ring-slate-500/30' };

/** The file's tile. The manifest is special: it is the file most reviews start from. */
export function FileGlyph({ name }: { name: string }): ReactNode {
  const tile: Tile =
    name === 'AndroidManifest.xml'
      ? { text: 'MF', tone: 'bg-ember-500/25 text-ember-100 ring-ember-400/60' }
      : EXT[name.slice(name.lastIndexOf('.') + 1).toLowerCase()] ?? FALLBACK;
  return (
    <span
      aria-hidden
      className={`grid h-[22px] w-[26px] shrink-0 place-items-center rounded-md font-mono text-[9px] font-bold leading-none tracking-tight ring-1 ring-inset ${tile.tone}`}
    >
      {tile.text}
    </span>
  );
}

const FOLDER_TONE: Record<string, string> = {
  sources: 'text-amber-300',
  res: 'text-sky-300',
  assets: 'text-sky-300',
  lib: 'text-rose-300',
  original: 'text-slate-400',
  unknown: 'text-slate-400',
};

export function FolderGlyph({ name, open, depth }: { name: string; open: boolean; depth: number }): ReactNode {
  // Only the top-level folders carry a colour; below them it is noise.
  const tone = depth === 0 ? (name.startsWith('smali') ? 'text-fuchsia-300' : FOLDER_TONE[name] ?? 'text-ember-300') : 'text-ember-300/80';
  return (
    <svg aria-hidden viewBox="0 0 24 20" className={`h-[18px] w-[22px] shrink-0 ${tone}`} fill="currentColor">
      {open ? (
        <path d="M2 4.5A2.5 2.5 0 0 1 4.5 2h4.2c.6 0 1.2.3 1.6.8L11.7 4.5H19A2.5 2.5 0 0 1 21.5 7v1H6.4a2.5 2.5 0 0 0-2.4 1.8L2 16.2V4.5Zm2.7 5.7A1.2 1.2 0 0 1 5.9 9.3H22a1 1 0 0 1 1 1.3l-2 6.2A2.5 2.5 0 0 1 18.6 18.5H3.5a1 1 0 0 1-1-1.3l2.2-7Z" />
      ) : (
        <path d="M2 4.5A2.5 2.5 0 0 1 4.5 2h4.2c.6 0 1.2.3 1.6.8L11.7 4.5H19.5A2.5 2.5 0 0 1 22 7v9a2.5 2.5 0 0 1-2.5 2.5h-15A2.5 2.5 0 0 1 2 16V4.5Z" />
      )}
    </svg>
  );
}
