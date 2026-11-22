/**
 * The app's icon in a rounded square, or a monogram tile when there is none.
 *
 * The mask is a squircle-ish radius (about 22% of the side, the shape both
 * stores use) with a hairline ring and a soft shadow, so an icon with a dark or
 * transparent background still reads as a tile on the dark surface. A broken
 * data URL falls back to the monogram rather than showing the browser's
 * broken-image glyph.
 */
import { useState } from 'react';
import { hueOf } from './model';

const SIZE = {
  sm: { box: 'size-9', text: 'text-base' },
  md: { box: 'size-12', text: 'text-xl' },
  lg: { box: 'size-[4.5rem]', text: 'text-3xl' },
} as const;

export function AppIcon({
  src, name, seed, size = 'md',
}: { src?: string; name: string; seed?: string; size?: keyof typeof SIZE }) {
  const [failed, setFailed] = useState<string | undefined>();
  const s = SIZE[size];
  const box = `${s.box} shrink-0 rounded-[22%] shadow-lg shadow-black/40 ring-1 ring-inset ring-white/15`;

  if (src && failed !== src) {
    return (
      <img
        src={src}
        alt={`${name} app icon`}
        onError={() => setFailed(src)}
        draggable={false}
        className={`${box} bg-slate-800 object-cover`}
      />
    );
  }
  const hue = hueOf(seed ?? name);
  return (
    <div
      role="img"
      aria-label={`${name} (no icon available)`}
      className={`${box} flex items-center justify-center font-bold text-white ${s.text}`}
      style={{ background: `linear-gradient(145deg, hsl(${hue} 55% 46%), hsl(${(hue + 40) % 360} 60% 30%))` }}
    >
      <span aria-hidden>{name.trim().charAt(0).toUpperCase() || '?'}</span>
    </div>
  );
}
