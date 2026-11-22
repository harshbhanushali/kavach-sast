/** The Kavach mark and wordmark. The drawing lives in brand.ts so reports share it. */
import { useId } from 'react';
import { BRAND, markSvg } from '../brand';

export function KavachMark({ size = 36, className = '', title }: { size?: number; className?: string; title?: string }) {
  // useId gives ":r1:"; colons are not valid in an SVG id reference.
  const uid = `km${useId().replace(/[^a-zA-Z0-9]/g, '')}`;
  return (
    <span
      className={`inline-block shrink-0 leading-none ${className}`}
      style={{ width: size, height: Math.round((size * 72) / 64) }}
      // Static markup from brand.ts, never user input.
      dangerouslySetInnerHTML={{ __html: markSvg(uid, { width: size, title }) }}
    />
  );
}

export function KavachLogo({ size = 60, tagline = true }: { size?: number; tagline?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <KavachMark size={size} />
      <div className="leading-tight">
        <h1 className="flex items-baseline gap-2 text-[1.6rem] font-extrabold uppercase tracking-[0.2em] text-slate-50">
          {BRAND.name}
          <span lang="sa" className="text-[1.5rem] font-semibold normal-case tracking-normal text-amber-300">{BRAND.devanagari}</span>
        </h1>
        {tagline && <p className="text-[0.85rem] text-slate-400">{BRAND.short}</p>}
      </div>
    </div>
  );
}
