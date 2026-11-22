/**
 * The product's identity, in one place.
 *
 * Kavach (कवच) is Sanskrit for armour. The mark draws on Maa Kalika as a
 * protector, through three of her emblems rather than her likeness: the khadga
 * (her sword), the crescent that crowns her, and the third eye that sees what
 * others miss. The blade rises through a crescent guard inside a shield, and the
 * third eye is cut into the blade. Ember and gold on near-black.
 */
export const BRAND = {
  name: 'Kavach SAST',
  devanagari: 'कवच',
  tagline: 'Static analysis for Android and iOS, with a report you can hand over.',
  /** Short form for places where the full line will not fit. */
  short: 'Static analysis for your app',
} as const;

/**
 * The mark as a self-contained SVG string, so the console, the printed reports
 * and the favicon draw exactly the same thing. `uid` keeps gradient ids unique
 * when several marks share one document.
 */
export function markSvg(uid: string, opts: { width?: number; height?: number; title?: string } = {}): string {
  const w = opts.width ?? 64;
  const h = opts.height ?? Math.round((w * 72) / 64);
  const label = opts.title ? `role="img" aria-label="${opts.title}"` : 'aria-hidden="true"';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 64 72" fill="none" ${label}>
  <defs>
    <linearGradient id="${uid}-rim" x1="8" y1="2" x2="56" y2="70" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#fcd34d"/><stop offset=".45" stop-color="#f97316"/><stop offset="1" stop-color="#be123c"/>
    </linearGradient>
    <radialGradient id="${uid}-body" cx="32" cy="28" r="42" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#2e0f19"/><stop offset="1" stop-color="#0a0508"/>
    </radialGradient>
    <linearGradient id="${uid}-blade" x1="32" y1="8" x2="32" y2="46" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#fb923c"/><stop offset=".55" stop-color="#e11d48"/><stop offset="1" stop-color="#9f1239"/>
    </linearGradient>
    <linearGradient id="${uid}-gold" x1="16" y1="40" x2="48" y2="62" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#fde68a"/><stop offset="1" stop-color="#f59e0b"/>
    </linearGradient>
  </defs>
  <path d="M32 2.8 58.6 12.2V37c0 16.6-11.6 27.4-26.6 33.2C17 64.4 5.4 53.6 5.4 37V12.2Z" fill="url(#${uid}-body)" stroke="url(#${uid}-rim)" stroke-width="2.6" stroke-linejoin="round"/>
  <path d="M32 8.4 53.2 15.6V37c0 13.4-9.4 22.2-21.2 27.2C20.2 59.2 10.8 50.4 10.8 37V15.6Z" stroke="#fcd34d" stroke-opacity=".28" stroke-width=".9" stroke-linejoin="round"/>
  <path d="M32 8C38 16 41 24 40.2 31 39.6 38 37.2 43 35.8 46.4H28.2C26.8 43 24.4 38 23.8 31 23 24 26 16 32 8Z" fill="url(#${uid}-blade)"/>
  <path d="M32 18.2c4.5 4.7 4.5 12.6 0 18.4-4.5-5.8-4.5-13.7 0-18.4Z" fill="#0a0508"/>
  <ellipse cx="32" cy="27.4" rx="2.1" ry="3.4" fill="#fde68a"/>
  <path d="M14.4 40.6C16.6 54.4 47.4 54.4 49.6 40.6 44.6 48.2 19.4 48.2 14.4 40.6Z" fill="url(#${uid}-gold)"/>
  <rect x="30.5" y="49.4" width="3" height="9.2" rx="1.2" fill="url(#${uid}-gold)"/>
  <circle cx="32" cy="61.3" r="2.7" fill="url(#${uid}-gold)"/>
</svg>`;
}

/**
 * The mark as a `data:` URL, for the one place that cannot hold markup: a
 * printed page's running header and footer (`@page` margin boxes), which can
 * only draw a background. Base64 keeps the URL free of quotes and brackets, so it
 * passes the report sanitiser's check that every `url()` is an embedded image.
 */
export function markDataUri(uid = 'run'): string {
  return `data:image/svg+xml;base64,${btoa(markSvg(uid, { width: 64, height: 72 }))}`;
}

/**
 * A full A4 sheet (210 x 297) with the mark centred on it, as a `data:` URL, for the
 * report's watermark. It is drawn in greys (the ember and gold would read as stray
 * colour at this strength) and at very low opacity: seen on a blank page, ignored on
 * a full one. It is laid over the content, not under it, so a table's white cells
 * cannot cut holes in it. Printed pages use it as one fixed background; the on-screen
 * preview repeats it down each sheet, one per A4 page.
 */
export function watermarkDataUri(opacity = 0.07): string {
  const grey = (hex: string) => {
    const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
    const y = Math.round(0.2126 * r + 0.7152 * g + 0.0722 * b).toString(16).padStart(2, '0');
    return `#${y}${y}${y}`;
  };
  const inner = markSvg('wm', { width: 64, height: 72 })
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>$/, '')
    .replace(/#[0-9a-f]{6}\b/gi, grey);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 210 297"><g opacity="${opacity}" transform="translate(45 81) scale(1.875)">${inner}</g></svg>`;
  return `data:image/svg+xml;base64,${btoa(svg)}`;
}
