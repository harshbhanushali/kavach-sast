/**
 * The app's icon, as a small data URL for the report and the console.
 *
 * iOS ships icons as Apple's "CgBI" PNG variant: BGRA byte order, premultiplied
 * alpha and a raw deflate stream with no zlib header. No browser will draw one,
 * so it is converted back to an ordinary PNG here. Android icons are plain
 * PNG/WebP resources, except adaptive icons, whose foreground layer is used on
 * its own when there is no flat fallback.
 *
 * Everything is best-effort: an app without a usable icon simply has none, and
 * the UI falls back to a monogram. An icon is never a reason to fail a scan.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { deflateSync, inflateRawSync } from 'node:zlib';
import { dictGet } from './plist.ts';
import type { PlistValue } from './plist.ts';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
/** Icons above this are dropped rather than bloating every stored scan. */
const MAX_ICON_BYTES = 90 * 1024;

type Chunk = { type: string; data: Buffer };

function chunksOf(png: Buffer): Chunk[] {
  const chunks: Chunk[] = [];
  let at = 8;
  while (at + 12 <= png.length) {
    const length = png.readUInt32BE(at);
    const type = png.toString('latin1', at + 4, at + 8);
    if (at + 12 + length > png.length) break;
    chunks.push({ type, data: png.subarray(at + 8, at + 8 + length) });
    at += 12 + length;
    if (type === 'IEND') break;
  }
  return chunks;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer: Buffer): number {
  let c = 0xffffffff;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type: string, data: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'latin1');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])));
  return Buffer.concat([head, data, crc]);
}

/** The PNG filter predictors, reversed. Bytes per pixel is 4 for RGBA. */
function unfilter(raw: Buffer, width: number, height: number): Buffer | undefined {
  const bpp = 4;
  const stride = width * bpp;
  if (raw.length < height * (stride + 1)) return undefined;
  const out = Buffer.alloc(height * stride);

  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const src = y * (stride + 1) + 1;
    const dst = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const a = x >= bpp ? out[dst + x - bpp] : 0;
      const b = y > 0 ? out[dst - stride + x] : 0;
      const c = x >= bpp && y > 0 ? out[dst - stride + x - bpp] : 0;
      let predictor = 0;
      if (filter === 1) predictor = a;
      else if (filter === 2) predictor = b;
      else if (filter === 3) predictor = (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        predictor = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      } else if (filter > 4) return undefined;
      out[dst + x] = (raw[src + x] + predictor) & 0xff;
    }
  }
  return out;
}

/**
 * Converts an Apple CgBI PNG to a standard one; passes a normal PNG through.
 * Returns undefined for anything it does not understand (interlaced, palette).
 */
export function normalisePng(png: Buffer): Buffer | undefined {
  if (png.length < 33 || !png.subarray(0, 8).equals(PNG_SIGNATURE)) return undefined;
  const chunks = chunksOf(png);
  if (!chunks.some((c) => c.type === 'CgBI')) return png;

  const header = chunks.find((c) => c.type === 'IHDR')?.data;
  if (!header || header.length < 13) return undefined;
  const width = header.readUInt32BE(0);
  const height = header.readUInt32BE(4);
  const depth = header[8];
  const colourType = header[9];
  const interlace = header[12];
  // CgBI is always 8-bit RGBA in practice; refuse the rest rather than guess.
  if (depth !== 8 || colourType !== 6 || interlace !== 0 || width > 1024 || height > 1024) return undefined;

  let pixels: Buffer | undefined;
  try {
    const compressed = Buffer.concat(chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
    pixels = unfilter(inflateRawSync(compressed), width, height);
  } catch {
    return undefined;
  }
  if (!pixels) return undefined;

  // BGRA premultiplied -> RGBA straight.
  for (let i = 0; i < pixels.length; i += 4) {
    const b = pixels[i];
    const g = pixels[i + 1];
    const r = pixels[i + 2];
    const a = pixels[i + 3];
    pixels[i] = a === 0 ? 0 : Math.min(255, Math.round((r * 255) / a));
    pixels[i + 1] = a === 0 ? 0 : Math.min(255, Math.round((g * 255) / a));
    pixels[i + 2] = a === 0 ? 0 : Math.min(255, Math.round((b * 255) / a));
  }

  // Re-filter with "none" (0) on every row; simple, and the size cap covers it.
  const stride = width * 4;
  const rows = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y += 1) pixels.copy(rows, y * (stride + 1) + 1, y * stride, (y + 1) * stride);

  const ihdr = Buffer.from(header.subarray(0, 13));
  return Buffer.concat([
    PNG_SIGNATURE,
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(rows, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Pixel width from a PNG's IHDR, or 0. */
function pngWidth(png: Buffer): number {
  return png.length > 24 && png.subarray(0, 8).equals(PNG_SIGNATURE) ? png.readUInt32BE(16) : 0;
}

function dataUrl(mime: string, bytes: Buffer): string | undefined {
  return bytes.length <= MAX_ICON_BYTES ? `data:${mime};base64,${bytes.toString('base64')}` : undefined;
}

/* -------------------------------------------------------------------- iOS */

/** The icon file base names Info.plist declares, across the iPhone and iPad keys. */
function declaredIosIcons(info: PlistValue): string[] {
  const names: string[] = [];
  for (const key of ['CFBundleIcons', 'CFBundleIcons~ipad']) {
    const primary = dictGet(dictGet(info, key), 'CFBundlePrimaryIcon');
    const files = dictGet(primary, 'CFBundleIconFiles');
    if (Array.isArray(files)) for (const f of files) if (typeof f === 'string') names.push(f);
    const name = dictGet(primary, 'CFBundleIconName');
    if (typeof name === 'string') names.push(name);
  }
  const legacy = dictGet(info, 'CFBundleIconFiles');
  if (Array.isArray(legacy)) for (const f of legacy) if (typeof f === 'string') names.push(f);
  return names;
}

/**
 * The largest loose icon PNG at the root of the app bundle.
 *
 * Icons in an asset catalogue (Assets.car) are not readable without Apple's
 * tooling; most apps also ship the loose `AppIcon60x60@2x.png` files, which is
 * what this finds. The declared names are tried first, then any icon-like PNG.
 */
export function iosIcon(appDir: string, info: PlistValue): string | undefined {
  let entries: string[];
  try {
    entries = readdirSync(appDir).filter((f) => /\.png$/i.test(f));
  } catch {
    return undefined;
  }
  const declared = declaredIosIcons(info).map((n) => n.replace(/\.png$/i, '').toLowerCase());
  const matches = (f: string, preferDeclared: boolean) => {
    const base = f.toLowerCase().replace(/\.png$/, '');
    return preferDeclared ? declared.some((d) => base.startsWith(d)) : /icon/i.test(base) && !/launch|splash|small|spotlight|notification/i.test(base);
  };
  const candidates = [
    ...entries.filter((f) => matches(f, true)),
    ...entries.filter((f) => !matches(f, true) && matches(f, false)),
  ];

  let best: { width: number; png: Buffer } | undefined;
  for (const file of candidates.slice(0, 24)) {
    try {
      const full = join(appDir, file);
      if (statSync(full).size > 400 * 1024) continue;
      const png = normalisePng(readFileSync(full));
      const width = png ? pngWidth(png) : 0;
      if (png && width >= 40 && width <= 512 && (!best || width > best.width)) best = { width, png };
    } catch {
      // Unreadable icon: try the next.
    }
  }
  return best ? dataUrl('image/png', best.png) : undefined;
}

/* ---------------------------------------------------------------- Android */

/** The image type from the file's own signature, or undefined for anything else (vector XML, say). */
function sniffImage(bytes: Buffer): string | undefined {
  if (bytes.length > 12 && bytes.subarray(0, 8).equals(PNG_SIGNATURE)) return 'image/png';
  if (bytes.length > 12 && bytes.toString('latin1', 0, 4) === 'RIFF' && bytes.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  return undefined;
}

const DENSITY_ORDER = ['xxxhdpi', 'xxhdpi', 'xhdpi', 'hdpi', 'mdpi', 'ldpi', 'nodpi', ''];

/**
 * The launcher icon from an apktool-decoded APK.
 *
 * `iconRef` is the manifest's android:icon (e.g. `@mipmap/ic_launcher`). The
 * highest-density bitmap of that name wins; an adaptive icon has no bitmap of
 * its own, so its foreground layer is the fallback.
 */
export function androidIcon(decoded: string, iconRef: string | undefined): string | undefined {
  const res = join(decoded, 'res');
  if (!existsSync(res)) return undefined;

  const wanted = (iconRef ?? '@mipmap/ic_launcher').replace(/^@(mipmap|drawable)\//, '');
  const names = [wanted, 'ic_launcher', `${wanted}_foreground`, 'ic_launcher_foreground', 'ic_launcher_round'];

  let dirs: string[];
  try {
    dirs = readdirSync(res).filter((d) => /^(mipmap|drawable)/.test(d));
  } catch {
    return undefined;
  }
  const density = (dir: string) => {
    const i = DENSITY_ORDER.findIndex((d) => d && dir.includes(d));
    return i < 0 ? DENSITY_ORDER.length : i;
  };
  dirs.sort((a, b) => density(a) - density(b));

  for (const name of names) {
    for (const dir of dirs) {
      // The extension is not trusted: protected and resource-optimised APKs
      // ship the bitmap as a bare `ic_launcher`, so the image type is read from
      // its first bytes.
      for (const file of [`${name}.png`, `${name}.webp`, `${name}.jpg`, name]) {
        const full = join(res, dir, file);
        if (!existsSync(full)) continue;
        try {
          if (statSync(full).isDirectory()) continue;
          const bytes = readFileSync(full);
          const mime = sniffImage(bytes);
          const url = mime ? dataUrl(mime, bytes) : undefined;
          if (url) return url;
        } catch {
          // Unreadable candidate: try the next.
        }
      }
    }
  }
  return undefined;
}
