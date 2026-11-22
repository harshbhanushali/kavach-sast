/**
 * Property list reader, binary and XML.
 *
 * An IPA's Info.plist is almost always the binary form, which is why this
 * exists: without it the iOS analyser could read nothing but strings. Written
 * in-process rather than shelling out to `plutil` so the backend runs the same
 * on Linux as on macOS — a self-hosted deployment should not need a Mac to scan
 * an IPA.
 *
 * Format reference: CFBinaryPlist.c. Header is `bplist00`, the last 32 bytes are
 * the trailer, and the trailer points at an offset table addressing every object.
 */
import { parseXml } from './xml.ts';
import type { XmlNode } from './xml.ts';

export type PlistValue =
  | string | number | boolean | Date | Buffer | null
  | PlistValue[]
  | { [key: string]: PlistValue };

/* ------------------------------------------------------------------ binary */

class BinaryPlistReader {
  // Plain fields rather than constructor parameter properties: the backend runs
  // on Node's type-stripping loader, which erases types but never emits code,
  // and a parameter property is code.
  private readonly buf: Buffer;
  private readonly offsets: number[] = [];
  private readonly objectRefSize: number;
  private readonly topObject: number;

  constructor(buf: Buffer) {
    this.buf = buf;
    if (buf.length < 40) throw new Error('plist too short to contain a trailer');

    const trailer = buf.subarray(buf.length - 32);
    const offsetIntSize = trailer.readUInt8(6);
    this.objectRefSize = trailer.readUInt8(7);
    const numObjects = Number(trailer.readBigUInt64BE(8));
    this.topObject = Number(trailer.readBigUInt64BE(16));
    const offsetTableOffset = Number(trailer.readBigUInt64BE(24));

    if (offsetIntSize < 1 || offsetIntSize > 8 || numObjects > 5_000_000) {
      throw new Error('implausible plist trailer');
    }
    for (let i = 0; i < numObjects; i += 1) {
      this.offsets.push(this.readUInt(offsetTableOffset + i * offsetIntSize, offsetIntSize));
    }
  }

  private readUInt(at: number, size: number): number {
    let value = 0;
    for (let i = 0; i < size; i += 1) value = value * 256 + this.buf.readUInt8(at + i);
    return value;
  }

  /** Reads the length nibble, following the `0xF` escape to a full integer. */
  private readLength(at: number, low: number): { length: number; next: number } {
    if (low !== 0xf) return { length: low, next: at + 1 };
    const marker = this.buf.readUInt8(at + 1);
    const size = 1 << (marker & 0x0f);
    return { length: this.readUInt(at + 2, size), next: at + 2 + size };
  }

  parse(): PlistValue {
    return this.object(this.topObject, 0);
  }

  private object(index: number, depth: number): PlistValue {
    // A malformed plist can describe a cycle; depth is the cheap guard.
    if (depth > 64) return null;
    const at = this.offsets[index];
    if (at === undefined || at >= this.buf.length) return null;

    const marker = this.buf.readUInt8(at);
    const type = marker >> 4;
    const low = marker & 0x0f;

    switch (type) {
      case 0x0:
        if (low === 0x8) return false;
        if (low === 0x9) return true;
        return null;

      case 0x1: {
        const size = 1 << low;
        // Signed 64-bit is the only width CF writes as negative.
        if (size === 8) return Number(this.buf.readBigInt64BE(at + 1));
        return this.readUInt(at + 1, size);
      }

      case 0x2:
        return low === 3 ? this.buf.readDoubleBE(at + 1) : this.buf.readFloatBE(at + 1);

      case 0x3:
        // Seconds since 2001-01-01, the Core Foundation epoch.
        return new Date((this.buf.readDoubleBE(at + 1) + 978_307_200) * 1000);

      case 0x4: {
        const { length, next } = this.readLength(at, low);
        return this.buf.subarray(next, next + length);
      }

      case 0x5: {
        const { length, next } = this.readLength(at, low);
        return this.buf.subarray(next, next + length).toString('latin1');
      }

      case 0x6: {
        const { length, next } = this.readLength(at, low);
        return this.buf.subarray(next, next + length * 2).swap16().toString('utf16le');
      }

      case 0x8:
        return this.readUInt(at + 1, low + 1);

      case 0xa:
      case 0xc: {
        const { length, next } = this.readLength(at, low);
        const out: PlistValue[] = [];
        for (let i = 0; i < length; i += 1) {
          out.push(this.object(this.readUInt(next + i * this.objectRefSize, this.objectRefSize), depth + 1));
        }
        return out;
      }

      case 0xd: {
        const { length, next } = this.readLength(at, low);
        const out: { [key: string]: PlistValue } = {};
        for (let i = 0; i < length; i += 1) {
          const keyRef = this.readUInt(next + i * this.objectRefSize, this.objectRefSize);
          const valueRef = this.readUInt(
            next + length * this.objectRefSize + i * this.objectRefSize,
            this.objectRefSize,
          );
          const key = this.object(keyRef, depth + 1);
          if (typeof key === 'string') out[key] = this.object(valueRef, depth + 1);
        }
        return out;
      }

      default:
        return null;
    }
  }
}

/* --------------------------------------------------------------------- xml */

/**
 * XML plists interleave <key> with the value element that follows it, so the
 * children are read pairwise rather than as a mapping.
 */
function fromXml(node: XmlNode): PlistValue {
  switch (node.name) {
    case 'true': return true;
    case 'false': return false;
    case 'integer': return Number(textOf(node)) || 0;
    case 'real': return Number(textOf(node)) || 0;
    case 'string': return textOf(node);
    case 'data': return Buffer.from(textOf(node), 'base64');
    case 'date': return new Date(textOf(node));
    case 'array': return node.children.map(fromXml);
    case 'dict': {
      const out: { [key: string]: PlistValue } = {};
      for (let i = 0; i < node.children.length - 1; i += 1) {
        if (node.children[i].name !== 'key') continue;
        out[textOf(node.children[i])] = fromXml(node.children[i + 1]);
        i += 1;
      }
      return out;
    }
    default: return null;
  }
}

/**
 * The XML reader in `xml.ts` builds an element tree and drops text nodes, which
 * is right for a manifest and wrong for a plist, where the text *is* the value.
 * Rather than complicate that parser, XML plists are read with a targeted
 * scanner here.
 */
const TEXT = new WeakMap<XmlNode, string>();
function textOf(node: XmlNode): string {
  return TEXT.get(node) ?? '';
}

function parseXmlPlist(source: string): PlistValue {
  // Re-parse with text capture: walk tags and keep the run of characters
  // between an open tag and its matching close.
  const stack: XmlNode[] = [];
  let root: XmlNode | null = null;
  const token = /<\s*(\/?)\s*([\w:.-]+)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)\s*>|([^<]+)/g;
  let match: RegExpExecArray | null;

  while ((match = token.exec(source)) !== null) {
    const [, closing, name, , selfClosing, text] = match;

    if (text !== undefined) {
      if (stack.length > 0) {
        const top = stack[stack.length - 1];
        TEXT.set(top, (TEXT.get(top) ?? '') + text);
      }
      continue;
    }
    if (name === 'plist' || name?.startsWith('?') || name?.startsWith('!')) {
      if (!closing && !selfClosing && name === 'plist') stack.push({ name, attrs: {}, children: [], line: 0, raw: '' });
      else if (closing && name === 'plist') stack.pop();
      continue;
    }
    if (closing) {
      stack.pop();
      continue;
    }
    const node: XmlNode = { name, attrs: {}, children: [], line: 0, raw: '' };
    if (stack.length > 0) stack[stack.length - 1].children.push(node);
    else root ??= node;
    if (stack.length === 1 && stack[0].name === 'plist' && !root) root = node;
    if (!selfClosing) stack.push(node);
  }

  // The root is the first element inside <plist>; when <plist> was pushed it
  // holds exactly one child.
  const top = root ?? null;
  return top ? fromXml(top) : null;
}

/* ------------------------------------------------------------------- entry */

/** Parses either plist encoding. Returns null when the buffer is neither. */
export function parsePlist(buffer: Buffer): PlistValue {
  if (buffer.subarray(0, 8).toString('latin1') === 'bplist00') {
    try {
      return new BinaryPlistReader(buffer).parse();
    } catch {
      return null;
    }
  }
  const text = buffer.toString('utf8');
  if (text.includes('<plist')) {
    try {
      const dict = text.match(/<plist[^>]*>([\s\S]*)<\/plist>/)?.[1] ?? text;
      return parseXmlPlist(dict);
    } catch {
      return null;
    }
  }
  return null;
}

/** Narrow helper: the value at `key`, when the plist is a dictionary. */
export function dictGet(value: PlistValue, key: string): PlistValue {
  if (value && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value)) {
    return (value as Record<string, PlistValue>)[key] ?? null;
  }
  return null;
}

/** A plist as indented text. Deliberately not JSON: dates and data are not. */
export function renderPlist(value: PlistValue, depth: number): string {
  const pad = '  '.repeat(depth);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((v) => `${pad}  ${renderPlist(v, depth + 1)}`).join('\n')}\n${pad}]`;
  }
  if (value instanceof Date) return value.toISOString();
  // <data> is a Buffer, which is an object: without this it would print byte by byte.
  if (Buffer.isBuffer(value)) return `<data ${value.length} bytes>`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, PlistValue>);
    if (entries.length === 0) return '{}';
    return `{\n${entries
      .map(([k, v]) => `${pad}  ${k} = ${renderPlist(v, depth + 1)}`)
      .join('\n')}\n${pad}}`;
  }
  if (typeof value === 'string') return JSON.stringify(value);
  return String(value);
}

/**
 * The first line of a binary property list once decoded for display.
 *
 * The scan decodes plists to analyse them and the Explorer decodes them again to
 * show them. A finding's line number is only right if both produce the same
 * text, so both take this line from here: with the header in one and not the
 * other, every line number in a binary plist was off by one.
 */
export const BINARY_PLIST_NOTE = '// Apple binary property list, decoded for display.\n';
