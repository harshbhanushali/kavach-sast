/**
 * A small XML reader, sufficient for AndroidManifest.xml and network security
 * config.
 *
 * Hand-rolled rather than pulled from npm because the input is narrow and
 * known: apktool's output is machine-generated, well-formed, namespace-prefixed
 * XML with no DTDs, no entities beyond the predefined five, and no mixed
 * content that matters here. A general parser would be more dependency than the
 * problem deserves.
 *
 * It is NOT a general XML parser and should not be reused as one.
 */

export type XmlNode = {
  name: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  /**
   * 1-based line in the source document.
   *
   * Carried so a manifest finding can say `AndroidManifest.xml:42` instead of
   * just naming the file. A reviewer with a line number opens the right place;
   * one with a filename goes hunting through 400 lines of generated XML.
   */
  line: number;
  /** The element's opening tag, verbatim, for the report's evidence column. */
  raw: string;
};

const ENTITIES: Record<string, string> = {
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'",
};

function decode(text: string): string {
  return text.replace(/&(amp|lt|gt|quot|apos);/g, (m) => ENTITIES[m] ?? m);
}

function parseAttrs(raw: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([\w:.-]+)\s*=\s*"([^"]*)"|([\w:.-]+)\s*=\s*'([^']*)'/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(raw)) !== null) {
    const key = match[1] ?? match[3];
    const value = match[2] ?? match[4] ?? '';
    attrs[key] = decode(value);
  }
  return attrs;
}

/** Parses a document and returns its root element, or null if there is none. */
export function parseXml(source: string): XmlNode | null {
  // Strip the pieces that carry no information for our purposes. Comments go
  // first so that a tag commented out cannot be read as live configuration.
  const text = source
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<\?[\s\S]*?\?>/g, '')
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')
    .replace(/<!DOCTYPE[^>]*>/gi, '');

  const stack: XmlNode[] = [];
  let root: XmlNode | null = null;
  const tag = /<\s*(\/?)\s*([\w:.-]+)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)\s*>/g;
  let match: RegExpExecArray | null;

  // Newline offsets, so a match index becomes a line number in one binary
  // search rather than by counting newlines for every tag.
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  }
  const lineAt = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  while ((match = tag.exec(text)) !== null) {
    const [, closing, name, rawAttrs, selfClosing] = match;

    if (closing) {
      // Tolerate a stray close tag rather than throwing: a partially malformed
      // manifest should still yield the components we can see.
      const index = stack.map((n) => n.name).lastIndexOf(name);
      if (index >= 0) stack.length = index;
      continue;
    }

    const node: XmlNode = {
      name,
      attrs: parseAttrs(rawAttrs),
      children: [],
      line: lineAt(match.index),
      raw: match[0].trim(),
    };
    if (stack.length === 0) {
      root ??= node;
    } else {
      stack[stack.length - 1].children.push(node);
    }
    if (!selfClosing) stack.push(node);
  }

  return root;
}

/** Every descendant with the given tag name, depth-first. */
export function findAll(node: XmlNode | null, name: string): XmlNode[] {
  if (!node) return [];
  const out: XmlNode[] = [];
  const stack = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.name === name) out.push(current);
    for (let i = current.children.length - 1; i >= 0; i -= 1) stack.push(current.children[i]);
  }
  return out;
}

/** The first descendant with the given tag name. */
export function findFirst(node: XmlNode | null, name: string): XmlNode | null {
  return findAll(node, name)[0] ?? null;
}

/**
 * Reads an attribute ignoring its namespace prefix.
 *
 * apktool emits `android:exported`, but a manifest merged from a library may
 * bind the Android namespace to a different prefix. Matching on the local name
 * avoids missing an exported component over a naming detail.
 */
export function attr(node: XmlNode, localName: string): string | undefined {
  const direct = node.attrs[`android:${localName}`] ?? node.attrs[localName];
  if (direct !== undefined) return direct;
  const key = Object.keys(node.attrs).find((k) => k.split(':').pop() === localName);
  return key ? node.attrs[key] : undefined;
}
