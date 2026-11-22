/**
 * Keeping the scanner's own toolchain out of what a user can read.
 *
 * A report says what was found in the app. Which programs on the server found
 * it is not the reader's business, and naming them in a scan's limitations or
 * method (which are stored, exported as JSON and printed in the PDF) tells the
 * world how the service is built. New scans are written without those names;
 * this cleans the ones stored before that rule existed.
 */

/** The legacy wording, with the tool replaced by what it does. */
export function neutraliseText(text: string): string {
  return text
    .replace(/\s*Install it \(brew install [^)]*\)[^.]*\./g, '')
    .replace(/\bapktool\b/gi, 'the resource decoder')
    .replace(/\bjadx\b/gi, 'the decompiler')
    .replace(/\bapksigner\b/gi, 'signature verification')
    .replace(/\bkeytool\b/gi, 'certificate reading')
    .replace(/\bthe the\b/gi, 'the')
    .replace(/\bshown as smali\b/g, 'shown as Dalvik assembly')
    .replace(/\bfallback to smali\b/g, 'fallback to Dalvik assembly');
}

const TOOL_LINES: [RegExp, string][] = [
  [/^apktool\b/i, 'manifest and resource decoding'],
  [/^jadx\b/i, 'decompilation to Java'],
  [/^smali\b/i, 'code read as Dalvik assembly (no Java decompiler)'],
  [/^apksigner\b/i, 'signature parsing and verification'],
];

type Stored = {
  limitations?: string[];
  method?: { decompiler?: string; tools?: string[] };
};

/** Cleans one stored scan document in place. Returns whether anything changed. */
export function neutraliseScan(doc: Stored): boolean {
  let changed = false;

  if (Array.isArray(doc.limitations)) {
    doc.limitations = doc.limitations.map((line) => {
      const clean = neutraliseText(line);
      if (clean !== line) changed = true;
      return clean;
    });
  }

  const method = doc.method;
  if (method) {
    if (method.decompiler === 'jadx') {
      method.decompiler = 'java';
      changed = true;
    }
    if (Array.isArray(method.tools)) {
      method.tools = method.tools.map((line) => {
        const swap = TOOL_LINES.find(([pattern]) => pattern.test(line));
        if (!swap) return line;
        changed = true;
        return swap[1];
      });
    }
  }
  return changed;
}

/**
 * Notes the decompiler writes into the code it produces.
 *
 * Besides `/* JADX WARN: ... *\/` comments, a method it could not recover gets
 * a stack trace of its own internals (`at jadx.core.dex.visitors...`). Those are
 * about the decompile, not the app, and they name the tool. Replaced in place,
 * never removed: a finding's line number must still land on the same line.
 */
export function scrubDecompilerNotes(text: string): string {
  return text
    .replace(/\bjadx(?:\.[\w$]+)+/gi, 'decompiler.internal')
    .replace(/JADX/g, 'DECOMPILER')
    .replace(/Jadx/g, 'Decompiler')
    .replace(/jadx/g, 'decompiler');
}
