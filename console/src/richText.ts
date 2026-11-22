/**
 * Picking the code out of a sentence.
 *
 * Scanner prose is written for people but is full of things a person copies or
 * looks up: a command to run, a manifest attribute, a class or action name, a
 * URI. Left as plain text they blur into the sentence, and the one thing the
 * reader will paste into a terminal is the hardest thing on the page to find.
 *
 * This finds them by shape. A `backtick` span is always code, and the rest is a
 * best guess that errs on the side of leaving text alone: a missed highlight
 * costs nothing, a wrong one makes prose look broken. Pure and dependency-free
 * so the console and the printed report mark the same things.
 */
export type Piece = { kind: 'text' | 'code' | 'command'; value: string };

const TOOLS = 'adb|frida|lldb|jdb|curl|keytool|apksigner|jarsigner|apktool|jadx|openssl|sqlite3|codesign|otool|plutil|readelf|objdump|xcrun';
const SUBCOMMANDS =
  'shell|am|start|startservice|broadcast|content|query|insert|update|delete|install|uninstall|backup|restore|jdwp|logcat|run-as|pull|push|forward|dumpsys|pm|packages|verify|print|dump|extract';

// A command is a tool name plus at least one argument that looks like one. A
// bare "adb" in prose ("anyone with adb access") is not a command.
const ARG = String.raw`(?:<[^>\n]*>\S*|-{1,2}[\w-]+(?:=\S*)?|\S*[\/:=.]\S*|(?:${SUBCOMMANDS})\b)`;

const PATTERN = new RegExp(
  [
    '`([^`\\n]+)`', // 1: an explicit span
    `\\b((?:${TOOLS})(?:[ \\t]+${ARG})+)`, // 2: a command
    String.raw`(<[A-Za-z][\w-]*(?:\s+[\w:.-]+="[^"]*")*\s*\/?>)`, // 3: an XML element
    String.raw`(\b[A-Za-z][\w:-]*="[^"]*")`, // 4: an attribute with its value
    String.raw`(\b[a-z][a-z0-9+.-]*:\/\/[^\s,;)<>]+)`, // 5: a URI with a scheme
    String.raw`(\b[A-Za-z_][\w$]*(?:\.[A-Za-z_$][\w$]*){2,}\b)`, // 6: a dotted class, package, action or permission name
    String.raw`(\bandroid:[A-Za-z]+\b)`, // 7: a bare manifest attribute
  ].join('|'),
  'g',
);

const STARTS_WITH_TOOL = new RegExp(`^(?:${TOOLS})\\s`);

/** Trailing sentence punctuation is not part of the thing it follows. */
const TRAIL = /[.,;:!?)]+$/;

export function pieces(text: string): Piece[] {
  const out: Piece[] = [];
  let last = 0;
  const push = (kind: Piece['kind'], value: string) => {
    if (!value) return;
    const prev = out[out.length - 1];
    if (prev && prev.kind === kind && kind === 'text') prev.value += value;
    else out.push({ kind, value });
  };

  for (const m of text.matchAll(PATTERN)) {
    const at = m.index ?? 0;
    if (at < last) continue;
    push('text', text.slice(last, at));
    let value = m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5] ?? m[6] ?? m[7] ?? '';
    // A backtick span that opens with a tool name is a command, so it gets a copy button like the rest.
    const kind: Piece['kind'] = m[2] !== undefined || (m[1] !== undefined && STARTS_WITH_TOOL.test(value)) ? 'command' : 'code';
    let tail = '';
    if (m[1] === undefined && m[3] === undefined && m[4] === undefined) {
      const trail = value.match(TRAIL)?.[0];
      // "androgoat://..." is a placeholder, not a URI with a sentence's full stop after it.
      if (trail && !value.slice(0, -trail.length).endsWith('://')) {
        tail = trail;
        value = value.slice(0, -trail.length);
      }
    }
    push(kind, value);
    push('text', tail);
    last = at + m[0].length;
  }
  push('text', text.slice(last));
  return out;
}
