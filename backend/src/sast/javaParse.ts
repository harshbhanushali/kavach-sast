/**
 * A small reader for decompiled Java, enough to follow values through a method.
 *
 * jadx writes regular, one-statement-per-line Java, so a full grammar is not
 * needed: the reader splits a file into classes, their field initialisers and
 * their methods, and each method into statements. Everything is kept as text.
 * The checks built on top (`javaFlow.ts`) work on expressions as strings, which
 * is precise enough for `new SecretKeySpec(key.getBytes(), "AES")` and
 * `db.rawQuery("... " + name, null)` and does not pretend to be a compiler.
 *
 * What it does not do, on purpose: resolve types or overloads, follow generics,
 * or model control flow. A value assigned on one branch is treated as assigned.
 */

export type Param = { name: string; type: string };

export type Statement = { line: number; text: string };

export type MethodUnit = {
  name: string;
  params: Param[];
  /** Everything between the braces, including statements of nested anonymous classes. */
  statements: Statement[];
  line: number;
  owner: ClassUnit;
};

export type ClassUnit = {
  name: string;
  /** `extends` and `implements` names, so a ContentProvider or BroadcastReceiver can be recognised. */
  supers: string[];
  fields: Statement[];
  methods: MethodUnit[];
  parent?: ClassUnit;
};

export type ParsedFile = { classes: ClassUnit[]; lines: string[] };

/** Brace and parenthesis depth change of a line, ignoring strings, characters and comments. */
export function depthChange(text: string): { braces: number; parens: number } {
  let braces = 0;
  let parens = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const quote = c;
      i += 1;
      while (i < text.length && text[i] !== quote) i += text[i] === '\\' ? 2 : 1;
    } else if (c === '/' && text[i + 1] === '/') {
      break;
    } else if (c === '{') braces += 1;
    else if (c === '}') braces -= 1;
    else if (c === '(') parens += 1;
    else if (c === ')') parens -= 1;
  }
  return { braces, parens };
}

/** Removes a trailing line comment and a leading block-comment marker line. */
function stripComment(line: string): string {
  const trimmed = line.trim();
  if (trimmed.startsWith('/*') || trimmed.startsWith('*') || trimmed.startsWith('//')) return '';
  // A `//` or `/*` inside a string literal (a URL) is not a comment. jadx leaves `/* synthetic */`
  // inside a method header, which would otherwise stop it being recognised as one.
  let inString: string | undefined;
  let out = '';
  for (let i = 0; i < trimmed.length; i += 1) {
    const c = trimmed[i];
    if (inString) {
      out += c;
      if (c === '\\') {
        out += trimmed[i + 1] ?? '';
        i += 1;
      } else if (c === inString) inString = undefined;
    } else if (c === '"' || c === "'") {
      inString = c;
      out += c;
    } else if (c === '/' && trimmed[i + 1] === '/') return out.trim();
    else if (c === '/' && trimmed[i + 1] === '*') {
      const end = trimmed.indexOf('*/', i + 2);
      if (end < 0) return out.trim();
      out += ' ';
      i = end + 1;
    } else out += c;
  }
  return out.trim();
}

/** Joins physical lines into statements: a statement ends at `;`, `{` or `}`, with parentheses balanced. */
export function statementsOf(lines: string[]): Statement[] {
  const out: Statement[] = [];
  let pending = '';
  let start = 0;
  let parens = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const text = stripComment(lines[i]);
    if (!text) continue;
    if (!pending) start = i + 1;
    pending = pending ? `${pending} ${text}` : text;
    parens += depthChange(text).parens;
    if (parens > 0) continue;
    parens = 0;
    if (/[;{}]$/.test(text) || /^@/.test(pending) || /:$/.test(text)) {
      out.push({ line: start, text: pending });
      pending = '';
    }
  }
  if (pending) out.push({ line: start, text: pending });
  return out;
}

const CONTROL = /^(if|else|for|while|switch|catch|try|do|synchronized|return|throw|new|case|default)\b/;
const CLASS_HEADER = /\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)(?:<[^{]*?>)?\s*(?:extends\s+([\w.$<>, ?]+?))?\s*(?:implements\s+([\w.$<>, ?]+?))?\s*\{$/;
const METHOD_HEADER = /^(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*(?:<[^>]+>\s+)?(?:[\w$.<>\[\],? ]+?\s+)?([A-Za-z_$][\w$]*)\s*\(((?:[^()]|\([^()]*\))*)\)\s*(?:throws\s+[\w.$, ]+)?\s*\{$/;

function parseParams(list: string): Param[] {
  if (!list.trim()) return [];
  const params: Param[] = [];
  let depth = 0;
  let current = '';
  for (const c of list) {
    if (c === '<') depth += 1;
    else if (c === '>') depth -= 1;
    if (c === ',' && depth === 0) {
      params.push(paramOf(current));
      current = '';
    } else current += c;
  }
  if (current.trim()) params.push(paramOf(current));
  return params;
}

function paramOf(text: string): Param {
  const cleaned = text.replace(/\b(final)\b|@\w+(\([^)]*\))?/g, '').trim();
  const match = cleaned.match(/^(.*\S)\s+([A-Za-z_$][\w$]*)$/);
  return match ? { type: match[1].trim(), name: match[2] } : { type: '', name: cleaned };
}

type Frame =
  | { kind: 'class'; unit: ClassUnit }
  | { kind: 'method'; unit: MethodUnit }
  | { kind: 'block' };

export function parseJava(content: string): ParsedFile {
  const lines = content.split('\n');
  const classes: ClassUnit[] = [];
  const stack: Frame[] = [];
  const currentClass = (): ClassUnit | undefined => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      const frame = stack[i];
      if (frame.kind === 'class') return frame.unit;
    }
    return undefined;
  };
  const currentMethod = (): MethodUnit | undefined => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      const frame = stack[i];
      if (frame.kind === 'method') return frame.unit;
    }
    return undefined;
  };

  for (const statement of statementsOf(lines)) {
    const text = statement.text;
    const { braces } = depthChange(text);
    const innermost = stack[stack.length - 1];
    const insideMethod = Boolean(currentMethod());

    // Statements are recorded before the stack changes, so the opening line of a
    // method is not part of its own body.
    if (insideMethod) {
      if (!/^[{}]+$/.test(text)) currentMethod()!.statements.push(statement);
    } else if (innermost?.kind === 'class' && /;$/.test(text) && braces === 0) {
      innermost.unit.fields.push(statement);
    }

    // `} else {`, `} catch (X e) {`: a close followed by an open.
    const closes = (text.match(/^\}+/) ?? [''])[0].length;
    for (let i = 0; i < closes; i += 1) stack.pop();
    const rest = text.slice(closes).trim();
    if (!rest) continue;
    const net = braces + closes; // braces opened by `rest`

    if (net > 0 && rest.endsWith('{')) {
      const owner = currentClass();
      const top = stack[stack.length - 1];
      const classMatch = !currentMethod() && rest.match(CLASS_HEADER);
      if (classMatch) {
        const unit: ClassUnit = {
          name: classMatch[1],
          supers: [classMatch[2], classMatch[3]]
            .filter((s): s is string => Boolean(s))
            .flatMap((s) => s.split(',').map((x) => x.trim().replace(/<.*>/, '').split('.').pop()!)),
          fields: [],
          methods: [],
          parent: owner,
        };
        classes.push(unit);
        stack.push({ kind: 'class', unit });
      } else if (top?.kind === 'class' && owner && !CONTROL.test(rest)) {
        const header = rest.match(METHOD_HEADER);
        if (header && header[1] !== 'new') {
          const unit: MethodUnit = { name: header[1], params: parseParams(header[2]), statements: [], line: statement.line, owner };
          owner.methods.push(unit);
          stack.push({ kind: 'method', unit });
        } else {
          stack.push({ kind: 'block' });
        }
      } else {
        for (let i = 0; i < net; i += 1) stack.push({ kind: 'block' });
      }
    } else if (net > 0) {
      for (let i = 0; i < net; i += 1) stack.push({ kind: 'block' });
    } else if (net < 0) {
      for (let i = 0; i < -net; i += 1) stack.pop();
    }
  }
  return { classes, lines };
}
