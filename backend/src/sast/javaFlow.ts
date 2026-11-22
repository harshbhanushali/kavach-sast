/**
 * Following values through decompiled Java.
 *
 * Pattern rules say "this call exists". The weaknesses that matter most are about
 * what reaches a call: an AES key that is a string constant, a SQL string built
 * from an intent extra, a URL that arrived from outside and was handed to a
 * WebView. This pass reads each method, tracks which names hold constants and
 * which hold untrusted input, and reports when one of them reaches a call that
 * should not receive it.
 *
 * It is deliberately small:
 *
 * - Values are tracked by name within a class, in statement order, with no model
 *   of branches or loops. A name assigned on any path counts as assigned.
 * - A call is followed one hop at a time across methods of the same file: if a
 *   helper passes its parameter to `new IvParameterSpec(...)`, every call site
 *   that hands the helper a constant is reported at the call site.
 * - Anything it cannot resolve is left alone. The failure it prefers is a
 *   missed finding, never an invented one, so each source and sink is named
 *   rather than guessed from a variable's spelling.
 */
import { readText } from './fileCache.ts';
import { PATTERN_RULES } from './rules.ts';
import type { PatternRule } from './rules.ts';
import { findingFrom, snippetAround } from './scanner.ts';
import type { WalkedFile } from './scanner.ts';
import type { SastFinding, SastLocation } from './types.ts';
import { redact } from './types.ts';
import { parseJava } from './javaParse.ts';
import type { ClassUnit, MethodUnit, Statement } from './javaParse.ts';

// ---------------------------------------------------------------------------
// Expressions, as text
// ---------------------------------------------------------------------------

const KEYWORDS = new Set([
  'new', 'this', 'super', 'null', 'true', 'false', 'return', 'int', 'long', 'byte', 'char', 'short', 'float', 'double',
  'boolean', 'void', 'String', 'instanceof', 'final', 'static', 'if', 'else', 'for', 'while', 'class',
]);

/** String literals with their contents blanked, so text inside quotes is never read as code. */
export function blankStrings(expr: string): string {
  let out = '';
  for (let i = 0; i < expr.length; i += 1) {
    const c = expr[i];
    if (c === '"' || c === "'") {
      out += c;
      i += 1;
      while (i < expr.length && expr[i] !== c) {
        out += ' ';
        i += expr[i] === '\\' ? 2 : 1;
      }
      out += c;
    } else out += c;
  }
  return out;
}

/** Splits at a separator that is not inside parentheses, brackets, braces or quotes. */
export function splitTop(expr: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < expr.length; i += 1) {
    const c = expr[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < expr.length && expr[j] !== c) j += expr[j] === '\\' ? 2 : 1;
      current += expr.slice(i, j + 1);
      i = j;
      continue;
    }
    if ('([{'.includes(c)) depth += 1;
    else if (')]}'.includes(c)) depth -= 1;
    if (depth === 0 && c === separator) {
      parts.push(current.trim());
      current = '';
    } else current += c;
  }
  if (current.trim() || parts.length > 0) parts.push(current.trim());
  return parts;
}

export type Call = { callee: string; args: string[]; index: number };

/** Every call whose callee text matches `callee`, with its arguments split at the top level. */
export function findCalls(text: string, callee: RegExp): Call[] {
  const calls: Call[] = [];
  const re = new RegExp(`(?:${callee.source})\\s*\\(`, 'g');
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let end = -1;
    for (let i = open; i < text.length; i += 1) {
      const c = text[i];
      if (c === '"' || c === "'") {
        i += 1;
        while (i < text.length && text[i] !== c) i += text[i] === '\\' ? 2 : 1;
      } else if (c === '(') depth += 1;
      else if (c === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end < 0) continue;
    const inner = text.slice(open + 1, end);
    calls.push({ callee: m[0].slice(0, -1).trim(), args: inner.trim() ? splitTop(inner, ',') : [], index: m.index });
  }
  return calls;
}

/** `this.key`, `Outer.this.key` and a lone cast read as the plain name. */
function normalise(expr: string): string {
  return expr
    .replace(/\b[\w$]+\s*\.\s*this\s*\./g, '')
    .replace(/\bthis\s*\.\s*/g, '')
    .replace(/^\s*\((?:[\w$.]+(?:\[\])*)\)\s*/, '')
    .trim();
}

/** Identifiers that are values: not keywords, not called, not members of something else. */
export function valueNames(expr: string): string[] {
  const text = blankStrings(normalise(expr));
  const names: string[] = [];
  const re = /(?<![\w$.])([A-Za-z_$][\w$]*)(?!\s*\()/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (!KEYWORDS.has(m[1])) names.push(m[1]);
  }
  return names;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export type Value =
  | { kind: 'string'; value: string }
  | { kind: 'bytes'; zero: boolean; text?: string }
  | { kind: 'number'; value: number };

const STRING_LITERAL = /^"((?:[^"\\]|\\.)*)"$/;

function unescape(text: string): string {
  return text.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_m, g: string) =>
    g.startsWith('u') && g.length === 5 ? String.fromCharCode(parseInt(g.slice(1), 16)) : g === 'n' ? '\n' : g === 't' ? '\t' : g,
  );
}

function stripParens(expr: string): string {
  let text = expr.trim();
  while (text.startsWith('(') && text.endsWith(')') && splitTop(text.slice(1, -1), ',').length === 1) {
    // Only strip when the outer pair matches each other.
    let depth = 0;
    let matched = true;
    for (let i = 0; i < text.length - 1; i += 1) {
      if (text[i] === '(') depth += 1;
      else if (text[i] === ')') depth -= 1;
      if (depth === 0) {
        matched = false;
        break;
      }
    }
    if (!matched) break;
    text = text.slice(1, -1).trim();
  }
  return text;
}

export function evalConst(expression: string, consts: Map<string, Value>): Value | undefined {
  const expr = stripParens(normalise(expression));
  if (!expr) return undefined;

  const literal = expr.match(STRING_LITERAL);
  if (literal) return { kind: 'string', value: unescape(literal[1]) };
  if (/^-?\d+[lL]?$/.test(expr)) return { kind: 'number', value: Number(expr.replace(/[lL]$/, '')) };
  if (/^0[xX][0-9a-fA-F]+$/.test(expr)) return { kind: 'number', value: parseInt(expr, 16) };

  // new byte[16]: sixteen zero bytes, which is as constant as a key can be.
  if (/^new\s+byte\s*\[\s*\d+\s*\]$/.test(expr)) return { kind: 'bytes', zero: true };
  const initialiser = expr.match(/^(?:new\s+(?:byte|String)\s*\[\s*\]\s*)?\{([^{}]*)\}$/);
  if (initialiser) {
    const items = splitTop(initialiser[1], ',').filter(Boolean);
    if (items.length > 0 && items.every((i) => /^(?:\(byte\)\s*)?-?(?:0[xX][0-9a-fA-F]+|\d+)$/.test(i.trim()))) {
      return { kind: 'bytes', zero: items.every((i) => /^(?:\(byte\)\s*)?0+$/.test(i.trim())) };
    }
    // new String[]{"which", "su"}: constant when every element is.
    if (/^new\s+String\s*\[\s*\]/.test(expr) || items.every((i) => STRING_LITERAL.test(i.trim()))) {
      const parts = items.map((i) => evalConst(i, consts));
      if (items.length > 0 && parts.every((p) => p?.kind === 'string')) {
        return { kind: 'string', value: parts.map((p) => (p as { value: string }).value).join(' ') };
      }
    }
    return undefined;
  }

  const wrapped = expr.match(/^new\s+String\s*\(([\s\S]*)\)$/) ?? expr.match(/^String\s*\.\s*valueOf\s*\(([\s\S]*)\)$/);
  if (wrapped) {
    const inner = evalConst(splitTop(wrapped[1], ',')[0], consts);
    if (inner?.kind === 'string') return inner;
    if (inner?.kind === 'bytes' && inner.text !== undefined) return { kind: 'string', value: inner.text };
    return undefined;
  }

  // "literal".getBytes(...) / .toCharArray(), and the same on a constant name.
  const toBytes = expr.match(/^([\s\S]+?)\s*\.\s*(?:getBytes|toCharArray)\s*\(([\s\S]*)\)$/);
  if (toBytes) {
    const inner = evalConst(toBytes[1], consts);
    if (inner?.kind === 'string') return { kind: 'bytes', zero: false, text: inner.value };
    return undefined;
  }

  const decoded = expr.match(/^(?:Base64\s*\.\s*decode|Base64\s*\.\s*getDecoder\s*\(\s*\)\s*\.\s*decode|Hex\s*\.\s*decodeHex|Hex\s*\.\s*decode)\s*\(([\s\S]*)\)$/);
  if (decoded) {
    const inner = evalConst(splitTop(decoded[1], ',')[0], consts);
    if (inner?.kind === 'string') return { kind: 'bytes', zero: false, text: inner.value };
    return undefined;
  }

  if (/^[A-Za-z_$][\w$]*$/.test(expr)) return consts.get(expr);
  const qualified = expr.match(/^[A-Z][\w$]*\s*\.\s*([A-Za-z_$][\w$]*)$/);
  if (qualified && /^[A-Z][A-Z0-9_]*$/.test(qualified[1])) return consts.get(qualified[1]);

  // "a" + "b" + CONSTANT
  const parts = splitTop(expr, '+');
  if (parts.length > 1) {
    let joined = '';
    for (const part of parts) {
      const v = evalConst(part, consts);
      if (!v || v.kind === 'bytes') return undefined;
      joined += v.kind === 'string' ? v.value : String(v.value);
    }
    return { kind: 'string', value: joined };
  }
  return undefined;
}

/** Whether an expression builds a string from parts, at least one of which is not constant. */
export function isDynamicString(expression: string, consts: Map<string, Value>, dynamic: Set<string>): boolean {
  const expr = stripParens(normalise(expression));
  if (evalConst(expr, consts)) return false;
  if (/^[A-Za-z_$][\w$]*$/.test(expr)) return dynamic.has(expr);
  const parts = splitTop(expr, '+');
  if (parts.length > 1) return parts.some((p) => !evalConst(p, consts));
  if (/^String\s*\.\s*format\s*\(/.test(expr)) return splitTop(expr.slice(expr.indexOf('(') + 1, expr.lastIndexOf(')')), ',').slice(1).some((a) => !evalConst(a, consts));
  if (/^new\s+StringBuilder\b|\.append\s*\(/.test(expr)) {
    return findCalls(expr, /\.\s*append|new\s+StringBuilder|new\s+StringBuffer/).some((c) => c.args.some((a) => a && !evalConst(a, consts)));
  }
  return false;
}

// ---------------------------------------------------------------------------
// Sources of untrusted input
// ---------------------------------------------------------------------------

/** Expressions that produce data an outside party chose. */
const SOURCE_EXPRESSIONS: RegExp[] = [
  /\bgetIntent\s*\(\s*\)\s*\.\s*(?:get\w*Extra|getData|getDataString|getExtras|getAction|getStringExtra)\b/,
  /\b(?:intent|data|extras|bundle\d*|args|arguments|savedInstanceState|msg)\s*\.\s*(?:get(?:String|Int|Long|Boolean|Parcelable|Serializable|CharSequence|ByteArray)(?:Extra)?|getData|getDataString|getExtras|getQueryParameter|getAction)\s*\(/i,
  /\.\s*(?:getQueryParameter|getLastPathSegment|getPathSegments|getEncodedQuery|getEncodedPath|getEncodedFragment)\s*\(/,
  /\.\s*getText\s*\(\s*\)(?:\s*\.\s*toString\s*\(\s*\))?/,
  /\.\s*getEditableText\s*\(\s*\)/,
  /\bgetArguments\s*\(\s*\)\s*\.\s*get/,
  /\b(?:parcel|parcel\d+|in|source|dest)\s*\.\s*read(?:String|Value|Serializable|Parcelable|Bundle|CharSequence|StringArray)\s*\(/,
  /\.\s*getPrimaryClip\s*\(/,
];

export function hasSource(expression: string): boolean {
  const text = blankStrings(expression);
  return SOURCE_EXPRESSIONS.some((re) => re.test(text));
}

const ENTRY_SUPERS = /^(ContentProvider|BroadcastReceiver|Service|IntentService|JobIntentService|Activity|AppCompatActivity|FragmentActivity|Fragment|WebViewClient|WebChromeClient)$/;

/**
 * Parameters that carry outside data into a method the framework calls.
 *
 * A ContentProvider's `query(uri, projection, selection, args, order)` is called
 * with whatever another app sent; so is a receiver's `onReceive(context, intent)`
 * and a WebViewClient's `shouldOverrideUrlLoading(view, url)`. Their parameters
 * are inputs by contract, not by guess.
 */
function entryParams(method: MethodUnit): number[] {
  const supers = new Set(method.owner.supers);
  const name = method.name;
  const take = (predicate: (type: string, i: number) => boolean) =>
    method.params.map((p, i) => (predicate(p.type, i) ? i : -1)).filter((i) => i >= 0);

  if (supers.has('ContentProvider') && /^(query|insert|update|delete|openFile|openAssetFile|call|bulkInsert)$/.test(name)) {
    return take((type) => /^(Uri|String|String\[\]|ContentValues|Bundle)$/.test(type));
  }
  if (supers.has('BroadcastReceiver') && name === 'onReceive') return take((type) => type === 'Intent');
  if ((supers.has('Service') || supers.has('IntentService') || supers.has('JobIntentService')) && /^(onStartCommand|onBind|onHandleIntent|onHandleWork)$/.test(name)) {
    return take((type) => type === 'Intent');
  }
  if (/^(onNewIntent|onActivityResult)$/.test(name)) return take((type) => type === 'Intent');
  if (/^(shouldOverrideUrlLoading|shouldInterceptRequest)$/.test(name) && supers.has('WebViewClient')) {
    return take((type) => type === 'String' || type === 'WebResourceRequest');
  }
  return [];
}

// ---------------------------------------------------------------------------
// The sinks
// ---------------------------------------------------------------------------

type Action = { need: 'taint' | 'dynamic' | 'const' | 'nonconst'; rule: string };

type Sink = {
  /** Callee text, as a regular expression source. */
  callee: string;
  /** Which arguments to examine. */
  args: number[];
  /** Minimum number of arguments the call must have, to tell overloads apart. */
  minArgs?: number;
  maxArgs?: number;
  actions: Action[];
  /** Skip the call when this matches the enclosing method's text. */
  unless?: RegExp;
};

const SQL_ACTIONS: Action[] = [
  { need: 'taint', rule: 'code.sql_injection' },
  { need: 'dynamic', rule: 'code.sql_concatenation' },
];

const SINKS: Sink[] = [
  // SQL
  { callee: '\\.\\s*rawQuery', args: [0], actions: SQL_ACTIONS },
  { callee: '\\.\\s*rawQueryWithFactory', args: [1], actions: SQL_ACTIONS },
  { callee: '\\.\\s*execSQL', args: [0], actions: SQL_ACTIONS },
  { callee: '\\.\\s*compileStatement', args: [0], actions: SQL_ACTIONS },
  { callee: '\\.\\s*appendWhere', args: [0], actions: SQL_ACTIONS },
  { callee: '\\.\\s*query', args: [2], minArgs: 5, actions: SQL_ACTIONS },
  { callee: '\\.\\s*update', args: [2], minArgs: 4, maxArgs: 5, actions: SQL_ACTIONS },
  { callee: '\\.\\s*delete', args: [1], minArgs: 3, maxArgs: 3, actions: SQL_ACTIONS },
  { callee: '\\.\\s*(?:executeQuery|executeUpdate|prepareStatement)', args: [0], actions: SQL_ACTIONS },

  // WebView
  {
    callee: '\\.\\s*(?:loadUrl|evaluateJavascript)',
    args: [0],
    actions: [{ need: 'taint', rule: 'code.webview_untrusted_url' }, { need: 'dynamic', rule: 'code.webview_dynamic_url' }],
  },
  { callee: '\\.\\s*loadData', args: [0], actions: [{ need: 'taint', rule: 'code.webview_untrusted_url' }] },
  { callee: '\\.\\s*loadDataWithBaseURL', args: [1], actions: [{ need: 'taint', rule: 'code.webview_untrusted_url' }] },

  // Commands, files, reflection
  {
    callee: '\\.\\s*exec',
    args: [0],
    actions: [{ need: 'taint', rule: 'code.command_injection' }, { need: 'nonconst', rule: 'code.runtime_exec' }],
  },
  {
    callee: 'new\\s+ProcessBuilder',
    args: [0],
    actions: [{ need: 'taint', rule: 'code.command_injection' }, { need: 'nonconst', rule: 'code.runtime_exec' }],
  },
  {
    callee: 'new\\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)',
    args: [0, 1],
    actions: [{ need: 'taint', rule: 'code.path_traversal' }],
    unless: /getCanonicalPath|getCanonicalFile|\.normalize\s*\(|\.startsWith\s*\(|contains\(\s*"\.\."/,
  },
  { callee: '\\.\\s*(?:openFileOutput|openFileInput)', args: [0], actions: [{ need: 'taint', rule: 'code.path_traversal' }] },
  { callee: '(?:\\bClass\\s*\\.\\s*forName|\\.\\s*loadClass)', args: [0], actions: [{ need: 'taint', rule: 'code.unsafe_reflection' }] },

  // Messaging
  { callee: '\\.\\s*sendTextMessage', args: [0], actions: [{ need: 'taint', rule: 'code.sms_untrusted_destination' }] },

  // Cryptography: a constant where a secret belongs
  { callee: 'new\\s+SecretKeySpec', args: [0], actions: [{ need: 'const', rule: 'crypto.hardcoded_key_constant' }] },
  { callee: 'new\\s+IvParameterSpec', args: [0], actions: [{ need: 'const', rule: 'crypto.hardcoded_iv' }] },
  { callee: 'new\\s+GCMParameterSpec', args: [1], actions: [{ need: 'const', rule: 'crypto.hardcoded_iv' }] },
  { callee: 'new\\s+PBEKeySpec', args: [0], actions: [{ need: 'const', rule: 'secret.hardcoded_password_arg' }] },
  { callee: 'new\\s+PasswordAuthentication', args: [1], actions: [{ need: 'const', rule: 'secret.hardcoded_password_arg' }] },
  { callee: '\\.\\s*setPassword', args: [0], actions: [{ need: 'const', rule: 'secret.hardcoded_password_arg' }] },
  { callee: '\\bDriverManager\\s*\\.\\s*getConnection', args: [2], minArgs: 3, actions: [{ need: 'const', rule: 'secret.hardcoded_password_arg' }] },
];

/**
 * Whether the thing `.putString` is called on is a SharedPreferences editor.
 *
 * `putString` is also how a React Native map, a Bundle and a JSON builder are filled, none of which
 * persist anything. The receiver is either a chain ending in `.edit()`, or a name declared as an
 * Editor or SharedPreferences, or one named like one.
 */
function isPreferencesReceiver(before: string, env: Env): boolean {
  const chain = before.trimEnd();
  if (/\.\s*edit\s*\(\s*\)$/.test(chain) || /\.\s*(?:getSharedPreferences|getDefaultSharedPreferences|getPreferences)\s*\([^()]*\)$/.test(chain)) return true;
  const name = chain.match(/([A-Za-z_$][\w$]*)$/)?.[1];
  if (!name) return false;
  const type = env.types.get(name);
  if (type) return /(?:Shared)?Preferences(?:\.Editor)?$|Editor$/.test(type);
  return /^(?:edit(?:or)?|prefs?|preferences|sp)\d*$/i.test(name) || /editor/i.test(name);
}

/** A literal that could be a key, IV or password: text or bytes, never a number, never empty. */
function isSecretValue(value: Value | undefined): boolean {
  if (!value || value.kind === 'number') return false;
  return !(value.kind === 'string' && value.value.length === 0);
}

/**
 * `"Statements_" + name + ".html"`: a literal that starts the path and does not end in a separator.
 * The input can no longer begin a path segment, so `../` in it names a directory that does not exist
 * rather than the parent of this one.
 */
function fixedPrefix(expression: string): boolean {
  const parts = splitTop(stripParens(normalise(expression)), '+');
  if (parts.length < 2) return false;
  const first = parts[0].trim().match(STRING_LITERAL);
  return Boolean(first && first[1].length > 0 && !/[\\/]$/.test(first[1]));
}

/** Sinks whose condition is on the shape of the call, not on a value. */
const SHAPES: { callee: string; rule: string; test: (args: string[], fileText: string) => boolean }[] = [
  { callee: '\\.\\s*authenticate', rule: 'code.biometric_no_crypto', test: (args, file) => (args.length === 1 && /\bBiometricPrompt\b/.test(file)) || (args.length >= 4 && args[0].trim() === 'null') },
  { callee: '\\.\\s*registerReceiver', rule: 'code.receiver_registered_unprotected', test: (args) => args.length === 2 || (args.length === 3 && /^(?:2|[\w.]*RECEIVER_EXPORTED)$/.test(args[2].trim())) },
  { callee: 'new\\s+ObjectInputStream', rule: 'code.insecure_deserialization', test: () => true },
];

const SENSITIVE_NAME = /(?:pass(?:word|wd|phrase|code)?|pwd|secret|token|api[_-]?key|credential|\bpin\b|cvv|card[_-]?(?:number|no)|\bssn\b|\botp\b)/i;
const SENSITIVE_IDENT = /^(?:\w*(?:pass(?:word|wd|phrase)|pwd|secret|token|apikey|api_key|credential|cvv|cardnumber|card_number|ssn|otp)\w*|pin|pin\w+)$/i;

const LOG_CALLS = '(?:\\bLog\\s*\\.\\s*[vdiwe]|\\bLog\\s*\\.\\s*wtf|System\\s*\\.\\s*(?:out|err)\\s*\\.\\s*print(?:ln)?|\\bTimber\\s*\\.\\s*[vdiwe])';
const PREFERENCE_PUTS = '\\.\\s*put(?:String|Int|Long|Boolean|Float|StringSet)';

// ---------------------------------------------------------------------------
// The analysis
// ---------------------------------------------------------------------------

type Labels = Set<string>;

type Env = {
  /** Declared types of names, so `editor.putString` can be told from `map.putString`. */
  types: Map<string, string>;
  consts: Map<string, Value>;
  tainted: Map<string, Labels>;
  dynamic: Set<string>;
};

export type FlowHit = { rule: string; file: string; line: number; text: string };

type Summary = { rule: string; need: Action['need']; param: number };

const SRC = 'src';

function cloneEnv(env: Env): Env {
  return { types: new Map(env.types), consts: new Map(env.consts), tainted: new Map([...env.tainted].map(([k, v]) => [k, new Set(v)])), dynamic: new Set(env.dynamic) };
}

function labelsOf(expression: string, env: Env): Labels {
  const out: Labels = new Set();
  const expr = stripParens(normalise(expression));
  // A parsed number, a length or an equality test carries no attacker data onward.
  if (/^(?:Integer|Long|Short|Double|Float|Boolean)\s*\./.test(expr)) return out;
  if (/\.\s*(?:length|size|isEmpty|equals|equalsIgnoreCase|contains|startsWith|endsWith|hashCode|intValue)\s*\(\s*[^()]*\)$/.test(expr)) return out;
  if (hasSource(expr)) out.add(SRC);
  for (const name of valueNames(expr)) {
    const labels = env.tainted.get(name);
    if (labels) for (const l of labels) out.add(l);
  }
  return out;
}

/** `Type name = value;`, `name = value;`, `this.name = value;`, `name += value;` */
const ASSIGNMENT = /^(?:(?:final|static|volatile|transient|private|public|protected)\s+)*(?:([\w$.<>\[\],? ]+?)\s+)?([A-Za-z_$][\w$.]*)\s*(\+?=)\s*([\s\S]+?);$/;

function parseAssignment(text: string): { name: string; op: string; value: string; declared: boolean; type?: string } | undefined {
  if (/^(?:return|throw|if|while|for|else|case|new)\b/.test(text)) return undefined;
  const m = text.match(ASSIGNMENT);
  if (!m) return undefined;
  const name = normalise(m[2]);
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  return { name, op: m[3], value: m[4], declared: Boolean(m[1]), type: m[1]?.trim() };
}

function bind(env: Env, name: string, value: string, op: string, type?: string): void {
  if (type) env.types.set(name, type);
  const constant = op === '=' ? evalConst(value, env.consts) : undefined;
  if (constant) env.consts.set(name, constant);
  else env.consts.delete(name);

  const labels = labelsOf(value, env);
  if (op === '+=') for (const l of env.tainted.get(name) ?? []) labels.add(l);
  if (labels.size > 0) env.tainted.set(name, labels);
  else if (op === '=') env.tainted.delete(name);

  if (isDynamicString(value, env.consts, env.dynamic) || (op === '+=' && !constant)) env.dynamic.add(name);
  else if (op === '=') env.dynamic.delete(name);
}

function classChain(cls: ClassUnit): ClassUnit[] {
  const chain: ClassUnit[] = [];
  for (let c: ClassUnit | undefined = cls; c; c = c.parent) chain.unshift(c);
  return chain;
}

function fieldEnv(cls: ClassUnit): Env {
  const env: Env = { types: new Map(), consts: new Map(), tainted: new Map(), dynamic: new Set() };
  for (const c of classChain(cls)) {
    for (const field of c.fields) {
      const a = parseAssignment(field.text);
      if (a) bind(env, a.name, a.value, '=', a.type);
    }
  }
  return env;
}

/**
 * A zero-filled array that is then filled in (`new SecureRandom().nextBytes(iv)`) is not constant.
 * Names passed to a call that writes into its argument, and names assigned by element, stop being treated as constants.
 */
function forgetMutated(text: string, env: Env): void {
  for (const call of findCalls(text, /\.\s*(?:nextBytes|read|readFully|fill|generateSeed|getRandomBytes)|\barraycopy|\bArrays\s*\.\s*fill/)) {
    for (const arg of call.args) {
      const name = normalise(arg);
      if (/^[A-Za-z_$][\w$]*$/.test(name)) env.consts.delete(name);
    }
  }
  const element = text.match(/^([A-Za-z_$][\w$.]*)\s*\[[^\]]*\]\s*=/);
  if (element) env.consts.delete(normalise(element[1]));
}

type MethodResult = { hits: FlowHit[]; summaries: Summary[] };

function analyseMethod(
  method: MethodUnit,
  base: Env,
  file: string,
  fileText: string,
  summaries: Map<string, Summary[]>,
): MethodResult {
  const env = cloneEnv(base);
  const hits: FlowHit[] = [];
  const found: Summary[] = [];
  const entries = new Set(entryParams(method));

  method.params.forEach((p, i) => {
    const labels: Labels = new Set([`p:${i}`]);
    if (entries.has(i)) labels.add(SRC);
    env.tainted.set(p.name, labels);
    env.consts.delete(p.name);
    env.types.set(p.name, p.type);
  });

  const bodyText = method.statements.map((s) => s.text).join('\n');

  const report = (rule: string, statement: Statement) => hits.push({ rule, file, line: statement.line, text: statement.text });

  const sinkCheck = (statement: Statement) => {
    const text = statement.text;

    for (const sink of SINKS) {
      if (sink.unless?.test(bodyText)) continue;
      for (const call of findCalls(text, new RegExp(sink.callee))) {
        if (call.args.length < (sink.minArgs ?? 1)) continue;
        if (sink.maxArgs !== undefined && call.args.length > sink.maxArgs) continue;
        for (const index of sink.args) {
          const arg = call.args[index];
          if (arg === undefined) continue;
          for (const action of sink.actions) {
            if (action.need === 'const') {
              const value = evalConst(arg, env.consts);
              if (isSecretValue(value)) {
                report(action.rule, statement);
                break;
              }
              const labels = labelsOf(arg, env);
              for (const l of labels) if (l.startsWith('p:')) found.push({ rule: action.rule, need: 'const', param: Number(l.slice(2)) });
              continue;
            }
            const labels = labelsOf(arg, env);
            if (action.need === 'taint') {
              if (labels.has(SRC)) {
                if (action.rule === 'code.path_traversal' && fixedPrefix(arg)) continue;
                report(action.rule, statement);
                break;
              }
              for (const l of labels) if (l.startsWith('p:')) found.push({ rule: action.rule, need: 'taint', param: Number(l.slice(2)) });
              continue;
            }
            if (action.need === 'nonconst') {
              if (!evalConst(arg, env.consts)) {
                report(action.rule, statement);
                break;
              }
              continue;
            }
            if (isDynamicString(arg, env.consts, env.dynamic)) {
              report(action.rule, statement);
              break;
            }
          }
        }
      }
    }

    for (const shape of SHAPES) {
      for (const call of findCalls(text, new RegExp(shape.callee))) {
        if (shape.test(call.args, fileText)) report(shape.rule, statement);
      }
    }

    // Calls to helpers in this file whose parameters reach a sink.
    for (const [name, entries] of summaries) {
      for (const call of findCalls(text, new RegExp(`(?<![\\w$])${name}`))) {
        for (const summary of entries) {
          const arg = call.args[summary.param];
          if (arg === undefined) continue;
          if (summary.need === 'const') {
            const value = evalConst(arg, env.consts);
            if (isSecretValue(value)) report(summary.rule, statement);
            else for (const l of labelsOf(arg, env)) if (l.startsWith('p:')) found.push({ ...summary, param: Number(l.slice(2)) });
          } else {
            const labels = labelsOf(arg, env);
            if (labels.has(SRC)) report(summary.rule, statement);
            else for (const l of labels) if (l.startsWith('p:')) found.push({ ...summary, param: Number(l.slice(2)) });
          }
        }
      }
    }

    // Sensitive values written to a log.
    for (const call of findCalls(text, new RegExp(LOG_CALLS))) {
      const args = /System/.test(call.callee) ? call.args : call.args.slice(1);
      const joined = args.join(' + ');
      if (!joined || evalConst(joined, env.consts)) continue;
      const parts = splitTop(args.join(' + '), '+');
      // A label that introduces a value ("password is: " + x), not a message that mentions the word
      // ("Failed to get auth token", e).
      const literalHint = parts.some(
        (p, i) =>
          STRING_LITERAL.test(p.trim()) &&
          SENSITIVE_NAME.test(p) &&
          /(?:[:=]|\bis|\bwas)\s*"$/i.test(p.trim()) &&
          parts[i + 1] !== undefined &&
          !evalConst(parts[i + 1], env.consts),
      );
      const logged = args.filter((a) => !/^(?:e|ex|exc|err|error|exception|th|t|throwable|e\d)$/.test(a.trim()));
      const identHint =
        valueNames(logged.join(' + ')).some((n) => SENSITIVE_IDENT.test(n)) ||
        logged.some((a) => /\.\s*get\w*(?:Password|Secret|Token|Pin)\w*\s*\(/i.test(a));
      const dynamicPart = parts.some((p) => !evalConst(p, env.consts));
      if ((identHint || literalHint) && dynamicPart) report('code.sensitive_data_logged', statement);
    }

    // A sensitive-looking value copied to the clipboard, where every app can read it.
    for (const call of findCalls(text, /\.\s*setPrimaryClip/)) {
      const copied = call.args.join(' ');
      const literal = [...copied.matchAll(/"((?:[^"\\]|\\.)*)"/g)].some((m) => SENSITIVE_NAME.test(m[1]));
      const named = valueNames(copied).some((n) => SENSITIVE_IDENT.test(n));
      if (literal || named) report('storage.clipboard', statement);
    }

    // Sensitive values kept in SharedPreferences.
    if (!/\bEncryptedSharedPreferences\b|\bEncryptedFile\b/.test(fileText)) {
      for (const call of findCalls(text, new RegExp(PREFERENCE_PUTS))) {
        if (!isPreferencesReceiver(text.slice(0, call.index), env)) continue;
        const key = call.args[0] === undefined ? undefined : evalConst(call.args[0], env.consts);
        if (key?.kind === 'string' && SENSITIVE_NAME.test(key.value) && call.args.length >= 2) report('storage.sensitive_in_preferences', statement);
      }
    }
  };

  for (const statement of method.statements) {
    const text = statement.text;

    // for (String s : tainted)
    const each = text.match(/^for\s*\(\s*(?:final\s+)?[\w$.<>\[\],? ]+?\s+([A-Za-z_$][\w$]*)\s*:\s*([\s\S]+)\)\s*\{$/);
    if (each) {
      const labels = labelsOf(each[2], env);
      if (labels.size > 0) env.tainted.set(each[1], labels);
    }

    sinkCheck(statement);
    forgetMutated(statement.text, env);

    const assignment = parseAssignment(text);
    if (assignment) bind(env, assignment.name, assignment.value, assignment.op, assignment.type);
  }

  // A method that is a verifier or trust manager and accepts everything.
  const body = method.statements.map((s) => s.text.replace(/\s+/g, ' ').trim()).filter((t) => t !== '}');
  const first = method.statements[0] ?? { line: method.line, text: method.name };
  if (method.name === 'verify' && method.params.length === 2 && /SSLSession/.test(method.params[1].type) && body.length === 1 && body[0] === 'return true;') {
    hits.push({ rule: 'net.hostname_verifier_disabled', file, line: method.line, text: `verify(...) { ${first.text} }` });
  }
  if (/^check(?:Server|Client)Trusted$/.test(method.name) && method.params.length >= 2 && body.every((t) => t === 'return;')) {
    hits.push({ rule: 'net.trust_manager_accepts_all', file, line: method.line, text: `${method.name}(...) accepts every certificate chain` });
  }

  return { hits, summaries: found };
}

/** Token that must appear for a file to be worth parsing: every sink and shape above starts with one. */
const WORTH_PARSING =
  /setPrimaryClip|rawQuery|execSQL|compileStatement|appendWhere|\.query\(|\.update\(|\.delete\(|executeQuery|executeUpdate|prepareStatement|loadUrl|evaluateJavascript|loadData|\.exec\(|ProcessBuilder|new File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|openFile(?:Out|In)put|forName|loadClass|sendTextMessage|SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|PasswordAuthentication|setPassword|getConnection|\.authenticate\(|registerReceiver|ObjectInputStream|createPackageContext|Log\.|System\.(?:out|err)|Timber|\.put(?:String|Int|Long|Boolean|Float)\(|SSLSession|checkServerTrusted/;

const MAX_FLOW_BYTES = 600 * 1024;

export function flowHitsFor(file: string, content: string): FlowHit[] {
  if (!WORTH_PARSING.test(content)) return [];
  const parsed = parseJava(content);
  const hits: FlowHit[] = [];

  // One environment per class, with the constants its fields hold and the fields
  // that receive outside data anywhere in the class.
  const envs = new Map<ClassUnit, Env>();
  for (const cls of parsed.classes) envs.set(cls, fieldEnv(cls));
  for (const cls of parsed.classes) {
    const env = envs.get(cls)!;
    for (const method of cls.methods) {
      const local = new Set(method.params.map((p) => p.name));
      const scratch = cloneEnv(env);
      for (const s of method.statements) {
        const a = parseAssignment(s.text);
        if (!a) continue;
        if (a.declared) local.add(a.name);
        bind(scratch, a.name, a.value, a.op, a.type);
        const labels = scratch.tainted.get(a.name);
        if (!local.has(a.name) && labels?.has(SRC)) {
          // A field assigned from outside data: every method of the class can see it.
          env.tainted.set(a.name, new Set([SRC]));
        }
      }
    }
  }

  // Helpers first: which parameters reach which sink, repeated so a helper that
  // calls another helper is understood too.
  const summaries = new Map<string, Summary[]>();
  const rounds = 3;
  for (let round = 0; round < rounds; round += 1) {
    let changed = false;
    for (const cls of parsed.classes) {
      for (const method of cls.methods) {
        const result = analyseMethod(method, envs.get(cls)!, file, content, summaries);
        const known = summaries.get(method.name) ?? [];
        for (const s of result.summaries) {
          if (!known.some((k) => k.rule === s.rule && k.need === s.need && k.param === s.param)) {
            known.push(s);
            changed = true;
          }
        }
        if (known.length > 0) summaries.set(method.name, known);
      }
    }
    if (!changed) break;
  }

  const seen = new Set<string>();
  for (const cls of parsed.classes) {
    for (const method of cls.methods) {
      for (const hit of analyseMethod(method, envs.get(cls)!, file, content, summaries).hits) {
        const key = `${hit.rule}:${hit.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push(hit);
      }
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const MAX_LOCATIONS = 12;

/**
 * Runs the flow checks over decompiled Java and returns findings in the same shape
 * as the pattern rules, so they merge with them and are attributed and ranked the same.
 */
export function scanJavaFlow(
  root: string,
  files: WalkedFile[],
  isFirstParty: (relativePath: string) => boolean = () => false,
  /** Fraction of files examined, so a long pass can show it is moving. */
  onProgress?: (fraction: number) => void,
): SastFinding[] {
  const byRule = new Map<string, { locations: SastLocation[]; occurrences: number; app: Set<SastLocation> }>();

  const step = Math.max(1, Math.floor(files.length / 40));
  for (const [index, file] of files.entries()) {
    if (onProgress && index % step === 0) onProgress(index / files.length);
    if (!file.relative.endsWith('.java') || file.size > MAX_FLOW_BYTES) continue;
    let content: string;
    try {
      content = readText(file.absolute);
    } catch {
      continue;
    }
    const lines = content.split('\n');
    const appFile = isFirstParty(file.relative);
    for (const hit of flowHitsFor(file.relative, content)) {
      const entry = byRule.get(hit.rule) ?? { locations: [], occurrences: 0, app: new Set() };
      entry.occurrences += 1;
      if (entry.locations.length < MAX_LOCATIONS || appFile) {
        const location: SastLocation = {
          file: file.relative,
          line: hit.line,
          excerpt: redact(hit.text.length > 240 ? `${hit.text.slice(0, 240)}…` : hit.text),
          snippet: snippetAround(lines, Math.max(0, hit.line - 1)),
        };
        if (entry.locations.length < MAX_LOCATIONS) {
          entry.locations.push(location);
          if (appFile) entry.app.add(location);
        } else {
          const replace = entry.locations.findLastIndex((l) => !entry.app.has(l));
          if (replace >= 0) {
            entry.locations[replace] = location;
            entry.app.add(location);
          }
        }
      }
      byRule.set(hit.rule, entry);
    }
  }
  void root;

  const findings: SastFinding[] = [];
  for (const [ruleId, entry] of byRule) {
    const rule: PatternRule | undefined = PATTERN_RULES.find((r) => r.id === ruleId);
    if (!rule) throw new Error(`flow rule ${ruleId} has no definition`);
    findings.push(findingFrom(rule, entry.locations, entry.occurrences));
  }
  return findings;
}
