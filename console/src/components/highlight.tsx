/**
 * Colouring decompiled source, and marking the part that matters.
 *
 * Deliberately a tokeniser rather than a parser, and deliberately small. The
 * files here are decompiled Java, Android XML and the odd properties file —
 * the job is to make a key stand out from the tag around it, not to be a
 * language server. Anything it cannot classify stays plain, which is the right
 * failure: unstyled text is readable, mis-styled text is misleading.
 */
import type { ReactNode } from 'react';

type Token = { text: string; kind?: string };

const CLASS: Record<string, string> = {
  keyword: 'text-violet-300',
  type: 'text-sky-300',
  string: 'text-emerald-300',
  number: 'text-amber-200',
  comment: 'text-slate-500 italic',
  annotation: 'text-fuchsia-300',
  tag: 'text-sky-300',
  attr: 'text-violet-300',
  punct: 'text-slate-500',
  secret: 'rounded bg-rose-500/30 px-0.5 font-bold text-rose-100 ring-1 ring-rose-400/50',
};

const JAVA_KEYWORDS = new Set([
  'abstract','assert','boolean','break','byte','case','catch','char','class','const','continue',
  'default','do','double','else','enum','extends','final','finally','float','for','goto','if',
  'implements','import','instanceof','int','interface','long','native','new','package','private',
  'protected','public','return','short','static','strictfp','super','switch','synchronized','this',
  'throw','throws','transient','try','void','volatile','while','true','false','null','var','record',
]);

/** Java, and near enough for Kotlin or smali to be an improvement on plain. */
function tokenizeJava(line: string): Token[] {
  const tokens: Token[] = [];
  // Order matters: comments and strings first, so a keyword inside either is
  // not coloured as code.
  const pattern =
    /(\/\/.*$|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(@[A-Za-z_][\w.]*)|(\b\d[\w.]*\b)|([A-Za-z_$][\w$]*)|([{}()[\];,.<>+\-*/%=!&|^~?:])/g;

  let last = 0;
  for (const m of line.matchAll(pattern)) {
    if (m.index! > last) tokens.push({ text: line.slice(last, m.index) });
    const [text] = m;
    if (m[1]) tokens.push({ text, kind: 'comment' });
    else if (m[2]) tokens.push({ text, kind: 'string' });
    else if (m[3]) tokens.push({ text, kind: 'annotation' });
    else if (m[4]) tokens.push({ text, kind: 'number' });
    else if (m[5]) {
      tokens.push({
        text,
        kind: JAVA_KEYWORDS.has(text)
          ? 'keyword'
          : // A leading capital is a type far more often than not in decompiled
            // output, where locals are `str2` and types are `WebViewClient`.
            /^[A-Z]/.test(text)
            ? 'type'
            : undefined,
      });
    } else tokens.push({ text, kind: 'punct' });
    last = m.index! + text.length;
  }
  if (last < line.length) tokens.push({ text: line.slice(last) });
  return tokens;
}

function tokenizeXml(line: string): Token[] {
  const tokens: Token[] = [];
  const pattern = /(<!--.*?-->)|(<\/?[\w:.-]+|\/?>)|([\w:.-]+)(?==)|("(?:[^"]*)")/g;
  let last = 0;
  for (const m of line.matchAll(pattern)) {
    if (m.index! > last) tokens.push({ text: line.slice(last, m.index) });
    const [text] = m;
    if (m[1]) tokens.push({ text, kind: 'comment' });
    else if (m[2]) tokens.push({ text, kind: 'tag' });
    else if (m[3]) tokens.push({ text, kind: 'attr' });
    else tokens.push({ text, kind: 'string' });
    last = m.index! + text.length;
  }
  if (last < line.length) tokens.push({ text: line.slice(last) });
  return tokens;
}

/**
 * Values that are the finding itself.
 *
 * A highlighted *line* tells you where to look; a highlighted *value* tells you
 * what you are looking at. On a 200-character line of Android resources the
 * difference is the whole point.
 */
const SECRET_SHAPES: RegExp[] = [
  /\bAIza[0-9A-Za-z_-]{35}\b/,                       // Google API key
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,                     // AWS access key id
  /\bsk_(live|test)_[0-9a-zA-Z]{16,}\b/,             // Stripe
  /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/,                // Slack
  /\bgh[pousr]_[0-9A-Za-z]{36,}\b/,                  // GitHub
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWT
  /\bSG\.[\w-]{20,}\.[\w-]{20,}\b/,                  // SendGrid
  /\bAC[0-9a-f]{32}\b/,                              // Twilio SID
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,              // PEM
];

/** Split a token's text so a secret inside it can be marked on its own. */
function markSecrets(tokens: Token[]): Token[] {
  const out: Token[] = [];
  for (const token of tokens) {
    let rest = token.text;
    let guard = 0;
    while (rest && guard++ < 8) {
      let best: { index: number; text: string } | undefined;
      for (const shape of SECRET_SHAPES) {
        const m = rest.match(shape);
        if (m && (best === undefined || m.index! < best.index)) {
          best = { index: m.index!, text: m[0] };
        }
      }
      if (!best) break;
      if (best.index > 0) out.push({ text: rest.slice(0, best.index), kind: token.kind });
      out.push({ text: best.text, kind: 'secret' });
      rest = rest.slice(best.index + best.text.length);
    }
    if (rest) out.push({ text: rest, kind: token.kind });
  }
  return out;
}

export function highlight(line: string, path: string): ReactNode {
  if (!line) return ' ';
  const xml = /\.(xml|plist|entitlements|mobileprovision)$/i.test(path);
  const tokens = markSecrets(xml ? tokenizeXml(line) : tokenizeJava(line));

  return tokens.map((token, i) =>
    token.kind ? (
      <span key={i} className={CLASS[token.kind]}>
        {token.text}
      </span>
    ) : (
      <span key={i}>{token.text}</span>
    ),
  );
}
