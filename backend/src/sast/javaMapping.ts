/**
 * From a smali location to the readable class it came from.
 *
 * Some checks (a hardcoded key, a trust-all TrustManager) decide by reading a
 * method body, and that analysis runs on smali, so their findings arrive naming
 * `smali_classes4/com/foo/Bar.smali`. A reviewer wants the Java: the decompiled
 * class, at the method, with the code around it. This maps one to the other.
 *
 * It is a best-effort mapping and says so by behaviour: if the decompiler
 * produced no Java for the class, the location is returned untouched and stays
 * smali, rather than pointing at a file that is not there.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { snippetAround } from './scanner.ts';
import type { SastLocation } from './types.ts';

const SMALI = /^smali(?:_classes\d+)?\/(.+)\.smali$/;

/** The call inside the method that is the actual evidence, when the method itself is not the point. */
const EVIDENCE: Record<string, RegExp> = {
  'crypto.hardcoded_key': /new\s+(?:SecretKeySpec|IvParameterSpec)\s*\(/,
};

export type JavaFiles = Map<string, string[] | null>;

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A line that declares `name` rather than calling it: a return type sits in front of it. */
function declares(line: string, name: string): boolean {
  const at = new RegExp(`(?<![.\\w$])${escape(name)}\\s*\\(`).exec(line);
  if (!at) return false;
  const before = line.slice(0, at.index).trim();
  if (before === '' || /^(return|throw|new|else|if|for|while|case)\b/.test(line.trim())) return false;
  return /[\w>\]]$/.test(before) && !/[=(,]$/.test(before);
}

export function mapSmaliToJava(
  location: SastLocation,
  ruleId: string,
  javaRoot: string | undefined,
  cache: JavaFiles = new Map(),
): SastLocation {
  const match = SMALI.exec(location.file);
  if (!match || !javaRoot) return location;

  // jadx writes a nested class inside its outer class's file.
  const parts = match[1].split('/');
  const [outer, ...nested] = (parts.pop() ?? '').split('$');
  const relative = `sources/${[...parts, outer].join('/')}.java`;

  if (!cache.has(relative)) {
    const absolute = join(javaRoot, relative);
    cache.set(relative, existsSync(absolute) ? readFileSync(absolute, 'utf8').split('\n') : null);
  }
  const lines = cache.get(relative);
  if (!lines) return location;

  // The smali finding names its method in the excerpt (`checkServerTrusted(...)`) or its context.
  const name = /^([\w$<>]+)\s*\(/.exec(location.excerpt ?? '')?.[1] ?? /^([\w$<>]+)\(/.exec(location.method ?? '')?.[1];

  // Start inside the nested class when there is one, so a method that exists in both is the right one.
  let from = 0;
  for (const inner of nested.filter((n) => /^[A-Za-z_]/.test(n))) {
    const at = lines.findIndex((l, i) => i >= from && new RegExp(`\\bclass\\s+${escape(inner)}\\b`).test(l));
    if (at >= 0) from = at;
  }

  let index = name ? lines.findIndex((l, i) => i >= from && declares(l, name)) : -1;
  const evidence = EVIDENCE[ruleId];
  if (index >= 0 && evidence) {
    const call = lines.slice(index, index + 80).findIndex((l) => evidence.test(l));
    if (call >= 0) index += call;
  }
  // An obfuscated or renamed method cannot be found by name, but the call that is the evidence can.
  if (index < 0 && evidence) index = lines.findIndex((l, i) => i >= from && evidence.test(l));
  if (index < 0) index = lines.findIndex((l) => new RegExp(`\\b(class|interface|enum)\\s+${escape(outer)}\\b`).test(l));

  const { snippet: _smaliSnippet, ...rest } = location;
  return index >= 0
    ? { ...rest, file: relative, line: index + 1, snippet: snippetAround(lines, index) }
    : { ...rest, file: relative, line: undefined };
}

/**
 * The same mapping, plus the declaration of a hardcoded key's value.
 *
 * A key is usually declared in one place (`static final String KEY = "..."`) and
 * used in another (`new SecretKeySpec(KEY.getBytes(), ...)`), and the compiler
 * inlines the constant into the method that smali analysis reads. Pointing only
 * at the use hides the thing that leaked, so the declaration is added as a
 * second location when the literal can be found in the class.
 */
export function mapSmaliLocations(
  location: SastLocation,
  ruleId: string,
  javaRoot: string | undefined,
  cache: JavaFiles = new Map(),
): SastLocation[] {
  const primary = mapSmaliToJava(location, ruleId, javaRoot, cache);
  if (primary.file === location.file) return [location];
  const literal = /builds a key from the literal "([^"]+)"/.exec(location.excerpt ?? '')?.[1];
  const lines = cache.get(primary.file);
  if (!literal || !lines) return [primary];

  // Only an assignment counts as the declaration: `KEY = "..."`, or the same followed by
  // `.getBytes(...)`. A string that merely appears in a call or a message is not where a key lives.
  const assignment = new RegExp(`=\\s*"${escape(literal)}"(?:\\.getBytes\\([^)]*\\))?\\s*;`);
  const at = lines.findIndex((l, i) => i + 1 !== primary.line && assignment.test(l));
  if (at < 0) return [primary];
  return [
    primary,
    { ...primary, line: at + 1, excerpt: lines[at].trim().slice(0, 160), snippet: snippetAround(lines, at) },
  ];
}
