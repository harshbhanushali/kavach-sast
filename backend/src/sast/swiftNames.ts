/**
 * Readable names for Swift symbols.
 *
 * A compiled Swift method is named by its mangled symbol, `__T07DVIA_v211AppDelegateC11application…`, which
 * is a reviewer's first obstacle in the code view. This reads the part that carries meaning (the module, the
 * type it belongs to, and the member's own name) and leaves the rest of the signature out. It is not a full
 * demangler: it does not decode parameter types, generics or substitutions, and a symbol it cannot make sense
 * of is returned unchanged, so a name is never made up.
 *
 * No browser or database imports, so it can be exercised from node.
 */

/** Swift 4 (`_T0`), 4.2 (`$S`) and 5 (`$s`) manglings, with the underscores the symbol table adds. */
const SWIFT_SYMBOL = /^_{0,2}(?:\$[sS]|T0)(.+)$/s;

/** The identifier at `at`: its digits give its length. A leading `0` marks a word-substituted one. */
function identifier(text: string, at: number): { name: string; end: number } | undefined {
  let i = at;
  if (text[i] === '0') i += 1;
  const digits = /^\d+/.exec(text.slice(i));
  if (!digits) return undefined;
  const length = Number(digits[0]);
  const start = i + digits[0].length;
  if (length === 0 || start + length > text.length) return undefined;
  return { name: text.slice(start, start + length), end: start + length };
}

/** What the symbol's tail says it is, for the cases that are common and unambiguous. */
function role(tail: string): string {
  if (/vfi$/.test(tail)) return ' (initial value)';
  if (/vg$/.test(tail)) return ' (getter)';
  if (/vs$/.test(tail)) return ' (setter)';
  if (/v[mwW]$/.test(tail)) return ' (accessor)';
  if (/f[uU]\d*_/.test(tail)) return ' (closure)';
  if (/F[A-Za-z]{0,2}$/.test(tail) || /yyF|tF$/.test(tail)) return '(…)';
  return '';
}

/** `Module.Type.member` for a Swift symbol; undefined when it is not one or cannot be read. */
export function demangleSwift(symbol: string): string | undefined {
  const m = SWIFT_SYMBOL.exec(symbol);
  if (!m) return undefined;
  const rest = m[1];
  const module = identifier(rest, 0);
  if (!module) return undefined;

  const path = [module.name];
  let at = module.end;
  let member: string | undefined;
  while (path.length < 7) {
    const id = identifier(rest, at);
    if (!id) break;
    const kind = rest[id.end];
    if (kind === 'C' || kind === 'V' || kind === 'O') {
      path.push(id.name);
      at = id.end + 1;
    } else {
      member = id.name;
      at = id.end;
      break;
    }
  }

  const tail = rest.slice(at);
  if (member === undefined) {
    // No member name: a constructor or destructor of the type just named.
    if (path.length === 1) return undefined;
    const special = /^f([cCdD])/.exec(tail);
    if (!special) return path.join('.');
    return `${path.join('.')}.${special[1] === 'c' || special[1] === 'C' ? 'init' : 'deinit'}`;
  }
  return `${path.join('.')}.${member}${role(tail)}`;
}

/**
 * A symbol or Objective-C style method name, made readable where it can be.
 * `-[_TtC7DVIA_v211AppDelegate application:openURL:options:]` becomes
 * `-[DVIA_v2.AppDelegate application:openURL:options:]`.
 */
export function readableSymbol(name: string): string {
  const swift = demangleSwift(name);
  if (swift) return swift;
  if (!name.includes('_TtC')) return name;
  return name.replace(/_TtC(\d+)([A-Za-z0-9_]+)/g, (whole, length: string, rest: string) => {
    const moduleLength = Number(length);
    if (rest.length <= moduleLength) return whole;
    const module = rest.slice(0, moduleLength);
    const after = /^(\d+)([A-Za-z0-9_]+)/.exec(rest.slice(moduleLength));
    if (!after) return whole;
    const typeLength = Number(after[1]);
    if (after[2].length < typeLength) return whole;
    return `${module}.${after[2].slice(0, typeLength)}${after[2].slice(typeLength)}`;
  });
}
