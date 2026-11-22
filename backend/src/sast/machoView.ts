/**
 * A readable view of a Mach-O binary, for the Explorer.
 *
 * An Android scan can show decompiled Java because jadx exists. Nothing
 * comparable runs in-process for an iOS binary: native code cannot be turned
 * back into source without a disassembler, and a scanner that claimed otherwise
 * would be inventing it. What a binary does carry, in the clear, is a good deal
 * of its shape: what it links, which system APIs it imports (and from where),
 * which Objective-C classes and selectors it defines and which Swift types.
 * That is what a reviewer reads first in Hopper or Ghidra anyway, so this
 * renders exactly that, as text, from the same file the scan read.
 *
 * Two honest limits are written into the output rather than left to be
 * discovered: an App Store binary is FairPlay-encrypted, which hides everything
 * inside `__TEXT` (selectors, strings, code) until it is decrypted on a device;
 * and Swift names are shown as the identifier chain, not fully demangled.
 */
import { pickSlice, readMachO } from './macho.ts';
import type { MachOFacts } from './macho.ts';

const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const LC_LOAD_DYLIB = 0xc;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;

/** Ceilings: one huge binary must not produce a multi-megabyte "source file". */
const MAX_SYMBOLS = 4000;
const MAX_NAMES = 3000;

type Section = { name: string; segment: string; offset: number; size: number };
type Symbol = { name: string; library?: string };

type Parsed = {
  sections: Section[];
  imports: Symbol[];
  defined: string[];
};

const cstr = (buf: Buffer, from: number, to: number): string => {
  const end = buf.indexOf(0, from);
  return buf.toString('latin1', from, end === -1 || end > to ? to : end);
};

/** Dylib install names in load order: the order `n_desc` ordinals index. */
function parseStructure(buf: Buffer, base: number): Parsed | undefined {
  const magic = buf.readUInt32LE(base);
  if (magic !== MH_MAGIC_64 && magic !== MH_CIGAM_64) return undefined; // 32-bit: not worth a second parser
  const swapped = magic === MH_CIGAM_64;
  const u32 = (at: number) => (swapped ? buf.readUInt32BE(at) : buf.readUInt32LE(at));
  const u16 = (at: number) => (swapped ? buf.readUInt16BE(at) : buf.readUInt16LE(at));
  const u64 = (at: number) => Number(swapped ? buf.readBigUInt64BE(at) : buf.readBigUInt64LE(at));

  const ncmds = u32(base + 16);
  const sections: Section[] = [];
  const libraries: string[] = [];
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;

  let at = base + 32;
  for (let i = 0; i < ncmds && at + 8 <= buf.length; i += 1) {
    const cmd = u32(at);
    const size = u32(at + 4);
    if (size < 8 || at + size > buf.length) break;

    if (cmd === LC_SEGMENT_64 && at + 72 <= buf.length) {
      const segment = cstr(buf, at + 8, at + 24);
      const nsects = u32(at + 64);
      for (let s = 0; s < nsects && at + 72 + (s + 1) * 80 <= at + size; s += 1) {
        const sec = at + 72 + s * 80;
        sections.push({
          name: cstr(buf, sec, sec + 16),
          segment: cstr(buf, sec + 16, sec + 32),
          size: u64(sec + 40),
          offset: u32(sec + 48),
        });
      }
      void segment;
    } else if (cmd === LC_SYMTAB && at + 24 <= buf.length) {
      symtab = { symoff: u32(at + 8), nsyms: u32(at + 12), stroff: u32(at + 16), strsize: u32(at + 20) };
    } else if (
      cmd === LC_LOAD_DYLIB || cmd === LC_LOAD_WEAK_DYLIB || cmd === LC_REEXPORT_DYLIB || cmd === LC_LOAD_UPWARD_DYLIB
    ) {
      const nameOffset = u32(at + 8);
      if (nameOffset < size) libraries.push(cstr(buf, at + nameOffset, at + size));
    }
    at += size;
  }

  const imports: Symbol[] = [];
  const defined: string[] = [];
  if (symtab) {
    const limit = Math.min(symtab.nsyms, 400_000);
    for (let i = 0; i < limit; i += 1) {
      const entry = base + symtab.symoff + i * 16;
      if (entry + 16 > buf.length) break;
      const nStrx = u32(entry);
      const type = buf[entry + 4];
      const nSect = buf[entry + 5];
      const desc = u16(entry + 6);
      if (type & 0xe0) continue; // debugging (stab) entries
      const nameAt = base + symtab.stroff + nStrx;
      if (nStrx === 0 || nameAt >= buf.length) continue;
      const name = cstr(buf, nameAt, base + symtab.stroff + symtab.strsize);
      if (!name) continue;

      if ((type & 0x0e) === 0x0e && nSect > 0) {
        defined.push(name);
      } else if ((type & 0x0e) === 0 && (type & 0x01) === 1) {
        // Undefined external: an import. The library is named by the two-level namespace ordinal.
        const ordinal = (desc >> 8) & 0xff;
        imports.push({ name, library: ordinal >= 1 && ordinal <= libraries.length ? libraries[ordinal - 1] : undefined });
      }
    }
  }
  return { sections, imports, defined };
}

/**
 * Strings packed back to back in a section, NUL-separated.
 *
 * `__objc_classname` and `__objc_methname` hold more than names: flags and
 * alignment bytes sit between them and read as short garbage strings. Only
 * identifier-shaped text is kept.
 */
function sectionStrings(buf: Buffer, base: number, s: Section | undefined, shape: RegExp): string[] {
  if (!s || s.size === 0) return [];
  const start = base + s.offset;
  const end = Math.min(buf.length, start + s.size);
  const out: string[] = [];
  let from = start;
  for (let i = start; i < end; i += 1) {
    if (buf[i] === 0) {
      if (i > from) {
        const text = buf.toString('utf8', from, i);
        if (shape.test(text)) out.push(text);
      }
      from = i + 1;
    }
  }
  return out;
}

/**
 * The identifier chain of a Swift mangled name: `$s7DVIA_v219LoginViewControllerC...`
 * becomes `DVIA_v2.LoginViewController`. Not a demangler; it recovers the part a
 * reader looks for, which module and type a symbol belongs to.
 */
export function swiftIdentifiers(mangled: string): string | undefined {
  const m = /^_?\$[sS]/.exec(mangled);
  if (!m) return undefined;
  const parts: string[] = [];
  let i = m[0].length;
  while (i < mangled.length && parts.length < 8) {
    const digits = /^\d+/.exec(mangled.slice(i));
    if (!digits) {
      // Skip one mangling operator character and keep looking for the next length-prefixed name.
      i += 1;
      continue;
    }
    const len = Number(digits[0]);
    const start = i + digits[0].length;
    if (len < 1 || len > 80 || start + len > mangled.length) break;
    parts.push(mangled.slice(start, start + len));
    i = start + len;
  }
  return parts.length > 0 ? parts.join('.') : undefined;
}

const list = (title: string, rows: string[], total = rows.length): string[] => {
  const shown = rows.slice(0, MAX_NAMES);
  return [
    '',
    `== ${title} (${total}) ==`,
    ...(shown.length > 0 ? shown : ['(none found)']),
    ...(total > shown.length ? [`... ${total - shown.length} more not shown ...`] : []),
  ];
};

export function renderBinaryView(buf: Buffer, displayPath: string): string {
  const facts: MachOFacts = readMachO(buf);
  const lines: string[] = [
    `// Binary view of ${displayPath}`,
    '// Generated from the Mach-O file itself. This is not decompiled source: native code cannot be turned back',
    '// into source without a disassembler. It is the structure a reviewer reads first: what the binary links,',
    '// which system APIs it imports, and which Objective-C and Swift types it defines.',
  ];

  if (!facts.parsed) return [...lines, '', 'This file could not be parsed as a Mach-O binary.'].join('\n');

  lines.push(
    '',
    '== Header ==',
    `architecture : ${facts.arch ?? 'unknown'}${facts.cpu ? ` (${facts.cpu})` : ''}${facts.archCount > 1 ? `, slice 1 of ${facts.archCount}` : ''}`,
    `file type    : ${facts.fileType ?? 'unknown'}`,
    `uuid         : ${facts.uuid ?? 'n/a'}`,
    `min OS / SDK : ${facts.minOs ?? 'n/a'} / ${facts.sdk ?? 'n/a'}`,
    `language     : ${[facts.swift && 'Swift', facts.objc && 'Objective-C'].filter(Boolean).join(' + ') || 'unknown (C/C++ or stripped)'}`,
    `PIE          : ${facts.pie ? 'yes' : 'no'}    ARC: ${facts.arc ? 'yes' : 'no'}    stack canary: ${facts.stackCanary ? 'yes' : 'no'}`,
    `encrypted    : ${facts.encrypted ? 'YES (FairPlay)' : 'no'}`,
    `symbols      : ${facts.symbolCount} (${facts.localSymbols} local)`,
    `signature    : ${facts.signature.present ? `${facts.signature.adhoc ? 'ad-hoc' : 'signed'}${facts.signature.teamId ? `, team ${facts.signature.teamId}` : ''}${facts.signature.identifier ? `, id ${facts.signature.identifier}` : ''}` : 'none'}`,
  );

  if (facts.encrypted) {
    lines.push(
      '',
      '!! This binary is FairPlay-encrypted (an App Store build). Everything inside __TEXT, including the code,',
      '!! selectors and string literals, is ciphertext until it is decrypted on a device, so those sections below',
      '!! will be empty or meaningless. The symbol table and load commands are outside the encrypted range and',
      '!! are still accurate. Scan a development, ad-hoc or enterprise build for a full view.',
    );
  }

  lines.push(...list('Linked libraries', [...facts.linkedLibraries, ...facts.weakLibraries.map((w) => `${w}  (weak)`)]));
  if (facts.rpaths.length > 0) lines.push(...list('Runtime search paths (rpath)', facts.rpaths));

  const { offset: base } = pickSlice(buf);
  let parsed: Parsed | undefined;
  try {
    parsed = parseStructure(buf, base);
  } catch {
    parsed = undefined;
  }
  if (!parsed) {
    return [...lines, '', 'The symbol table could not be read (32-bit or unusual image), so imports and types are not listed.'].join('\n');
  }

  // Imports, grouped by the library that provides them: the quickest way to see
  // what a binary does (Security, CommonCrypto, WebKit, CoreLocation...).
  const byLibrary = new Map<string, string[]>();
  for (const imp of parsed.imports.slice(0, MAX_SYMBOLS)) {
    const key = imp.library?.replace(/^.*\//, '') ?? '(unresolved)';
    byLibrary.set(key, [...(byLibrary.get(key) ?? []), imp.name]);
  }
  lines.push('', `== Imported symbols (${parsed.imports.length}) ==`);
  if (byLibrary.size === 0) lines.push('(none found)');
  for (const [library, names] of [...byLibrary.entries()].sort((a, b) => b[1].length - a[1].length)) {
    lines.push('', `-- ${library} (${names.length})`, ...names.sort());
  }
  if (parsed.imports.length > MAX_SYMBOLS) lines.push('', `... ${parsed.imports.length - MAX_SYMBOLS} more imports not shown ...`);

  // Types defined here. ObjC class names survive stripping (they are runtime
  // metadata), which is why this is the most useful list on a release build.
  const objcClasses = new Set<string>();
  for (const name of parsed.defined) {
    const m = /^_OBJC_CLASS_\$_(.+)$/.exec(name);
    if (m) objcClasses.add(m[1]);
  }
  const bySection = (n: string) => parsed!.sections.find((s) => s.name === n);
  for (const name of sectionStrings(buf, base, bySection('__objc_classname'), /^[A-Za-z_][\w$.]{2,}$/)) objcClasses.add(name);
  lines.push(...list('Objective-C classes', [...objcClasses].sort(), objcClasses.size));

  const selectors = [...new Set(sectionStrings(buf, base, bySection('__objc_methname'), /^[A-Za-z_.][\w$.:]+$/))].sort();
  lines.push(...list('Objective-C selectors', selectors, selectors.length));

  const swift = new Set<string>();
  for (const name of parsed.defined) {
    const chain = swiftIdentifiers(name);
    if (chain) swift.add(chain);
  }
  // The app's own module first: it is the code someone wrote, and it is what a
  // reviewer reads before the framework types the same binary happens to mention.
  const moduleName = (displayPath.split('/').pop() ?? '').replace(/\.[^.]*$/, '').replace(/[^A-Za-z0-9]/g, '_');
  const own = [...swift].filter((c) => c === moduleName || c.startsWith(`${moduleName}.`)).sort();
  const others = [...swift].filter((c) => !own.includes(c)).sort();
  if (own.length > 0) lines.push(...list(`Swift types and functions in module ${moduleName}`, own, own.length));
  lines.push(...list(own.length > 0 ? 'Swift types and functions from other modules' : 'Swift types and functions (identifier chains)', others, others.length));

  const other = parsed.defined
    .filter((n) => !/^_OBJC_|^_?\$[sS]/.test(n) && !/^(l|L)?_?\$?(_swift|swift)/.test(n))
    .sort();
  lines.push(...list('Other defined symbols', other.slice(0, MAX_SYMBOLS), other.length));

  lines.push('', '== Sections ==', ...parsed.sections.map((s) => `${(s.segment + ',' + s.name).padEnd(34)} ${s.size} bytes`));
  lines.push('', '(String literals are in the _strings/ file for the main executable.)');
  return lines.join('\n');
}
