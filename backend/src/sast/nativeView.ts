/**
 * Readable views of Android files that are not text, so a finding that names
 * one has something to open.
 *
 * A native library cannot be decompiled in-process, and a keystore must never
 * be printed, but both can be described: an ELF carries its dependencies, its
 * JNI entry points and the symbols it imports and exports in the clear, and a
 * keystore has a size, a hash and a recognisable header. That is what these
 * render, and each view says plainly what it is not.
 */
import { createHash } from 'node:crypto';
import { readElf } from './elf.ts';

/** Ceilings so one library with a huge symbol table cannot produce a huge "source file". */
const MAX_NAMES = 3000;

type Section = { type: number; offset: number; size: number; link: number; entsize: number };

type ElfStructure = {
  needed: string[];
  soname?: string;
  imports: string[];
  exports: string[];
  jni: string[];
  sections: { name: string; size: number }[];
};

const SHT_DYNSYM = 11;
const SHT_DYNAMIC = 6;
const DT_NEEDED = 1;
const DT_SONAME = 14;

function cstr(buf: Buffer, from: number, limit: number): string {
  if (from < 0 || from >= buf.length) return '';
  const end = buf.indexOf(0, from);
  return buf.toString('latin1', from, end === -1 || end > limit ? limit : end);
}

/** Dynamic dependencies, imports and exports straight from the section headers; undefined when there are none to read. */
function parseElf(buf: Buffer): ElfStructure | undefined {
  if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7f454c46) return undefined;
  const is64 = buf[4] === 2;
  const le = buf[5] !== 2;
  const u16 = (at: number) => (le ? buf.readUInt16LE(at) : buf.readUInt16BE(at));
  const u32 = (at: number) => (le ? buf.readUInt32LE(at) : buf.readUInt32BE(at));
  const word = (at: number) => Number(is64 ? (le ? buf.readBigUInt64LE(at) : buf.readBigUInt64BE(at)) : u32(at));

  const shoff = word(is64 ? 0x28 : 0x20);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const shstrndx = u16(is64 ? 0x3e : 0x32);
  if (!shoff || !shentsize || !shnum || shoff + shnum * shentsize > buf.length) return undefined;

  const names: number[] = [];
  const sections: Section[] = [];
  for (let i = 0; i < shnum; i += 1) {
    const at = shoff + i * shentsize;
    names.push(u32(at));
    sections.push(
      is64
        ? { type: u32(at + 4), offset: word(at + 24), size: word(at + 32), link: u32(at + 40), entsize: word(at + 56) }
        : { type: u32(at + 4), offset: word(at + 16), size: word(at + 20), link: u32(at + 24), entsize: word(at + 36) },
    );
  }
  const shstr = sections[shstrndx];
  const sectionList = sections
    .map((s, i) => ({ name: shstr ? cstr(buf, shstr.offset + names[i], buf.length) : '', size: s.size }))
    .filter((s) => s.name);

  const result: ElfStructure = { needed: [], imports: [], exports: [], jni: [], sections: sectionList };

  const dynamic = sections.find((s) => s.type === SHT_DYNAMIC);
  if (dynamic) {
    const strtab = sections[dynamic.link];
    const step = is64 ? 16 : 8;
    for (let at = dynamic.offset; at + step <= dynamic.offset + dynamic.size && at + step <= buf.length; at += step) {
      const tag = word(at);
      const val = word(at + (is64 ? 8 : 4));
      if (tag === 0) break;
      if (!strtab) continue;
      if (tag === DT_NEEDED) result.needed.push(cstr(buf, strtab.offset + val, buf.length));
      else if (tag === DT_SONAME) result.soname = cstr(buf, strtab.offset + val, buf.length);
    }
  }

  const dynsym = sections.find((s) => s.type === SHT_DYNSYM);
  if (dynsym) {
    const strtab = sections[dynsym.link];
    const size = is64 ? 24 : 16;
    const count = Math.min(Math.floor(dynsym.size / size), 400_000);
    for (let i = 1; i < count; i += 1) {
      const at = dynsym.offset + i * size;
      if (at + size > buf.length || !strtab) break;
      const nameOff = u32(at);
      const info = is64 ? buf[at + 4] : buf[at + 12];
      const shndx = u16(is64 ? at + 6 : at + 14);
      const name = cstr(buf, strtab.offset + nameOff, buf.length);
      if (!name) continue;
      const binding = info >> 4; // 1 = global, 2 = weak
      if (shndx === 0) {
        if (binding !== 0) result.imports.push(name);
      } else if (binding === 1 || binding === 2) {
        if (name.startsWith('Java_') || name === 'JNI_OnLoad' || name === 'JNI_OnUnload') result.jni.push(name);
        else result.exports.push(name);
      }
    }
  }
  return result;
}

const list = (title: string, rows: string[]): string[] => {
  const shown = rows.slice(0, MAX_NAMES);
  return [
    '',
    `== ${title} (${rows.length}) ==`,
    ...(shown.length > 0 ? shown : ['(none found)']),
    ...(rows.length > shown.length ? [`... ${rows.length - shown.length} more not shown ...`] : []),
  ];
};

export function renderElfView(buf: Buffer, displayPath: string): string {
  const lines = [
    `// Native library view of ${displayPath}`,
    '// Generated from the ELF file itself. This is not decompiled source: native code cannot be turned back into',
    '// source without a disassembler. It is the structure a reviewer reads first: what the library depends on,',
    '// which JNI functions it exposes to Java, and which system functions it imports.',
  ];
  const facts = readElf(buf);
  if (!facts.parsed) return [...lines, '', 'This file could not be parsed as an ELF library.'].join('\n');

  lines.push(
    '',
    '== Protections ==',
    `class        : ${facts.is64Bit ? 'ELF64' : 'ELF32'}`,
    `PIE          : ${facts.pie ? 'yes' : 'NO'}`,
    `NX stack     : ${facts.nx ? 'yes' : 'NO (executable stack)'}`,
    `stack canary : ${facts.stackCanary ? 'yes' : 'NO'}`,
    `RELRO        : ${facts.relro}`,
    `RPATH/RUNPATH: ${facts.rpath || facts.runpath ? 'present' : 'none'}`,
    `symbols      : ${facts.symbolsStripped ? 'stripped' : 'NOT stripped (debug symbols shipped)'}`,
    `fortified    : ${facts.fortified ? 'yes' : 'no'}`,
  );

  let structure: ElfStructure | undefined;
  try {
    structure = parseElf(buf);
  } catch {
    structure = undefined;
  }
  if (!structure) {
    return [...lines, '', 'The section headers were removed or are unreadable, so dependencies and symbols are not listed.'].join('\n');
  }

  if (structure.soname) lines.push('', `soname: ${structure.soname}`);
  lines.push(...list('Needed libraries', structure.needed));
  lines.push(...list('JNI functions (callable from Java)', structure.jni.sort()));
  lines.push(...list('Imported functions', structure.imports.sort()));
  lines.push(...list('Exported symbols', structure.exports.sort()));
  lines.push('', '== Sections ==', ...structure.sections.map((s) => `${s.name.padEnd(24)} ${s.size} bytes`));
  return lines.join('\n');
}

/** A short name for what a file's first bytes say it is. */
function kindOf(head: Buffer): string {
  if (head.length >= 4 && head.readUInt32BE(0) === 0xfeedfeed) return 'Java KeyStore (JKS)';
  if (head.length >= 4 && head.readUInt32BE(0) === 0xcececece) return 'Java KeyStore (JCEKS)';
  if (head.length >= 2 && head[0] === 0x30 && (head[1] === 0x82 || head[1] === 0x80 || head[1] === 0x81)) {
    return 'DER / PKCS#12 container (certificate, key or keystore)';
  }
  if (head.subarray(0, 4).toString('latin1') === '\x7fELF') return 'ELF binary';
  if (head.subarray(0, 4).toString('latin1') === 'PK\x03\x04') return 'ZIP archive';
  if (head.subarray(0, 8).toString('latin1') === '\x89PNG\r\n\x1a\n') return 'PNG image';
  if (head.subarray(0, 3).toString('latin1') === 'dex') return 'DEX bytecode';
  if (head.subarray(0, 6).toString('latin1') === 'SQLite') return 'SQLite database';
  return 'binary data';
}

/**
 * What a binary file is, without showing it.
 *
 * Used for files a finding names that no viewer can usefully display, such as
 * a keystore: the contents are never printed (a key store is exactly what must
 * not end up in a report), but the reviewer still gets the size, the digest to
 * match against the file in their own copy, and what the header says it is.
 */
export function binaryStub(buf: Buffer, displayPath: string): string {
  return [
    `// ${displayPath}`,
    '// This is a binary file, so its contents are not shown. For a keystore or a key, they never are.',
    '',
    `type   : ${kindOf(buf.subarray(0, 16))}`,
    `size   : ${buf.length} bytes`,
    `sha256 : ${createHash('sha256').update(buf).digest('hex')}`,
    '',
    'To inspect it, extract this file from the APK and open it with the tool for its format.',
  ].join('\n');
}
