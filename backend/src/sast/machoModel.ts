/**
 * The parts of a 64-bit Mach-O needed to say what a function does without decompiling it.
 *
 * `macho.ts` reads the header facts and `machoView.ts` lists names. Following a call needs
 * more: where each section sits in memory, which imported symbol a stub stands for, what a
 * pointer in a data section really points at (dyld resolves those at load time, in one of two
 * encodings), where each function begins, and which Objective-C class implements which method.
 * This reads exactly that, and nothing is executed.
 *
 * Addresses are plain numbers: a 64-bit iOS binary lives well below 2^53.
 */
import { pickSlice } from './macho.ts';

const MH_MAGIC_64 = 0xfeedfacf;
const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const LC_DYSYMTAB = 0xb;
const LC_LOAD_DYLIB = 0xc;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;
const LC_DYLD_INFO = 0x22;
const LC_DYLD_INFO_ONLY = 0x80000022;
const LC_FUNCTION_STARTS = 0x26;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

export type Section = {
  name: string;
  segment: string;
  addr: number;
  size: number;
  offset: number;
  flags: number;
  reserved1: number;
  reserved2: number;
};

export type Segment = { name: string; vmaddr: number; vmsize: number; fileoff: number; filesize: number };

export type Symbol = { name: string; value: number; section: number; type: number; external: boolean; defined: boolean; ordinal: number };

export type SlotTarget = { kind: 'bind'; symbol: string; library?: string } | { kind: 'rebase'; target: number };

export type ObjcMethod = { selector: string; imp: number; className: string; classMethod: boolean };
export type ObjcClass = { name: string; address: number; superclass?: string; methods: ObjcMethod[] };

export type MachoModel = {
  buf: Buffer;
  /** File offset of this architecture's slice. */
  base: number;
  imageBase: number;
  segments: Segment[];
  sections: Section[];
  libraries: string[];
  symbols: Symbol[];
  /** Name of each stub: stub address -> imported symbol. */
  stubs: Map<number, string>;
  /** Imported symbol behind each pointer slot dyld fills (GOT, lazy pointers, class references). */
  slots: Map<number, SlotTarget>;
  functionStarts: number[];
  classes: ObjcClass[];
  /** Whether the binary is FairPlay-encrypted, in which case code and strings are not readable. */
  encrypted: boolean;
  /** Read a NUL-terminated string at a virtual address. */
  cstringAt(addr: number): string | undefined;
  /** Read a pointer-sized value at a virtual address, resolved through dyld's fixups. */
  pointerAt(addr: number): number | undefined;
  /** File offset of a virtual address, if it is file-backed. */
  fileOffset(addr: number): number | undefined;
  sectionAt(addr: number): Section | undefined;
};

const cstr = (buf: Buffer, from: number, to: number): string => {
  const end = buf.indexOf(0, from);
  return buf.toString('latin1', from, end === -1 || end > to ? to : end);
};

/** Unsigned LEB128, as the dyld opcode streams use. */
function uleb(buf: Buffer, at: { i: number }): number {
  let result = 0;
  let shift = 0;
  for (;;) {
    const byte = buf[at.i++];
    result += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 56) break;
  }
  return result;
}

function sleb(buf: Buffer, at: { i: number }): number {
  let result = 0;
  let shift = 0;
  let byte = 0;
  do {
    byte = buf[at.i++];
    result += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  } while (byte & 0x80 && shift < 56);
  if (byte & 0x40) result -= 2 ** shift;
  return result;
}

export function readModel(file: Buffer): MachoModel | undefined {
  const slice = pickSlice(file);
  const base = slice.offset;
  if (base + 32 > file.length || file.readUInt32LE(base) !== MH_MAGIC_64) return undefined; // 32-bit or unknown

  const buf = file;
  const u32 = (at: number) => buf.readUInt32LE(at);
  const u64 = (at: number) => Number(buf.readBigUInt64LE(at));
  const ncmds = u32(base + 16);

  const segments: Segment[] = [];
  const sections: Section[] = [];
  const libraries: string[] = [];
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  let dysym: { indirectoff: number; nindirect: number } | undefined;
  let dyld: { bindOff: number; bindSize: number; lazyOff: number; lazySize: number } | undefined;
  let functionStartsAt: { off: number; size: number } | undefined;
  let chained: { off: number; size: number } | undefined;
  let encrypted = false;

  let at = base + 32;
  for (let i = 0; i < ncmds && at + 8 <= buf.length; i += 1) {
    const cmd = u32(at);
    const size = u32(at + 4);
    if (size < 8 || at + size > buf.length) break;
    if (cmd === LC_SEGMENT_64) {
      const segName = cstr(buf, at + 8, at + 24);
      segments.push({ name: segName, vmaddr: u64(at + 24), vmsize: u64(at + 32), fileoff: u64(at + 40), filesize: u64(at + 48) });
      const nsects = u32(at + 64);
      for (let s = 0; s < nsects && at + 72 + (s + 1) * 80 <= at + size; s += 1) {
        const sec = at + 72 + s * 80;
        sections.push({
          name: cstr(buf, sec, sec + 16),
          segment: cstr(buf, sec + 16, sec + 32),
          addr: u64(sec + 32),
          size: u64(sec + 40),
          offset: u32(sec + 48),
          flags: u32(sec + 64),
          reserved1: u32(sec + 68),
          reserved2: u32(sec + 72),
        });
      }
    } else if (cmd === LC_SYMTAB) {
      symtab = { symoff: u32(at + 8), nsyms: u32(at + 12), stroff: u32(at + 16), strsize: u32(at + 20) };
    } else if (cmd === LC_DYSYMTAB) {
      dysym = { indirectoff: u32(at + 56), nindirect: u32(at + 60) };
    } else if (cmd === LC_DYLD_INFO || cmd === LC_DYLD_INFO_ONLY) {
      dyld = { bindOff: u32(at + 16), bindSize: u32(at + 20), lazyOff: u32(at + 32), lazySize: u32(at + 36) };
    } else if (cmd === LC_FUNCTION_STARTS) {
      functionStartsAt = { off: u32(at + 8), size: u32(at + 12) };
    } else if (cmd === LC_DYLD_CHAINED_FIXUPS) {
      chained = { off: u32(at + 8), size: u32(at + 12) };
    } else if (cmd === 0x2c) {
      // LC_ENCRYPTION_INFO_64: cryptoff, cryptsize, cryptid
      encrypted = u32(at + 16) !== 0;
    } else if (cmd === LC_LOAD_DYLIB || cmd === LC_LOAD_WEAK_DYLIB || cmd === LC_REEXPORT_DYLIB || cmd === LC_LOAD_UPWARD_DYLIB) {
      const nameOffset = u32(at + 8);
      if (nameOffset < size) libraries.push(cstr(buf, at + nameOffset, at + size));
    }
    at += size;
  }

  const text = segments.find((s) => s.name === '__TEXT');
  const imageBase = text?.vmaddr ?? 0;

  const fileOffset = (addr: number): number | undefined => {
    for (const seg of segments) {
      if (addr >= seg.vmaddr && addr < seg.vmaddr + seg.filesize) return base + seg.fileoff + (addr - seg.vmaddr);
    }
    return undefined;
  };
  const sectionAt = (addr: number) => sections.find((s) => addr >= s.addr && addr < s.addr + s.size);

  // --- symbols
  const symbols: Symbol[] = [];
  if (symtab) {
    const limit = Math.min(symtab.nsyms, 600_000);
    for (let i = 0; i < limit; i += 1) {
      const entry = base + symtab.symoff + i * 16;
      if (entry + 16 > buf.length) break;
      const strx = u32(entry);
      const type = buf[entry + 4];
      const section = buf[entry + 5];
      const desc = buf.readUInt16LE(entry + 6);
      const value = u64(entry + 8);
      const nameAt = base + symtab.stroff + strx;
      const name = strx && nameAt < buf.length ? cstr(buf, nameAt, base + symtab.stroff + symtab.strsize) : '';
      const kind = type & 0x0e;
      symbols.push({ name, value, section, type, external: (type & 1) === 1, defined: kind === 0x0e && section > 0, ordinal: (desc >> 8) & 0xff });
    }
  }

  // --- pointers in data sections
  const slots = new Map<number, SlotTarget>();
  const library = (ordinal: number) => (ordinal >= 1 && ordinal <= libraries.length ? libraries[ordinal - 1] : undefined);

  if (chained) readChainedFixups(buf, base, chained.off, segments, libraries, slots, imageBase);
  if (dyld) {
    readBindStream(buf, base, dyld.bindOff, dyld.bindSize, segments, libraries, slots);
    readBindStream(buf, base, dyld.lazyOff, dyld.lazySize, segments, libraries, slots);
  }

  // --- stubs: each one stands for the imported symbol the indirect table names
  const stubs = new Map<number, string>();
  if (dysym && symtab) {
    const indirect = (index: number): string | undefined => {
      if (index < 0 || index >= dysym!.nindirect) return undefined;
      const sym = u32(base + dysym!.indirectoff + index * 4);
      if (sym >= 0x80000000) return undefined; // INDIRECT_SYMBOL_LOCAL / ABS
      return symbols[sym]?.name || undefined;
    };
    for (const sec of sections) {
      const type = sec.flags & 0xff;
      if (type === 0x8 /* S_SYMBOL_STUBS */ && sec.reserved2 > 0) {
        const count = Math.floor(sec.size / sec.reserved2);
        for (let k = 0; k < count; k += 1) {
          const name = indirect(sec.reserved1 + k);
          if (name) stubs.set(sec.addr + k * sec.reserved2, name);
        }
      } else if (type === 0x6 /* S_NON_LAZY_SYMBOL_POINTERS */ || type === 0x7 /* S_LAZY_SYMBOL_POINTERS */) {
        const count = Math.floor(sec.size / 8);
        for (let k = 0; k < count; k += 1) {
          const name = indirect(sec.reserved1 + k);
          if (name) slots.set(sec.addr + k * 8, { kind: 'bind', symbol: name });
        }
      }
    }
  }
  void library;

  // --- function starts
  const functionStarts: number[] = [];
  if (functionStartsAt) {
    const cursor = { i: base + functionStartsAt.off };
    const end = cursor.i + functionStartsAt.size;
    let addr = imageBase;
    while (cursor.i < end) {
      const delta = uleb(buf, cursor);
      if (delta === 0) break;
      addr += delta;
      functionStarts.push(addr);
    }
  }

  const model: MachoModel = {
    buf,
    base,
    imageBase,
    segments,
    sections,
    libraries,
    symbols,
    stubs,
    slots,
    functionStarts,
    classes: [],
    encrypted,
    fileOffset,
    sectionAt,
    cstringAt(addr: number) {
      const off = fileOffset(addr);
      if (off === undefined || off >= buf.length) return undefined;
      const end = buf.indexOf(0, off);
      const to = end === -1 ? Math.min(buf.length, off + 4096) : Math.min(end, off + 4096);
      return buf.toString('utf8', off, to);
    },
    pointerAt(addr: number) {
      const slot = slots.get(addr);
      if (slot) return slot.kind === 'rebase' ? slot.target : undefined;
      const off = fileOffset(addr);
      if (off === undefined || off + 8 > buf.length) return undefined;
      const value = Number(buf.readBigUInt64LE(off) & 0x0000ffffffffffffn);
      // In a binary with chained fixups an unlisted slot holds an encoded pointer, not an address.
      return chained ? undefined : value;
    },
  };

  if (!encrypted) model.classes = readObjcClasses(model);
  return model;
}

/** Classic dyld bind opcode stream: which symbol goes in which pointer slot. */
function readBindStream(
  buf: Buffer,
  base: number,
  off: number,
  size: number,
  segments: Segment[],
  libraries: string[],
  slots: Map<number, SlotTarget>,
): void {
  if (!off || !size || base + off + size > buf.length) return;
  const cursor = { i: base + off };
  const end = cursor.i + size;
  let symbol = '';
  let ordinal = 0;
  let seg = 0;
  let segOffset = 0;
  const bind = () => {
    const segment = segments[seg];
    if (segment && symbol) {
      slots.set(segment.vmaddr + segOffset, { kind: 'bind', symbol, library: ordinal >= 1 ? libraries[ordinal - 1] : undefined });
    }
  };
  while (cursor.i < end) {
    const byte = buf[cursor.i++];
    const opcode = byte & 0xf0;
    const imm = byte & 0x0f;
    if (opcode === 0x00) {
      // BIND_OPCODE_DONE; lazy streams hold several, separated by it.
    } else if (opcode === 0x10) ordinal = imm;
    else if (opcode === 0x20) ordinal = uleb(buf, cursor);
    else if (opcode === 0x30) ordinal = imm === 0 ? 0 : -imm;
    else if (opcode === 0x40) {
      const stop = buf.indexOf(0, cursor.i);
      symbol = buf.toString('latin1', cursor.i, stop === -1 ? end : stop);
      cursor.i = stop === -1 ? end : stop + 1;
    } else if (opcode === 0x50) {
      // type
    } else if (opcode === 0x60) sleb(buf, cursor);
    else if (opcode === 0x70) {
      seg = imm;
      segOffset = uleb(buf, cursor);
    } else if (opcode === 0x80) segOffset += uleb(buf, cursor);
    else if (opcode === 0x90) {
      bind();
      segOffset += 8;
    } else if (opcode === 0xa0) {
      bind();
      segOffset += 8 + uleb(buf, cursor);
    } else if (opcode === 0xb0) {
      bind();
      segOffset += 8 + imm * 8;
    } else if (opcode === 0xc0) {
      const count = uleb(buf, cursor);
      const skip = uleb(buf, cursor);
      for (let k = 0; k < count; k += 1) {
        bind();
        segOffset += 8 + skip;
      }
    } else if (opcode === 0xd0) break; // threaded binds: arm64e only, not followed
  }
}

/** Chained fixups (iOS 15+): the pointers themselves carry either a bind ordinal or a rebase target. */
function readChainedFixups(
  buf: Buffer,
  base: number,
  off: number,
  segments: Segment[],
  libraries: string[],
  slots: Map<number, SlotTarget>,
  imageBase: number,
): void {
  const header = base + off;
  if (header + 28 > buf.length) return;
  const startsOffset = buf.readUInt32LE(header + 4);
  const importsOffset = buf.readUInt32LE(header + 8);
  const symbolsOffset = buf.readUInt32LE(header + 12);
  const importsCount = buf.readUInt32LE(header + 16);
  const importsFormat = buf.readUInt32LE(header + 20);

  const imports: { symbol: string; ordinal: number }[] = [];
  const importSize = importsFormat === 1 ? 4 : importsFormat === 2 ? 8 : 16;
  for (let k = 0; k < importsCount && k < 200_000; k += 1) {
    const at = header + importsOffset + k * importSize;
    if (at + importSize > buf.length) break;
    let ordinal: number;
    let nameOffset: number;
    if (importsFormat === 1) {
      const v = buf.readUInt32LE(at);
      ordinal = v & 0xff;
      nameOffset = v >>> 9;
    } else {
      const v = buf.readUInt32LE(at);
      ordinal = v & 0xffff;
      nameOffset = Number(buf.readBigUInt64LE(at) >> 32n) & 0xffffffff;
      if (importsFormat === 2) nameOffset = v >>> 9, ordinal = v & 0xff;
    }
    const nameAt = header + symbolsOffset + nameOffset;
    imports.push({ symbol: nameAt < buf.length ? cstr(buf, nameAt, Math.min(buf.length, nameAt + 512)) : '', ordinal });
  }

  const starts = header + startsOffset;
  const segCount = buf.readUInt32LE(starts);
  for (let s = 0; s < segCount && s < segments.length; s += 1) {
    const infoOffset = buf.readUInt32LE(starts + 4 + s * 4);
    if (!infoOffset) continue;
    const info = starts + infoOffset;
    const pageSize = buf.readUInt16LE(info + 4);
    const pointerFormat = buf.readUInt16LE(info + 6);
    const segmentOffset = Number(buf.readBigUInt64LE(info + 8));
    const pageCount = buf.readUInt16LE(info + 20);
    const segmentVm = segments[s].vmaddr;
    void segmentOffset;
    for (let page = 0; page < pageCount; page += 1) {
      const pageStart = buf.readUInt16LE(info + 22 + page * 2);
      if (pageStart === 0xffff) continue;
      let addr = segmentVm + page * pageSize + (pageStart & 0x7fff);
      for (let guard = 0; guard < 1_000_000; guard += 1) {
        const fileAt = base + segments[s].fileoff + (addr - segmentVm);
        if (fileAt + 8 > buf.length) break;
        const raw = buf.readBigUInt64LE(fileAt);
        const here = addr;
        let next = 0;
        let isBind = false;
        let ordinal = 0;
        let target = 0;
        if (pointerFormat === 2 || pointerFormat === 6) {
          isBind = (raw >> 63n) === 1n;
          next = Number((raw >> 51n) & 0xfffn);
          if (isBind) ordinal = Number(raw & 0xffffffn);
          else {
            target = Number(raw & 0xfffffffffn);
            if (pointerFormat === 6) target += imageBase;
          }
          addr += next * 4;
        } else {
          // arm64e family (1, 9, 12)
          const auth = (raw >> 63n) === 1n;
          isBind = ((raw >> 62n) & 1n) === 1n;
          next = Number((raw >> 51n) & 0x7ffn);
          if (isBind) ordinal = pointerFormat === 12 ? Number(raw & 0xffffffn) : Number(raw & 0xffffn);
          else target = auth ? Number(raw & 0xffffffffn) + imageBase : Number(raw & 0x7ffffffffffn);
          if (!auth && !isBind && pointerFormat !== 1) target = Number(raw & 0x7ffffffffffn);
          addr += next * 8;
        }
        if (isBind) {
          const imp = imports[ordinal];
          if (imp) slots.set(here, { kind: 'bind', symbol: imp.symbol, library: imp.ordinal >= 1 && imp.ordinal <= libraries.length ? libraries[imp.ordinal - 1] : undefined });
        } else {
          slots.set(here, { kind: 'rebase', target });
        }
        if (next === 0) break;
      }
    }
  }
}

/** Objective-C classes the binary defines, with each method's implementation address. */
function readObjcClasses(model: MachoModel): ObjcClass[] {
  const list = model.sections.find((s) => s.name === '__objc_classlist');
  if (!list) return [];
  const out: ObjcClass[] = [];
  const count = Math.min(Math.floor(list.size / 8), 50_000);
  for (let i = 0; i < count; i += 1) {
    const classAddr = model.pointerAt(list.addr + i * 8);
    if (classAddr === undefined) continue;
    const cls = readOneClass(model, classAddr, false);
    if (!cls) continue;
    const isa = model.pointerAt(classAddr);
    if (isa !== undefined) {
      const meta = readOneClass(model, isa, true, cls.name);
      if (meta) cls.methods.push(...meta.methods);
    }
    out.push(cls);
  }
  return out;
}

function readOneClass(model: MachoModel, classAddr: number, meta: boolean, nameOverride?: string): ObjcClass | undefined {
  // class_t: isa, superclass, cache, vtable, data
  const dataWord = model.pointerAt(classAddr + 32);
  if (dataWord === undefined) return undefined;
  // The low bits of the data pointer are flags. (JavaScript's & works on 32 bits, so this is done by division.)
  const ro = Math.floor(dataWord / 8) * 8;
  // class_ro_t: flags, instanceStart, instanceSize, reserved, ivarLayout, name, baseMethods ...
  const nameAddr = model.pointerAt(ro + 24);
  const name = nameOverride ?? (nameAddr !== undefined ? model.cstringAt(nameAddr) : undefined);
  if (!name) return undefined;
  const methodsAddr = model.pointerAt(ro + 32);
  const methods: ObjcMethod[] = [];
  if (methodsAddr) {
    const entsizeAndFlags = model.buf.readUInt32LE(model.fileOffset(methodsAddr) ?? 0);
    const countAt = model.fileOffset(methodsAddr + 4);
    const methodCount = countAt === undefined ? 0 : model.buf.readUInt32LE(countAt);
    const small = (entsizeAndFlags & 0x80000000) !== 0;
    const entsize = small ? 12 : 24;
    for (let m = 0; m < Math.min(methodCount, 5000); m += 1) {
      const entry = methodsAddr + 8 + m * entsize;
      let selector: string | undefined;
      let imp: number | undefined;
      if (small) {
        const nameOff = model.buf.readInt32LE(model.fileOffset(entry) ?? 0);
        const impOff = model.buf.readInt32LE(model.fileOffset(entry + 8) ?? 0);
        const selSlot = entry + nameOff;
        const selPtr = model.pointerAt(selSlot);
        selector = selPtr !== undefined ? model.cstringAt(selPtr) : undefined;
        imp = entry + 8 + impOff;
      } else {
        const namePtr = model.pointerAt(entry);
        selector = namePtr !== undefined ? model.cstringAt(namePtr) : undefined;
        imp = model.pointerAt(entry + 16);
      }
      if (selector && imp !== undefined) methods.push({ selector, imp, className: name, classMethod: meta });
    }
  }
  return { name, address: classAddr, methods };
}
