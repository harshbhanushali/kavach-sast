/**
 * ELF reader, for the Android native-library hardening checks.
 *
 * This is the gap the earlier scan reported honestly and could not fill: the
 * `binary` category came back "not assessed" on Android because nothing looked
 * at `lib/**\/*.so`. The standard `checksec` facts are read here: NX, PIE, stack
 * canary, RELRO, RPATH/RUNPATH, stripped symbols and fortify.
 *
 * Parsed in-process rather than shelling out to `readelf` or `objdump`, for the
 * same reason the Mach-O reader is: binutils is not present on every host, and
 * the header layout is small and stable enough that reading it directly is less
 * fragile than depending on another tool's output format.
 *
 * Layout reference: ELF-64 gABI. The 32-bit variant differs only in field
 * widths and the order of p_flags, both handled below.
 */

const PT_DYNAMIC = 2;
const PT_GNU_RELRO = 0x6474e552;
const PT_GNU_STACK = 0x6474e551;

const SHT_SYMTAB = 2;

const DT_NULL = 0n;
const DT_RPATH = 15n;
const DT_RUNPATH = 29n;
const DT_BIND_NOW = 24n;
const DT_FLAGS = 30n;
const DF_BIND_NOW = 0x8n;

/** e_type values. */
const ET_EXEC = 2;
const ET_DYN = 3;

export type RelroState = 'full' | 'partial' | 'none';

export type ElfFacts = {
  parsed: boolean;
  is64Bit: boolean;
  /**
   * A shared object (`DYN`) is position-independent by construction. An
   * executable is only PIE when it is also `DYN`; an `EXEC` is not.
   */
  pie: boolean;
  /** NX: the stack is non-executable. */
  nx: boolean;
  stackCanary: boolean;
  relro: RelroState;
  rpath: boolean;
  runpath: boolean;
  symbolsStripped: boolean;
  /** Built with _FORTIFY_SOURCE: the `_chk` variants are linked. */
  fortified: boolean;
};

const EMPTY: ElfFacts = {
  parsed: false, is64Bit: false, pie: false, nx: false, stackCanary: false,
  relro: 'none', rpath: false, runpath: false, symbolsStripped: false, fortified: false,
};

export function isElf(buf: Buffer): boolean {
  return buf.length > 4 && buf.readUInt32BE(0) === 0x7f454c46; // \x7fELF
}

export function readElf(buf: Buffer): ElfFacts {
  if (!isElf(buf) || buf.length < 64) return EMPTY;

  const is64Bit = buf.readUInt8(4) === 2;
  const littleEndian = buf.readUInt8(5) === 1;

  const u16 = (at: number) => (littleEndian ? buf.readUInt16LE(at) : buf.readUInt16BE(at));
  const u32 = (at: number) => (littleEndian ? buf.readUInt32LE(at) : buf.readUInt32BE(at));
  const u64 = (at: number) => (littleEndian ? buf.readBigUInt64LE(at) : buf.readBigUInt64BE(at));
  /** Reads an address-width word as a Number, which is safe below 2^53. */
  const addr = (at: number) => (is64Bit ? Number(u64(at)) : u32(at));

  try {
    const eType = u16(16);
    const phoff = is64Bit ? Number(u64(32)) : u32(28);
    const shoff = is64Bit ? Number(u64(40)) : u32(32);
    const phentsize = u16(is64Bit ? 54 : 42);
    const phnum = u16(is64Bit ? 56 : 44);
    const shentsize = u16(is64Bit ? 58 : 46);
    const shnum = u16(is64Bit ? 60 : 48);

    // --- program headers: NX, RELRO, and where the dynamic section lives ---
    let nx = true;          // absent PT_GNU_STACK means the default, which is NX.
    let hasRelroSegment = false;
    let dynamicOffset = -1;
    let dynamicSize = 0;

    for (let i = 0; i < phnum && phoff > 0; i += 1) {
      const at = phoff + i * phentsize;
      if (at + phentsize > buf.length) break;

      const pType = u32(at);
      // p_flags sits at a different offset in the two classes: right after
      // p_type on 64-bit, and after p_memsz on 32-bit.
      const pFlags = is64Bit ? u32(at + 4) : u32(at + 24);

      if (pType === PT_GNU_STACK) {
        nx = (pFlags & 0x1) === 0; // PF_X on the stack segment means no NX.
      } else if (pType === PT_GNU_RELRO) {
        hasRelroSegment = true;
      } else if (pType === PT_DYNAMIC) {
        dynamicOffset = addr(at + (is64Bit ? 8 : 4));
        dynamicSize = addr(at + (is64Bit ? 32 : 16));
      }
    }

    // --- dynamic section: BIND_NOW (full RELRO), RPATH, RUNPATH ---
    let bindNow = false;
    let rpath = false;
    let runpath = false;

    if (dynamicOffset > 0 && dynamicOffset < buf.length) {
      const entrySize = is64Bit ? 16 : 8;
      const end = Math.min(buf.length, dynamicOffset + (dynamicSize || buf.length - dynamicOffset));
      for (let at = dynamicOffset; at + entrySize <= end; at += entrySize) {
        const tag = is64Bit ? u64(at) : BigInt(u32(at));
        if (tag === DT_NULL) break;
        const value = is64Bit ? u64(at + 8) : BigInt(u32(at + 4));

        if (tag === DT_BIND_NOW) bindNow = true;
        else if (tag === DT_FLAGS && (value & DF_BIND_NOW) !== 0n) bindNow = true;
        else if (tag === DT_RPATH) rpath = true;
        else if (tag === DT_RUNPATH) runpath = true;
      }
    }

    // Full RELRO needs both the read-only segment and immediate binding;
    // either one alone is partial.
    const relro: RelroState = hasRelroSegment ? (bindNow ? 'full' : 'partial') : 'none';

    // --- section headers: a real symbol table means symbols are not stripped ---
    let symbolsStripped = true;
    for (let i = 0; i < shnum && shoff > 0; i += 1) {
      const at = shoff + i * shentsize;
      if (at + shentsize > buf.length) break;
      if (u32(at + 4) === SHT_SYMTAB) {
        symbolsStripped = false;
        break;
      }
    }

    // --- linked symbols, read from the raw bytes ---
    //
    // The names are distinctive enough that a substring search does not produce
    // false positives, and it avoids walking .dynsym and its string table for
    // two boolean facts.
    const text = buf.toString('latin1');
    const stackCanary = text.includes('__stack_chk_fail') || text.includes('__stack_chk_guard');
    const fortified = /__(memcpy|memset|strcpy|strcat|sprintf|snprintf|read|printf|vsnprintf)_chk/.test(text);

    return {
      parsed: true,
      is64Bit,
      // A shared library is ET_DYN and therefore position-independent. An
      // ET_EXEC is a fixed-address executable and is not.
      pie: eType === ET_DYN || (eType !== ET_EXEC && eType !== 0),
      nx,
      stackCanary,
      relro,
      rpath,
      runpath,
      symbolsStripped,
      fortified,
    };
  } catch {
    // A truncated or malformed object is reported as unparsed, never as clean.
    return EMPTY;
  }
}
