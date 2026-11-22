/**
 * Mach-O reader, for the iOS binary-protections and signing checks.
 *
 * Reads the header, the load commands and the embedded code signature directly,
 * which avoids a dependency on `otool` and `codesign` — tools that only exist
 * where Xcode does. That keeps a self-hosted scanner on Linux able to assess an
 * IPA to the same depth as one on a Mac.
 *
 * What it recovers: the hardening flags (PIE, stack execution), the architecture
 * and file type, linked and weak libraries, rpaths, segment protections, whether
 * local symbols were stripped, Swift and Objective-C presence, the build SDK and
 * minimum OS, and — from the code-signature SuperBlob — the code directory
 * (identifier, team id, hash type, ad-hoc and hardened-runtime flags) and the
 * entitlements that were actually signed into the binary. The last is the ground
 * truth: an App Store IPA carries no provisioning profile, but it always carries
 * a signature.
 */

const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const MH_MAGIC_32 = 0xfeedface;
const MH_CIGAM_32 = 0xcefaedfe;
const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;

const MH_ALLOW_STACK_EXECUTION = 0x20000;
const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;

const LC_SEGMENT = 0x1;
const LC_SYMTAB = 0x2;
const LC_DYSYMTAB = 0xb;
const LC_LOAD_DYLIB = 0xc;
const LC_ID_DYLIB = 0xd;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;
const LC_SEGMENT_64 = 0x19;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_BUILD_VERSION = 0x32;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_RPATH = 0x8000001c;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

/** Code-signature SuperBlob magics (big-endian on disk). */
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_ENTITLEMENTS = 5;
const CS_ADHOC = 0x2;
const CS_RUNTIME = 0x10000;

const CPU_ARCH_ABI64 = 0x01000000;
const CPU_TYPE_ARM = 12;
const CPU_TYPE_X86 = 7;

export type CodeSignatureFacts = {
  /** The signature SuperBlob parsed; false when LC_CODE_SIGNATURE was absent or unreadable. */
  present: boolean;
  adhoc: boolean;
  hardenedRuntime: boolean;
  identifier?: string;
  teamId?: string;
  hashType?: string;
  /** The entitlements plist that was signed into the binary, as raw XML bytes. */
  entitlementsXml?: Buffer;
};

export type MachOFacts = {
  parsed: boolean;
  is64Bit: boolean;
  pie: boolean;
  /** cryptid != 0: the App Store has applied FairPlay encryption. */
  encrypted: boolean;
  allowsStackExecution: boolean;
  /** Linked against the stack protector. */
  stackCanary: boolean;
  /** Linked against the ARC runtime rather than manual retain/release. */
  arc: boolean;
  rpaths: string[];
  archCount: number;

  /** e.g. "arm64", "arm64e", "armv7", "x86_64". */
  arch?: string;
  /** e.g. "ARM64 (all)". */
  cpu?: string;
  /** "executable" | "dylib" | "bundle" | "object" | numeric. */
  fileType?: string;
  swift: boolean;
  objc: boolean;
  noHeapExecution: boolean;
  /** Any segment mapped readable, writable and executable at once. */
  rwxSegments: string[];
  /** Local (non-exported) symbols still present. Near zero once stripped. */
  localSymbols: number;
  symbolCount: number;
  uuid?: string;
  minOs?: string;
  sdk?: string;
  /** LC_ID_DYLIB install name, for dylibs and frameworks. */
  installName?: string;
  linkedLibraries: string[];
  weakLibraries: string[];
  signature: CodeSignatureFacts;
};

const NO_SIGNATURE: CodeSignatureFacts = { present: false, adhoc: false, hardenedRuntime: false };

/** Reads a 32-bit word in the image's own byte order. */
function readU32(buf: Buffer, at: number, swapped: boolean): number {
  return swapped ? buf.readUInt32BE(at) : buf.readUInt32LE(at);
}

/** Packed x.y.z version: 16 bits, 8 bits, 8 bits. */
function version(v: number): string {
  const patch = v & 0xff;
  return `${v >>> 16}.${(v >>> 8) & 0xff}${patch ? `.${patch}` : ''}`;
}

function cString(buf: Buffer, from: number, to: number): string {
  return buf.subarray(from, to).toString('latin1').replace(/\0[\s\S]*$/, '');
}

function archName(cputype: number, cpusubtype: number): { arch: string; cpu: string } {
  const sub = cpusubtype & 0x00ffffff;
  if (cputype === (CPU_TYPE_ARM | CPU_ARCH_ABI64)) {
    return sub === 2 ? { arch: 'arm64e', cpu: 'ARM64E (pointer authentication)' } : { arch: 'arm64', cpu: 'ARM64' };
  }
  if (cputype === CPU_TYPE_ARM) {
    const names: Record<number, string> = { 6: 'armv6', 9: 'armv7', 11: 'armv7s', 12: 'armv7k' };
    const arch = names[sub] ?? 'arm';
    return { arch, cpu: `ARM (${arch})` };
  }
  if (cputype === (CPU_TYPE_X86 | CPU_ARCH_ABI64)) return { arch: 'x86_64', cpu: 'x86-64' };
  if (cputype === CPU_TYPE_X86) return { arch: 'i386', cpu: 'x86 (32-bit)' };
  return { arch: `cpu-${cputype}`, cpu: `CPU type ${cputype}` };
}

/**
 * Chooses which slice of a fat binary to inspect.
 *
 * arm64 is preferred: it is what runs on every device that can install a current
 * app. Failing that, the first slice. `archCount` is reported so a multi-slice
 * binary is visible, and the caller states that only one slice was read.
 */
export function pickSlice(buf: Buffer): { offset: number; size: number; archCount: number } {
  const magic = buf.readUInt32BE(0);
  if (magic !== FAT_MAGIC && magic !== FAT_CIGAM) return { offset: 0, size: buf.length, archCount: 1 };

  const swapped = magic === FAT_CIGAM;
  const read = (at: number) => (swapped ? buf.readUInt32LE(at) : buf.readUInt32BE(at));
  const nfat = read(4);
  if (nfat < 1 || nfat > 32) return { offset: 0, size: buf.length, archCount: 1 };

  let chosen: { offset: number; size: number } | undefined;
  for (let i = 0; i < nfat; i += 1) {
    // fat_arch: cputype, cpusubtype, offset, size, align.
    const at = 8 + i * 20;
    if (at + 20 > buf.length) break;
    const cputype = read(at);
    const entry = { offset: read(at + 8), size: read(at + 12) };
    if (!chosen) chosen = entry;
    if (cputype === (CPU_TYPE_ARM | CPU_ARCH_ABI64)) {
      chosen = entry;
      break;
    }
  }
  return { ...(chosen ?? { offset: 0, size: buf.length }), archCount: nfat };
}

/**
 * The code signature: a big-endian SuperBlob of indexed blobs. The code
 * directory gives the identity; the entitlements blob is the plist the signer
 * embedded, which is what the kernel enforces at runtime.
 */
function readCodeSignature(buf: Buffer, sliceBase: number, dataoff: number, datasize: number): CodeSignatureFacts {
  const start = sliceBase + dataoff;
  const end = Math.min(buf.length, start + datasize);
  if (start + 12 > end || buf.readUInt32BE(start) !== CSMAGIC_EMBEDDED_SIGNATURE) return NO_SIGNATURE;

  const count = buf.readUInt32BE(start + 8);
  if (count > 64) return NO_SIGNATURE;

  const facts: CodeSignatureFacts = { present: true, adhoc: false, hardenedRuntime: false };
  for (let i = 0; i < count; i += 1) {
    const entry = start + 12 + i * 8;
    if (entry + 8 > end) break;
    const slot = buf.readUInt32BE(entry);
    const at = start + buf.readUInt32BE(entry + 4);
    if (at + 8 > end) continue;
    const magic = buf.readUInt32BE(at);
    const length = buf.readUInt32BE(at + 4);
    if (length < 8 || at + length > end) continue;

    if (slot === CSSLOT_CODEDIRECTORY && magic === CSMAGIC_CODEDIRECTORY && length >= 44) {
      const codeVersion = buf.readUInt32BE(at + 8);
      const flags = buf.readUInt32BE(at + 12);
      const identOffset = buf.readUInt32BE(at + 20);
      const hashType = buf.readUInt8(at + 37);
      facts.adhoc = (flags & CS_ADHOC) !== 0;
      facts.hardenedRuntime = (flags & CS_RUNTIME) !== 0;
      facts.identifier = cString(buf, at + identOffset, at + length);
      facts.hashType = { 1: 'SHA-1', 2: 'SHA-256', 3: 'SHA-256 (truncated)', 4: 'SHA-384' }[hashType];
      if (codeVersion >= 0x20200 && length >= 52) {
        const teamOffset = buf.readUInt32BE(at + 48);
        if (teamOffset > 0 && teamOffset < length) facts.teamId = cString(buf, at + teamOffset, at + length);
      }
    } else if (slot === CSSLOT_ENTITLEMENTS && magic === CSMAGIC_EMBEDDED_ENTITLEMENTS) {
      facts.entitlementsXml = Buffer.from(buf.subarray(at + 8, at + length));
    }
  }
  return facts;
}

export function readMachO(buf: Buffer): MachOFacts {
  const empty: MachOFacts = {
    parsed: false, is64Bit: false, pie: false, encrypted: false,
    allowsStackExecution: false, stackCanary: false, arc: false,
    rpaths: [], archCount: 0, swift: false, objc: false, noHeapExecution: false,
    rwxSegments: [], localSymbols: 0, symbolCount: 0,
    linkedLibraries: [], weakLibraries: [], signature: NO_SIGNATURE,
  };
  if (buf.length < 32) return empty;

  const { offset: base, archCount } = pickSlice(buf);
  if (base + 32 > buf.length) return empty;

  const magic = buf.readUInt32LE(base);
  const is64Bit = magic === MH_MAGIC_64 || magic === MH_CIGAM_64;
  const is32Bit = magic === MH_MAGIC_32 || magic === MH_CIGAM_32;
  if (!is64Bit && !is32Bit) return empty;

  const swapped = magic === MH_CIGAM_64 || magic === MH_CIGAM_32;
  const cputype = readU32(buf, base + 4, swapped);
  const cpusubtype = readU32(buf, base + 8, swapped);
  const filetype = readU32(buf, base + 12, swapped);
  const ncmds = readU32(buf, base + 16, swapped);
  const flags = readU32(buf, base + 24, swapped);
  const headerSize = is64Bit ? 32 : 28;

  let encrypted = false;
  let swift = false;
  let objc = false;
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  let fixups: { dataoff: number; datasize: number } | undefined;
  let localSymbols = 0;
  let signatureLoc: { dataoff: number; datasize: number } | undefined;
  let uuid: string | undefined;
  let minOs: string | undefined;
  let sdk: string | undefined;
  let installName: string | undefined;
  const rpaths: string[] = [];
  const linkedLibraries: string[] = [];
  const weakLibraries: string[] = [];
  const rwxSegments: string[] = [];
  let at = base + headerSize;

  for (let i = 0; i < ncmds && at + 8 <= buf.length; i += 1) {
    const cmd = readU32(buf, at, swapped);
    const cmdSize = readU32(buf, at + 4, swapped);
    if (cmdSize < 8 || at + cmdSize > buf.length) break;

    switch (cmd) {
      case LC_ENCRYPTION_INFO:
      case LC_ENCRYPTION_INFO_64:
        // encryption_info_command: cmd, cmdsize, cryptoff, cryptsize, cryptid
        if (at + 20 <= buf.length && readU32(buf, at + 16, swapped) !== 0) encrypted = true;
        break;

      case LC_RPATH:
        if (at + 12 <= buf.length) {
          const pathOffset = readU32(buf, at + 8, swapped);
          if (pathOffset < cmdSize) rpaths.push(cString(buf, at + pathOffset, at + cmdSize));
        }
        break;

      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      case LC_ID_DYLIB: {
        // dylib_command: cmd, cmdsize, name.offset, timestamp, current, compat.
        const nameOffset = readU32(buf, at + 8, swapped);
        if (nameOffset < cmdSize) {
          const name = cString(buf, at + nameOffset, at + cmdSize);
          if (cmd === LC_ID_DYLIB) installName = name;
          else if (cmd === LC_LOAD_WEAK_DYLIB) weakLibraries.push(name);
          else linkedLibraries.push(name);
        }
        break;
      }

      case LC_UUID:
        if (at + 24 <= buf.length) {
          const hex = buf.subarray(at + 8, at + 24).toString('hex');
          uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`.toUpperCase();
        }
        break;

      case LC_BUILD_VERSION:
        // build_version_command: cmd, cmdsize, platform, minos, sdk, ntools.
        if (at + 20 <= buf.length) {
          minOs = version(readU32(buf, at + 12, swapped));
          sdk = version(readU32(buf, at + 16, swapped));
        }
        break;

      case LC_VERSION_MIN_IPHONEOS:
        if (at + 16 <= buf.length && !minOs) {
          minOs = version(readU32(buf, at + 8, swapped));
          sdk = version(readU32(buf, at + 12, swapped));
        }
        break;

      case LC_SYMTAB:
        if (at + 24 <= buf.length) {
          symtab = {
            symoff: readU32(buf, at + 8, swapped),
            nsyms: readU32(buf, at + 12, swapped),
            stroff: readU32(buf, at + 16, swapped),
            strsize: readU32(buf, at + 20, swapped),
          };
        }
        break;

      case LC_DYSYMTAB:
        // dysymtab_command: cmd, cmdsize, ilocalsym, nlocalsym, ...
        if (at + 16 <= buf.length) localSymbols = readU32(buf, at + 12, swapped);
        break;

      case LC_DYLD_CHAINED_FIXUPS:
        if (at + 16 <= buf.length) {
          fixups = { dataoff: readU32(buf, at + 8, swapped), datasize: readU32(buf, at + 12, swapped) };
        }
        break;

      case LC_CODE_SIGNATURE:
        if (at + 16 <= buf.length) {
          signatureLoc = { dataoff: readU32(buf, at + 8, swapped), datasize: readU32(buf, at + 12, swapped) };
        }
        break;

      case LC_SEGMENT:
      case LC_SEGMENT_64: {
        const wide = cmd === LC_SEGMENT_64;
        const segName = cString(buf, at + 8, at + 24);
        // segment_command(_64): ... maxprot, initprot, nsects, flags after the
        // four address/size fields, which are 4 bytes wide in the 32-bit form.
        const protAt = at + 24 + (wide ? 32 : 16);
        if (protAt + 12 > buf.length) break;
        const initprot = readU32(buf, protAt + 4, swapped);
        const nsects = readU32(buf, protAt + 8, swapped);
        if ((initprot & 7) === 7) rwxSegments.push(segName);

        const sectionsAt = protAt + 16;
        const sectionSize = wide ? 80 : 68;
        for (let s = 0; s < nsects && sectionsAt + (s + 1) * sectionSize <= at + cmdSize; s += 1) {
          const name = cString(buf, sectionsAt + s * sectionSize, sectionsAt + s * sectionSize + 16);
          if (name.startsWith('__swift5_') || name.startsWith('__swift4_') || name === '__swift_ast') swift = true;
          if (name === '__objc_classlist' || name === '__objc_imageinfo' || name === '__objc_classrefs') objc = true;
        }
        break;
      }

      default:
        break;
    }
    at += cmdSize;
  }

  // Swift binaries also announce themselves by linking the runtime.
  if (linkedLibraries.some((l) => /libswift/i.test(l))) swift = true;

  // The hardening symbols are looked up in the symbol string table and, on
  // binaries using chained fixups, in the fixups import pool — the places a
  // linker records what a binary imports. Searching the whole file instead (as
  // this reader once did) matched the names inside unrelated string literals,
  // so a binary that merely *mentioned* `__stack_chk_fail` passed. Where neither
  // region can be located the whole image is the fallback, as before.
  const regions: Buffer[] = [];
  if (symtab && base + symtab.stroff + symtab.strsize <= buf.length && symtab.strsize > 0) {
    regions.push(buf.subarray(base + symtab.stroff, base + symtab.stroff + symtab.strsize));
  }
  if (fixups && base + fixups.dataoff + fixups.datasize <= buf.length && fixups.datasize > 0) {
    regions.push(buf.subarray(base + fixups.dataoff, base + fixups.dataoff + fixups.datasize));
  }
  const text = (regions.length > 0 ? Buffer.concat(regions) : buf).toString('latin1');

  const signature = signatureLoc
    ? readCodeSignature(buf, base, signatureLoc.dataoff, signatureLoc.datasize)
    : NO_SIGNATURE;
  const names = archName(cputype, cpusubtype);

  return {
    parsed: true,
    is64Bit,
    pie: (flags & MH_PIE) !== 0,
    encrypted,
    allowsStackExecution: (flags & MH_ALLOW_STACK_EXECUTION) !== 0,
    stackCanary: text.includes('__stack_chk_fail') || text.includes('__stack_chk_guard'),
    arc: text.includes('_objc_release') || text.includes('_objc_retainAutoreleasedReturnValue') || text.includes('_swift_release'),
    rpaths,
    archCount,
    arch: names.arch,
    cpu: names.cpu,
    fileType: ({ 1: 'object', 2: 'executable', 6: 'dylib', 8: 'bundle' } as Record<number, string>)[filetype] ?? `type-${filetype}`,
    swift,
    objc,
    noHeapExecution: (flags & MH_NO_HEAP_EXECUTION) !== 0,
    rwxSegments,
    localSymbols,
    symbolCount: symtab?.nsyms ?? 0,
    uuid,
    minOs,
    sdk,
    installName,
    linkedLibraries,
    weakLibraries,
    signature,
  };
}
