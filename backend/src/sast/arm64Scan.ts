/**
 * What each function in an iOS binary calls, and which string literals it uses.
 *
 * This is not a disassembler. It reads a function's 32-bit instruction words, follows the few
 * forms the compiler uses to load an address (`adrp` + `add`, `adrp` + `ldr`), a small
 * constant (`movz`/`movk`) or a register copy, and notes where it ends up:
 *
 * - a `bl` to a stub is a call to an imported function (`_CC_MD5`, `_SecItemAdd`);
 * - a `bl` to `_objc_msgSend` with a selector reference in `x1` is a message send, and the
 *   selector says which method (`isEqualToString:`, `evaluatePolicy:localizedReason:reply:`);
 * - an address inside `__cstring` or `__cfstring` is a string literal the function uses, and
 *   a literal sitting in an argument register at a call is an argument of that call.
 *
 * Together that answers questions a string table cannot: *which* function compares to a
 * literal, whether the function that builds a credential from the server trust also evaluates
 * it, which key a value is stored under. Everything it cannot follow it leaves out; a register
 * written by an instruction it does not model is forgotten rather than guessed.
 */
import type { MachoModel } from './machoModel.ts';

/** One argument of a call, as far as it could be followed. */
export type Arg = { imm?: number; str?: string; sym?: string };

export type Call =
  | { kind: 'import'; name: string; args: Arg[] }
  | { kind: 'msg'; selector: string; receiver?: string; args: Arg[] }
  | { kind: 'internal'; target: number };

export type FunctionFact = {
  address: number;
  size: number;
  name: string;
  /** Objective-C method this is, when it is one. */
  objc?: { className: string; selector: string; classMethod: boolean };
  calls: Call[];
  strings: string[];
  /** Imported data symbols the function loads (constants such as `kSecAttrAccessibleAlways`). */
  refs: string[];
  /** Objective-C classes the function references (`UIWebView`, `NSUserDefaults`). */
  classes: string[];
};

type Reg = { addr?: number; imm?: number; big?: bigint; sym?: string; cls?: string };

const OBJC_MSGSEND = /^_?objc_msgSend(?:Super2?)?(?:_stret|_fpret|_fp2ret)?$/;

/**
 * Whether the bits of `w` selected by `mask` equal `pattern`.
 *
 * JavaScript's bitwise operators return signed 32-bit integers, so a plain `(w & mask) === pattern`
 * is false for every instruction whose top bit is set, which is most of arm64.
 */
function is(w: number, mask: number, pattern: number): boolean {
  return ((w & mask) >>> 0) === pattern;
}

function adrpOffset(w: number): number {
  const immlo = (w >> 29) & 3;
  const immhi = (w >> 5) & 0x7ffff;
  return signExtend((immhi << 2) | immlo, 21) * 4096;
}

function signExtend(value: number, bits: number): number {
  const shift = 32 - bits;
  return (value << shift) >> shift;
}

/** Stores, branches and compares read their register operands instead of writing rd. */
function isStoreOrBranch(w: number): boolean {
  const op = w >>> 24;
  // Branches: b.cond, cbz/cbnz, tbz/tbnz, br/blr/ret
  if ((op & 0xfe) === 0x54 || (op & 0x7e) === 0x34 || (op & 0x7e) === 0x36 || is(w, 0xfe000000, 0xd6000000)) return true;
  // Load/store: single register (unsigned offset, pre/post index, unscaled) and pairs. A load writes rt; a store does not.
  if (is(w, 0x3b000000, 0x39000000) || is(w, 0x3b200c00, 0x38000000) || is(w, 0x3b200c00, 0x38000400) || is(w, 0x3b200c00, 0x38000c00)) {
    return ((w >> 22) & 1) === 0;
  }
  if (is(w, 0x3a000000, 0x28000000)) return ((w >> 22) & 1) === 0;
  return false;
}

function isLoadPair(w: number): boolean {
  return is(w, 0x3a000000, 0x28000000) && ((w >> 22) & 1) === 1;
}

const bytesOf = (value: bigint, count: number): string => {
  let out = '';
  for (let i = 0; i < count; i += 1) {
    const b = Number((value >> BigInt(i * 8)) & 0xffn);
    if (b === 0) break;
    if (b < 0x20 || b > 0x7e) return '';
    out += String.fromCharCode(b);
  }
  return out;
};

/**
 * A Swift string of up to 15 bytes lives in two registers: the first eight bytes, then the rest
 * with a discriminator (0xE0 plus the length) in the top byte. Loaded with movz/movk, it never
 * touches a string table, which is where a short password would otherwise hide.
 */
function smallString(low: bigint | undefined, high: bigint | undefined): string | undefined {
  if (high === undefined) return undefined;
  const marker = Number((high >> 56n) & 0xffn);
  if (marker < 0xe0 || marker > 0xef) return undefined;
  const length = marker & 0xf;
  if (length < 1) return undefined;
  const first = low === undefined ? '' : bytesOf(low, 8);
  const second = bytesOf(high & 0x00ffffffffffffffn, 7);
  const text = (first + second).slice(0, length);
  return text.length === length && length >= 3 ? text : undefined;
}

export function analyseFunctions(model: MachoModel, options: { limit?: number } = {}): FunctionFact[] {
  const text = model.sections.find((s) => s.name === '__text' && s.segment === '__TEXT');
  if (!text || model.encrypted || model.functionStarts.length === 0) return [];

  const starts = [...new Set(model.functionStarts)].filter((a) => a >= text.addr && a < text.addr + text.size).sort((a, b) => a - b);
  const startSet = new Set(starts);

  // Names: Objective-C methods first, then symbols the binary kept.
  const objc = new Map<number, { className: string; selector: string; classMethod: boolean }>();
  const classByAddress = new Map<number, string>();
  for (const cls of model.classes) {
    classByAddress.set(cls.address, cls.name);
    for (const m of cls.methods) objc.set(m.imp, { className: m.className, selector: m.selector, classMethod: m.classMethod });
  }
  const symbolAt = new Map<number, string>();
  for (const s of model.symbols) if (s.defined && s.name) symbolAt.set(s.value, s.name);

  // Selector stubs (`_objc_msgSend$selector`, Xcode 14+): each loads a selector reference and jumps to objc_msgSend.
  const selectorStubs = new Map<number, string>();
  const stubsSection = model.sections.find((s) => s.name === '__objc_stubs');
  if (stubsSection) {
    for (let a = stubsSection.addr; a + 32 <= stubsSection.addr + stubsSection.size; a += 32) {
      const off = model.fileOffset(a);
      if (off === undefined) continue;
      const w0 = model.buf.readUInt32LE(off);
      const w1 = model.buf.readUInt32LE(off + 4);
      if (is(w0, 0x9f000000, 0x90000000) && is(w1, 0xffc00000, 0xf9400000)) {
        const page = Math.floor(a / 4096) * 4096 + adrpOffset(w0);
        const slot = page + ((w1 >> 10) & 0xfff) * 8;
        const ptr = model.pointerAt(slot);
        const sel = ptr !== undefined ? model.cstringAt(ptr) : undefined;
        if (sel) selectorStubs.set(a, sel);
      }
    }
  }

  const sectionOf = (name: string) => model.sections.find((s) => s.name === name);
  const selrefs = sectionOf('__objc_selrefs');
  const classrefs = sectionOf('__objc_classrefs');
  const within = (s: { addr: number; size: number } | undefined, a: number) => Boolean(s) && a >= s!.addr && a < s!.addr + s!.size;
  const cfstring = sectionOf('__cfstring');
  const cstringSections = model.sections.filter((s) => (s.flags & 0xff) === 0x2 /* S_CSTRING_LITERALS */ || s.name === '__cstring');

  /** The literal at an address, if it is in a string section. */
  const literalAt = (addr: number | undefined): string | undefined => {
    if (addr === undefined) return undefined;
    if (cfstring && within(cfstring, addr)) {
      const entry = addr - ((addr - cfstring.addr) % 32);
      const ptr = model.pointerAt(entry + 16);
      return ptr !== undefined ? model.cstringAt(ptr) : undefined;
    }
    for (const sec of cstringSections) if (within(sec, addr)) return model.cstringAt(addr);
    return undefined;
  };

  const facts: FunctionFact[] = [];
  const limit = options.limit ?? 200_000;

  for (let f = 0; f < starts.length && facts.length < limit; f += 1) {
    const address = starts[f];
    const end = f + 1 < starts.length ? starts[f + 1] : text.addr + text.size;
    const offset = model.fileOffset(address);
    if (offset === undefined) continue;
    const words = Math.min((end - address) >> 2, 60_000);

    const regs: Reg[] = Array.from({ length: 32 }, () => ({}));
    const calls: Call[] = [];
    const strings = new Set<string>();
    const refs = new Set<string>();
    const classes = new Set<string>();

    const argOf = (r: number): Arg => {
      const reg = regs[r];
      const arg: Arg = {};
      if (reg.imm !== undefined) arg.imm = reg.imm;
      const literal = literalAt(reg.addr) ?? (reg.big !== undefined ? smallString(reg.big, regs[r + 1]?.big) : undefined);
      if (literal !== undefined) arg.str = literal;
      if (reg.sym) arg.sym = reg.sym;
      return arg;
    };
    const snapshot = (): Arg[] => [0, 1, 2, 3, 4, 5, 6, 7].map(argOf);

    const finishBig = () => {
      // Short Swift strings completed in registers become literals of the function.
      for (let r = 0; r < 31; r += 1) {
        const big = regs[r].big;
        if (big === undefined) continue;
        const joined = smallString(big, regs[r + 1]?.big);
        if (joined) strings.add(joined);
      }
    };
    const clearCallerSaved = () => {
      finishBig();
      for (let r = 0; r <= 18; r += 1) regs[r] = {};
    };

    for (let i = 0; i < words; i += 1) {
      const pc = address + i * 4;
      const w = model.buf.readUInt32LE(offset + i * 4);
      const rd = w & 31;
      const rn = (w >> 5) & 31;

      if (is(w, 0x9f000000, 0x90000000)) {
        // ADRP
        regs[rd] = { addr: Math.floor(pc / 4096) * 4096 + adrpOffset(w) };
      } else if (is(w, 0x9f000000, 0x10000000)) {
        // ADR
        const imm = signExtend(((w >> 5) & 0x7ffff) * 4 + ((w >> 29) & 3), 21);
        regs[rd] = { addr: pc + imm };
        const lit = literalAt(regs[rd].addr);
        if (lit) strings.add(lit);
      } else if (is(w, 0xff000000, 0x91000000)) {
        // ADD (immediate), 64-bit
        const imm = ((w >> 10) & 0xfff) << (((w >> 22) & 1) === 1 ? 12 : 0);
        const base = regs[rn].addr;
        regs[rd] = base !== undefined ? { addr: base + imm } : {};
        if (regs[rd].addr !== undefined) {
          const lit = literalAt(regs[rd].addr);
          if (lit) strings.add(lit);
        }
      } else if (is(w, 0xffc00000, 0xf9400000) || is(w, 0xff000000, 0x58000000)) {
        // LDR xt, [xn, #imm] (64-bit, unsigned offset), or LDR xt, <pc-relative literal>: the linker rewrites
        // an adrp + ldr pair into `nop; ldr xt, #imm` when the target is close enough.
        const rt = rd;
        regs[rt] = {};
        let slot: number | undefined;
        if (is(w, 0xff000000, 0x58000000)) slot = pc + signExtend((w >> 5) & 0x7ffff, 19) * 4;
        else if (regs[rn].addr !== undefined) slot = regs[rn].addr! + ((w >> 10) & 0xfff) * 8;
        if (slot !== undefined) {
          const bound = model.slots.get(slot);
          if (bound?.kind === 'bind') {
            regs[rt] = { sym: bound.symbol };
            if (classrefs && within(classrefs, slot)) {
              regs[rt].cls = bound.symbol.replace(/^_?OBJC_CLASS_\$_/, '');
              classes.add(regs[rt].cls!);
            } else refs.add(bound.symbol.replace(/^_/, ''));
          } else {
            const value = model.pointerAt(slot);
            if (value !== undefined) {
              if (selrefs && within(selrefs, slot)) {
                const sel = model.cstringAt(value);
                if (sel) regs[rt] = { sym: `sel:${sel}` };
              } else if (classrefs && within(classrefs, slot)) {
                const cname = classByAddress.get(value);
                regs[rt] = cname ? { cls: cname } : { addr: value };
                if (cname) classes.add(cname);
              } else {
                regs[rt] = { addr: value };
                const lit = literalAt(value);
                if (lit) strings.add(lit);
              }
            }
          }
        }
      } else if (is(w, 0x7f800000, 0x52800000) || is(w, 0x7f800000, 0x72800000)) {
        // MOVZ / MOVK
        const keep = is(w, 0x7f800000, 0x72800000);
        const imm16 = BigInt((w >> 5) & 0xffff);
        const shift = BigInt(((w >> 21) & 3) * 16);
        let value = keep ? (regs[rd].big ?? BigInt(regs[rd].imm ?? 0)) : 0n;
        if (keep) value &= ~(0xffffn << shift);
        value |= imm16 << shift;
        regs[rd] = { imm: Number(value & 0x7fffffffn), big: value };
      } else if (is(w, 0xffe0ffe0, 0xaa0003e0) || is(w, 0xffe0ffe0, 0x2a0003e0)) {
        // MOV xd, xm
        regs[rd] = { ...regs[(w >> 16) & 31] };
      } else if (is(w, 0xfc000000, 0x94000000) || is(w, 0xfc000000, 0x14000000)) {
        // BL / B
        const isCall = is(w, 0xfc000000, 0x94000000);
        const target = pc + signExtend(w & 0x3ffffff, 26) * 4;
        const outside = target < address || target >= end;
        if (isCall || outside) {
          const stub = model.stubs.get(target);
          const selStub = selectorStubs.get(target);
          if (selStub) calls.push({ kind: 'msg', selector: selStub, receiver: regs[0].cls, args: snapshot() });
          else if (stub && OBJC_MSGSEND.test(stub)) {
            const sel = regs[1].sym?.startsWith('sel:') ? regs[1].sym.slice(4) : undefined;
            if (sel) calls.push({ kind: 'msg', selector: sel, receiver: regs[0].cls, args: snapshot() });
          } else if (stub) calls.push({ kind: 'import', name: stub.replace(/^_/, ''), args: snapshot() });
          else if (startSet.has(target)) calls.push({ kind: 'internal', target });
          clearCallerSaved();
        }
        // An unconditional branch ends the block: what follows is reached some other way, so nothing known carries over.
        if (!isCall) {
          finishBig();
          for (let r = 0; r < 32; r += 1) regs[r] = {};
        }
      } else if (is(w, 0xfffffc1f, 0xd63f0000)) {
        // BLR xn: a call through a pointer; named when it came from a bound slot.
        const sym = regs[rn].sym;
        if (sym && !sym.startsWith('sel:')) calls.push({ kind: 'import', name: sym.replace(/^_/, ''), args: snapshot() });
        clearCallerSaved();
      } else if (w === 0xd65f03c0 || is(w, 0xfffffc1f, 0xd65f0000)) {
        // RET: the next function begins at its own start, so state does not carry.
        finishBig();
        for (let r = 0; r < 32; r += 1) regs[r] = {};
      } else if (!isStoreOrBranch(w) && rd !== 31) {
        // Something we do not model wrote rd: forget it, rather than keep a stale value.
        regs[rd] = {};
        if (isLoadPair(w)) regs[(w >> 10) & 31] = {};
      }
    }
    finishBig();

    const owner = objc.get(address);
    const name = owner
      ? `${owner.classMethod ? '+' : '-'}[${owner.className} ${owner.selector}]`
      : (symbolAt.get(address) ?? `sub_${address.toString(16)}`);
    facts.push({ address, size: end - address, name, objc: owner, calls, strings: [...strings], refs: [...refs], classes: [...classes] });
  }
  return facts;
}
