/**
 * Findings for the native libraries an APK ships.
 *
 * Aggregated per protection rather than per library: an app with 40 `.so` files
 * missing stack canaries should produce one finding listing them, not 40
 * findings that bury everything else in the report.
 *
 * Third-party libraries are included and attributed, for the reason stated in
 * `rules.ts`: a library compiled without NX is still shipped in your APK and
 * still exploitable there, but the reader should be able to see it came from a
 * dependency rather than their own build flags.
 */
import { execFileSync } from 'node:child_process';
import { readElf } from './elf.ts';
import type { ElfFacts } from './elf.ts';
import type { SastFinding, SastLocation, SastSeverity } from './types.ts';

/** Libraries whose hardening the app's own build flags do not control. */
// libapp.so is a Flutter app's Dart snapshot, produced by the Dart compiler: the app team has no flag for it.
const VENDOR = /\/(libflutter|libapp|libunity|libmonobdwgc|libil2cpp|libhermes|libjsc|libreactnative|libfb|libmain|libRSSupport|librsjni)\.so$/;

export type NativeLibReport = {
  findings: SastFinding[];
  /** One row per library, for the report's inventory table. */
  inventory: { name: string; /** The entry inside the APK, e.g. lib/arm64-v8a/libfoo.so. */ path: string; facts: ElfFacts }[];
};

type Rule = {
  ruleId: string;
  title: (n: number) => string;
  severity: SastSeverity;
  description: string;
  impact: string;
  remediation: string;
  masvs?: string;
  cwe?: string;
  /** True when the library FAILS this protection. */
  fails: (f: ElfFacts) => boolean;
};

const RULES: Rule[] = [
  {
    ruleId: 'native.no_nx',
    title: (n) => `${n} native librar${n === 1 ? 'y has' : 'ies have'} an executable stack`,
    severity: 'medium',
    description: 'PT_GNU_STACK is marked executable, so the NX protection is off for these objects.',
    impact: 'Data written to the stack can be executed, which removes the main barrier to turning a memory-corruption bug into code execution.',
    remediation: 'Link with -Wl,-z,noexecstack. An executable stack is almost always inherited from hand-written assembly with a missing .note.GNU-stack section.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-119',
    fails: (f) => !f.nx,
  },
  {
    ruleId: 'native.no_pie',
    title: (n) => `${n} native librar${n === 1 ? 'y is' : 'ies are'} not position-independent`,
    severity: 'medium',
    description: 'The object is a fixed-address ELF rather than ET_DYN.',
    impact: 'It loads at a predictable address, so ASLR does not apply and exploitation becomes reliable rather than probabilistic.',
    remediation: 'Compile with -fPIC and link with -pie. The NDK does this by default; an explicit override usually removed it.',
    masvs: 'MASVS-RESILIENCE-1',
    cwe: 'CWE-121',
    fails: (f) => !f.pie,
  },
  {
    ruleId: 'native.no_stack_canary',
    title: (n) => `${n} native librar${n === 1 ? 'y has' : 'ies have'} no stack protector`,
    severity: 'medium',
    description: 'No reference to __stack_chk_fail or __stack_chk_guard is present.',
    impact: 'Stack buffer overflows are not detected on return, so a corrupted return address is simply used.',
    remediation: 'Compile with -fstack-protector-strong. Note this does not apply to pure Dart/Flutter or Rust objects, which do not use the C stack protector.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-121',
    fails: (f) => !f.stackCanary,
  },
  {
    ruleId: 'native.no_relro',
    title: (n) => `${n} native librar${n === 1 ? 'y has' : 'ies have'} no RELRO`,
    severity: 'medium',
    description: 'Neither a PT_GNU_RELRO segment nor immediate binding is present.',
    impact: 'The GOT stays writable at runtime, so an arbitrary-write primitive can redirect any library call to attacker-chosen code.',
    remediation: 'Link with -Wl,-z,relro,-z,now for full RELRO.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-119',
    fails: (f) => f.relro === 'none',
  },
  {
    ruleId: 'native.partial_relro',
    title: (n) => `${n} native librar${n === 1 ? 'y has' : 'ies have'} only partial RELRO`,
    severity: 'low',
    description: 'A RELRO segment exists but the object does not bind symbols immediately.',
    impact: 'Part of the GOT remains writable after startup, leaving a smaller version of the full-RELRO weakness.',
    remediation: 'Add -Wl,-z,now so the dynamic linker resolves everything before marking the GOT read-only.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-119',
    fails: (f) => f.relro === 'partial',
  },
  {
    ruleId: 'native.runpath',
    title: (n) => `${n} native librar${n === 1 ? 'y sets' : 'ies set'} RPATH or RUNPATH`,
    severity: 'medium',
    description: 'The object carries a hardcoded library search path.',
    impact: 'If any directory on that path is writable, an attacker can place a library there and have it loaded into the app process.',
    remediation: 'Remove -rpath/-runpath from the link flags. Android resolves dependencies from the APK lib directory without them.',
    masvs: 'MASVS-CODE-4',
    cwe: 'CWE-426',
    fails: (f) => f.rpath || f.runpath,
  },
  {
    ruleId: 'native.symbols_not_stripped',
    title: (n) => `${n} native librar${n === 1 ? 'y retains' : 'ies retain'} debug symbols`,
    severity: 'low',
    description: 'A .symtab section is present, so local and debug symbols shipped with the build.',
    impact: 'Function names and layout make the library substantially easier to reverse engineer and to hook precisely.',
    remediation: 'Strip release objects (llvm-strip, or the NDK\'s automatic stripping for externalNativeBuild).',
    masvs: 'MASVS-RESILIENCE-3',
    fails: (f) => !f.symbolsStripped,
  },
];

export function analyseNativeLibraries(
  apkPath: string,
  entries: string[],
  /** Called with each library as it is read, so a caller can render a view without extracting it again. */
  onLibrary?: (entry: string, buf: Buffer) => void,
): NativeLibReport {
  const soEntries = entries.filter((e) => /^lib\/[^/]+\/.+\.so$/.test(e));
  const inventory: NativeLibReport['inventory'] = [];

  // One architecture is enough: the same source is compiled with the same flags
  // for every ABI, so scanning all of them multiplies the work and reports each
  // library several times. arm64 is what ships to essentially every device.
  const preferred = soEntries.filter((e) => e.startsWith('lib/arm64-v8a/'));
  const abi = preferred.length > 0 ? preferred : soEntries;
  const seen = new Set<string>();

  for (const entry of abi) {
    const name = entry.split('/').pop()!;
    if (seen.has(name)) continue;
    seen.add(name);
    try {
      const buf = execFileSync('/usr/bin/unzip', ['-p', apkPath, entry], {
        maxBuffer: 256 * 1024 * 1024,
        timeout: 60_000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const facts = readElf(buf);
      if (facts.parsed) {
        inventory.push({ name, path: entry, facts });
        onLibrary?.(entry, buf);
      }
    } catch {
      // An entry that cannot be extracted is left out of the inventory rather
      // than counted as passing.
    }
  }

  const findings: SastFinding[] = [];
  for (const rule of RULES) {
    const failing = inventory.filter((lib) => rule.fails(lib.facts));
    if (failing.length === 0) continue;

    // When every failing library is a third-party runtime the app cannot
    // rebuild, the finding is still reported but not pinned on the developer.
    const ownCode = failing.filter((lib) => !VENDOR.test(`/${lib.name}`));
    const vendorOnly = ownCode.length === 0;

    const locations: SastLocation[] = failing.slice(0, 12).map((lib) => ({
      file: lib.path,
      excerpt: VENDOR.test(`/${lib.name}`) ? 'bundled runtime' : undefined,
    }));

    findings.push({
      ruleId: rule.ruleId,
      title: vendorOnly ? `${rule.title(failing.length)} (bundled runtimes)` : rule.title(failing.length),
      category: 'binary',
      severity: vendorOnly ? downgrade(rule.severity) : rule.severity,
      description: rule.description,
      impact: vendorOnly
        ? `${rule.impact} Every affected object here is a bundled runtime you do not compile, so the fix belongs to that dependency rather than to your build flags.`
        : rule.impact,
      remediation: vendorOnly
        ? 'Track the upstream dependency for a hardened release. Your own native code is not affected.'
        : rule.remediation,
      masvs: rule.masvs,
      cwe: rule.cwe,
      locations,
      occurrences: failing.length,
    });
  }

  return { findings, inventory };
}

/** Vendor-only findings drop one step; they are context, not a defect to fix. */
function downgrade(severity: SastSeverity): SastSeverity {
  return severity === 'high' ? 'medium' : severity === 'medium' ? 'low' : 'info';
}
