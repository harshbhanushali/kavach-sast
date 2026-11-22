/**
 * The other Mach-O images in an IPA: frameworks, dylibs, app extensions.
 *
 * A modern iOS app is mostly its dependencies, and the main executable's
 * hardening says nothing about them. Each embedded image is read with the same
 * Mach-O reader as the main binary, so the report can name the weakest one
 * instead of implying the whole bundle is as hardened as its executable.
 */
import { closeSync, existsSync, openSync, readFileSync, readSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { readMachO } from './macho.ts';
import { dictGet, parsePlist } from './plist.ts';
import type { PlistValue } from './plist.ts';
import type { WalkedFile } from './scanner.ts';
import type { IosFacts } from './types.ts';

type EmbeddedBinary = IosFacts['binaries'][number];

/** Ceilings so a pathological IPA cannot stall the scan. */
const MAX_BINARIES = 200;
const MAX_BINARY_BYTES = 200 * 1024 * 1024;

const MACHO_MAGICS = new Set([
  0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, // thin, both byte orders
  0xcafebabe, 0xbebafeca, // fat
]);

function isMachO(path: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const head = Buffer.alloc(4);
    if (readSync(fd, head, 0, 4, 0) < 4) return false;
    return MACHO_MAGICS.has(head.readUInt32BE(0)) || MACHO_MAGICS.has(head.readUInt32LE(0));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function plistAt(path: string): PlistValue {
  try {
    return existsSync(path) ? parsePlist(readFileSync(path)) : null;
  } catch {
    return null;
  }
}

const asString = (v: PlistValue): string | undefined => (typeof v === 'string' && v ? v : undefined);

/** Which embedded images to read, and what kind each is. */
function classify(relative: string): { kind: EmbeddedBinary['kind']; container: string } | undefined {
  // Frameworks/Foo.framework/Foo — the image sits directly in the bundle.
  const framework = relative.match(/^(.*?\.framework)\/([^/]+)$/);
  if (framework && !framework[2].includes('.')) return { kind: 'framework', container: framework[1] };

  if (relative.endsWith('.dylib')) return { kind: 'dylib', container: dirname(relative) };

  const extension = relative.match(/^(.*?\.appex)\/([^/]+)$/);
  if (extension && !extension[2].includes('.')) return { kind: 'extension', container: extension[1] };

  // Watch/Companion.app/Companion
  const watch = relative.match(/^(.*\/Watch\/[^/]+\.app)\/([^/]+)$/);
  if (watch && !watch[2].includes('.')) return { kind: 'watch', container: watch[1] };

  return undefined;
}

/**
 * `files` are Payload-relative, so every path starts with `Foo.app/`. `appRoot`
 * is the absolute path to that `Foo.app`, and `appName` is its directory name.
 */
export function inventoryBinaries(
  appRoot: string,
  appName: string,
  files: WalkedFile[],
): { binaries: EmbeddedBinary[]; extensions: IosFacts['extensions']; truncated: boolean } {
  const binaries: EmbeddedBinary[] = [];
  const extensions: IosFacts['extensions'] = [];
  const seenContainers = new Set<string>();
  let truncated = false;

  for (const file of files) {
    if (!file.relative.startsWith(`${appName}/`)) continue;
    const inApp = file.relative.slice(appName.length + 1);
    // The main executable is analysed separately, with string rules and all.
    if (!inApp.includes('/')) continue;

    const cls = classify(inApp);
    if (!cls) continue;
    if (file.size > MAX_BINARY_BYTES || file.size < 32) continue;
    if (binaries.length >= MAX_BINARIES) {
      truncated = true;
      break;
    }
    if (!isMachO(file.absolute)) continue;

    let facts;
    try {
      facts = readMachO(readFileSync(file.absolute));
    } catch {
      continue;
    }
    if (!facts.parsed) continue;

    const infoPath = join(appRoot, cls.container, 'Info.plist');
    const info = plistAt(infoPath);
    const name = cls.kind === 'dylib'
      ? (inApp.split('/').pop() ?? inApp)
      : (cls.container.split('/').pop() ?? cls.container).replace(/\.(framework|appex|app)$/, '');

    binaries.push({
      name,
      kind: cls.kind,
      path: inApp,
      version: asString(dictGet(info, 'CFBundleShortVersionString')) ?? asString(dictGet(info, 'CFBundleVersion')),
      bundleId: asString(dictGet(info, 'CFBundleIdentifier')),
      sizeBytes: file.size,
      swift: facts.swift,
      objc: facts.objc,
      arc: facts.arc,
      stackCanary: facts.stackCanary,
      // Stripped once local symbols are gone. A handful survive in a stripped
      // image, so the threshold is not zero.
      stripped: facts.localSymbols < 50,
      signed: facts.signature.present,
    });

    if (cls.kind === 'extension' && !seenContainers.has(cls.container)) {
      seenContainers.add(cls.container);
      extensions.push({
        name,
        bundleId: asString(dictGet(info, 'CFBundleIdentifier')),
        point: asString(dictGet(dictGet(info, 'NSExtension'), 'NSExtensionPointIdentifier')),
      });
    }
  }

  return { binaries, extensions, truncated };
}
