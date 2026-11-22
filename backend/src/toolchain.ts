/**
 * Locates the external tools the scanner shells out to.
 *
 * Adapted from the toolchain module of the author's earlier Kavach project (a runtime-protection platform), trimmed
 * to what SAST actually uses: `apktool` (decoding resources and the manifest),
 * `apksigner` (reading the signing scheme and certificate), `jadx` (decompiling
 * to readable Java, optional), and a JDK (`javaHome`/`keytool`, which the first
 * two need on their environment to run at all). The injector's own tools — d8,
 * zipalign, dexdump — never belonged to this product and are not here.
 *
 * Resolved once at startup and reported through /healthz and
 * /v1/sast/capability, so a deployment missing a tool says so on its status
 * page rather than failing halfway through someone's first upload.
 *
 * Resolution order is PATH first, then the conventional install locations for
 * the platform. PATH first matters: it is the one mechanism that works the same
 * on an Apple Silicon Mac, an Intel Mac and a Linux box, and it is what someone
 * who installed a tool by hand expects to be honoured. The hardcoded fallbacks
 * exist only because a GUI-launched process on macOS often inherits a PATH that
 * omits Homebrew entirely.
 */
import { accessSync, constants, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

export type Toolchain = {
  ok: boolean;
  javaHome?: string;
  apktool?: string;
  apksigner?: string;
  keytool?: string;
  /** Optional: produces readable Java instead of smali for the scanner. */
  jadx?: string;
  missing: string[];
};

function isExecutableFile(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** `which`, without spawning a shell. */
function onPath(name: string, env: NodeJS.ProcessEnv): string | undefined {
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    if (isExecutableFile(candidate)) return candidate;
  }
  return undefined;
}

function firstExisting(candidates: string[]): string | undefined {
  return candidates.find((candidate) => candidate && existsSync(candidate));
}

/** An explicit override, then PATH, then the conventional locations. */
function locate(
  name: string,
  env: NodeJS.ProcessEnv,
  override: string | undefined,
  fallbacks: string[],
): string | undefined {
  if (override && existsSync(override)) return override;
  return onPath(name, env) ?? firstExisting(fallbacks);
}

/**
 * A JDK home, preferring one that actually ships `keytool`.
 *
 * Deriving it from a `keytool` on PATH covers every JDK layout there is without
 * enumerating them — except on macOS, where /usr/bin/keytool is a stub that
 * shims out to the selected JDK and tells us nothing about where that is.
 */
export function resolveJavaHome(env: NodeJS.ProcessEnv): string | undefined {
  if (env.JAVA_HOME && existsSync(env.JAVA_HOME)) return env.JAVA_HOME;

  const keytool = onPath('keytool', env);
  if (keytool && !keytool.startsWith('/usr/bin/')) {
    return dirname(dirname(keytool));
  }

  return firstExisting([
    '/opt/homebrew/opt/openjdk@21', // Homebrew, Apple Silicon
    '/usr/local/opt/openjdk@21', // Homebrew, Intel
    '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home',
    '/usr/lib/jvm/java-21-openjdk-amd64', // Debian/Ubuntu
    '/usr/lib/jvm/java-21-openjdk', // Fedora/Arch
  ]);
}

export function resolveToolchain(env: NodeJS.ProcessEnv = process.env): Toolchain {
  const javaHome = resolveJavaHome(env);

  const tools = {
    apktool: locate('apktool', env, env.KAVACH_APKTOOL, [
      '/opt/homebrew/bin/apktool',
      '/usr/local/bin/apktool',
    ]),
    apksigner: locate('apksigner', env, undefined, []),
    keytool: locate('keytool', env, javaHome ? join(javaHome, 'bin', 'keytool') : undefined, []),
  };

  // jadx is optional and reported separately: the scanner works without it, it
  // just falls back to smali. Listing it in `missing` would make /healthz say
  // the deployment is broken when it is merely less readable.
  const jadx = locate('jadx', env, env.KAVACH_JADX, [
    '/opt/homebrew/bin/jadx',
    '/usr/local/bin/jadx',
    '/usr/bin/jadx',
  ]);

  const missing = Object.entries(tools)
    .filter(([, path]) => !path)
    .map(([name]) => name);

  return { ok: missing.length === 0, javaHome, ...tools, jadx, missing };
}
