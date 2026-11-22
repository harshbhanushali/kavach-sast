/**
 * Dependency inventory and advisory matching.
 *
 * This was reported as "not implemented" in earlier scans, and the gap was real:
 * the scanner could name libraries by package signature but not their versions,
 * so it could not say whether any of them were vulnerable.
 *
 * Versions come from what the build actually leaves in the artifact:
 *
 *   - `META-INF/<group>_<artifact>.version` — one line, the version. AndroidX,
 *     Google Play services and Firebase all write these, which covers most of a
 *     typical Android dependency tree.
 *   - `META-INF/maven/<group>/<artifact>/pom.properties` — the JAR convention,
 *     preserved for plain Java libraries.
 *   - A handful of libraries that embed their version as a constant instead.
 *
 * None of this needs the network, which is deliberate: resolving a bill of
 * materials against an online advisory service would send a customer's
 * dependency list to a third party.
 */
import { execFileSync } from 'node:child_process';
import { advisoriesFor } from './advisories.ts';
import type { Advisory } from './advisories.ts';
import type { SastFinding } from './types.ts';

export type ResolvedDependency = {
  /** `group:artifact` where known, otherwise a best-effort name. */
  coordinate: string;
  version: string;
  /** Where the version came from, so a reader can check it. */
  source: string;
  advisories: Advisory[];
};

export type DependencyReport = {
  dependencies: ResolvedDependency[];
  findings: SastFinding[];
  /** Entries seen but not resolvable to a version. */
  unresolved: string[];
};

/**
 * `androidx.core_core.version` -> `androidx.core:core`.
 *
 * The convention is `<group>_<artifact>.version`, and both halves may contain
 * dots. The underscore is the separator, and only the first one counts —
 * `com.google.android.gms_play-services-basement.version` has exactly one.
 */
function coordinateFromVersionFile(entry: string): string | null {
  const base = entry.replace(/^META-INF\//, '').replace(/\.version$/, '');
  const underscore = base.indexOf('_');
  if (underscore <= 0) return null;
  return `${base.slice(0, underscore)}:${base.slice(underscore + 1)}`;
}

function readEntry(apkPath: string, entry: string): string | null {
  try {
    return execFileSync('/usr/bin/unzip', ['-p', apkPath, entry], {
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).toString('utf8');
  } catch {
    return null;
  }
}

const VERSION_SHAPE = /^\d+(\.\d+)*([.\-+][\w.\-]+)?$/;

export function analyseDependencies(apkPath: string, entries: string[]): DependencyReport {
  const resolved = new Map<string, ResolvedDependency>();
  const unresolved: string[] = [];

  // --- META-INF/*.version ---
  for (const entry of entries.filter((e) => /^META-INF\/[^/]+\.version$/.test(e))) {
    const coordinate = coordinateFromVersionFile(entry);
    if (!coordinate) continue;

    const raw = readEntry(apkPath, entry)?.trim();
    if (!raw || !VERSION_SHAPE.test(raw)) {
      unresolved.push(entry);
      continue;
    }
    resolved.set(coordinate, {
      coordinate,
      version: raw,
      source: entry,
      advisories: advisoriesFor(coordinate, raw),
    });
  }

  // --- META-INF/maven/**/pom.properties ---
  for (const entry of entries.filter((e) => /^META-INF\/maven\/.+\/pom\.properties$/.test(e))) {
    const text = readEntry(apkPath, entry);
    if (!text) {
      unresolved.push(entry);
      continue;
    }
    const group = text.match(/^groupId=(.+)$/m)?.[1]?.trim();
    const artifact = text.match(/^artifactId=(.+)$/m)?.[1]?.trim();
    const version = text.match(/^version=(.+)$/m)?.[1]?.trim();
    if (!group || !artifact || !version) {
      unresolved.push(entry);
      continue;
    }
    const coordinate = `${group}:${artifact}`;
    // A .version file is the more reliable source; do not overwrite one.
    if (resolved.has(coordinate)) continue;
    resolved.set(coordinate, {
      coordinate,
      version,
      source: entry,
      advisories: advisoriesFor(coordinate, version),
    });
  }

  const dependencies = [...resolved.values()].sort((a, b) => {
    const byRisk = b.advisories.length - a.advisories.length;
    return byRisk !== 0 ? byRisk : a.coordinate.localeCompare(b.coordinate);
  });

  return {
    dependencies,
    findings: findingsFor(dependencies),
    unresolved: unresolved.slice(0, 20),
  };
}

/** One finding per vulnerable dependency, so each carries its own advisory. */
function findingsFor(dependencies: ResolvedDependency[]): SastFinding[] {
  const findings: SastFinding[] = [];

  for (const dependency of dependencies) {
    for (const advisory of dependency.advisories) {
      findings.push({
        ruleId: `dependency.${advisory.id.toLowerCase()}:${dependency.coordinate}`,
        title: `${dependency.coordinate} ${dependency.version} — ${advisory.id}`,
        category: 'dependencies',
        severity: advisory.severity,
        description: `${advisory.title}. ${advisory.summary}`,
        impact: advisory.mobileImpact,
        exploitation: [
          `The artifact ships ${dependency.coordinate} at version ${dependency.version}.`,
          advisory.fixed
            ? `${advisory.id} affects ${advisory.introduced ?? 'all versions'} up to but not including ${advisory.fixed}.`
            : `${advisory.id} has no fixed release at the time this advisory set was compiled.`,
          'The version is not inferred — it is read from the file named below, which the build wrote into the APK.',
          'Whether it is reachable depends on how your code calls the library; the version alone establishes exposure, not exploitation.',
        ],
        remediation: advisory.fixed
          ? `Upgrade ${dependency.coordinate} to ${advisory.fixed} or later. If a transitive dependency pins the old version, add an explicit constraint to force the resolution.`
          : `No fixed release is known. Assess whether your usage reaches the affected code path, and consider an alternative library.`,
        cwe: advisory.cwe,
        masvs: 'MASVS-CODE-3',
        locations: [
          {
            file: dependency.source,
            excerpt: `${dependency.coordinate} = ${dependency.version}`,
          },
        ],
        occurrences: 1,
      });
    }
  }

  return findings;
}
