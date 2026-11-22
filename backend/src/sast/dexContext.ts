/**
 * Relates a decompiled smali file back to the DEX it came from.
 *
 * A finding used to report two unrelated locations for one problem:
 *
 *     smali_classes2/owasp/sat/agoat/CloudServicesActivity.smali:73
 *     classes2.dex
 *
 * The first is where a human reads it; the second is where it actually lives in
 * the shipped artifact. They are the same thing seen from two sides, and not
 * saying so left the reader to guess — or worse, to count one issue as two.
 *
 * apktool's output convention makes the mapping exact:
 *
 *     classes.dex   -> smali/
 *     classes2.dex  -> smali_classes2/
 *     classesN.dex  -> smali_classesN/
 *
 * so a smali path determines its DEX with no guessing. The class descriptor and
 * the enclosing method come from the file itself, which turns a line number into
 * something a reviewer can find in a decompiler, a stack trace, or `dexdump`
 * output — none of which speak in smali file paths.
 */

export type DexContext = {
  /** The DEX in the APK this source was decompiled from. */
  dex?: string;
  /** JVM descriptor, e.g. `Lowasp/sat/agoat/CloudServicesActivity;`. */
  className?: string;
  /** Enclosing method as smali declares it, e.g. `onCreate(Landroid/os/Bundle;)V`. */
  method?: string;
};

/**
 * `smali_classes2/a/b/C.smali` -> `classes2.dex`.
 *
 * Returns undefined for anything outside a smali tree — resources, assets and
 * the manifest have no DEX, and claiming one would be worse than saying nothing.
 */
export function dexForSmaliPath(relative: string): string | undefined {
  const match = relative.match(/^smali(?:_classes(\d+))?\//);
  if (!match) return undefined;
  const index = match[1];
  return index ? `classes${index}.dex` : 'classes.dex';
}

/**
 * jadx merges every DEX into one Java source tree, so a path under `sources/`
 * cannot say which `classesN.dex` a class came from.
 *
 * Rather than guess, the DEX is left unset and the class descriptor carries the
 * identification — which is the part a reader actually uses. Inventing
 * `classes.dex` for everything would be worse than saying nothing.
 */
export function isJavaSourcePath(relative: string): boolean {
  return /^sources\/.+\.java$/.test(relative);
}

/**
 * `/* JADX INFO: loaded from: classes2.dex *\/` -> `classes2.dex`.
 *
 * jadx writes this near the top of a class it recovered from a secondary DEX.
 * Reading it back keeps the compiled reference intact even though the Java
 * tree itself is flat.
 */
export function dexFromJadxHeader(lines: string[]): string | undefined {
  // jadx puts this after the package line and any suppression comments, which
  // on a Kotlin class can run well past a dozen lines.
  for (const line of lines.slice(0, 40)) {
    const match = line.match(/JADX INFO: loaded from:\s*(classes\d*\.dex)/);
    if (match) return match[1];
  }
  return undefined;
}

/** `sources/owasp/sat/agoat/Foo.java` -> `Lowasp/sat/agoat/Foo;`. */
export function classForJavaPath(relative: string): string | undefined {
  const match = relative.match(/^sources\/(.+)\.java$/);
  return match ? `L${match[1]};` : undefined;
}

/**
 * The Java method enclosing a line.
 *
 * Braces are counted from the top of the file so a nested class or an anonymous
 * inner class does not report its outer method. Deliberately simple: a full
 * parse would be the right answer for a compiler and overkill for a label.
 */
export function javaMethodAt(lines: string[], index: number): string | undefined {
  const SIGNATURE =
    /^\s*(?:@\w+\s+)*(?:public|private|protected|static|final|synchronized|abstract|native|\s)*[\w<>\[\],.$ ]+\s+([\w$]+)\s*\(([^)]*)\)\s*(?:throws [\w., ]+)?\s*\{/;

  for (let i = Math.min(index, lines.length - 1); i >= 0; i -= 1) {
    const match = lines[i].match(SIGNATURE);
    if (!match) continue;
    // `if (...) {` and `for (...) {` also end in a brace; exclude the keywords.
    if (/\b(if|for|while|switch|catch|synchronized|try|else)\s*\(/.test(lines[i])) continue;
    const args = match[2].trim();
    return `${match[1]}(${args ? args.split(',').length + ' arg' + (args.split(',').length === 1 ? '' : 's') : ''})`;
  }
  return undefined;
}

/** The `.class` descriptor a smali file declares. */
export function classOf(lines: string[]): string | undefined {
  for (const line of lines) {
    // `.class public final Lcom/example/Foo;` — the descriptor is the last token.
    const match = line.match(/^\.class\b.*?(L[\w$/]+;)\s*$/);
    if (match) return match[1];
    // Stop early: `.class` is always the first directive in a smali file.
    if (line.startsWith('.method')) break;
  }
  return undefined;
}

/**
 * The method a given line sits inside.
 *
 * Scans backwards to the nearest `.method`, stopping if a `.end method` is met
 * first — which means the line is between methods (a field declaration or an
 * annotation) and belongs to no method at all.
 */
export function methodAt(lines: string[], index: number): string | undefined {
  for (let i = Math.min(index, lines.length - 1); i >= 0; i -= 1) {
    const line = lines[i].trim();
    if (line.startsWith('.end method')) return undefined;
    if (line.startsWith('.method ')) {
      // `.method public onCreate(Landroid/os/Bundle;)V` -> the signature.
      const match = line.match(/\.method\s+(?:[\w-]+\s+)*([\w$<>]+\([^)]*\).+)$/);
      return match ? match[1] : undefined;
    }
  }
  return undefined;
}

/** Everything that relates one smali line back to the compiled artifact. */
export function dexContextFor(relative: string, lines: string[], index: number): DexContext {
  if (isJavaSourcePath(relative)) {
    return {
      // jadx merges every DEX into one tree but records the origin in a header
      // comment, so the compiled container is recoverable after all.
      dex: dexFromJadxHeader(lines),
      className: classForJavaPath(relative),
      method: javaMethodAt(lines, index),
    };
  }
  const dex = dexForSmaliPath(relative);
  if (!dex) return {};
  return { dex, className: classOf(lines), method: methodAt(lines, index) };
}

/**
 * A single human-readable reference: DEX, class and method.
 *
 * `classes2.dex › Lowasp/sat/agoat/CloudServicesActivity;->onCreate(Landroid/os/Bundle;)V`
 */
export function describeDexContext(context: DexContext): string | undefined {
  if (!context.dex) return undefined;
  const target = context.className
    ? `${context.className}${context.method ? `->${context.method}` : ''}`
    : undefined;
  return target ? `${context.dex} › ${target}` : context.dex;
}
