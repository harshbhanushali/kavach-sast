/**
 * Reproducing each finding yourself, with the tools everyone already has.
 *
 * A scanner asking to be believed is a scanner nobody acts on. The useful
 * output is not "we found a debug certificate" but the command that shows you
 * the debug certificate, run against the same file, so a developer can confirm
 * it in thirty seconds and an auditor can confirm it without this tool at all.
 *
 * Every command here is derived from the finding's own location — the real
 * path, the real line, the real DEX — so it is copy-pasteable rather than
 * illustrative.
 */
import { useState } from 'react';
import type { SastFinding } from '../sastTypes';

/** A shell snippet with a one-line reason and a copy button. */
function Command({ why, cmd }: { why: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="group/cmd">
      <p className="text-xs text-slate-400">{why}</p>
      <div className="mt-1 flex items-start gap-2 rounded-md border border-slate-800 bg-slate-950/70 px-2.5 py-1.5">
        <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[11.5px] leading-relaxed text-emerald-200/90">
          {cmd}
        </code>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard?.writeText(cmd).catch(() => undefined);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
          className="shrink-0 rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400 opacity-0 transition hover:bg-slate-800 hover:text-slate-200 focus:opacity-100 group-hover/cmd:opacity-100"
        >
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
    </div>
  );
}

/**
 * iOS verification, following the OWASP MASTG static-analysis workflow.
 *
 * An IPA is a zip around a signed Mach-O bundle: there is no decompiler step
 * and running one would be nonsense. What MASTG actually asks for is unzip,
 * then `plutil` for the property lists, `codesign` for the entitlements,
 * `security cms` for the provisioning profile, and `otool`/`nm` for the binary.
 * Those are the commands below.
 */
function iosCommands(finding: SastFinding, file: string): { why: string; cmd: string }[] {
  const path = finding.locations[0]?.file ?? '';
  const unzip = {
    why: 'Unpack the IPA. It is a zip; everything below reads the extracted bundle.',
    cmd: `unzip -q -o ${file} -d extracted && APP=$(ls -d extracted/Payload/*.app)`,
  };

  if (/Info\.plist$/i.test(path)) {
    return [
      unzip,
      {
        why: 'Print Info.plist as readable text. The binary plist is unreadable until converted.',
        cmd: 'plutil -p "$APP/Info.plist"',
      },
      {
        why: 'Read the App Transport Security block, which is where the transport findings come from.',
        cmd: 'plutil -extract NSAppTransportSecurity xml1 -o - "$APP/Info.plist"',
      },
    ];
  }

  if (/mobileprovision$/i.test(path)) {
    return [
      unzip,
      {
        why: 'The provisioning profile is CMS-signed; decode it to XML before reading.',
        cmd: 'security cms -D -i "$APP/embedded.mobileprovision" | plutil -p -',
      },
      {
        why: 'Show the entitlements the profile grants, including get-task-allow.',
        cmd: 'security cms -D -i "$APP/embedded.mobileprovision" | plutil -extract Entitlements xml1 -o - -',
      },
    ];
  }

  if (/entitlements$/i.test(path)) {
    return [
      unzip,
      {
        why: 'Read the entitlements actually embedded in the signature, which is what the OS enforces.',
        cmd: 'codesign -d --entitlements :- "$APP" 2>/dev/null | plutil -p -',
      },
    ];
  }

  // Everything else is the app binary: symbols, strings and load commands.
  const commands = [unzip, {
    why: 'Locate the main executable named by CFBundleExecutable.',
    cmd: 'BIN="$APP/$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")"',
  }];

  if (finding.category === 'binary') {
    commands.push(
      {
        why: 'Read the Mach-O header flags. PIE shows here as the PIE flag.',
        cmd: 'otool -hv "$BIN"',
      },
      {
        why: 'Check FairPlay encryption. cryptid 0 means the binary is not encrypted and can be read directly.',
        cmd: 'otool -l "$BIN" | grep -A4 LC_ENCRYPTION_INFO',
      },
      {
        why: 'Stack protector and ARC show up as linked runtime symbols.',
        cmd: 'nm -m "$BIN" | grep -E "stack_chk|objc_release|objc_autorelease" | head',
      },
    );
  } else {
    commands.push(
      {
        why: 'The finding matched a symbol or literal in the binary. This is the same table the scan read.',
        cmd: `nm -m "$BIN" 2>/dev/null | grep -i ${shellWord(finding)} | head`,
      },
      {
        why: 'If it is a literal rather than a symbol, it appears in the string table instead.',
        cmd: `strings -a "$BIN" | grep -i ${shellWord(finding)} | head`,
      },
      {
        why: 'List the frameworks and dylibs the binary links, to see which component it belongs to.',
        cmd: 'otool -L "$BIN"',
      },
    );
  }
  return commands;
}

/**
 * A grep term for a finding, taken from what it actually matched.
 *
 * Built from the excerpt rather than the title so the command finds the same
 * thing the scan did — "NSUserDefaults used for storage" greps for nothing.
 */
function shellWord(finding: SastFinding): string {
  const excerpt = finding.locations[0]?.excerpt ?? '';
  const token = excerpt.match(/[A-Za-z_][A-Za-z0-9_]{5,40}/)?.[0] ?? finding.ruleId.split('.').pop() ?? '';
  return `'${token.replace(/'/g, "")}'`;
}

/** The command that shows a given finding, chosen from where it was found. */
/** The command that shows a given finding, chosen from where it was found. */
export function commandsFor(
  finding: SastFinding,
  file: string,
  platform: 'android' | 'ios',
): { why: string; cmd: string }[] {
  if (platform === 'ios') return iosCommands(finding, file);

  const location = finding.locations[0];
  const path = location?.file ?? '';
  const line = location?.line;

  // Signing findings are read straight off the APK; no decode needed.
  if (finding.category === 'signing' || path.startsWith('META-INF')) {
    return [
      {
        why: 'Print the signing certificates and the schemes the APK carries.',
        cmd: `apksigner verify --print-certs -v ${file}`,
      },
      {
        why: 'The Android debug certificate has this exact subject on every machine with the SDK.',
        cmd: `apksigner verify --print-certs ${file} | grep -i "CN=Android Debug"`,
      },
    ];
  }

  // Manifest and resources: decode with apktool and read the file.
  if (path === 'AndroidManifest.xml' || path.startsWith('res/') || path.startsWith('assets/')) {
    return [
      {
        why: 'Decode the artifact. This writes the manifest and resources as readable XML.',
        cmd: `apktool d -f -o decoded ${file}`,
      },
      {
        why: line
          ? `Read the flagged line in context (line ${line}).`
          : 'Read the flagged file.',
        cmd: line
          ? `sed -n '${Math.max(1, line - 3)},${line + 3}p' decoded/${path}`
          : `cat decoded/${path}`,
      },
    ];
  }

  // Dependencies: the version file the coordinate was read from.
  if (finding.category === 'dependencies') {
    return [
      {
        why: 'List the version files the build wrote into the artifact — this is where the version came from.',
        cmd: `unzip -l ${file} | grep -E "META-INF/.*\\\\.version|pom.properties"`,
      },
      {
        why: 'Read the exact version string for this dependency.',
        cmd: `unzip -p ${file} '${path}'`,
      },
    ];
  }

  // Native code.
  if (path.endsWith('.so')) {
    return [
      {
        why: 'Extract the native library from the artifact.',
        cmd: `unzip -o ${file} '${path}' -d extracted`,
      },
      {
        why: 'Read its hardening flags — this is what the finding was derived from.',
        cmd: `readelf -lWd extracted/${path} | grep -E "GNU_RELRO|BIND_NOW|GNU_STACK"`,
      },
    ];
  }

  // Decompiled code: jadx for readable Java, and the DEX it came from.
  const commands = [
    {
      why: 'Decompile to readable Java. This is the same tool and the same output the scan read.',
      cmd: `jadx --no-res --no-debug-info -d jadx-out ${file}`,
    },
  ];
  if (path.startsWith('sources/') && line) {
    commands.push({
      why: `Read the flagged line in context (line ${line}).`,
      cmd: `sed -n '${Math.max(1, line - 4)},${line + 4}p' jadx-out/${path}`,
    });
  } else if (path) {
    commands.push({ why: 'Read the flagged file.', cmd: `cat jadx-out/${path}` });
  }
  if (location?.className) {
    const cls = location.className.replace(/^L|;$/g, '').replace(/\//g, '.');
    commands.push({
      why: `Confirm the class is really in the shipped ${location.dex ?? 'dex'}, not just in the decompiler's output.`,
      cmd: `unzip -o ${file} '${location.dex ?? 'classes*.dex'}' -d dex && dexdump -f dex/${location.dex ?? 'classes.dex'} | grep -F '${cls}'`,
    });
  }
  return commands;
}

export function HowToVerify({
  findings,
  fileName,
  sha256,
  platform,
}: {
  findings: SastFinding[];
  fileName: string;
  sha256: string;
  platform: 'android' | 'ios';
}) {
  const [open, setOpen] = useState<Set<string>>(new Set());

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <p className="text-sm font-medium text-slate-100">Start from the same file</p>
        <p className="mt-1 max-w-[80ch] text-xs leading-relaxed text-slate-400">
          Every command below assumes the artifact this report describes. Check the digest first —
          if it does not match, you are looking at a different build and the line numbers will not
          line up.
        </p>
        <div className="mt-3 space-y-3">
          <Command why="Confirm you have the same artifact." cmd={`shasum -a 256 ${fileName}`} />
          <div className="rounded-md border border-slate-800 bg-slate-950/70 px-2.5 py-1.5">
            <p className="text-[10px] uppercase tracking-wide text-slate-500">expected</p>
            <code className="break-all font-mono text-[11.5px] text-slate-300">{sha256}</code>
          </div>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          {platform === 'ios' ? (
            <>
              Tools used below: <code className="text-slate-400">unzip</code>,{' '}
              <code className="text-slate-400">plutil</code>, <code className="text-slate-400">codesign</code>,{' '}
              <code className="text-slate-400">security</code>, <code className="text-slate-400">otool</code>,{' '}
              <code className="text-slate-400">nm</code>, <code className="text-slate-400">strings</code> \u2014
              the OWASP MASTG static-analysis toolchain, all shipped with Xcode command line tools.
            </>
          ) : (
            <>
              Tools used below: <code className="text-slate-400">apktool</code>,{' '}
              <code className="text-slate-400">jadx</code>, <code className="text-slate-400">apksigner</code>,{' '}
              <code className="text-slate-400">dexdump</code>, <code className="text-slate-400">unzip</code>,{' '}
              <code className="text-slate-400">readelf</code>. All are standard; none is specific to this
              console.
            </>
          )}
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40">
        <div className="border-b border-slate-800 px-4 py-3">
          <p className="text-sm font-medium text-slate-100">Reproduce each finding</p>
          <p className="mt-0.5 text-xs text-slate-400">
            Commands are built from each finding&rsquo;s own path, line and DEX, so they run as written.
          </p>
        </div>
        <ul className="divide-y divide-slate-800">
          {findings.map((f) => {
            const isOpen = open.has(f.ruleId);
            return (
              <li key={f.ruleId}>
                <button
                  type="button"
                  onClick={() =>
                    setOpen((prev) => {
                      const next = new Set(prev);
                      if (next.has(f.ruleId)) next.delete(f.ruleId);
                      else next.add(f.ruleId);
                      return next;
                    })
                  }
                  className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-slate-800/40"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-slate-100">{f.title}</span>
                    <span className="block truncate font-mono text-[11px] text-slate-500">
                      {f.locations[0]?.file ?? f.title}
                      {f.locations[0]?.line ? `:${f.locations[0].line}` : ''}
                    </span>
                  </span>
                  <span className="shrink-0 text-xs text-slate-500">{isOpen ? 'Hide' : 'Verify'}</span>
                </button>
                {isOpen && (
                  <div className="space-y-3 px-4 pb-4">
                    {commandsFor(f, fileName, platform).map((c, i) => (
                      <Command key={i} why={c.why} cmd={c.cmd} />
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
