/**
 * The security-controls catalogue.
 *
 * Every protection an app can implement on the client, what it is for, and the
 * ways it is commonly defeated. The point is calibration, not reassurance: a
 * pinning, root-detection or biometric check is worth having, and it is also
 * code running on a device the attacker owns, so each one has a known bypass.
 * Putting the two side by side lets a team see which controls buy real time,
 * which only look like they do, and what would make each harder to remove.
 *
 * The bypass entries stay at the level of technique and tool family, the way
 * OWASP's mobile testing guide and any penetration-test report describe them.
 * They are here so defenders can judge and harden their own controls; they are
 * not scripts.
 *
 * Detection is by reference. The scanner reads strings and decompiled code, so
 * "detected" means the check exists in the artifact, not that it is reachable or
 * that its result is acted on. The console and the report say so.
 */
import type { ArtifactFacts, ControlGroup, FindingOrigin, SastFinding, SecurityControl } from './types.ts';

type Def = Omit<SecurityControl, 'status' | 'origin' | 'libraries' | 'evidence' | 'occurrences' | 'note'> & {
  platforms: ('android' | 'ios')[];
  /** Any of these rule ids appearing among the scan's secure findings means the control is present. */
  rules: string[];
  /** Rule ids that, if flagged as a defect or hotspot, undermine the control; named in the note. */
  undermined_by?: string[];
  /** Controls the scanner has no way to look for yet: reported as not assessed, never as missing. */
  unassessable?: boolean;
  /** Build a scan-specific note from what was found. */
  noteFor?: (ctx: { present: Set<string>; flagged: Set<string>; artifact: ArtifactFacts }) => string | undefined;
};

const GROUP_ORDER: ControlGroup[] = ['network', 'device-integrity', 'tamper', 'authentication', 'storage', 'platform', 'build'];

export const CONTROL_CATALOGUE: Def[] = [
  /* ------------------------------------------------------------- network */
  {
    id: 'transport_security',
    title: 'Encrypted transport enforced',
    group: 'network',
    platforms: ['ios'],
    rules: ['secure.ats_enforced'],
    what: 'App Transport Security makes the platform refuse plain HTTP and weak TLS for every connection the app makes.',
    bypassEffort: 'low',
    bypass: [
      'Install a proxy CA certificate on the device. Unless the app pins, it trusts the user-installed root and the proxy sees every request in clear.',
      'On a jailbroken device, system-wide tweaks that disable certificate validation remove the protection for every app.',
    ],
    harden: [
      'Pin the server certificate or public key so a user-installed CA is not enough.',
      'Keep ATS strict: no NSAllowsArbitraryLoads, and no exception domain you cannot justify.',
      'Add server-side checks that do not depend on the client being honest, such as attestation and anomaly detection.',
    ],
    masvs: 'MASVS-NETWORK-1',
  },
  {
    id: 'cleartext_blocked',
    title: 'Cleartext traffic blocked',
    group: 'network',
    platforms: ['android'],
    rules: ['secure.cleartext_blocked'],
    what: 'The manifest or network security config forbids plain HTTP, so traffic is encrypted in transit.',
    bypassEffort: 'low',
    bypass: [
      'Repackage the APK with a modified network security config that trusts user CAs or allows cleartext, then re-sign it. Tools such as apk-mitm automate this.',
      'On a rooted device, add the proxy CA to the system store (Magisk modules do this), which every app then trusts.',
    ],
    harden: [
      'Pin certificates in the network security config and again in code.',
      'Verify the app signature at runtime and server-side so a repackaged build is recognised.',
    ],
    masvs: 'MASVS-NETWORK-1',
  },
  {
    id: 'certificate_pinning',
    title: 'Certificate pinning',
    group: 'network',
    platforms: ['android', 'ios'],
    rules: ['ios.ssl_pinning', 'secure.certificate_pinning', 'android.pinning_code'],
    undermined_by: ['net.trust_all_certs', 'net.allow_all_hostnames', 'net.ios_cert_validation_disabled', 'net.ios_trust_override'],
    what: 'The app accepts only a known certificate or public key, so a mis-issued or user-installed CA cannot be used to read its traffic.',
    bypassEffort: 'low',
    bypass: [
      'Runtime hooking (Frida, objection, Xposed-based modules) replaces the validation routine with one that always succeeds. Public "universal unpinning" scripts cover the common libraries: OkHttp, TrustManager, NSURLSession, AFNetworking, Alamofire, TrustKit.',
      'Repackaging: edit the pin set or the network security config in the APK, or patch the comparison in the binary, then re-sign.',
      'A jailbreak or root tweak that hooks the system trust evaluation turns pinning off for every app at once.',
    ],
    harden: [
      'Pin the public key, include a backup key, and plan rotation so an update is not the only way out.',
      'Pin in more than one place, including native code, so one hook does not remove all of it.',
      'Detect hooking frameworks and tampering, and fail closed rather than silently falling back.',
      'Treat pinning as friction, not a boundary: bind sessions to device attestation so a stolen token is not enough.',
    ],
    masvs: 'MASVS-NETWORK-4',
  },

  /* --------------------------------------------------- device integrity */
  {
    id: 'root_jailbreak_detection',
    title: 'Root / jailbreak detection',
    group: 'device-integrity',
    platforms: ['android', 'ios'],
    rules: ['ios.jailbreak_detection', 'android.root_detection'],
    what: 'The app checks whether the device is rooted or jailbroken, where an attacker has full control of the process and the file system.',
    bypassEffort: 'low',
    bypass: [
      'Hide the tools: Magisk DenyList and Zygisk modules on Android, jailbreak-hiding tweaks on iOS, so file and package checks come back clean.',
      'Hook the check: Frida or Xposed makes the detection method return "not rooted". Checks that read a single file path or package name are the easiest.',
      'Patch the binary or smali so the branch that reacts to the result is never taken, then re-sign.',
    ],
    harden: [
      'Do not rely on the device’s own answer. Verify server-side with hardware-backed attestation (Play Integrity, App Attest) and act on the verdict.',
      'Layer different kinds of check (files, processes, syscalls, mount points, sandbox behaviour) and run them in more than one place and at more than one moment.',
      'Keep the reaction unpredictable and away from the check, so patching one branch does not defeat it.',
    ],
    masvs: 'MASVS-RESILIENCE-1',
  },
  {
    id: 'debugger_detection',
    title: 'Debugger detection',
    group: 'device-integrity',
    platforms: ['android', 'ios'],
    rules: ['ios.anti_debug', 'android.debugger_detection'],
    what: 'The app notices when a debugger is attached to it, which is how an analyst steps through logic and reads secrets from memory.',
    bypassEffort: 'low',
    bypass: [
      'Hook or patch the check (ptrace PT_DENY_ATTACH, sysctl P_TRACED, Debug.isDebuggerConnected, TracerPid) so it reports nothing attached.',
      'Attach before the check runs, or use a dynamic-instrumentation framework instead of a debugger, which most of these checks do not look for.',
    ],
    harden: [
      'Repeat the check at several points and in native code, using direct system calls rather than library wrappers that can be hooked.',
      'Combine with integrity checks on the code itself, so a patched check is itself detected.',
      'Never ship a debuggable build: this is a second line, not a first.',
    ],
    masvs: 'MASVS-RESILIENCE-2',
  },
  {
    id: 'emulator_detection',
    title: 'Emulator detection',
    group: 'device-integrity',
    platforms: ['android'],
    rules: ['android.emulator_detection'],
    what: 'The app recognises emulators and virtual devices, where analysis is cheap and automation is easy.',
    bypassEffort: 'low',
    bypass: [
      'Spoof the build properties and system properties the checks read (Magisk property modules, or an emulator image with realistic values).',
      'Run on a physical device, which defeats all property-based checks by definition.',
    ],
    harden: [
      'Use hardware attestation, which an emulator cannot produce, instead of inspecting strings the attacker can edit.',
      'Look at behaviour as well as properties: sensors, timing, telephony and graphics signals.',
    ],
    masvs: 'MASVS-RESILIENCE-5',
  },
  {
    id: 'hook_detection',
    title: 'Hooking / instrumentation detection',
    group: 'device-integrity',
    platforms: ['android', 'ios'],
    rules: ['ios.hook_detection', 'android.hook_detection'],
    what: 'The app looks for Frida, Xposed, Substrate or injected libraries, the tools used to change its behaviour while it runs.',
    bypassEffort: 'moderate',
    bypass: [
      'Rename or rebuild the instrumentation (custom Frida builds, renamed server and gadget, non-default ports) so string and port checks find nothing.',
      'Hook the detection routine itself, or load before it runs. Detection that lives in one Java or Objective-C method is easy to find and neutralise.',
    ],
    harden: [
      'Check several independent signals (loaded images, memory maps, thread names, inline-hook prologues, timing) from native code.',
      'Keep detection and reaction apart, and make the reaction subtle, such as degraded server-side trust, so it does not point an analyst at the check.',
    ],
    masvs: 'MASVS-RESILIENCE-4',
  },
  {
    id: 'device_attestation',
    title: 'Device / app attestation',
    group: 'device-integrity',
    platforms: ['android', 'ios'],
    rules: ['ios.device_attestation', 'android.device_attestation'],
    what: 'A hardware-backed signal, verified by the vendor, that the request comes from a genuine device running the genuine app.',
    bypassEffort: 'high',
    bypass: [
      'Basic and device-level verdicts can sometimes be obtained on rooted devices with spoofing modules, until the vendor tightens them. Strong, hardware-backed verdicts cannot.',
      'The client only forwards the token. If the server does not verify it, or does not verify a fresh nonce, the whole control is bypassed by never calling it.',
    ],
    harden: [
      'Verify the token on your server with a per-request nonce, and require the strongest verdict for high-value actions.',
      'Decide what to do on failure on the server. A client that decides is a client that can be patched.',
    ],
    masvs: 'MASVS-RESILIENCE-1',
  },

  /* -------------------------------------------------------------- tamper */
  {
    id: 'code_signing',
    title: 'Code signing',
    group: 'tamper',
    platforms: ['android', 'ios'],
    rules: ['secure.code_signature', 'secure.modern_signing'],
    what: 'The operating system only installs and runs code signed by a known developer identity, and refuses a package modified after signing.',
    bypassEffort: 'low',
    bypass: [
      'Re-sign the modified app with the attacker’s own certificate. The platform checks that the signature is valid, not that it is yours (standard signing tools on Android; sideloading tools and developer certificates on iOS).',
      'On a jailbroken or rooted device, signature enforcement can be turned off entirely.',
    ],
    harden: [
      'Verify your own signing certificate at runtime and, better, on the server with attestation, so a re-signed copy is recognised.',
      'Use Play App Signing and keep keys off developer machines.',
    ],
    masvs: 'MASVS-RESILIENCE-2',
  },
  {
    id: 'runtime_integrity',
    title: 'Runtime signature / integrity check',
    group: 'tamper',
    platforms: ['android'],
    rules: ['android.signature_check'],
    what: 'The app reads its own signing certificate and compares it with an expected value, to notice a repackaged copy.',
    bypassEffort: 'low',
    bypass: [
      'Hook PackageManager so the check sees the original certificate, or patch the comparison. Signature-spoofing patch tools do this generically.',
      'Remove the call in smali and rebuild. If the result is only used in Java, one edit is enough.',
    ],
    harden: [
      'Do the comparison in native code and in several places, with the expected value derived rather than stored as a plain constant.',
      'Send a signature digest to the server inside an attestation token and let the server decide.',
    ],
    masvs: 'MASVS-RESILIENCE-2',
  },
  {
    id: 'not_debuggable',
    title: 'Release build is not debuggable',
    group: 'tamper',
    platforms: ['android', 'ios'],
    rules: ['secure.not_debuggable', 'secure.distribution_profile'],
    what: 'The build does not grant the debuggable flag (Android) or get-task-allow (iOS), so a debugger cannot attach on an unmodified device.',
    bypassEffort: 'low',
    bypass: [
      'Repackage with the flag switched on and re-sign, then debug the modified copy.',
      'On a rooted device, a system-property change makes every app debuggable; on a jailbroken device the debugging restriction is not enforced.',
    ],
    harden: [
      'Check the flag at runtime and treat a debuggable copy of a release build as tampered.',
      'Combine with signature verification so the modified copy is rejected, not just flagged.',
    ],
    masvs: 'MASVS-RESILIENCE-2',
  },
  {
    id: 'code_obfuscation',
    title: 'Code obfuscation / symbol stripping',
    group: 'tamper',
    platforms: ['ios'],
    rules: ['secure.symbols_stripped'],
    what: 'Local symbols are removed, so the binary carries fewer function names for a reader to follow.',
    bypassEffort: 'moderate',
    bypass: [
      'Objective-C selectors and Swift metadata survive stripping, so class-dump style tools still recover most of the structure.',
      'Disassemblers (Ghidra, Hopper, IDA) with decompilers rebuild readable logic from the instructions; names only save the analyst time.',
    ],
    harden: [
      'Use a commercial obfuscator or control-flow and string obfuscation for the few routines that matter: licence checks, key derivation, pinning.',
      'Keep secrets out of the binary altogether; obfuscation delays, it does not hide.',
    ],
    masvs: 'MASVS-RESILIENCE-3',
  },
  {
    id: 'android_obfuscation',
    title: 'Code obfuscation (R8 / ProGuard)',
    group: 'tamper',
    platforms: ['android'],
    rules: [],
    unassessable: true,
    what: 'Class, method and field names are shortened or removed, and code is restructured, so the decompiled app is harder to read.',
    bypassEffort: 'moderate',
    bypass: [
      'Public decompilers still produce working Java; renaming is reversible with mapping heuristics and manual annotation.',
      'Dynamic instrumentation observes real behaviour regardless of names.',
    ],
    harden: [
      'Enable R8 with full mode for release, and add string and control-flow obfuscation for security-critical routines.',
      'Do not rely on it to hide secrets or logic that must stay private; move those to the server.',
    ],
    masvs: 'MASVS-RESILIENCE-3',
  },
  {
    id: 'binary_hardening',
    title: 'Memory-safety hardening',
    group: 'tamper',
    platforms: ['android', 'ios'],
    rules: ['secure.binary_hardening', 'secure.hardened_native'],
    what: 'Position-independent code, a stack protector, non-executable stack and automatic reference counting make memory-corruption bugs harder to exploit.',
    bypassEffort: 'high',
    bypass: [
      'Not something a user removes at runtime. It is defeated by finding a memory-corruption bug plus an information leak to learn addresses, which is expensive.',
    ],
    harden: [
      'Keep the compiler and linker flags on for every library, including third-party ones.',
      'Prefer memory-safe languages for new parsing and crypto code.',
    ],
    masvs: 'MASVS-RESILIENCE-1',
  },

  /* ------------------------------------------------------ authentication */
  {
    id: 'biometric_authentication',
    title: 'Biometric authentication',
    group: 'authentication',
    platforms: ['android', 'ios'],
    rules: ['ios.biometric_auth', 'android.biometric_prompt'],
    what: 'The user must present a fingerprint or face to continue.',
    bypassEffort: 'low',
    bypass: [
      'If the result is just a boolean the app checks, hook the success callback (LAContext evaluatePolicy, BiometricPrompt onAuthenticationSucceeded) with Frida or objection and the gate opens with no biometric at all.',
      'Reaching the protected screen directly, skipping the prompt, works whenever the screen itself does not re-check.',
    ],
    harden: [
      'Bind the biometric to a key: a Keystore key that requires authentication per use (Android, with a CryptoObject) or a Keychain item with biometric access control (iOS). Then a hooked callback cannot produce the secret.',
      'Use the result to decrypt or sign something the server verifies, not to flip a local flag.',
    ],
    masvs: 'MASVS-AUTH-2',
    noteFor: ({ present, artifact }) =>
      artifact.platform === 'android'
        ? present.has('android.biometric_crypto')
          ? 'A CryptoObject is used alongside the prompt, so the result can be bound to a Keystore key.'
          : 'No CryptoObject was found with the prompt: the result is probably a flag, which a hooked callback can set.'
        : undefined,
  },

  /* ------------------------------------------------------------- storage */
  {
    id: 'secure_credential_storage',
    title: 'Keychain / Keystore storage',
    group: 'storage',
    platforms: ['android', 'ios'],
    rules: ['ios.keychain_used', 'android.keystore_used'],
    undermined_by: ['code.ios_weak_keychain_accessibility'],
    what: 'Credentials and keys live in the platform’s protected store, not in preferences or files.',
    bypassEffort: 'moderate',
    bypass: [
      'On a jailbroken or rooted device, dump the store (objection keychain dump on iOS) when items use a permissive accessibility class.',
      'Hardware-backed keys cannot be copied out, but they can be used: hook the app’s own decrypt or sign call and the key does the work for the attacker.',
    ],
    harden: [
      'Use the most restrictive accessibility class that works (when-passcode-set, this-device-only) and require user authentication per use for sensitive keys.',
      'Prefer StrongBox or the Secure Enclave, and keep what the key protects short-lived.',
    ],
    masvs: 'MASVS-STORAGE-1',
  },
  {
    id: 'encrypted_database',
    title: 'Encrypted local database',
    group: 'storage',
    platforms: ['android', 'ios'],
    rules: ['ios.sqlcipher', 'ios.realm_encryption', 'secure.encrypted_database'],
    what: 'Local data is encrypted at rest, so a copied database file is unreadable.',
    bypassEffort: 'moderate',
    bypass: [
      'The app must open the database, so the key exists in memory at run time. Instrumentation reads it from the open handle or from the call that supplies it.',
      'If the key is a constant in the binary or derived from something on the device, static analysis recovers it.',
    ],
    harden: [
      'Generate the key per install and keep it in the Keychain or Keystore, ideally gated on user authentication.',
      'Store as little as possible; data that never reaches the device cannot be extracted from it.',
    ],
    masvs: 'MASVS-STORAGE-2',
  },
  {
    id: 'file_protection',
    title: 'File protection at rest',
    group: 'storage',
    platforms: ['ios'],
    rules: ['ios.file_protection_complete', 'secure.data_protection'],
    what: 'Files are encrypted with a key tied to the passcode and unreadable while the device is locked.',
    bypassEffort: 'moderate',
    bypass: [
      'It only protects a locked device. With the device unlocked, or on a jailbroken one, the app’s files are readable like any other.',
    ],
    harden: [
      'Do not rely on it alone for secrets. Encrypt sensitive payloads inside the app with a Keychain-held key.',
    ],
    masvs: 'MASVS-STORAGE-2',
  },
  {
    id: 'backup_disabled',
    title: 'Backups disabled',
    group: 'storage',
    platforms: ['android'],
    rules: ['secure.backup_disabled'],
    what: 'allowBackup is off, so adb backup and cloud backup cannot copy the app’s private data.',
    bypassEffort: 'low',
    bypass: [
      'Root access reads the private directory directly, with no backup involved.',
      'Repackaging with the flag turned on and installing that copy makes the data backup-able.',
    ],
    harden: [
      'Treat the setting as hygiene, not protection. Encrypt sensitive local data independently.',
    ],
    masvs: 'MASVS-STORAGE-2',
  },

  /* ------------------------------------------------------------ platform */
  {
    id: 'screen_protection',
    title: 'Screen-capture protection',
    group: 'platform',
    platforms: ['android', 'ios'],
    rules: ['android.screen_protection', 'ios.screen_capture_detection', 'ios.secure_text_entry'],
    what: 'Sensitive screens are blocked from screenshots and recording, and hidden in the task switcher.',
    bypassEffort: 'low',
    bypass: [
      'Hook the call that sets the flag (Window.setFlags, addFlags) or the capture-detection result so protection is never applied.',
      'Capture from outside the app: a second camera, a rooted screen recorder, or a screen-mirroring path the flag does not cover.',
    ],
    harden: [
      'Apply protection per sensitive screen and verify it is still set when the screen is shown.',
      'Keep the most sensitive values out of view at all, for example masked until the user taps to reveal.',
    ],
    masvs: 'MASVS-PLATFORM-3',
  },
];

/** How the detection looked on this scan, folded into a control. */
function summarise(
  def: Def,
  matched: SastFinding[],
  flagged: SastFinding[],
  artifact: ArtifactFacts,
  present: Set<string>,
): SecurityControl {
  const { platforms: _platforms, rules: _rules, undermined_by, unassessable, noteFor, ...base } = def;
  const locations = matched.flatMap((f) => f.locations);
  const origins = new Set<FindingOrigin>(matched.map((f) => f.origin ?? 'unknown'));
  const libraries = [...new Set(matched.flatMap((f) => f.libraries ?? []))];

  let origin: FindingOrigin | undefined;
  if (matched.length > 0) {
    const known = [...origins].filter((o) => o !== 'unknown');
    origin = known.length === 0 ? 'unknown' : known.length > 1 ? 'mixed' : known[0];
  }

  const notes: string[] = [];
  let noteTone: SecurityControl['noteTone'];
  if (matched.length > 0 && origin === 'third-party') {
    notes.push(
      `Only found in bundled library code${libraries.length ? ` (${libraries.slice(0, 3).join(', ')})` : ''}. The app’s own code may not use it.`,
    );
  }
  // A defect that sits entirely inside a bundled library is that library's own
  // behaviour, not a statement about how the app uses this control.
  const undermining = (undermined_by ?? []).flatMap((id) =>
    flagged.filter((f) => f.ruleId.split(':')[0] === id && f.origin !== 'third-party'),
  );
  if (matched.length > 0 && undermining.length > 0) {
    notes.push(`Also flagged: ${undermining.map((f) => f.title).join('; ')}. That weakens or cancels this control.`);
    noteTone = 'warning';
  }
  const extra = noteFor?.({ present, flagged: new Set(flagged.map((f) => f.ruleId)), artifact });
  if (matched.length > 0 && extra) notes.push(extra);

  return {
    ...base,
    status: matched.length > 0 ? 'detected' : unassessable ? 'not-assessed' : 'not-detected',
    origin,
    libraries: libraries.length ? libraries : undefined,
    evidence: locations.slice(0, 6).map((l) => ({ file: l.file, line: l.line, excerpt: l.excerpt })),
    occurrences: matched.reduce((n, f) => n + Math.max(f.occurrences, f.locations.length), 0),
    note: notes.length ? notes.join(' ') : undefined,
    noteTone: notes.length ? (noteTone ?? 'info') : undefined,
  };
}

/**
 * Builds the controls list for one scan.
 *
 * Present controls come first within each group, then missing ones, because the
 * reader's first question is what the app has and the second is what it lacks.
 */
export function controlsOf(input: {
  platform: 'android' | 'ios';
  secure: SastFinding[];
  findings: SastFinding[];
  hotspots: SastFinding[];
  artifact: ArtifactFacts;
}): SecurityControl[] {
  const present = new Set(input.secure.map((f) => f.ruleId.split(':')[0]));
  const flagged = [...input.findings, ...input.hotspots];

  const controls = CONTROL_CATALOGUE.filter((d) => d.platforms.includes(input.platform)).map((def) => {
    const matched = input.secure.filter((f) => def.rules.includes(f.ruleId.split(':')[0]));
    return summarise(def, matched, flagged, input.artifact, present);
  });

  // An app with no native code has nothing for the hardening flags to apply to.
  for (const c of controls) {
    if (
      c.id === 'binary_hardening' && input.platform === 'android' &&
      c.status === 'not-detected' && input.artifact.nativeLibraryDetail.length === 0
    ) {
      c.status = 'not-assessed';
      c.note = 'No native libraries were inspected, so there is nothing for these flags to apply to.';
      c.noteTone = 'info';
    }
  }

  const statusRank = { detected: 0, 'not-detected': 1, 'not-assessed': 2 } as const;
  return controls.sort(
    (a, b) =>
      GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group) ||
      statusRank[a.status] - statusRank[b.status],
  );
}
