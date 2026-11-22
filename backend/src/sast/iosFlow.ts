/**
 * What the functions of an iOS app do, judged from the calls they make and the literals they use.
 *
 * `arm64Scan.ts` reads each function once and records what it calls and which strings it
 * touches. The checks here are statements about those records: "this function answers an
 * authentication challenge with the server trust and never evaluates it", "this function
 * writes a password-named key to NSUserDefaults", "this function compares against a literal
 * that looks like a credential". Each names the function, so the report can say where.
 *
 * Code from statically linked libraries is left out, by class-name prefix and Swift module,
 * so the findings are about the app. Where a function's origin cannot be told it is kept.
 */
import { analyseFunctions } from './arm64Scan.ts';
import type { Arg, Call, FunctionFact } from './arm64Scan.ts';
import { readModel } from './machoModel.ts';
import { SQLITE_INTERNALS } from './rulesIos.ts';
import type { MachoModel } from './machoModel.ts';
import { readableSymbol } from './swiftNames.ts';

export type IosHit = {
  rule: string;
  fn: FunctionFact;
  evidence: string;
  /** Hits sharing a key are the same finding seen from different functions; one location is kept. */
  key?: string;
  /** Lines of the function's block in the listing (counted from its header, 0 being the header) that show the evidence. */
  marks?: number[];
};

export type IosAnalysis = {
  hits: IosHit[];
  /** The readable listing the findings point into: one block per function, header first. */
  listing: { lines: string[]; headerLine: Map<number, number>; /** How many lines each function's block takes, by address. */ blockSize: Map<number, number> };
  functionCount: number;
  appFunctionCount: number;
  encrypted: boolean;
};

const LIBRARY_CLASS =
  /^(?:AF[A-Z]|SD[A-Z]|FB(?:SDK)?[A-Z]|FIR[A-Z]|G(?:AD|MO|MS|CK|AM|NS|IM)[A-Z]|GUL[A-Z]|RCN[A-Z]|ABT[A-Z]|FPR[A-Z]|FIS[A-Z]|FLT[A-Z]|GAI(?:[A-Z]|$)|GAD[A-Z]|GMS[A-Z]|GTM[A-Z]|GPB[A-Z]|CBL_?[A-Z]|TD_?[A-Z]|YDB[A-Z]|GCDAsync|PF[A-Z]|BF[A-Z]|RLM[A-Z]|Yap[A-Z]|PSWebSocket|PDKeychain|DD[A-Z]|RCT[A-Z]|Flurry|FMDB|FMDatabase|MBProgress|SVProgress|MJ[A-Z]|Crashlytics|CLS[A-Z]|Fabric|Firebase|Realm|Parse|AppsFlyer|Mixpanel|Sentry|Lottie|SDWebImage|YY[A-Z]|Masonry|IQ[A-Z]|SAMKeychain|SSKeychain|Reachability|GoogleSign|GIDS|GTL|GDT|nanopb|RN[A-Z]|DeviceUID|RNEnc|RNDec|RNCrypt|RNOpenSSL|OpenSSL|TFHpple|MWFeed|AFNetworking|NSData\(DD|NS\w+\((?:DD|AF|SD|FB|YY|MJ|MB|Flurry)|UI\w+\((?:SD|AF|FB|YY|MJ|MB|WebCache|Flurry))/;

const SWIFT_MANGLED = /^_{0,2}(?:\$[sS]|T0)(\d+)/;

function swiftModule(name: string): string | undefined {
  const m = name.match(/^_{0,2}(?:\$[sS]|_?T0)(\d+)([A-Za-z0-9_]+)/) ?? name.match(/^_TtC(\d+)([A-Za-z0-9_]+)/);
  if (!m) return undefined;
  const length = Number(m[1]);
  return m[2].slice(0, length);
}

/** 'app', 'library', or 'unknown' when the name carries no tell. */
function originOf(fn: FunctionFact, appModule: string): 'app' | 'library' | 'unknown' {
  const owner = fn.objc?.className ?? fn.name.match(/^_{0,3}\d+-[+-]?\[([^\s\]]+)/)?.[1] ?? fn.name.match(/^[+-]\[([^\s\]]+)/)?.[1];
  if (owner) {
    const mod = swiftModule(owner);
    if (mod) return mod === appModule ? 'app' : 'library';
    if (LIBRARY_CLASS.test(owner)) return 'library';
    return 'unknown';
  }
  const mod = swiftModule(fn.name);
  if (mod) return mod === appModule ? 'app' : 'library';
  if (SWIFT_MANGLED.test(fn.name)) return 'unknown';
  return 'unknown';
}

const CALL_NAMES = (calls: Call[]): string[] =>
  calls.map((c) => (c.kind === 'import' ? c.name : c.kind === 'msg' ? c.selector : '')).filter(Boolean);

/** Names of everything a function reaches: its own calls, those of functions it calls directly, and of its blocks. */
function reach(fn: FunctionFact, byAddress: Map<number, FunctionFact>, blocksOf: Map<string, FunctionFact[]>, depth = 2): { names: Set<string>; refs: Set<string>; strings: Set<string> } {
  const names = new Set<string>();
  const refs = new Set<string>();
  const strings = new Set<string>();
  const seen = new Set<number>();
  const visit = (f: FunctionFact, d: number) => {
    if (seen.has(f.address)) return;
    seen.add(f.address);
    for (const n of CALL_NAMES(f.calls)) names.add(n);
    for (const r of f.refs) refs.add(r);
    for (const s of f.strings) strings.add(s);
    if (d <= 0) return;
    for (const c of f.calls) {
      if (c.kind === 'internal') {
        const target = byAddress.get(c.target);
        if (target) visit(target, d - 1);
      }
    }
    for (const block of blocksOf.get(f.name) ?? []) visit(block, d - 1);
  };
  visit(fn, depth);
  return { names, refs, strings };
}

// A value spliced into the statement: an open quote or comparison at the end, a quoted placeholder, or a placeholder after =.
// A placeholder for a table or column name beside bound parameters (`INSERT INTO %@ (%@) VALUES (?)`) is not that.
const SQL_DYNAMIC = /^\s*(?:select|insert\s+into|update|delete\s+from)\b.*(?:(?:=|\blike|\bin|\bvalues)\s*["'(]?\s*$|["']\s*$|(?:=|\blike)\s*['"]?%[@sd]|['"]%[@sd]['"]|\\\()/i;
const SENSITIVE_WORD = /(password|passwd|passcode|\bpin\b|token|secret|credential|cvv|card ?number|ssn|\botp\b|authorization)/i;
const COMPARE = /^(?:isEqualToString:|isEqual:|compare:|caseInsensitiveCompare:|isEqualToData:)$|SS2eeoiy?SbSS_SStFZ|SS7compare/;
const AUTH_NAME = /(login|signin|sign_in|auth|password|passwd|passcode|\bpin\b|credential|validate|unlock|secret|verify|isadmin|checkuser|checkpass)/i;
const AUTH_MESSAGE = /(incorrect|invalid|wrong|failed|failure|success|congratulations|welcome|access (?:granted|denied)|bypass|unlock|authenticat)/i;
const CREDENTIAL_PROPERTY = /(password|passwd|passcode|secret|apikey|api_key|token|credential)[A-Za-z]*(?:vfi|vpfi)/i;

/** A literal that is shaped like something chosen as a password or key, and not like a word, an identifier or a format. */
function credentialLike(text: string): boolean {
  if (text.length < 5 || text.length > 40 || /\s/.test(text)) return false;
  if (!/[A-Za-z]/.test(text) || !/[0-9@#$!%^&*+=?]/.test(text)) return false;
  if (/:\/\/|\/|\\|%[@dsflu]|"/.test(text)) return false;
  if (/^[0-9a-f]{16,}$/i.test(text) || /^[A-Za-z0-9+/]{20,}={0,2}$/.test(text) && text.length > 28) return false;
  if (/^[Tv]\d*@|^@"|^\^|^\{/.test(text)) return false; // type encodings and blocks
  if (/^[A-Z]-[A-Z]{2,5}\d{3,}$/.test(text)) return false; // error codes (I-FIS001005)
  if (/^\d+(?:\.\d+)+$/.test(text) || /^[A-Za-z]+(?:\.[A-Za-z0-9]+){1,}$/.test(text)) return false; // versions and reverse-DNS names
  if (/^_?[A-Za-z]+[A-Z][a-z]+\d*$/.test(text) && !/[@#$!%^&*+=?]/.test(text)) return false; // CamelCase identifiers
  return true;
}

const KEY_PARAM = /(?:^|[:A-Za-z])(?:[Pp]assword|[Pp]asscode|[Pp]assphrase|[Ss]ecret|[Aa]pi[Kk]ey|API[Kk]ey|[Aa]pp[Kk]ey|[Ss]ession[Kk]ey|[Cc]lient[Ss]ecret|[Aa]ccess[Tt]oken|[Aa]uth[Tt]oken|[Ee]ncryption[Kk]ey|[Pp]rivate[Kk]ey|[Ss]tartSession|[Aa]pplication[Ii]d)[A-Za-z]*:/;
const KEY_IMPORT: Record<string, number[]> = {
  sqlite3_key: [1],
  sqlite3_key_v2: [2],
  sqlite3_rekey: [1],
  CCCrypt: [3],
  CCCryptorCreate: [3],
  CCCryptorCreateWithMode: [4],
  CCHmac: [2],
  CCKeyDerivationPBKDF: [1],
};

const SENSITIVE_KEY = /(password|passwd|passcode|\bpin\b|token|secret|credential|cvv|\bssn\b|\botp\b|card ?number|authorization)/i;
const WEAK_CC_ALGORITHM: Record<number, string> = { 1: 'DES', 2: '3DES', 3: 'CAST', 4: 'RC4', 5: 'RC2', 6: 'Blowfish' };

/** Runtime plumbing every function is full of (reference counting, type metadata, the Swift trap strings). */
const PLUMBING_CALL = /^_{0,2}(?:objc_(?:retain|release|autorelease|storeStrong|retainAutorelease(?:ReturnValue)?|retainAutoreleasedReturnValue|autoreleaseReturnValue)|swift_(?:retain|release|bridgeObject(?:Retain|Release)|unknown(?:Retain|Release|UnownedInit)|beginAccess|endAccess|allocObject|deallocClassInstance|once|getTypeByMangledName)|_Block_(?:copy|release))$|Ma$/;
const PLUMBING_STRING = /^(?:Fatal error|Unexpectedly found nil while unwrapping an Optional value)/;
const clip = (text: string, length = 160) => (text.length > length ? `${text.slice(0, length - 1)}…` : text);
const literal = (text: string) => JSON.stringify(text.length > 90 ? `${text.slice(0, 90)}…` : text);

/** An argument as far as the scanner could follow it; `…` where it could not. */
function argText(a: Arg | undefined): string {
  if (!a) return '…';
  if (a.str !== undefined) return literal(a.str);
  if (a.sym) return a.sym;
  if (a.imm !== undefined) return a.imm > 9 ? `0x${a.imm.toString(16)}` : String(a.imm);
  return '…';
}

/** One call as a line of code: `[NSUserDefaults setObject:… forKey:"password"]`, `CCCrypt(0, 0, 1, "key", …)`. */
function callText(call: Call, byAddress: Map<number, FunctionFact>): string {
  if (call.kind === 'internal') {
    const target = byAddress.get(call.target);
    return `${target ? readableSymbol(target.name) : `sub_${call.target.toString(16)}`}()`;
  }
  if (call.kind === 'msg') {
    const receiver = call.receiver ?? '…';
    const parts = call.selector.split(':');
    if (parts.length === 1) return `[${receiver} ${call.selector}]`;
    const spelled = parts.slice(0, -1).map((part, i) => `${part}:${argText(call.args[i + 2])}`);
    return clip(`[${receiver} ${spelled.join(' ')}]`);
  }
  const name = readableSymbol(call.name);
  let last = call.args.length;
  while (last > 0 && argText(call.args[last - 1]) === '…') last -= 1;
  if (last === 0) return `${name}(…)`;
  return clip(`${name}(${call.args.slice(0, Math.min(last, 8)).map(argText).join(', ')}${last < call.args.length || last > 8 ? ', …' : ''})`);
}

/**
 * One function as a block of readable pseudo-code: its name, what it calls (one call to a line, with the
 * arguments the scanner could follow), the string literals it holds and the constants it reads. A function a
 * rule flagged says so on a line of its own, and the lines that show the evidence are marked so a finding can
 * quote them. It is what the machine code does, not source.
 */
function functionBlock(fn: FunctionFact, hits: IosHit[], byAddress: Map<number, FunctionFact>): string[] {
  const flagged = hits.length > 0;
  const readable = readableSymbol(fn.name);
  const out = [`${readable}   @0x${fn.address.toString(16)}`];
  if (readable !== fn.name) out.push(`    // symbol ${clip(fn.name, 200)}`);
  const annotation = new Set<number>();
  for (const h of hits) {
    annotation.add(out.length);
    out.push(`    ! ${h.rule}: ${clip(h.evidence, 200)}`);
  }

  const counted = new Map<string, number>();
  let hidden = 0;
  for (const call of fn.calls) {
    if (
      (call.kind === 'import' && PLUMBING_CALL.test(call.name)) ||
      (call.kind === 'msg' && /^(?:retain|release|autorelease)$/.test(call.selector)) ||
      (call.kind === 'internal' && /Ma$/.test(byAddress.get(call.target)?.name ?? ''))
    ) {
      hidden += 1;
      continue;
    }
    const text = callText(call, byAddress);
    counted.set(text, (counted.get(text) ?? 0) + 1);
  }
  const calls = [...counted];
  for (const [text, n] of calls.slice(0, flagged ? 60 : 24)) out.push(`    call  ${text}${n > 1 ? `   ×${n}` : ''}`);
  if (calls.length > (flagged ? 60 : 24)) out.push(`    call  … ${calls.length - (flagged ? 60 : 24)} more`);
  if (hidden > 0) out.push(`    // ${hidden} reference-counting and type-metadata calls not shown`);
  const strings = [...new Set(fn.strings.filter((t) => !PLUMBING_STRING.test(t)))];
  for (const text of strings.slice(0, flagged ? 40 : 12)) out.push(`    str   ${literal(text)}`);
  if (strings.length > (flagged ? 40 : 12)) out.push(`    str   … ${strings.length - (flagged ? 40 : 12)} more`);
  for (const ref of fn.refs.slice(0, 12)) out.push(`    uses  ${ref}`);

  // The lines that show each hit's evidence: the literal or call its text names, besides the finding's own line.
  for (const h of hits) {
    const wanted = [...h.evidence.matchAll(/"([^"]{3,})"/g)].map((x) => x[1].slice(0, 30));
    for (const x of h.evidence.matchAll(/\b(?:calls|to|uses|with)\s+([A-Za-z_][\w:$@.-]{2,})/g)) wanted.push(x[1]);
    const marks = new Set<number>(out.flatMap((line, i) => (annotation.has(i) && out[i].startsWith(`    ! ${h.rule}:`) ? [i] : [])));
    out.forEach((line, i) => {
      if (i === 0 || annotation.has(i) || line.startsWith('    // ')) return;
      if (marks.size < 5 && wanted.some((w) => line.includes(w))) marks.add(i);
    });
    h.marks = [...marks].sort((a, b) => a - b);
  }
  return out;
}

/**
 * The stretch of the code section the app's own classes occupy.
 *
 * The linker lays objects out in the order it is given them, so the classes of the app's target sit together
 * and each pod or static library sits in its own run. The anchors are classes that must be the app's: those in
 * the app's Swift module, those its storyboards name, and the one that implements
 * `application:didFinishLaunchingWithOptions:`. When they span too much of the binary (a React Native app mixes
 * its own modules in among the framework's) the region says nothing and is not used.
 */
function appRegion(model: MachoModel, appModule: string, nibNames: Set<string>): { lo: number; hi: number } | undefined {
  const text = model.sections.find((s) => s.name === '__text' && s.segment === '__TEXT');
  if (!text) return undefined;
  const anchors = model.classes.filter(
    (c) =>
      !LIBRARY_CLASS.test(c.name) &&
      (swiftModule(c.name) === appModule || nibNames.has(c.name) || c.methods.some((m) => m.selector === 'application:didFinishLaunchingWithOptions:')),
  );
  if (anchors.length < 1) return undefined;
  const inText = (a: number) => a >= text.addr && a < text.addr + text.size;
  // Classes in address order. The anchors are only the ones that can be proven, so the region grows over the
  // classes next to them that no library claims: an Objective-C helper (`Util`, `DeviceInfo`) is linked beside
  // the view controllers and names neither the module nor a nib.
  const ordered = model.classes
    .map((c) => ({ c, addresses: c.methods.map((m) => m.imp).filter(inText) }))
    .filter((x) => x.addresses.length > 0)
    .map((x) => ({ ...x, lo: Math.min(...x.addresses), hi: Math.max(...x.addresses) }))
    .sort((a, b) => a.lo - b.lo);
  const anchored = new Set(anchors);
  const neutral = (c: (typeof ordered)[number]['c']) => !LIBRARY_CLASS.test(c.name) && (!/^_TtC/.test(c.name) || swiftModule(c.name) === appModule);
  const first = ordered.findIndex((x) => anchored.has(x.c));
  const last = ordered.length - 1 - [...ordered].reverse().findIndex((x) => anchored.has(x.c));
  if (first < 0) return undefined;
  let from = first;
  while (from > 0 && neutral(ordered[from - 1].c)) from -= 1;
  let to = last;
  while (to < ordered.length - 1 && neutral(ordered[to + 1].c)) to += 1;
  const lo = from === 0 ? text.addr : ordered[from].lo;
  const hi = Math.max(...ordered.slice(from, to + 1).map((x) => x.hi)) + 4096;
  return (hi - lo) / text.size > 0.6 ? undefined : { lo, hi };
}

type ApiUse = { rule: string; test: (fn: FunctionFact) => string | undefined };

/**
 * A function and the thin wrappers it calls. Swift reaches an Objective-C class through a tiny accessor
 * (`$So9UIWebViewCMa`) that holds the class reference, so the class belongs to the caller; a large callee
 * (someone else's code) does not.
 */
/** `__T0So9UIWebViewCMa` is Swift's accessor for the Objective-C class UIWebView: the name holds the class. */
function accessorClass(name: string): string | undefined {
  const m = name.match(/So(\d+)([A-Za-z0-9_]+)/);
  if (!m) return undefined;
  const length = Number(m[1]);
  return length > 0 && length <= m[2].length ? m[2].slice(0, length) : undefined;
}

/** A metadata accessor holds a class reference for its callers, which are where the use is. */
const isAccessor = (fn: FunctionFact) => /Ma$/.test(fn.name) || (fn.size <= 64 && fn.calls.length <= 2 && fn.classes.length > 0);

/** A function this small is a wrapper or an accessor: what it does is attributed to its callers as well. */
const isThin = (fn: FunctionFact) => fn.size <= 96 || /Ma$/.test(fn.name);

function withThinCallees(fn: FunctionFact, byAddress: Map<number, FunctionFact>, depth = 2): FunctionFact {
  if (depth <= 0) return fn;
  const thin = fn.calls
    .filter((c): c is Extract<Call, { kind: 'internal' }> => c.kind === 'internal')
    .map((c) => byAddress.get(c.target))
    .filter((t): t is FunctionFact => Boolean(t) && (t!.size <= 96 || /Ma$/.test(t!.name)))
    .map((t) => withThinCallees(t, byAddress, depth - 1));
  if (thin.length === 0) return fn;
  return {
    ...fn,
    // The accessors' names carry the class when the binary kept its symbols (`__T0So9UIWebViewCMa`).
    calls: [...fn.calls, ...thin.flatMap((t) => t.calls)],
    classes: [...new Set([...fn.classes, ...thin.flatMap((t) => [...t.classes, ...(accessorClass(t.name) ? [accessorClass(t.name)!] : [])])])],
    refs: [...new Set([...fn.refs, ...thin.flatMap((t) => t.refs)])],
  };
}

const importNames = (fn: FunctionFact) => fn.calls.filter((c): c is Extract<Call, { kind: 'import' }> => c.kind === 'import').map((c) => c.name);
const selectors = (fn: FunctionFact) => fn.calls.filter((c): c is Extract<Call, { kind: 'msg' }> => c.kind === 'msg').map((c) => c.selector);

/** First thing in `candidates` that matches `re`. */
const firstMatch = (re: RegExp, ...candidates: string[][]): string | undefined => {
  for (const list of candidates) {
    const hit = list.find((x) => re.test(x));
    if (hit) return hit;
  }
  return undefined;
};

/**
 * APIs the string-level rules used to report from anywhere in the binary, which on an app that links
 * Google Mobile Ads, Realm or SQLCipher meant reporting the libraries' code as the app's. Here each
 * is judged for the functions that are not a known library's, so the finding names a function.
 */
const API_USE: ApiUse[] = [
  { rule: 'crypto.weak_hash', test: (fn) => firstMatch(/^CC_(?:MD2|MD4|MD5|SHA1)(?:_Init|_Update|_Final)?$/, importNames(fn)) },
  { rule: 'crypto.ios_kdf_review', test: (fn) => firstMatch(/^CCKeyDerivationPBKDF$/, importNames(fn)) },
  { rule: 'crypto.weak_prng_c', test: (fn) => firstMatch(/^(?:random|rand|srand|srandom|drand48|lrand48|rand_r)$/, importNames(fn)) },
  { rule: 'code.unsafe_c_string', test: (fn) => firstMatch(/^(?:strcpy|strcat|sprintf|vsprintf|gets|stpcpy)$/, importNames(fn)) },
  { rule: 'ios.dynamic_loading', test: (fn) => firstMatch(/^(?:dlopen|dlsym)$/, importNames(fn)) },
  { rule: 'ios.command_execution', test: (fn) => firstMatch(/^(?:system|popen|posix_spawn|execve)$/, importNames(fn)) },
  { rule: 'ios.nsuserdefaults_storage', test: (fn) => firstMatch(/^NSUserDefaults$/, fn.classes) ?? firstMatch(/^standardUserDefaults$/, selectors(fn)) ?? firstMatch(/UserDefaults/, importNames(fn)) },
  { rule: 'ios.location_tracking', test: (fn) => firstMatch(/^CLLocationManager$/, fn.classes) ?? firstMatch(/^(?:startUpdatingLocation|requestAlwaysAuthorization|requestWhenInUseAuthorization|startMonitoringSignificantLocationChanges)$/, selectors(fn)) },
  { rule: 'ios.idfa_tracking', test: (fn) => firstMatch(/^(?:ASIdentifierManager|ATTrackingManager)$/, fn.classes) ?? firstMatch(/^advertisingIdentifier$/, selectors(fn)) },
  { rule: 'code.ios_pasteboard', test: (fn) => firstMatch(/^UIPasteboard$/, fn.classes) ?? firstMatch(/^generalPasteboard$/, selectors(fn)) },
  { rule: 'ios.health_data', test: (fn) => firstMatch(/^HKHealthStore$/, fn.classes) },
  { rule: 'ios.temporary_file', test: (fn) => firstMatch(/^NSTemporaryDirectory$/, importNames(fn)) },
  { rule: 'ios.uncaught_exception_handler', test: (fn) => firstMatch(/^NSSetUncaughtExceptionHandler$/, importNames(fn)) },
  { rule: 'ios.webview_usage', test: (fn) => firstMatch(/^(?:UIWebView|WKWebView)$/, fn.classes) ?? firstMatch(/UIWebView|WKWebView/, importNames(fn)) ?? firstMatch(/^(?:loadHTMLString:baseURL:|evaluateJavaScript:completionHandler:|stringByEvaluatingJavaScriptFromString:)$/, selectors(fn)) },
  { rule: 'code.ios_webview_js', test: (fn) => firstMatch(/^UIWebView$/, fn.classes) ?? firstMatch(/^setJavaScriptEnabled:$/, selectors(fn)) },
  { rule: 'ios.cookie_storage', test: (fn) => firstMatch(/^NSHTTPCookieStorage$/, fn.classes) ?? firstMatch(/^sharedHTTPCookieStorage$/, selectors(fn)) },
  { rule: 'ios.coredata_unencrypted', test: (fn) => firstMatch(/^(?:NSPersistentContainer|NSPersistentStoreCoordinator)$/, fn.classes) ?? firstMatch(/NSPersistentContainer|NSPersistentStoreCoordinator/, importNames(fn)) },
  { rule: 'ios.sqlite_unencrypted', test: (fn) => firstMatch(/^sqlite3_(?:open|open_v2|exec|prepare|prepare_v2)$/, importNames(fn)) },
  { rule: 'ios.no_file_protection', test: (fn) => firstMatch(/^(?:writeToFile:atomically:|writeToURL:atomically:)$/, selectors(fn)) ?? firstMatch(/^NSFileProtectionNone$/, fn.refs) },
  { rule: 'ios.oslog_usage', test: (fn) => firstMatch(/^(?:NSLog|NSLogv|os_log_impl)$/, importNames(fn)) },
  { rule: 'ios.swift_print_logging', test: (fn) => firstMatch(/^\$ss(?:5print_9separator|10debugPrint_9separator)/, importNames(fn)) },
  { rule: 'ios.wifi_network_info', test: (fn) => firstMatch(/^(?:CNCopyCurrentNetworkInfo|CNCopySupportedInterfaces)$/, importNames(fn)) },
];

/** The rules `API_USE` answers; when the executable's functions were read, the string-level hits for these are dropped. */
export const FUNCTION_LEVEL_RULES = new Set([
  ...API_USE.map((a) => a.rule),
  // Judged by what a function does as well, so the whole-binary version would only add the libraries' code.
  'net.ios_tls_trust_unevaluated',
  'ios.biometric_not_keychain_bound',
  'ios.keychain_no_accessibility',
  'ios.url_scheme_handler',
]);

export function analyseIosBinary(buffer: Buffer, appModule: string, nibNames: Iterable<string> = []): IosAnalysis | undefined {
  const model: MachoModel | undefined = readModel(buffer);
  if (!model) return undefined;
  if (model.encrypted) return { hits: [], listing: { lines: [], headerLine: new Map(), blockSize: new Map() }, functionCount: 0, appFunctionCount: 0, encrypted: true };

  const all = analyseFunctions(model);
  const region = appRegion(model, appModule, new Set(nibNames));
  const byAddress = new Map(all.map((f) => [f.address, f]));
  const origin = new Map(
    all.map((f) => {
      const byName = originOf(f, appModule);
      if (byName === 'app' || !region) return [f.address, byName] as const;
      // A static library's code is linked apart from the app's own objects, so an address outside the
      // region the app's classes occupy belongs to a library even when its name says nothing.
      if (f.address >= region.lo && f.address <= region.hi) return [f.address, byName === 'library' ? 'library' : 'app'] as const;
      // A method of a named Objective-C class no library claims stays the app's: its helpers are not always
      // linked beside its view controllers. Only code with nothing to name it is given to the libraries.
      return [f.address, f.objc ? byName : 'library'] as const;
    }),
  );

  // A block belongs to the method its symbol names (`___74-[Class selector]_block_invoke`); without symbols
  // the link is lost, which only shortens what `reach` can see.
  const blockLookup = new Map<string, FunctionFact[]>();
  for (const fn of all) {
    const m = fn.name.match(/^_{0,3}\d+-\[([^\]]+)\]_block_invoke/);
    if (!m) continue;
    for (const sign of ['-', '+']) blockLookup.set(`${sign}[${m[1]}]`, [...(blockLookup.get(`${sign}[${m[1]}]`) ?? []), fn]);
  }

  const app = all.filter((f) => origin.get(f.address) !== 'library');
  const hits: IosHit[] = [];
  const add = (rule: string, fn: FunctionFact, evidence: string, key?: string) => hits.push({ rule, fn, evidence: evidence.split(fn.name).join(readableSymbol(fn.name)), key });

  for (const fn of app) {
    const names = CALL_NAMES(fn.calls);
    const own = new Set(names);
    const extended = reach(fn, byAddress, blockLookup);
    const has = (re: RegExp, set: Iterable<string> = extended.names) => [...set].some((n) => re.test(n));
    const isMethod = (re: RegExp) => re.test(fn.objc?.selector ?? fn.name);

    // --- An authentication-challenge handler that takes the server's word for it
    if (isMethod(/didReceiveChallenge|willSendRequestForAuthenticationChallenge|didReceiveAuthenticationChallenge|didReceive.*challenge/i)) {
      const trusts = has(/^credentialForTrust:$|NSURLCredential.*trust|URLCredential.*trust|credentialWithTrust|initWithTrust:/i);
      const evaluates = has(/^SecTrustEvaluate|^SecTrustGetCertificateAtIndex|^SecTrustCopyCertificateChain|^SecTrustCopyKey|^SecTrustSetAnchorCertificates|^SecTrustEvaluateAsync/);
      if (trusts && !evaluates) add('net.ios_tls_trust_unevaluated', fn, `${fn.name} answers the challenge with the server trust and never evaluates it`);
    }

    // --- Biometric check that is only a yes or no
    if (own.has('evaluatePolicy:localizedReason:reply:') || has(/evaluatePolicy.*localizedReason|LAContext.*evaluatePolicy/i, own)) {
      const bound = has(/^SecAccessControlCreateWithFlags$/) || [...extended.refs].some((r) => /kSecAccessControl|kSecAttrAccessControl|kSecUseOperationPrompt/.test(r));
      if (!bound) add('ios.biometric_not_keychain_bound', fn, `${fn.name} calls evaluatePolicy:localizedReason:reply: (LAContext) and uses its yes or no, with no Keychain item protected by it`);
    }

    // --- Keychain write that never says when the item may be read
    if (own.has('SecItemAdd')) {
      const says = [...extended.refs].some((r) => /kSecAttrAccessible|kSecAttrAccessControl/.test(r)) || has(/^SecAccessControlCreateWithFlags$/);
      if (!says) add('ios.keychain_no_accessibility', fn, `${fn.name} calls SecItemAdd without kSecAttrAccessible`);
    }

    // --- Sensitive data logged
    const logs = fn.calls.some((c) => (c.kind === 'import' && /^(NSLog|NSLogv|os_log_impl|printf|\$ss5print|\$ss10debugPrint)/.test(c.name.replace(/^_/, ''))) || (c.kind === 'import' && /^_?\$ss5print/.test(c.name)));
    if (logs) {
      const literal = fn.strings.find((s) => SENSITIVE_WORD.test(s) && (/%[@dsflu]|:\s*$|=\s*$|\bis\b|\bwas\b/.test(s) || s.length < 40));
      if (literal) add('ios.sensitive_data_logged', fn, `${fn.name} logs with "${literal.slice(0, 60)}"`);
    }

    // --- A sensitive value saved in NSUserDefaults
    const setsDefault = fn.calls.some((c) => (c.kind === 'msg' && /^set(?:Object|Value|Bool|Integer|Float|Double)?:forKey:$/.test(c.selector)) || (c.kind === 'import' && /NSUserDefaultsC.*forKey|UserDefaults.*set.*forKey/.test(c.name)));
    const usesDefaults = fn.calls.some((c) => (c.kind === 'msg' && (c.selector === 'standardUserDefaults' || c.receiver === 'NSUserDefaults')) || (c.kind === 'import' && /UserDefaults/.test(c.name))) || fn.refs.some((r) => /UserDefaults/.test(r)) || extended.names.has('standardUserDefaults');
    if (setsDefault && usesDefaults) {
      const keyLiteral = fn.strings.find((s) => SENSITIVE_KEY.test(s) && s.length < 40 && !/\s/.test(s));
      if (keyLiteral) add('ios.sensitive_in_userdefaults', fn, `${fn.name} stores a value under "${keyLiteral}" in UserDefaults`);
    }

    // --- A literal that is a credential, key or password passed to something that takes one
    for (const call of fn.calls) {
      if (call.kind === 'import') {
        const positions = KEY_IMPORT[call.name];
        if (!positions) continue;
        for (const p of positions) {
          const lit = call.args[p]?.str;
          if (lit && lit.length >= 4 && /[A-Za-z0-9].*[A-Za-z0-9]/.test(lit)) add('ios.hardcoded_secret_argument', fn, `${fn.name} passes the literal "${lit.slice(0, 40)}" to ${call.name}`);
        }
        if (call.name === 'CCCrypt' || call.name === 'CCCryptorCreate') {
          const alg = call.args[1]?.imm;
          const options = call.args[2]?.imm;
          if (alg !== undefined && WEAK_CC_ALGORITHM[alg]) add('crypto.ios_weak_cipher', fn, `${fn.name} calls ${call.name} with ${WEAK_CC_ALGORITHM[alg]}`);
          else if (options !== undefined && (options & 2) === 2 && alg !== undefined && alg < 7) add('crypto.ios_ecb_mode', fn, `${fn.name} calls ${call.name} in ECB mode`);
        }
        if (call.name === 'CCKeyDerivationPBKDF') {
          const rounds = call.args[6]?.imm;
          const prf = call.args[5]?.imm;
          if (rounds !== undefined && rounds > 0 && rounds < 10000) add('crypto.ios_weak_kdf', fn, `${fn.name} derives a key with PBKDF2 and only ${rounds} rounds`);
          else if (prf === 1) add('crypto.ios_weak_kdf', fn, `${fn.name} derives a key with PBKDF2-HMAC-SHA1`);
        }
      } else if (call.kind === 'msg' && KEY_PARAM.test(call.selector)) {
        const direct = call.args.slice(2).map((a) => a.str).find((s) => s && s.length >= 4 && !/\s/.test(s) && /[A-Za-z0-9].*[A-Za-z0-9]/.test(s));
        // Swift converts a string literal to an NSString before the call, so the argument register no longer
        // points at the literal; the function still holds it. A key-shaped literal in the same function is the key.
        const swiftApp = SWIFT_MANGLED.test(fn.name) && origin.get(fn.address) === 'app';
        const nearby = direct ?? (swiftApp ? fn.strings.find((s) => /^[A-Za-z0-9_$@!#%^&*+=.-]{12,64}$/.test(s) && /[A-Za-z]/.test(s) && /[0-9]/.test(s) && !/^[A-Z]-[A-Z]{2,5}\d{3,}$/.test(s) && !/^[A-Za-z]+(?:\.[A-Za-z0-9]+)+$/.test(s) && !/^_?[A-Za-z]+[A-Z][a-z]+\d*$/.test(s)) : undefined);
        if (nearby) add('ios.hardcoded_secret_argument', fn, `${fn.name} passes ${direct ? 'the literal' : 'a key-shaped literal'} "${nearby.slice(0, 40)}" to ${call.receiver ? `${call.receiver} ` : ''}${call.selector}`);
      }
    }

    // --- Credential-looking literal in code that checks or stores a credential
    const literals = fn.strings.filter(credentialLike);
    if (literals.length > 0) {
      const property = CREDENTIAL_PROPERTY.test(fn.name);
      // The function's own name is the strong signal. Messages like "Incorrect Username or Password" count only
      // in code known to be the app's, where a stray literal is unlikely to belong to a library.
      const authContext = AUTH_NAME.test(fn.name) || (origin.get(fn.address) === 'app' && fn.strings.some((s) => AUTH_MESSAGE.test(s) && s.length < 80));
      const compares = fn.calls.some((c) => (c.kind === 'msg' && COMPARE.test(c.selector)) || (c.kind === 'import' && COMPARE.test(c.name)));
      // A login function holding a credential-looking literal is enough; elsewhere the literal must be compared.
      const loginFunction = /(login|signin|password|passcode|credential|authenticate|unlock)/i.test(fn.name);
      if (property || (authContext && (compares || loginFunction))) {
        add('ios.hardcoded_credential_in_code', fn, `${fn.name} ${property ? 'initialises a credential-named value with' : 'compares against'} the literal "${literals[0].slice(0, 40)}"`);
      }
    }

    // --- A property list or file written to disk by a function that handles credentials
    const writesFile = fn.calls.some((c) => (c.kind === 'msg' && /^(?:writeToFile:atomically:|writeToURL:atomically:|writeToFile:options:error:|createFileAtPath:contents:attributes:)$/.test(c.selector)) || (c.kind === 'import' && /fopen|NSData.*write.*options|_T0.*writeToFile/.test(c.name)));
    if (writesFile) {
      const fileName = fn.strings.find((s) => /\.(?:plist|txt|json|dat|db|sqlite|xml|log)$/i.test(s));
      const sensitive = fn.strings.find((s) => SENSITIVE_WORD.test(s) && s.length < 40);
      if (fileName && (sensitive || AUTH_NAME.test(fn.name))) add('ios.sensitive_file_write', fn, `${fn.name} writes ${fileName}${sensitive ? ` (handles "${sensitive}")` : ''} without protection`);
    }

    // --- A method that is the whole of a login or entitlement decision
    if (fn.objc && /^(?:is|has|check|validate|verify)(?:Login|LoggedIn|User|Authenticated|Authorized|Admin|Premium|Subscribed|Unlocked|Pin|Passcode|Password)(?:Valid|Validated|Verified|Correct|Match|Matches|Ok|Success|Allowed|Entered)?:?$/.test(fn.objc.selector) && own.size <= 3) {
      add('ios.client_side_auth_check', fn, `${fn.name} makes a login or entitlement decision in the app, where one hook changes the answer`);
    }

    // --- SQL assembled from pieces, in code that is the app's
    const sql = fn.strings.find((t) => SQL_DYNAMIC.test(t) && !SQLITE_INTERNALS.test(t));
    if (sql) add('ios.sql_string_dynamic', fn, `${fn.name} builds SQL from pieces: ${sql.slice(0, 90)}`);

    // --- APIs whose use is worth knowing about, in the app's own functions
    const wide = withThinCallees(fn, byAddress);
    for (const api of isAccessor(fn) ? [] : API_USE) {
      const found = api.test(wide);
      if (found) add(api.rule, fn, `${fn.name} uses ${found}`, api.rule === 'ios.sqlite_unencrypted' || api.rule === 'ios.oslog_usage' ? undefined : undefined);
    }

    // --- A request to a cleartext URL, in the function that builds it
    const httpLiteral = fn.strings.find((s) => /^http:\/\/[^/\s]+\.[a-z]{2,}/i.test(s) && !/apple\.com|w3\.org|schemas\.|google-analytics|crashlytics|flurry|digicert|symantec|verisign/i.test(s));
    if (httpLiteral && own.size > 0) add('net.cleartext_url', fn, `${fn.name} uses ${httpLiteral.slice(0, 80)}`, httpLiteral.replace(/^http:\/\//i, '').split(/[/?#]/)[0]);

    // --- A URL handler that never checks who sent the URL
    if (isMethod(/^application:openURL:(?:options:|sourceApplication:annotation:)$|application\(_:open:options:\)/)) {
      const checks = [...extended.refs].some((r) => /OpenURLOptionsSourceApplicationKey|sourceApplication/i.test(r)) || [...extended.strings].some((s) => /sourceApplication|bundle ?identifier/i.test(s)) || fn.objc?.selector === 'application:openURL:sourceApplication:annotation:' && false;
      if (!checks) add('ios.url_scheme_handler', fn, `${fn.name} acts on a URL without checking which app sent it`);
    }
  }

  // A database library the app calls, and no app code that gives it a key.
  const DB_USE = /^(?:RLMRealm|RLMRealmConfiguration|CBLManager|CBLDatabase|YapDatabase|YapDatabaseConnection|FMDatabase|FMDatabaseQueue)$|RealmSwift|Realm.*Configuration|CBLManager|YapDatabase|GRDB|FMDB/;
  const KEYING = /^(?:setEncryptionKey:|encryptionKey|setKey:|setEncryptionKey:error:|sqlite3_key|sqlite3_key_v2|sqlite3_rekey|registerEncryptionKey:forDatabaseNamed:|setEncryptionKeyParameters:)$|encryptionKey|EncryptionKey/;
  const dbTokens = new Set<string>();
  const users = app.filter((f) => {
    if (isAccessor(f)) return false;
    const wide = withThinCallees(f, byAddress);
    const names = [
      ...wide.classes,
      ...wide.calls.map((c) => (c.kind === 'import' ? c.name : c.kind === 'msg' ? (c.receiver ?? '') : '')),
    ];
    const found = names.find((n) => DB_USE.test(n));
    if (found) dbTokens.add(/Realm|RLM/.test(found) ? 'Realm' : /CBL/.test(found) ? 'Couchbase Lite' : /Yap/.test(found) ? 'YapDatabase' : /GRDB/.test(found) ? 'GRDB' : 'FMDB');
    return Boolean(found);
  });
  const keyed = app.some((f) => f.calls.some((c) => (c.kind === 'msg' && KEYING.test(c.selector)) || (c.kind === 'import' && KEYING.test(c.name))));
  if (users.length > 0 && !keyed) {
    const names = [...new Set(users.slice(0, 3).map((f) => f.name))].join(', ');
    add('ios.embedded_database_unencrypted', users[0], `${users.length} app function${users.length === 1 ? '' : 's'} use ${[...dbTokens].slice(0, 6).join(', ')} and none gives it an encryption key (${names})`);
  }

  // The listing: every app function that did something worth reading, hit functions first.
  const hitsByAddress = new Map<number, IosHit[]>();
  for (const h of hits) hitsByAddress.set(h.fn.address, [...(hitsByAddress.get(h.fn.address) ?? []), h]);
  const interesting = app.filter((f) => f.calls.length > 0 || f.strings.length > 0 || hitsByAddress.has(f.address));
  const ordered = [...interesting.filter((f) => hitsByAddress.has(f.address)), ...interesting.filter((f) => !hitsByAddress.has(f.address))].slice(0, 4000);
  const lines: string[] = [];
  const headerLine = new Map<number, number>();
  const blockSize = new Map<number, number>();
  for (const fn of ordered) {
    headerLine.set(fn.address, lines.length + 1);
    const block = functionBlock(fn, hitsByAddress.get(fn.address) ?? [], byAddress);
    lines.push(...block);
    blockSize.set(fn.address, block.length);
  }

  return { hits, listing: { lines, headerLine, blockSize }, functionCount: all.length, appFunctionCount: app.length, encrypted: false };
}
