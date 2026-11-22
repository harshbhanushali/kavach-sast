/**
 * Whose code is this — yours, or a library you shipped?
 *
 * A scan of a real app returns findings from two very different places, and a
 * report that does not separate them wastes the reader's time. Of the 30
 * findings on a mid-size banking APK, most sit in `androidx`, `okhttp3` or an
 * analytics SDK. Those are not bugs the app team wrote and often not ones they
 * can fix in code — the remedy is a dependency upgrade, or nothing at all.
 * The handful in the app's own packages are the ones somebody has to act on
 * this week.
 *
 * So every location is attributed, and the finding carries the roll-up.
 *
 * Three signals feed the decision, in descending order of how much they prove:
 *
 * 1. **The app's own package roots.** If the manifest says the application id
 *    is `com.example.wallet`, then a class under `com/example/wallet/` is the
 *    app team's, full stop. This is checked first, so an app that genuinely
 *    ships code under a namespace that looks like a vendor's is still
 *    attributed to its author.
 * 2. **The resolved dependency coordinates.** `androidx.core:core` in the
 *    dependency list means `androidx.core.*` is library code, and this is
 *    ground truth read out of the artifact rather than a guess. It covers
 *    libraries nobody thought to add to the table below.
 * 3. **A table of well-known prefixes**, for libraries that ship no version
 *    metadata and so never appear in (2).
 *
 * Anything that matches none of them is `unknown`, which is reported as such
 * rather than guessed at. Claiming a finding is the app team's fault when it
 * is not is worse than admitting the attribution is uncertain.
 */
import type { FindingOrigin, Origin, SastFinding, SastLocation } from './types.ts';

export type { FindingOrigin, Origin, Provenance } from './types.ts';

/**
 * Package prefixes that are somebody else's code.
 *
 * Longest prefix wins, so `com.google.firebase` beats `com.google`. Names are
 * the ones a developer would search for, not the Maven coordinate — someone
 * reading "Firebase" knows what to do; "com.google.firebase:firebase-common"
 * makes them parse it first.
 */
const THIRD_PARTY_PREFIXES: { prefix: string; name: string }[] = [
  // Platform and language runtimes. Not "dependencies" in the build sense, but
  // equally not code the app team wrote.
  { prefix: 'java', name: 'Java standard library' },
  { prefix: 'javax', name: 'Java extensions' },
  { prefix: 'sun', name: 'JDK internals' },
  { prefix: 'android', name: 'Android framework' },
  { prefix: 'com.android', name: 'Android build tooling' },
  { prefix: 'dalvik', name: 'Android runtime' },
  { prefix: 'androidx', name: 'AndroidX' },
  { prefix: 'android.support', name: 'Android Support Library' },
  { prefix: 'kotlin', name: 'Kotlin standard library' },
  { prefix: 'kotlinx', name: 'Kotlin extensions' },
  { prefix: 'org.jetbrains', name: 'JetBrains annotations' },
  { prefix: 'org.intellij', name: 'JetBrains annotations' },
  { prefix: 'org.json', name: 'org.json' },
  { prefix: 'org.w3c', name: 'W3C DOM' },
  { prefix: 'org.xml', name: 'XML APIs' },
  { prefix: 'org.xmlpull', name: 'XmlPull' },

  // Google.
  { prefix: 'com.google.android.gms', name: 'Google Play Services' },
  { prefix: 'com.google.android.play', name: 'Google Play Core' },
  { prefix: 'com.google.android.material', name: 'Material Components' },
  { prefix: 'com.google.firebase', name: 'Firebase' },
  { prefix: 'com.google.gson', name: 'Gson' },
  { prefix: 'com.google.protobuf', name: 'Protocol Buffers' },
  { prefix: 'com.google.common', name: 'Guava' },
  { prefix: 'com.google.errorprone', name: 'Error Prone' },
  { prefix: 'com.google.crypto.tink', name: 'Tink' },
  { prefix: 'com.google.ads', name: 'Google Ads' },
  { prefix: 'com.google', name: 'Google' },

  // Networking and serialisation.
  { prefix: 'okhttp3', name: 'OkHttp' },
  { prefix: 'okio', name: 'Okio' },
  { prefix: 'retrofit2', name: 'Retrofit' },
  { prefix: 'com.squareup', name: 'Square' },
  { prefix: 'io.grpc', name: 'gRPC' },
  { prefix: 'com.fasterxml.jackson', name: 'Jackson' },
  { prefix: 'org.apache.http', name: 'Apache HttpClient' },
  { prefix: 'org.apache.commons', name: 'Apache Commons' },
  { prefix: 'org.apache.cordova', name: 'Cordova' },
  { prefix: 'org.apache', name: 'Apache' },

  // Crypto and security.
  { prefix: 'org.bouncycastle', name: 'Bouncy Castle' },
  { prefix: 'org.spongycastle', name: 'Spongy Castle' },
  { prefix: 'org.conscrypt', name: 'Conscrypt' },
  { prefix: 'net.sqlcipher', name: 'SQLCipher' },
  { prefix: 'net.zetetic', name: 'SQLCipher' },

  // UI, images, reactive.
  { prefix: 'com.bumptech.glide', name: 'Glide' },
  { prefix: 'com.airbnb', name: 'Airbnb (Lottie/Epoxy)' },
  { prefix: 'io.reactivex', name: 'RxJava' },
  { prefix: 'rx', name: 'RxJava' },
  { prefix: 'com.jakewharton', name: 'JakeWharton libraries' },

  // Cross-platform runtimes.
  { prefix: 'io.flutter', name: 'Flutter' },
  { prefix: 'dev.flutter', name: 'Flutter' },
  { prefix: 'dev.fluttercommunity', name: 'Flutter Community plugin' },
  { prefix: 'com.pichillilorenzo', name: 'flutter_inappwebview' },
  { prefix: 'com.baseflow', name: 'Baseflow (Flutter plugins)' },
  { prefix: 'com.it_nomads', name: 'flutter_secure_storage' },
  { prefix: 'com.tekartik', name: 'sqflite' },
  { prefix: 'com.dexterous', name: 'flutter_local_notifications' },
  { prefix: 'com.mr', name: 'Flutter plugin' },
  { prefix: 'com.scottyab', name: 'RootBeer' },
  { prefix: 'net.gotev', name: 'Android Upload Service' },
  { prefix: 'com.firebase', name: 'FirebaseUI' },
  { prefix: 'com.facebook.react', name: 'React Native' },
  { prefix: 'com.facebook', name: 'Facebook SDK' },
  { prefix: 'com.unity3d', name: 'Unity' },
  { prefix: 'org.chromium', name: 'Chromium / AndroidX WebKit' },

  // React Native community modules.
  //
  // These matter more than their obscurity suggests. They are npm packages
  // whose Android half is compiled into the APK, so they publish no
  // `META-INF/*.version` and never appear in the resolved dependency list —
  // the signal that catches every other library is blind to exactly these.
  // On a real React Native app they accounted for every unattributed finding,
  // and they are third-party code by any reading: nobody on the app team wrote
  // `com.reactnativecommunity.webview`.
  { prefix: 'com.reactnativecommunity', name: 'React Native Community' },
  { prefix: 'org.reactnative', name: 'React Native module' },
  { prefix: 'io.invertase', name: 'Invertase (RN Firebase / Notifee)' },
  { prefix: 'com.swmansion', name: 'Software Mansion (RN)' },
  { prefix: 'com.oblador', name: 'react-native-keychain / vector-icons' },
  { prefix: 'com.th3rdwave', name: 'react-native-safe-area-context' },
  { prefix: 'com.horcrux', name: 'react-native-svg' },
  { prefix: 'com.brentvatne', name: 'react-native-video' },
  { prefix: 'com.dylanvann', name: 'react-native-fast-image' },
  { prefix: 'com.learnium', name: 'react-native-device-info' },
  { prefix: 'com.zoontek', name: 'react-native-permissions' },
  { prefix: 'com.mrousavy', name: 'react-native-vision-camera / MMKV' },
  { prefix: 'com.margelo', name: 'Margelo (RN)' },
  { prefix: 'com.tencent.mmkv', name: 'MMKV' },
  { prefix: 'com.rnfs', name: 'react-native-fs' },
  { prefix: 'com.rnziparchive', name: 'react-native-zip-archive' },
  { prefix: 'com.henninghall', name: 'react-native-date-picker' },
  { prefix: 'com.bitgo', name: 'react-native-randombytes' },
  { prefix: 'org.linusu', name: 'react-native-get-random-values' },
  { prefix: 'com.reactlibrary', name: 'React Native module' },

  // Storage and DI.
  { prefix: 'io.realm', name: 'Realm' },
  { prefix: 'dagger', name: 'Dagger' },
  { prefix: 'javax.inject', name: 'Dagger' },
  { prefix: 'org.greenrobot', name: 'greenDAO / EventBus' },

  // Analytics, crash reporting, attribution, ads. The usual source of findings
  // in code nobody on the team has read.
  { prefix: 'com.crashlytics', name: 'Crashlytics' },
  { prefix: 'io.fabric', name: 'Fabric' },
  { prefix: 'com.appsflyer', name: 'AppsFlyer' },
  { prefix: 'com.adjust.sdk', name: 'Adjust' },
  { prefix: 'com.mixpanel', name: 'Mixpanel' },
  { prefix: 'com.segment', name: 'Segment' },
  { prefix: 'com.onesignal', name: 'OneSignal' },
  { prefix: 'com.braze', name: 'Braze' },
  { prefix: 'com.appboy', name: 'Braze' },
  { prefix: 'com.amplitude', name: 'Amplitude' },
  { prefix: 'com.newrelic', name: 'New Relic' },
  { prefix: 'com.applovin', name: 'AppLovin' },
  { prefix: 'com.ironsource', name: 'ironSource' },
  { prefix: 'com.vungle', name: 'Vungle' },
  { prefix: 'com.chartboost', name: 'Chartboost' },
  { prefix: 'com.mopub', name: 'MoPub' },

  // Cloud SDKs.
  { prefix: 'com.amazonaws', name: 'AWS SDK' },
  { prefix: 'software.amazon', name: 'AWS SDK' },
  { prefix: 'com.microsoft', name: 'Microsoft SDK' },
  { prefix: 'com.stripe', name: 'Stripe' },

  // Logging.
  { prefix: 'org.slf4j', name: 'SLF4J' },
  { prefix: 'ch.qos', name: 'Logback' },
  { prefix: 'timber.log', name: 'Timber' },

  // Ours, when the APK has been through the injector. Worth naming explicitly:
  // a finding in the protection we added is our problem, not the app team's.
  { prefix: 'ai.kavach', name: 'Kavach' },
];

/**
 * Native libraries that ship with a known runtime or SDK.
 *
 * A `.so` carries no package, so the file name is all there is to go on.
 */
const THIRD_PARTY_NATIVE: { pattern: RegExp; name: string }[] = [
  { pattern: /libflutter\.so$/, name: 'Flutter' },
  { pattern: /libreactnative|libhermes|libjsc/, name: 'React Native' },
  { pattern: /libunity\.so$|libil2cpp\.so$/, name: 'Unity' },
  { pattern: /libsqlcipher|libsqlite/, name: 'SQLite / SQLCipher' },
  { pattern: /libconscrypt/, name: 'Conscrypt' },
  { pattern: /libcrashlytics|libcrashpad/, name: 'Crashlytics' },
  { pattern: /libgms|libplaycore/, name: 'Google Play Services' },
  { pattern: /libc\+\+_shared\.so$/, name: 'NDK C++ runtime' },
  { pattern: /libkavach\.so$/, name: 'Kavach' },
];

/**
 * Application id suffixes that build variants add.
 *
 * `com.example.wallet.debug` is the same codebase as `com.example.wallet`, and
 * its classes live under the un-suffixed package. Without this the app's own
 * code in a debug build attributes to nobody.
 */
const VARIANT_SUFFIXES = /\.(debug|dev|development|staging|stage|qa|test|beta|alpha|internal|free|pro|lite|demo)$/;

/** The dotted package a location sits in, or undefined when it has none. */
export function packageOf(location: Pick<SastLocation, 'file' | 'className'>): string | undefined {
  // The JVM descriptor is the most reliable source when it is present: it comes
  // from the class itself rather than from wherever a decompiler put the file.
  if (location.className) {
    const match = location.className.match(/^L(.+);$/);
    if (match) {
      const parts = match[1].split('/');
      return parts.length > 1 ? parts.slice(0, -1).join('.') : undefined;
    }
  }

  // jadx: `sources/com/example/Foo.java`. apktool: `smali_classes2/com/example/Foo.smali`.
  const path = location.file.match(/^(?:sources|smali(?:_classes\d+)?)\/(.+)\.(?:java|smali)$/);
  if (!path) return undefined;
  const parts = path[1].split('/');
  return parts.length > 1 ? parts.slice(0, -1).join('.') : undefined;
}

/** `androidx.core:core` -> `androidx.core`. */
function packageFromCoordinate(coordinate: string): string | undefined {
  const group = coordinate.split(':')[0];
  return group && group.includes('.') ? group : undefined;
}

export type AttributionContext = {
  /** Application id from the manifest, or the iOS bundle id. */
  packageName?: string;
  /** Resolved dependency coordinates, used as ground truth for library roots. */
  dependencies?: { coordinate: string }[];
  /** Extra first-party roots, e.g. the packages of declared components. */
  extraAppRoots?: string[];
  /** Class names of every component the manifest declares. */
  declaredComponents?: string[];
};

/**
 * Package roots the app's own components live in, when they differ from its application id.
 *
 * An app published as `sg.vp.owasp_mobile.omtg_android` keeps its code in
 * `sg.vp.owasp_mobile.OMTG_Android`; matching only the application id leaves all of it
 * "unknown". A declared component whose package shares the application id's first two
 * segments is the app's own, whatever its third segment is called. Packages of known
 * libraries are never taken, since manifest merging declares their components too.
 */
export function componentRoots(context: AttributionContext): string[] {
  const app = context.packageName?.split('.') ?? [];
  if (app.length < 2) return [];
  const library = libraryRoots(context);
  const roots = new Set<string>();
  for (const name of context.declaredComponents ?? []) {
    const full = name.startsWith('.') ? `${context.packageName}${name}` : name.includes('.') ? name : `${context.packageName}.${name}`;
    const parts = full.split('.');
    if (parts.length < 3) continue;
    const pkg = parts.slice(0, -1).join('.');
    if (library.some(({ prefix }) => isUnder(pkg, prefix))) continue;
    if (parts[0].toLowerCase() !== app[0].toLowerCase() || parts[1].toLowerCase() !== app[1].toLowerCase()) continue;
    roots.add(parts.slice(0, Math.min(3, parts.length - 1)).join('.'));
  }
  return [...roots];
}

/** The package roots that belong to the app itself. */
export function appRoots(context: AttributionContext): string[] {
  const roots = new Set<string>();
  const add = (value?: string) => {
    if (!value) return;
    const trimmed = value.trim();
    // A root of one segment (`com`) would claim most of the artifact.
    if (trimmed.includes('.')) roots.add(trimmed);
  };

  add(context.packageName);
  if (context.packageName) add(context.packageName.replace(VARIANT_SUFFIXES, ''));
  for (const extra of context.extraAppRoots ?? []) add(extra);
  for (const root of componentRoots(context)) add(root);

  return [...roots];
}

function libraryRoots(context: AttributionContext): { prefix: string; name: string }[] {
  const roots = (context.dependencies ?? [])
    .map((d) => {
      const prefix = packageFromCoordinate(d.coordinate);
      return prefix ? { prefix, name: d.coordinate } : undefined;
    })
    .filter((r): r is { prefix: string; name: string } => Boolean(r));

  // Longest first so the most specific attribution wins.
  return [...roots, ...THIRD_PARTY_PREFIXES].sort((a, b) => b.prefix.length - a.prefix.length);
}

function isUnder(pkg: string, prefix: string): boolean {
  // Segment-aware: `com.exampleapp` must not match the root `com.example`.
  return pkg === prefix || pkg.startsWith(`${prefix}.`);
}

/** Classify one location. */
export function classify(
  location: Pick<SastLocation, 'file' | 'className'>,
  context: AttributionContext,
  cachedRoots?: { app: string[]; library: { prefix: string; name: string }[] },
): Provenance {
  const app = cachedRoots?.app ?? appRoots(context);
  const library = cachedRoots?.library ?? libraryRoots(context);

  const pkg = packageOf(location);

  if (pkg) {
    // The app's own namespace is checked first, deliberately. An app published
    // under `com.google.something` by Google is still Google's own code.
    for (const root of app) {
      if (isUnder(pkg, root)) {
        return { origin: 'first-party', because: `in the app's own package ${root}` };
      }
    }
    for (const { prefix, name } of library) {
      if (isUnder(pkg, prefix)) {
        return { origin: 'third-party', library: name, because: `in ${prefix}, which is ${name}` };
      }
    }
    return { origin: 'unknown', because: `package ${pkg} matches neither the app's namespace nor a known library` };
  }

  // Native code: no package, so the file name is the only signal.
  if (/\.so$/.test(location.file)) {
    for (const { pattern, name } of THIRD_PARTY_NATIVE) {
      if (pattern.test(location.file)) {
        return { origin: 'third-party', library: name, because: `a native library shipped by ${name}` };
      }
    }
    return { origin: 'unknown', because: 'a native library that could not be attributed by name' };
  }

  // The manifest, resources, assets and the signing block are properties of the
  // artifact the app team published. A library may have contributed an entry
  // via manifest merging, but the team ships the merged result and can change
  // it — so this is theirs to fix either way.
  if (/^(AndroidManifest\.xml|res\/|assets\/|META-INF\/|Info\.plist|.*\.mobileprovision|.*\.entitlements)/.test(location.file)) {
    return { origin: 'first-party', because: 'part of the artifact the app publishes' };
  }

  return { origin: 'unknown', because: 'not attributable to a package' };
}

/** How a finding's locations roll up. */
export function rollUp(locations: SastLocation[]): FindingOrigin {
  const origins = new Set(locations.map((l) => l.provenance?.origin).filter(Boolean));
  if (origins.size === 0) return 'unknown';
  if (origins.size === 1) return [...origins][0] as Origin;
  // A rule matching in both places is genuinely mixed, and saying so is more
  // useful than picking the worse of the two: the app-side hits are actionable
  // now and the library-side ones are not.
  if (origins.has('first-party') && origins.has('third-party')) return 'mixed';
  return origins.has('first-party') ? 'first-party' : 'third-party';
}

/**
 * Attribute every location on every finding, and roll the result up.
 *
 * Runs as a pass over finished findings rather than inside each scanner: the
 * app's package name and its dependency list are only known once the manifest
 * has been parsed, and threading them through every rule would couple the
 * pattern matching to artifact metadata it has no other use for.
 */
export function attribute(findings: SastFinding[], context: AttributionContext): SastFinding[] {
  const roots = { app: appRoots(context), library: libraryRoots(context) };

  return findings.map((finding) => {
    // A dependency advisory is about a third-party library by definition; the
    // location is a version file, which carries no package.
    if (finding.category === 'dependencies') {
      return { ...finding, origin: 'third-party' as const, libraries: [] };
    }

    const locations = finding.locations.map((location) => ({
      ...location,
      provenance: classify(location, context, roots),
    }));

    const libraries = [
      ...new Set(
        locations
          .map((l) => l.provenance?.library)
          .filter((name): name is string => Boolean(name)),
      ),
    ].sort();

    return { ...finding, locations, origin: rollUp(locations), libraries };
  });
}
