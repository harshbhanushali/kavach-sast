/**
 * Telling the console how far a scan has got.
 *
 * A scan of a large APK takes about two minutes, nearly all of it inside two
 * blocking calls to apktool and jadx. Until now the console showed an
 * indeterminate stripe for that whole time, which is honest but useless: a
 * stripe that means "working" looks identical whether the scan is thirty
 * seconds from finishing or wedged.
 *
 * The percentage is measured, not guessed. Each stage owns a slice of the bar
 * and reports how far through itself it is:
 *
 *   - jadx prints `progress: 3596 of 5245 (68%)` as it decompiles. It is
 *     redirected to a log the main thread tails, so the longest stage by far
 *     reports genuine class-by-class progress.
 *   - The rule pass is a loop this code owns, so it counts files scanned
 *     against files to scan.
 *   - The short stages report their own boundaries, which is all there is to
 *     report about a step that takes a second.
 *
 * Nothing here interpolates against a clock. A bar that advances because time
 * passed rather than because work happened is worse than no bar: it keeps
 * moving when the scan has hung.
 *
 * Kept in memory on purpose. It is worthless a second after the scan finishes,
 * survives nothing, and writing it to the database would mean a row per poll.
 */

export type ScanStage =
  | 'received'
  | 'unpacking'
  | 'decoding'
  | 'decompiling'
  | 'scanning'
  | 'inspecting'
  | 'reporting'
  | 'done';

/** Where each stage ends. Roughly proportional to observed wall-clock time. */
const BOUNDARY: Record<ScanStage, number> = {
  received: 2,
  unpacking: 8,
  decoding: 25,
  // jadx is the long pole by a wide margin on any real APK.
  decompiling: 70,
  scanning: 88,
  inspecting: 96,
  reporting: 99,
  done: 100,
};

/** What the console shows beside the bar. */
const LABEL: Record<ScanStage, string> = {
  received: 'Received',
  unpacking: 'Reading the archive',
  decoding: 'Decoding resources and the manifest',
  decompiling: 'Decompiling to readable Java',
  scanning: 'Running rules over the code',
  inspecting: 'Inspecting native libraries and dependencies',
  reporting: 'Building the report',
  done: 'Done',
};

export type Progress = { stage: ScanStage; percent: number; label: string; at: number };

const live = new Map<string, Progress>();

/** Progress older than this is from a scan nobody is watching any more. */
const TTL_MS = 10 * 60 * 1000;

/** Where each stage begins, derived from where the previous one ends. */
const ORDER: ScanStage[] = [
  'received', 'unpacking', 'decoding', 'decompiling',
  'scanning', 'inspecting', 'reporting', 'done',
];

function startOf(stage: ScanStage): number {
  const index = ORDER.indexOf(stage);
  return index <= 0 ? 0 : BOUNDARY[ORDER[index - 1]];
}

/**
 * Record progress.
 *
 * `fraction` is how far through the stage the work actually is, between 0 and
 * 1, when the stage can measure itself. Omitted, the stage is treated as
 * complete — which is what a step that finishes in a second should say.
 */
export function report(id: string | undefined, stage: ScanStage, fraction?: number): void {
  if (!id) return;

  const start = startOf(stage);
  const end = BOUNDARY[stage];
  const within = fraction === undefined ? 1 : Math.min(1, Math.max(0, fraction));
  const percent = Math.round(start + (end - start) * within);

  // Never go backwards. A late message from a finished stage arriving after
  // the next one started would otherwise make the bar jump back.
  const previous = live.get(id);
  if (previous && previous.percent > percent && previous.stage !== stage) return;

  live.set(id, {
    stage,
    percent: previous ? Math.max(previous.percent, percent) : percent,
    label: LABEL[stage],
    at: Date.now(),
  });

  // Opportunistic sweep — there is no scheduler here and no need for one.
  if (live.size > 64) {
    const cutoff = Date.now() - TTL_MS;
    for (const [key, value] of live) if (value.at < cutoff) live.delete(key);
  }
}

export function progressOf(id: string): Progress | undefined {
  return live.get(id);
}

export function forget(id: string | undefined): void {
  if (!id) return;
  live.delete(id);
  feed.delete(id);
}

/**
 * The callback shape the analysers take.
 *
 * `watch` names a file the caller should tail for finer progress — jadx's log.
 * The analyser cannot tail it itself: it is about to block this thread on the
 * very process writing it.
 */
export type ProgressSink = (stage: ScanStage, fraction?: number, watch?: string, event?: LiveEvent) => void;

/**
 * What the console's live map is told about while a scan runs.
 *
 * `files`: files that now exist (jadx writing its output). `visit`: files the rule pass has just read,
 * in the order it read them. `hit`: a rule matched in a file. These are the scan's own steps, not a
 * simulation. A `hit` is a rule match, which is not yet a finding: the report merges matches into
 * findings at the end, so the live count can be higher than the final one.
 */
export type LiveEvent =
  | { t: 'files'; paths: string[] }
  | { t: 'visit'; paths: string[] }
  | { t: 'hit'; file: string; title: string; severity: 'info' | 'low' | 'medium' | 'high' | 'critical'; category: string }
  /** The app's package, once the manifest is read, so the map can tell its own code from the libraries'. */
  | { t: 'app'; packageName: string; /** `packageName` is the iOS bundle's folder (`Acme.app`), not an Android package. */ bundle?: boolean };

/** Events held per scan. A large app is a hundred or so batches plus the hits; this is generous. */
const MAX_EVENTS = 6000;
const feed = new Map<string, LiveEvent[]>();

export function emit(id: string | undefined, event: LiveEvent): void {
  if (!id) return;
  const list = feed.get(id) ?? [];
  // A full buffer stops taking events rather than dropping old ones: a cursor into it must stay valid.
  if (list.length < MAX_EVENTS) list.push(event);
  feed.set(id, list);
}

/** Events after the first `after`, and the cursor to ask for next. */
export function eventsSince(id: string, after: number): { events: LiveEvent[]; next: number } {
  const list = feed.get(id) ?? [];
  const from = Math.max(0, Math.min(after, list.length));
  return { events: list.slice(from, from + 400), next: Math.min(list.length, from + 400) };
}
