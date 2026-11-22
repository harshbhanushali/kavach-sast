/**
 * The map's state: files appearing as the decompiler writes them, then read and flagged as the rule pass
 * goes through them. One model serves both the live view of a running scan and the replay of a finished one
 * (`replayTimeline.ts` feeds it the same kinds of step), so the two always look and behave alike.
 *
 * Nothing is known in advance, so the layout grows. A folder gets a place when its first file shows up, and
 * a file's place inside its folder never changes (a golden-angle spiral by arrival order), so the map
 * settles instead of reshuffling. Folders that start to overlap push each other apart a little every frame.
 *
 * Live events arrive in bursts, one poll's worth at a time, and are played out in order at a pace that keeps
 * the backlog short, so a burst reads as a stream.
 *
 * No browser or React imports, so it can be exercised from node.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type LiveEventIn =
  | { t: 'files'; paths: string[] }
  | { t: 'visit'; paths: string[] }
  | { t: 'hit'; file: string; title: string; severity: Severity; category: string }
  | { t: 'app'; packageName: string; /** `packageName` is the iOS bundle's folder (`Acme.app`), not an Android package. */ bundle?: boolean };

/** The folder a file is grouped under: `sources/com/acme/app/ui/Main.java` → `com/acme/app`. */
export function clusterKey(path: string, depth = 3): string {
  const parts = path.split('/');
  parts.pop();
  while (parts[0] && /^(?:sources|smali(?:_classes\d+)?|java|src)$/.test(parts[0]) && parts.length > 1) parts.shift();
  // `Payload/App.app/Frameworks/Realm.framework/Realm` → the framework; the app bundle is one group.
  if (parts[0] === 'Payload') parts.shift();
  const framework = parts.findIndex((p) => /\.(?:framework|appex|bundle)$/.test(p));
  if (framework >= 0) return parts.slice(0, framework + 1).join('/');
  // The rest of an app bundle is the app's own resources: one group, with the loose libraries beside them.
  if (/\.app$/.test(parts[0] ?? '')) return parts.slice(0, parts[1] === 'Frameworks' || parts[1] === 'PlugIns' ? 2 : 1).join('/');
  return parts.slice(0, depth).join('/') || '(root)';
}

export type LiveNode = { path: string; cluster: number; index: number; born: number; read: boolean; flags: Severity[]; titles: string[]; dx: number; dy: number };
export type LiveCluster = { name: string; x: number; y: number; size: number; nodes: number[]; /** The app's own package. */ own: boolean };
export type LogEntry = { title: string; file: string; severity: Severity; at: number; /** Which finding of a replayed report this is. */ ref?: number };
export type Callout = { node: number; title: string; severity: Severity; at: number; slot: number };

/** One step of the map: a file appears, a file is read, a rule matches in a file. */
export type MapItem = { k: 'add'; path: string } | { k: 'visit'; path: string } | { k: 'hit'; file: string; title: string; severity: Severity; ref?: number };

const GOLDEN = Math.PI * (3 - Math.sqrt(5));
const SPACING = 0.012;
const MAX_CLUSTERS = 80;
const MAX_NODES = 20000;
const OTHER = '(other folders)';

/** Offset of the `index`-th file from its folder's centre; fixed once chosen. */
export const nodeOffset = (index: number) => {
  const r = SPACING * Math.pow(index + 0.5, 0.45);
  const a = index * GOLDEN;
  return { dx: Math.cos(a) * r, dy: Math.sin(a) * r };
};
export const clusterRadius = (nodes: number) => SPACING * Math.pow(Math.max(1, nodes), 0.45) + 0.02;

export class LiveMap {
  nodes: LiveNode[] = [];
  clusters: LiveCluster[] = [];
  byPath = new Map<string, number>();
  private byKey = new Map<string, number>();
  private queue: MapItem[] = [];
  private head = 0;

  /** Where the hub is, and the folder it is heading to. */
  hub = { x: 0, y: 0 };
  current?: { path: string; cluster: number };
  beams: { node: number; at: number }[] = [];
  callouts: Callout[] = [];
  log: LogEntry[] = [];
  read = 0;
  counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  total = 0;
  /** Seconds since the first event, driven by `advance`. */
  clock = 0;
  /** The app's own package as a path (`com/acme/app`), or its bundle folder (`Acme.app`), once known; drawn as "your code". */
  ownPath?: string;
  /** Files added while this is set arrive already settled instead of flashing in (a replay starts from the whole app). */
  quiet = false;

  get discovered() {
    return this.nodes.length;
  }
  get backlog() {
    return this.queue.length - this.head;
  }

  /** Names the app's package (or, for iOS, its `.app` folder) so its own code can be told from the libraries'. */
  setApp(packageName: string, bundle = false) {
    this.bundle = bundle;
    this.ownPath = bundle ? packageName : packageName.replace(/\./g, '/');
    for (const c of this.clusters) c.own = this.isOwn(c.name);
  }

  private bundle = false;

  private isOwn(folder: string): boolean {
    if (!this.ownPath) return false;
    // An iOS bundle's frameworks and extensions are libraries; only the bundle's own folder is the app.
    return this.bundle ? folder === this.ownPath : folder.includes(this.ownPath);
  }

  push(events: LiveEventIn[]) {
    for (const e of events) {
      if (e.t === 'app') this.setApp(e.packageName, e.bundle);
      else if (e.t === 'files') for (const path of e.paths) this.queue.push({ k: 'add', path });
      else if (e.t === 'visit') for (const path of e.paths) this.queue.push({ k: 'visit', path });
      else this.queue.push({ k: 'hit', file: e.file, title: e.title, severity: e.severity });
    }
  }

  /** The folder a file lives in, created at the first free spot beside the others. */
  private clusterFor(path: string): number {
    const key = clusterKey(path, path.startsWith('sources/') ? 5 : 3);
    let index = this.byKey.get(key);
    if (index !== undefined) return index;
    // The last slot is kept for everything past the cap.
    const full = this.clusters.length >= MAX_CLUSTERS - 1;
    if (full) {
      index = this.byKey.get(OTHER);
      if (index !== undefined) return index;
    }
    const name = full ? OTHER : key;
    const radius = clusterRadius(1);
    let spot = { x: 0, y: 0 };
    if (this.clusters.length > 0) {
      for (let step = 0; step < 3000; step += 1) {
        const angle = step * 0.35;
        const dist = 0.0014 * step + 0.05;
        const x = Math.cos(angle) * dist;
        const y = Math.sin(angle) * dist * 0.82;
        if (this.clusters.every((c) => Math.hypot(c.x - x, c.y - y) >= clusterRadius(c.nodes.length) + radius + 0.02)) {
          spot = { x, y };
          break;
        }
      }
    }
    this.clusters.push({ name, ...spot, size: 0, nodes: [], own: this.isOwn(name) });
    index = this.clusters.length - 1;
    this.byKey.set(name === OTHER ? OTHER : key, index);
    return index;
  }

  private addNode(path: string): number {
    const existing = this.byPath.get(path);
    if (existing !== undefined) return existing;
    if (this.nodes.length >= MAX_NODES) return -1;
    const cluster = this.clusterFor(path);
    const c = this.clusters[cluster];
    const index = c.nodes.length;
    // Where the file sits in its folder never changes, so it is worked out once.
    const { dx, dy } = nodeOffset(index);
    const node: LiveNode = { path, cluster, index, born: this.quiet ? -10 : this.clock, read: false, flags: [], titles: [], dx, dy };
    this.nodes.push(node);
    c.nodes.push(this.nodes.length - 1);
    c.size = c.nodes.length;
    this.byPath.set(path, this.nodes.length - 1);
    return this.nodes.length - 1;
  }

  /** Where a node is drawn, in map units. */
  place(node: number) {
    const n = this.nodes[node];
    const c = this.clusters[n.cluster];
    return { x: c.x + n.dx, y: c.y + n.dy };
  }

  /** Plays one step now. `silent` leaves out the beam and the callout, for jumping to a point in a replay. */
  apply(item: MapItem, silent = false) {
    if (item.k === 'add') {
      this.addNode(item.path);
    } else if (item.k === 'visit') {
      const node = this.addNode(item.path);
      if (node < 0) return;
      if (!this.nodes[node].read) {
        this.nodes[node].read = true;
        this.read += 1;
      }
      this.current = { path: item.path, cluster: this.nodes[node].cluster };
      if (!silent) this.beams.push({ node, at: this.clock });
    } else {
      const node = this.addNode(item.file);
      this.total += 1;
      this.counts[item.severity] += 1;
      this.log.unshift({ title: item.title, file: item.file, severity: item.severity, at: this.clock, ref: item.ref });
      if (this.log.length > 40) this.log.length = 40;
      if (node < 0) return;
      this.nodes[node].flags.push(item.severity);
      this.nodes[node].titles.push(item.title);
      if (!silent) this.callouts.push({ node, title: item.title, severity: item.severity, at: this.clock, slot: 0 });
    }
  }

  /**
   * Plays out queued events and settles the layout. The pace keeps the backlog to about a second, and
   * speeds up when it is long, so a tab that was in the background catches up rather than lagging.
   */
  advance(dt: number) {
    this.clock += dt;
    const backlog = this.backlog;
    if (backlog > 0) {
      const take = Math.min(backlog, Math.max(1, Math.ceil(backlog * Math.min(1, dt / 0.9)), Math.ceil(backlog / 25)));
      for (let i = 0; i < take; i += 1) this.apply(this.queue[this.head + i]);
      this.head += take;
      if (this.head > 4096) {
        this.queue = this.queue.slice(this.head);
        this.head = 0;
      }
    }
    this.beams = this.beams.filter((b) => this.clock - b.at < 0.5).slice(-300);
    this.callouts = this.callouts.filter((c) => this.clock - c.at < 2.4);
    this.relax();

    if (this.current) {
      const target = this.clusters[this.current.cluster];
      const k = 1 - Math.exp(-dt * 9);
      this.hub.x += (target.x - this.hub.x) * k;
      this.hub.y += (target.y - this.hub.y) * k;
    }
  }

  /** Folders that overlap ease apart; the whole drifts gently toward the middle. */
  relax() {
    const cs = this.clusters;
    for (let i = 0; i < cs.length; i += 1) {
      for (let j = i + 1; j < cs.length; j += 1) {
        const a = cs[i];
        const b = cs[j];
        const need = clusterRadius(a.nodes.length) + clusterRadius(b.nodes.length) + 0.02;
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let d = Math.hypot(dx, dy);
        if (d >= need) continue;
        if (d < 1e-6) {
          dx = Math.cos(i + j);
          dy = Math.sin(i + j);
          d = 1;
        }
        const push = Math.min(0.02, (need - d) * 0.18);
        const ux = dx / d;
        const uy = dy / d;
        // The bigger folder moves less.
        const wa = b.nodes.length / (a.nodes.length + b.nodes.length || 1);
        a.x -= ux * push * wa;
        a.y -= uy * push * wa;
        b.x += ux * push * (1 - wa);
        b.y += uy * push * (1 - wa);
      }
    }
    for (const c of cs) {
      c.x *= 0.9995;
      c.y *= 0.9995;
    }
  }

  /** Runs the layout until it stops moving (or `rounds` is up), so a map built all at once starts settled. */
  settle(rounds = 400) {
    for (let i = 0; i < rounds; i += 1) this.relax();
  }

  /**
   * Back to "nothing read, nothing flagged", keeping the files and where they are. A replay uses it to jump
   * to an earlier point and play forward from there.
   */
  resetProgress() {
    for (const n of this.nodes) {
      n.read = false;
      n.flags = [];
      n.titles = [];
    }
    this.read = 0;
    this.total = 0;
    this.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    this.log = [];
    this.beams = [];
    this.callouts = [];
    this.current = undefined;
  }

  /** The box the map occupies, discs included. */
  bounds() {
    if (this.clusters.length === 0) return { minX: -1, maxX: 1, minY: -1, maxY: 1 };
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const c of this.clusters) {
      const r = clusterRadius(c.nodes.length);
      minX = Math.min(minX, c.x - r);
      maxX = Math.max(maxX, c.x + r);
      minY = Math.min(minY, c.y - r);
      maxY = Math.max(maxY, c.y + r);
    }
    return { minX, maxX, minY, maxY };
  }
}
