/**
 * Limits that keep one client, or one big upload, from taking the server down.
 *
 * Both are in memory and per process, which is right for this deployment: a
 * single instance with a single SQLite file. They exist to refuse excess work
 * early and cheaply, not to meter anyone.
 */

/** Allows `max` hits per key in each window; the count resets when the window ends. */
export class FixedWindowLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();
  private readonly max: number;
  private readonly windowMs: number;
  private readonly now: () => number;

  // Plain fields rather than constructor parameter properties: the server runs
  // TypeScript with Node's type stripping, which does not support those.
  constructor(max: number, windowMs: number, now: () => number = Date.now) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Records a hit and says whether it is allowed. */
  hit(key: string): { allowed: boolean; retryAfterSec: number } {
    const now = this.now();
    let window = this.windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, window);
    }
    window.count += 1;
    return { allowed: window.count <= this.max, retryAfterSec: Math.max(1, Math.ceil((window.resetAt - now) / 1000)) };
  }

  /** Whether the key is already over the limit, without counting this call. */
  blocked(key: string): { blocked: boolean; retryAfterSec: number } {
    const window = this.windows.get(key);
    const now = this.now();
    if (!window || window.resetAt <= now) return { blocked: false, retryAfterSec: 0 };
    return { blocked: window.count >= this.max, retryAfterSec: Math.max(1, Math.ceil((window.resetAt - now) / 1000)) };
  }

  reset(key: string): void {
    this.windows.delete(key);
  }

  /** Drops finished windows so the map does not grow with every address ever seen. */
  sweep(): void {
    const now = this.now();
    for (const [key, window] of this.windows) if (window.resetAt <= now) this.windows.delete(key);
  }

  get size(): number {
    return this.windows.size;
  }
}

export class BusyError extends Error {
  readonly retryAfterSec: number;

  constructor(retryAfterSec = 30) {
    super('the server is busy with other scans; try again shortly');
    this.name = 'BusyError';
    this.retryAfterSec = retryAfterSec;
  }
}

/**
 * At most `slots` scans run at once; up to `queue` more wait; the rest are refused.
 *
 * A scan decompiles an app into memory and onto disk, so unbounded concurrency
 * lets a handful of uploads exhaust the machine. Refusing with a Retry-After is
 * kinder than accepting work that will end in an out-of-memory kill.
 */
export class ScanGate {
  private running = 0;
  private readonly waiting: (() => void)[] = [];
  private drainWaiters: (() => void)[] = [];
  private readonly slots: number;
  private readonly queue: number;

  constructor(slots: number, queue: number) {
    this.slots = slots;
    this.queue = queue;
  }

  /** Resolves with a release function once a slot is free; rejects with BusyError when the queue is full. */
  async acquire(): Promise<() => void> {
    if (this.running < this.slots) {
      this.running += 1;
      return this.releaser();
    }
    if (this.waiting.length >= this.queue) throw new BusyError();
    // The slot is handed over by `release`, already counted, so there is no gap
    // in which a newcomer could take it and push the count past `slots`.
    await new Promise<void>((resolve) => this.waiting.push(resolve));
    return this.releaser();
  }

  private releaser(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = this.waiting.shift();
      if (next) {
        next(); // hand the slot straight to the next in line
        return;
      }
      this.running -= 1;
      if (this.running === 0) for (const done of this.drainWaiters.splice(0)) done();
    };
  }

  /** Whether a new scan would be refused right now. Checked before an upload is accepted, so a busy server does not first receive 600 MB. */
  get full(): boolean {
    return this.running >= this.slots && this.waiting.length >= this.queue;
  }

  get active(): number {
    return this.running;
  }

  get queued(): number {
    return this.waiting.length;
  }

  /** Resolves when nothing is running, or after `timeoutMs`. Returns whether it drained. */
  drain(timeoutMs: number): Promise<boolean> {
    if (this.running === 0 && this.waiting.length === 0) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs);
      timer.unref();
      this.drainWaiters.push(() => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }
}
