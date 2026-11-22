import type { ReactNode } from 'react';

export function Panel({ title, subtitle, children, actions }: {
  title?: string;
  subtitle?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="panel">
      {(title || actions) && (
        <header className="panel-header flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            {title && <h2 className="text-[0.95rem] font-semibold text-slate-50">{title}</h2>}
            {subtitle && <p className="mt-1 text-sm leading-relaxed text-slate-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function Button({ children, onClick, variant = 'default', disabled, title }: {
  children: ReactNode;
  onClick?: () => void;
  variant?: 'default' | 'primary' | 'danger' | 'ghost';
  disabled?: boolean;
  title?: string;
}) {
  const styles = {
    default: 'bg-slate-800 hover:bg-slate-700 text-slate-100 border-slate-600',
    primary: 'bg-ember-600 hover:bg-ember-500 text-white border-ember-400 shadow-sm',
    danger: 'bg-rose-700 hover:bg-rose-600 text-white border-rose-500 light:bg-[#be123c] light:hover:bg-[#e11d48] light:border-[#be123c]',
    ghost: 'bg-transparent hover:bg-slate-800 text-slate-300 border-transparent',
  }[variant];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded-md border px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${styles}`}
    >
      {children}
    </button>
  );
}

/**
 * Severity is ordinal, so the palette has to read as a ramp rather than as five
 * unrelated colours — an operator scanning the grid should feel "worse" moving
 * down it without stopping to read each label.
 */
const SEVERITY_STYLES: Record<string, string> = {
  info: 'bg-slate-700/50 text-slate-200 border-slate-500',
  low: 'bg-sky-500/15 text-sky-200 border-sky-600',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-600',
  high: 'bg-orange-500/15 text-orange-200 border-orange-600',
  critical: 'bg-rose-500/20 text-rose-200 border-rose-500',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`pill uppercase tracking-wide ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info}`}>
      {severity}
    </span>
  );
}

const FP_STYLES: Record<string, string> = {
  low: 'bg-emerald-500/15 text-emerald-200 border-emerald-600',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-600',
  high: 'bg-rose-500/15 text-rose-200 border-rose-600',
};

/**
 * Prominent on purpose. An operator ticking a box needs to know, at that moment,
 * what enabling it will do to real users — so this is a readable pill, not a dim
 * footnote they will skip.
 */
export function FpBadge({ risk, notes }: { risk: string; notes: string }) {
  return (
    <span
      title={notes}
      className={`pill cursor-help ${FP_STYLES[risk] ?? FP_STYLES.medium}`}
    >
      <span className="opacity-70">FP</span>
      {risk}
    </span>
  );
}

const BAND_STYLES: Record<string, string> = {
  low: 'bg-emerald-500/15 text-emerald-200 border-emerald-600',
  elevated: 'bg-amber-500/15 text-amber-200 border-amber-600',
  high: 'bg-orange-500/20 text-orange-200 border-orange-500',
  critical: 'bg-rose-500/25 text-rose-100 border-rose-400',
};

export function RiskBadge({ band, score }: { band: string; score: number }) {
  return (
    <span className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 ${BAND_STYLES[band] ?? BAND_STYLES.low}`}>
      <span className="tabular text-base font-bold leading-none">{score}</span>
      <span className="text-xs font-semibold uppercase tracking-wider opacity-85">{band}</span>
    </span>
  );
}

export function FindingList({ findings }: {
  findings: { level: string; code: string; message: string; checkId?: string }[];
}) {
  if (findings.length === 0) return null;
  return (
    <ul className="space-y-2">
      {findings.map((f, i) => (
        <li
          key={`${f.code}-${i}`}
          className={`rounded-md border-l-[3px] border-y border-r px-3.5 py-2.5 text-sm ${
            f.level === 'error'
              ? 'border-rose-500 border-y-rose-900/60 border-r-rose-900/60 bg-rose-950/40 text-rose-100'
              : 'border-amber-500 border-y-amber-900/60 border-r-amber-900/60 bg-amber-950/30 text-amber-100'
          }`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow !text-current opacity-80">{f.level}</span>
            {f.checkId && <code className="text-xs opacity-80">{f.checkId}</code>}
          </div>
          <p className="mt-1 leading-relaxed">{f.message}</p>
        </li>
      ))}
    </ul>
  );
}

export function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  const pct = max === 0 ? 0 : Math.min(100, (value / max) * 100);
  // Full coverage reads green, partial reads neutral — a glanceable difference
  // that does not require reading the numbers.
  const tone = pct === 100 ? 'bg-emerald-400' : pct >= 50 ? 'bg-ember-400' : 'bg-slate-400';
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span className="text-slate-300">{label}</span>
        <span className="tabular text-xs font-medium text-slate-400">
          {value}/{max}
        </span>
      </div>
      <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full transition-all ${tone}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-10 text-center text-sm text-slate-400">{children}</p>;
}

/** A labelled value, for the device detail grid. */
export function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-medium text-slate-100">{value}</dd>
    </div>
  );
}

/**
 * How much work defeating this check costs an attacker who owns the device.
 *
 * Shown on every row because it is the honest counterweight to a checkbox:
 * ticking a `trivial` check is still worth doing, but an operator should know
 * they have bought a speed bump rather than a wall. The bar is a second,
 * non-colour encoding so the distinction survives a colour-blind reader — the
 * word is always present too.
 */
export function BypassBadge({ difficulty }: { difficulty: string }) {
  const spec: Record<string, { bars: number; cls: string; title: string }> = {
    trivial: {
      bars: 1,
      cls: 'text-rose-300',
      title: 'Trivial to bypass — a public one-liner or an off-the-shelf tool defeats this.',
    },
    moderate: {
      bars: 2,
      cls: 'text-amber-300',
      title: 'Moderate — needs a custom script, or patching the artifact.',
    },
    hard: {
      bars: 3,
      cls: 'text-emerald-300',
      title: 'Hard — needs consistent lying across kernel entry points, patched syscall stubs, or defeating server-side verification.',
    },
  };
  const { bars, cls, title } = spec[difficulty] ?? spec.moderate;

  return (
    <span className={`flex w-[5.5rem] shrink-0 items-center justify-end gap-1 ${cls}`} title={title}>
      <span className="text-[11px] tabular-nums">{difficulty}</span>
      <span className="flex items-end gap-px" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <span
            key={n}
            className={`w-[3px] rounded-sm ${n <= bars ? 'bg-current' : 'bg-slate-700'}`}
            style={{ height: `${3 + n * 2}px` }}
          />
        ))}
      </span>
    </span>
  );
}
