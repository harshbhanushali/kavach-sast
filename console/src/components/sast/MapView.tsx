/**
 * The map itself: one canvas that draws a `LiveMap`, and the loop that keeps it moving.
 *
 * The live view of a running scan and the replay of a finished one both use this, so they cannot drift
 * apart. What differs is only who advances the map: the live view lets it play out the events the server
 * sends, the replay steps it along a timeline.
 *
 * Every dot is a file, grouped by folder. The hub fires a beam at each file it reads; where a rule matched
 * a flag lights up with its title; the app's own folder is drawn in orange.
 */
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { clusterRadius, type LiveMap, type Severity } from './liveModel.ts';

export const COLOR: Record<Severity, string> = {
  critical: '#fb4a6a',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  info: '#94a3b8',
};

const reducedMotion = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
export const base = (path: string) => path.split('/').pop() ?? path;
export const dir = (path: string) => path.split('/').slice(0, -1).join('/');
export const clip = (text: string, n: number) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);

export type MapViewHandle = { redraw: () => void };

type Hover = { x: number; y: number; text: string };

/**
 * `step` is called once a frame with the seconds since the last one, before drawing. While `running` is
 * false no loop runs at all (a paused replay costs nothing); `redraw()` draws once, for after a jump.
 */
export const MapView = forwardRef<MapViewHandle, {
  map: LiveMap;
  running: boolean;
  step: (dt: number) => void;
  label: string;
  caption: string;
  className?: string;
}>(function MapView({ map, running, step, label, caption, className }, handle) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const size = useRef({ w: 0, h: 0, dpr: 1 });
  const view = useRef({ minX: -1, maxX: 1, minY: -1, maxY: 1 });
  const stepRef = useRef(step);
  stepRef.current = step;
  const [hover, setHover] = useState<Hover | null>(null);

  const paint = (dt: number) => {
    const el = canvas.current;
    if (el) drawMap(el, map, size.current, view.current, dt, reducedMotion());
  };
  useImperativeHandle(handle, () => ({ redraw: () => paint(0.016) }));

  useEffect(() => {
    const host = box.current;
    const el = canvas.current;
    if (!host || !el) return;
    const fit = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      size.current = { w: host.clientWidth, h: host.clientHeight, dpr };
      el.width = Math.round(host.clientWidth * dpr);
      el.height = Math.round(host.clientHeight * dpr);
      paint(0.016);
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(host);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [map]);

  useEffect(() => {
    if (!running) return;
    let last = performance.now();
    let frame = 0;
    const loop = (now: number) => {
      // A tab that was in the background wakes with a long gap; the map should resume, not jump.
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      stepRef.current(dt);
      paint(dt);
      frame = requestAnimationFrame(loop);
    };
    frame = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(frame);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, map]);

  // The flagged file under the pointer, if any.
  const onMove = (e: React.MouseEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const { w, h } = size.current;
    const v = view.current;
    const scale = Math.min((w * 0.94) / (v.maxX - v.minX || 1), (h * 0.88) / (v.maxY - v.minY || 1));
    const ox = w / 2 - ((v.minX + v.maxX) / 2) * scale;
    const oy = h / 2 - ((v.minY + v.maxY) / 2) * scale;
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let best = -1;
    let bestD = 14 * 14;
    for (let i = 0; i < map.nodes.length; i += 1) {
      if (map.nodes[i].flags.length === 0) continue;
      const p = map.place(i);
      const d = (ox + p.x * scale - mx) ** 2 + (oy + p.y * scale - my) ** 2;
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    }
    if (best < 0) return setHover(null);
    setHover({ x: mx, y: my, text: `${base(map.nodes[best].path)} — ${map.nodes[best].titles.join('; ')}` });
  };

  return (
    <div
      ref={box}
      className={`relative overflow-hidden rounded-lg border border-hairline ${className ?? 'h-[480px] sm:h-[72vh] sm:min-h-[560px]'}`}
      style={{ background: 'radial-gradient(ellipse at 50% 45%, #14101c 0%, #0a0810 55%, #060509 100%)' }}
      onMouseMove={onMove}
      onMouseLeave={() => setHover(null)}
    >
      <canvas ref={canvas} className="absolute inset-0 h-full w-full" role="img" aria-label={label} />
      {hover && (
        <div
          className="pointer-events-none absolute z-10 max-w-xs rounded border border-hairline-strong bg-surface px-2 py-1 text-xs text-slate-100 shadow-lg"
          style={{ left: Math.min(hover.x + 12, (box.current?.clientWidth ?? 400) - 250), top: hover.y + 12 }}
        >
          {hover.text}
        </div>
      )}
      <div className="pointer-events-none absolute left-3 top-3 font-mono text-[10px] uppercase tracking-widest text-slate-500">{caption}</div>
    </div>
  );
});

type View = { minX: number; maxX: number; minY: number; maxY: number };

export function drawMap(el: HTMLCanvasElement, map: LiveMap, size: { w: number; h: number; dpr: number }, view: View, dt: number, calm: boolean) {
  const ctx = el.getContext('2d');
  if (!ctx) return;
  const { w, h, dpr } = size;
  if (w === 0 || h === 0) return;
  const clock = map.clock;

  // The view eases toward the map's box, so it zooms out as the app grows instead of jumping.
  const target = map.bounds();
  const k = 1 - Math.exp(-dt * 3);
  view.minX += (target.minX - view.minX) * k;
  view.maxX += (target.maxX - view.maxX) * k;
  view.minY += (target.minY - view.minY) * k;
  view.maxY += (target.maxY - view.maxY) * k;
  const scale = Math.min((w * 0.94) / (view.maxX - view.minX || 1), (h * 0.88) / (view.maxY - view.minY || 1));
  const ox = w / 2 - ((view.minX + view.maxX) / 2) * scale;
  const oy = h / 2 - ((view.minY + view.maxY) / 2) * scale;
  const sx = (x: number) => ox + x * scale;
  const sy = (y: number) => oy + y * scale;

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.lineWidth = 1;

  for (const c of map.clusters) {
    ctx.beginPath();
    ctx.arc(sx(c.x), sy(c.y), clusterRadius(c.nodes.length) * scale + 2, 0, Math.PI * 2);
    ctx.fillStyle = c.own ? 'rgba(251,146,60,0.06)' : 'rgba(150,170,255,0.025)';
    ctx.fill();
    ctx.strokeStyle = c.own ? 'rgba(251,146,60,0.32)' : 'rgba(150,170,255,0.1)';
    ctx.stroke();
  }

  // Files: dim when found, brighter once read; a newly found one flashes. Drawn in one pass per colour,
  // because switching the fill for every one of twenty thousand squares costs more than drawing them. On a
  // very large app the unread ones are thinned: they are background, and half of them read the same.
  const nodes = map.nodes;
  const thin = nodes.length > 8000 ? 2 : 1;
  const fresh: number[] = [];
  for (const pass of [false, true]) {
    ctx.fillStyle = pass ? 'rgba(190,215,255,0.62)' : 'rgba(150,170,255,0.2)';
    for (let i = 0; i < nodes.length; i += 1) {
      const n = nodes[i];
      if (n.read !== pass) continue;
      if (!calm && clock - n.born < 0.8) {
        fresh.push(i);
        continue;
      }
      if (!pass && thin > 1 && i % thin !== 0) continue;
      const c = map.clusters[n.cluster];
      ctx.fillRect(sx(c.x + n.dx) - 0.75, sy(c.y + n.dy) - 0.75, 1.5, 1.5);
    }
  }
  for (const i of fresh) {
    const n = nodes[i];
    const c = map.clusters[n.cluster];
    ctx.fillStyle = `rgba(255,214,170,${0.95 - (clock - n.born) * 0.8})`;
    ctx.fillRect(sx(c.x + n.dx) - 1.2, sy(c.y + n.dy) - 1.2, 2.4, 2.4);
  }

  const hub = { x: sx(map.hub.x), y: sy(map.hub.y) };
  const active = Boolean(map.current);

  // Beams to the files just read.
  if (active && !calm) {
    for (const b of map.beams) {
      const age = clock - b.at;
      const p = map.place(b.node);
      const x = sx(p.x);
      const y = sy(p.y);
      const bend = ((b.node % 7) - 3) * 0.045;
      ctx.strokeStyle = 'rgba(160,200,255,1)';
      ctx.globalAlpha = (1 - age / 0.5) * 0.26;
      ctx.beginPath();
      ctx.moveTo(hub.x, hub.y);
      ctx.quadraticCurveTo((hub.x + x) / 2 - (y - hub.y) * bend, (hub.y + y) / 2 + (x - hub.x) * bend, x, y);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }

  // Flags, fanned out when a file has several.
  for (let i = 0; i < map.nodes.length; i += 1) {
    const n = map.nodes[i];
    if (n.flags.length === 0) continue;
    const p = map.place(i);
    n.flags.forEach((sev, j) => {
      const count = n.flags.length;
      const radius = count > 1 ? Math.min(20, 4 + count * 1.3) : 0;
      const a = (j / count) * Math.PI * 2 - Math.PI / 2;
      const x = sx(p.x) + Math.cos(a) * radius;
      const y = sy(p.y) + Math.sin(a) * radius;
      const strong = sev === 'critical' || sev === 'high';
      ctx.fillStyle = COLOR[sev];
      ctx.shadowColor = COLOR[sev];
      ctx.shadowBlur = calm ? 0 : strong ? 14 : 8;
      ctx.beginPath();
      ctx.arc(x, y, strong ? 3.8 : 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }

  // Folder names: the biggest, without letting two labels sit on each other.
  ctx.font = '10px "JetBrains Mono", ui-monospace, monospace';
  ctx.textAlign = 'center';
  const taken: { x0: number; x1: number; y0: number; y1: number }[] = [];
  // The app's own folders are named first so a neighbour's label never takes their place.
  const named = [...map.clusters].sort((a, b) => b.nodes.length - a.nodes.length).slice(0, 12);
  for (const c of map.clusters) if (c.own && !named.includes(c)) named.push(c);
  for (const c of named.sort((a, b) => Number(b.own) - Number(a.own))) {
    const text = (c.own ? 'your code · ' : '') + clip(c.name, 28);
    const half = ctx.measureText(text).width / 2;
    const x = sx(c.x);
    const y = sy(c.y) - clusterRadius(c.nodes.length) * scale - 6;
    const rect = { x0: x - half - 3, x1: x + half + 3, y0: y - 11, y1: y + 3 };
    if (taken.some((r) => rect.x0 < r.x1 && rect.x1 > r.x0 && rect.y0 < r.y1 && rect.y1 > r.y0)) continue;
    taken.push(rect);
    ctx.fillStyle = c.own ? 'rgba(253,186,116,0.95)' : 'rgba(160,180,215,0.7)';
    ctx.fillText(text, x, y);
  }

  // The hub.
  if (active) {
    const spin = calm ? 0 : clock * 0.9;
    const glow = ctx.createRadialGradient(hub.x, hub.y, 0, hub.x, hub.y, 26);
    glow.addColorStop(0, 'rgba(251,146,60,0.35)');
    glow.addColorStop(1, 'rgba(251,146,60,0)');
    ctx.fillStyle = glow;
    ctx.fillRect(hub.x - 26, hub.y - 26, 52, 52);
    ctx.strokeStyle = 'rgba(251,146,60,0.75)';
    for (let s = 0; s < 12; s += 1) {
      const a = spin + (s / 12) * Math.PI * 2;
      const len = 14 + (s % 3) * 3;
      ctx.beginPath();
      ctx.moveTo(hub.x + Math.cos(a) * 9, hub.y + Math.sin(a) * 9);
      ctx.lineTo(hub.x + Math.cos(a) * len, hub.y + Math.sin(a) * len);
      ctx.stroke();
    }
    ctx.strokeStyle = '#fb923c';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(hub.x, hub.y, 8, 0, Math.PI * 2);
    ctx.stroke();
    ctx.lineWidth = 1;
  }

  // Callouts for the newest matches, stacked so none sits on another.
  ctx.font = '11px Inter, ui-sans-serif, system-ui, sans-serif';
  ctx.textAlign = 'left';
  const recent = map.callouts.slice(-3).reverse();
  recent.forEach((c, slot) => {
    const age = clock - c.at;
    const p = map.place(c.node);
    const x = sx(p.x);
    const y = sy(p.y);
    const label = clip(c.title, 38);
    const width = ctx.measureText(label).width + 22;
    const bx = Math.max(6, Math.min(w - width - 6, x + 16));
    const by = Math.max(6, Math.min(h - 28, y - 34 + slot * 26));
    ctx.globalAlpha = Math.max(0, Math.min(1, (2.4 - age) / 0.5, age / 0.12 + 0.2));
    ctx.strokeStyle = COLOR[c.severity];
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(bx, by + 11);
    ctx.stroke();
    ctx.fillStyle = 'rgba(14,9,12,0.92)';
    ctx.fillRect(bx, by, width, 22);
    ctx.strokeRect(bx + 0.5, by + 0.5, width - 1, 21);
    ctx.fillStyle = COLOR[c.severity];
    ctx.fillRect(bx, by, 3, 22);
    ctx.fillStyle = '#fbf3f4';
    ctx.fillText(label, bx + 11, by + 15);
    ctx.globalAlpha = 1;
  });
}
