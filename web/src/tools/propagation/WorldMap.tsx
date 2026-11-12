// Map of the measure (Signal, validated 2026-11-11: "l'animation est folle", keep it). A dot-matrix
// world on the Equal Earth projection; an arc is drawn from our server to each place asked, a spark
// travels along it, the place pulses in the colour of its answer (green up to date, amber a
// different value, red no answer). Our server wears a dashed ring that turns.
// The view frames our server and the places listed: the viewBox glides there in 900 ms, and --k
// (user units per screen pixel) keeps pins, labels and lines the same size whatever the zoom.
// The viewBox and --k are written on the element directly, never through React, so a batch of
// answers does not reset the framing. Everything that moves stops under prefers-reduced-motion.
// Keyboard: one stop per place, arrows go west to east, Enter opens its row in the list.
// Loaded lazily (d3-geo) so the page and the list come first.
import { memo, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { geoEqualEarth, geoPath } from 'd3-geo';
import { t } from '../../lib/i18n';
import { dots, GRID } from './dots';
import { Shape } from './marks';
import { rowStatus, type Row, type RowStatus } from './model';
import { TONE, type Tone } from './ResolverList';

const { W, H } = GRID;
const projection = geoEqualEarth().fitExtent(
  [
    [4, 4],
    [W - 4, H - 4],
  ],
  { type: 'Sphere' },
);
const SPHERE = geoPath(projection)({ type: 'Sphere' }) ?? '';

/** Severity of a place with several resolvers: what needs attention shows. */
const WORST: Record<RowStatus, number> = { stale: 0, missing: 1, rewritten: 2, error: 3, timeout: 4, pending: 5, regional: 6, fresh: 7 };
const MAX_SPARKS = 36;
const MAX_HALOS = 90;
const MAX_LABELS = 12;
const FIT_MS = 900;

export interface MapServer {
  lat: number;
  lon: number;
  city: string | null;
}

interface Site {
  key: string;
  x: number;
  y: number;
  rows: Row[];
  status: RowStatus;
  tone: Tone;
  city: string;
}

const reduced = () => typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
type Box = [number, number, number, number];

/** viewBox [x, y, w, h] around a box of points, padded, at the aspect of the element. */
function frame(pts: [number, number][], aspect: number): Box {
  if (!pts.length) pts = [[0, 0], [W, H]];
  let x0 = Math.min(...pts.map((p) => p[0]));
  let x1 = Math.max(...pts.map((p) => p[0]));
  let y0 = Math.min(...pts.map((p) => p[1]));
  let y1 = Math.max(...pts.map((p) => p[1]));
  // a single country should not fill the screen: at least 30 % of the world wide, so the land
  // around stays readable at the grid's resolution
  const minW = W * 0.3;
  if (x1 - x0 < minW) {
    const c = (x0 + x1) / 2;
    x0 = c - minW / 2;
    x1 = c + minW / 2;
  }
  const pad = Math.max(28, 0.09 * Math.max(x1 - x0, (y1 - y0) * aspect));
  x0 -= pad;
  x1 += pad;
  y0 -= pad * 1.3; // room above for the arcs, which bow north
  y1 += pad * 0.8;
  let w = x1 - x0;
  let h = y1 - y0;
  if (w / h < aspect) {
    const nw = h * aspect;
    x0 -= (nw - w) / 2;
    w = nw;
  } else {
    const nh = w / aspect;
    y0 -= (nh - h) / 2;
    h = nh;
  }
  // the frame stays on the world when it can: no band of empty space above the Arctic
  if (h <= H) y0 = Math.min(Math.max(y0, 0), H - h);
  if (w <= W) x0 = Math.min(Math.max(x0, 0), W - w);
  // never wider than the world itself
  if (w > W * 1.08) {
    const s = (W * 1.08) / w;
    const cx = x0 + w / 2;
    const cy = y0 + h / 2;
    w *= s;
    h *= s;
    x0 = cx - w / 2;
    y0 = cy - h / 2;
  }
  return [x0, y0, w, h];
}

/** Quadratic arc from our server to a place, bowed north. */
function arcPath(sx: number, sy: number, x: number, y: number): string {
  const d = Math.hypot(x - sx, y - sy);
  const mx = (sx + x) / 2 + (Math.abs(x - sx) < 2 ? 6 : 0);
  const my = (sy + y) / 2 - Math.max(18, d * 0.3);
  return `M${sx.toFixed(1)} ${sy.toFixed(1)}Q${mx.toFixed(1)} ${my.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)}`;
}

/**
 * Which places get a city label, and on which side: problems first, then the biggest, never two
 * overlapping; a label that would leave the frame on the right goes to the left of its pin.
 */
function pickLabels(sites: Site[], k: number, server: [number, number] | null, view: Box): Map<string, 'r' | 'l'> {
  const placed: Box[] = [];
  // the label of our server, on either side of it
  if (server) placed.push([server[0] - 220 * k, server[1] - 40 * k, 440 * k, 30 * k]);
  const out = new Map<string, 'r' | 'l'>();
  const order = [...sites].sort((a, b) => WORST[a.status] - WORST[b.status] || b.rows.length - a.rows.length || a.key.localeCompare(b.key));
  const right = view[0] + view[2] - 6 * k;
  // the pins themselves: a label never covers another place
  const pins: Box[] = sites.map((s) => [s.x - 5 * k, s.y - 5 * k, 10 * k, 10 * k]);
  for (const s of order) {
    if (out.size >= MAX_LABELS || !s.city) continue;
    const w = (s.city.length * 6.9 + 6) * k;
    const side = s.x + 9 * k + w > right ? 'l' : 'r';
    const b: Box = side === 'r' ? [s.x + 8 * k, s.y - 9 * k, w, 16 * k] : [s.x - 8 * k - w, s.y - 9 * k, w, 16 * k];
    if (b[0] < view[0] || b[1] < view[1] || b[1] + b[3] > view[1] + view[3]) continue;
    const hit = (p: Box) => b[0] < p[0] + p[2] && p[0] < b[0] + b[2] && b[1] < p[1] + p[3] && p[1] < b[1] + b[3];
    if (placed.some(hit) || pins.some(hit)) continue;
    placed.push(b);
    out.set(s.key, side);
  }
  return out;
}

const Defs = memo(function Defs() {
  const tones: [Tone, string][] = [
    ['ok', 'var(--in)'],
    ['warn', 'var(--warn)'],
    ['out', 'var(--out)'],
  ];
  return (
    <defs>
      {tones.flatMap(([t, c]) =>
        (['e', 'w'] as const).map((dir) => (
          <linearGradient key={t + dir} id={`pm-g-${t}-${dir}`} x1={dir === 'e' ? 0 : 1} x2={dir === 'e' ? 1 : 0} y1="0" y2="0">
            <stop offset="0" stopColor="var(--lab)" />
            <stop offset="1" stopColor={c} />
          </linearGradient>
        )),
      )}
    </defs>
  );
});

const Ground = memo(function Ground() {
  return (
    <>
      <path className="pm-rim" d={SPHERE} />
      <path className="pm-dots" d={dots()} />
    </>
  );
});

export default function WorldMap({
  rows,
  server,
  anycast,
  describe,
  label,
  onPick,
  highlight,
}: {
  /** local resolvers listed (anycast ones have no place of their own) */
  rows: Row[];
  server: MapServer | null;
  /** number of anycast resolvers listed: they answer from near our server */
  anycast: number;
  describe: (r: Row) => { title: string; body: ReactNode; aria: string };
  label: string;
  onPick: (ip: string) => void;
  highlight: string | null;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const svg = useRef<SVGSVGElement>(null);
  const vb = useRef<Box>([0, 0, W, H]);
  const anim = useRef<number | null>(null);
  const [size, setSize] = useState<{ w: number; h: number } | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const refs = useRef(new Map<string, SVGGElement>());
  const still = useMemo(reduced, []);

  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => {
      const w = Math.round(e.contentRect.width);
      const h = Math.round(e.contentRect.height);
      if (w > 0 && h > 0) setSize((s) => (s && s.w === w && s.h === h ? s : { w, h }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const srv = useMemo(() => (server ? (projection([server.lon, server.lat]) as [number, number] | null) : null), [server]);

  // one place per city (or per exact point): resolvers of the same city share their pin and arc
  const sites = useMemo(() => {
    const m = new Map<string, Site>();
    for (const r of rows) {
      const i = r.info;
      if (i.anycast || i.lat === null || i.lon === null) continue;
      const p = projection([i.lon, i.lat]);
      if (!p) continue;
      const key = `${i.country_code ?? ''}|${i.city ?? `${p[0].toFixed(0)},${p[1].toFixed(0)}`}`;
      const s = m.get(key);
      if (s) s.rows.push(r);
      else m.set(key, { key, x: p[0], y: p[1], rows: [r], status: 'pending', tone: 'wait', city: i.city ?? '' });
    }
    const list = [...m.values()];
    for (const s of list) {
      s.status = s.rows.map(rowStatus).sort((a, b) => WORST[a] - WORST[b])[0];
      s.tone = TONE[s.status];
    }
    return list.sort((a, b) => a.x - b.x || a.y - b.y);
  }, [rows]);

  // the shape of the set of places (not their answers): a new framing only when it changes
  const geoKey = useMemo(() => sites.map((s) => s.key).join(';'), [sites]);
  const aspect = size ? size.w / size.h : W / H;
  const target = useMemo(() => {
    const pts: [number, number][] = sites.map((s) => [s.x, s.y]);
    if (srv) pts.push(srv);
    return frame(pts, aspect);
  }, [geoKey, srv, aspect]); // eslint-disable-line react-hooks/exhaustive-deps
  const kTarget = size ? target[2] / size.w : 1;
  const labels = useMemo(() => pickLabels(sites, kTarget, srv, target), [geoKey, kTarget, srv, target]); // eslint-disable-line react-hooks/exhaustive-deps

  // glide the viewBox to the target; --k follows it frame by frame
  useLayoutEffect(() => {
    const el = svg.current;
    if (!el || !size) return;
    const apply = (b: Box) => {
      vb.current = b;
      el.setAttribute('viewBox', b.map((v) => v.toFixed(2)).join(' '));
      el.style.setProperty('--k', (b[2] / size.w).toFixed(4));
    };
    if (anim.current) cancelAnimationFrame(anim.current);
    const first = el.dataset.framed !== '1';
    // the first framing starts from the whole world at this aspect
    const from: Box = first ? frame([[0, 0], [W, H]], aspect) : vb.current;
    el.dataset.framed = '1';
    if (still) {
      apply(target);
      return;
    }
    apply(from);
    const t0 = performance.now();
    const ease = (t: number) => 1 - Math.pow(1 - t, 4);
    const stepFn = (t: number) => {
      const p = Math.min(1, (t - t0) / FIT_MS);
      const e = ease(p);
      apply(from.map((v, i) => v + (target[i] - v) * e) as Box);
      anim.current = p < 1 ? requestAnimationFrame(stepFn) : null;
    };
    anim.current = requestAnimationFrame(stepFn);
    return () => {
      if (anim.current) cancelAnimationFrame(anim.current);
    };
  }, [target, size, still, aspect]);

  const arcs = useMemo(
    () =>
      srv
        ? sites.map((s, i) => ({
            key: s.key,
            d: arcPath(srv[0], srv[1], s.x, s.y),
            dir: s.x >= srv[0] ? 'e' : 'w',
            delay: Math.round(i * Math.min(110, 1500 / Math.max(1, sites.length))),
          }))
        : [],
    [geoKey, srv], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const toneOf = useMemo(() => new Map(sites.map((s) => [s.key, s.tone])), [sites]);
  const sparks = useMemo(() => {
    if (still || !arcs.length) return [];
    const every = Math.max(1, Math.ceil(arcs.length / MAX_SPARKS));
    return arcs.filter((_, i) => i % every === 0);
  }, [arcs, still]);
  // halos: every place while they are few, else the problems first
  const halos = useMemo(() => {
    if (sites.length <= MAX_HALOS) return new Set(sites.map((s) => s.key));
    return new Set([...sites].sort((a, b) => WORST[a.status] - WORST[b.status]).slice(0, MAX_HALOS).map((s) => s.key));
  }, [sites]);

  const order = sites.map((s) => s.key);
  const tabStop = focusKey && order.includes(focusKey) ? focusKey : order[0];
  const byKey = new Map(sites.map((s) => [s.key, s]));
  const hlKey = highlight ? sites.find((s) => s.rows.some((r) => r.info.ip === highlight))?.key : undefined;

  const move = (e: KeyboardEvent, key: string) => {
    const i = order.indexOf(key);
    let next: string | undefined;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = order[(i + 1) % order.length];
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = order[(i - 1 + order.length) % order.length];
    else if (e.key === 'Home') next = order[0];
    else if (e.key === 'End') next = order[order.length - 1];
    else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      const s = byKey.get(key);
      if (s) onPick(s.rows[0].info.ip);
      return;
    } else if (e.key === 'Escape') {
      setActive(null);
      return;
    }
    if (next) {
      e.preventDefault();
      setFocusKey(next);
      setActive(next);
      refs.current.get(next)?.focus();
    }
  };

  // tooltip, placed from the current viewBox
  const tipSite = active ? byKey.get(active) : undefined;
  let tip: ReactNode = null;
  if (tipSite && size) {
    const [x0, y0, w, h] = vb.current;
    const left = ((tipSite.x - x0) / w) * size.w;
    const top = ((tipSite.y - y0) / h) * size.h;
    const sorted = [...tipSite.rows].sort((a, b) => WORST[rowStatus(a)] - WORST[rowStatus(b)]);
    const first = describe(sorted[0]);
    const lp = Math.max(0, Math.min(100, (left / size.w) * 100));
    tip = (
      <div
        className="pm-tip"
        role="tooltip"
        style={{ left, top, ['--tx' as string]: `-${Math.round(lp)}%`, ['--ty' as string]: top < size.h * 0.4 ? '16px' : 'calc(-100% - 16px)' }}
      >
        <div className="pm-tip__title">{sorted.length > 1 ? t('{city} · {n} résolveurs', { city: tipSite.city || t('Ce lieu'), n: sorted.length }) : first.title}</div>
        {sorted.length > 1 ? (
          <ul className="pm-tip__list">
            {sorted.slice(0, 6).map((r) => {
              const d = describe(r);
              return (
                <li key={r.info.ip}>
                  <span className={`dot dot--${TONE[rowStatus(r)] === 'wait' ? 'pending' : TONE[rowStatus(r)]}`} aria-hidden /> {d.title}
                </li>
              );
            })}
            {sorted.length > 6 && <li className="pm-tip__more">{t('et {n} autres', { n: sorted.length - 6 })}</li>}
          </ul>
        ) : (
          first.body
        )}
      </div>
    );
  }

  const homeCity = server?.city ?? t('Notre serveur');
  const homeLabel = anycast ? t('{city} · {n} anycast', { city: homeCity, n: anycast }) : homeCity;
  // the label of our server goes to the right when the frame leaves no room on its left
  const homeRight = !!srv && srv[0] - (26 + homeLabel.length * 7.2) * kTarget < target[0];

  return (
    <div className="pm" ref={wrap} onMouseLeave={() => setActive((a) => (a === focusKey ? a : null))}>
      <svg ref={svg} className={`pm-svg ${still ? 'pm-svg--still' : ''}`} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" role="group" aria-label={label}>
        <Defs />
        <Ground />
        <g className="pm-arcs" aria-hidden>
          {arcs.map((a) => {
            const t = toneOf.get(a.key) ?? 'wait';
            return (
              <path
                key={a.key}
                d={a.d}
                pathLength={1}
                className={`pm-arc pm-arc--${t}`}
                stroke={t === 'wait' ? undefined : `url(#pm-g-${t}-${a.dir})`}
                style={{ animationDelay: `${a.delay}ms` }}
              />
            );
          })}
        </g>
        <g className="pm-sparks" aria-hidden>
          {sparks.map((a, i) => (
            <g key={a.key}>
              <animateMotion dur={`${(2.4 + (i % 4) * 0.45).toFixed(2)}s`} begin={`${(1.3 + (i % 14) * 0.22).toFixed(2)}s`} repeatCount="indefinite" path={a.d} />
              <g className="pm-k">
                <circle className="pm-spark" r={2.2} />
              </g>
            </g>
          ))}
        </g>
        {sites.map((s, i) => {
          const d = describe(s.rows[0]);
          const aria = s.rows.length > 1 ? t('{city}, {n} résolveurs : {list}', { city: s.city || t('Lieu'), n: s.rows.length, list: s.rows.map((r) => describe(r).aria).join(' ; ') }) : d.aria;
          return (
            <g
              key={s.key}
              ref={(el) => {
                if (el) refs.current.set(s.key, el);
                else refs.current.delete(s.key);
              }}
              transform={`translate(${s.x.toFixed(1)} ${s.y.toFixed(1)})`}
              className={`pm-site pm-site--${s.tone} ${s.key === hlKey ? 'pm-site--hl' : ''} ${s.rows.some((r) => r.remeasuring) ? 'pm-site--again' : ''}`}
              tabIndex={s.key === tabStop ? 0 : -1}
              role="img"
              aria-label={aria}
              onMouseEnter={() => setActive(s.key)}
              onFocus={() => {
                setFocusKey(s.key);
                setActive(s.key);
              }}
              onBlur={() => setActive((a) => (a === s.key ? null : a))}
              onKeyDown={(e) => move(e, s.key)}
              onClick={() => onPick(s.rows[0].info.ip)}
            >
              <g className="pm-k">
                <circle className="pm-hit" r={11} />
                {halos.has(s.key) && s.tone !== 'wait' && <circle className="pm-halo" r={8} style={{ animationDelay: `${((i * 0.21) % 2.4).toFixed(2)}s` }} />}
                {s.key === hlKey && <circle className="pm-ring-hl" r={10} />}
                {s.status === 'fresh' || s.status === 'pending' ? <circle className="pm-pin" r={4.5} /> : <Shape status={s.status} r={4.6} />}
                {labels.has(s.key) && (
                  <text className="pm-label" x={labels.get(s.key) === 'l' ? -9 : 9} y={4} textAnchor={labels.get(s.key) === 'l' ? 'end' : undefined}>
                    {s.city}
                  </text>
                )}
              </g>
            </g>
          );
        })}
        {srv && (
          <g className="pm-home" transform={`translate(${srv[0].toFixed(1)} ${srv[1].toFixed(1)})`} aria-hidden>
            <g className="pm-k">
              <circle className="pm-home__ring" r={20} />
              <circle className="pm-home__dot" r={6} />
              <text className="pm-home__label" x={homeRight ? 26 : -26} y={-22} textAnchor={homeRight ? 'start' : 'end'}>
                {homeLabel}
              </text>
            </g>
          </g>
        )}
      </svg>
      {tip}
    </div>
  );
}
