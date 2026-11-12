// Daily volume: stacked bars drawn by hand in SVG. Aligned messages in --in at the baseline,
// non-aligned on top in --out (both are measured states, tokens only). One axis, recessive grid,
// legend, per-day tooltip on hover and keyboard focus, and the same figures as a table.
import { useEffect, useRef, useState } from 'react';
import { fmtInt } from '../../lib/format';
import { locale, rich, t } from '../../lib/i18n';

export interface DayPoint {
  day: string;
  reports: number;
  messages: number;
  dmarcPass: number;
}

const H = 190;
const PAD = { top: 12, right: 8, bottom: 26, left: 44 };

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
const dd = (iso: string) => new Intl.DateTimeFormat(locale(), { timeZone: 'UTC', day: '2-digit', month: '2-digit' }).format(new Date(iso.slice(0, 10)));
const ddFull = (iso: string) => new Intl.DateTimeFormat(locale(), { timeZone: 'UTC', day: '2-digit', month: '2-digit', year: 'numeric' }).format(new Date(iso.slice(0, 10)));
const pct = (n: number, d: number) => (d ? `${new Intl.NumberFormat(locale()).format(Math.round((n / d) * 1000) / 10)} %` : t('n/d'));

/** Bar with only its top corners rounded (data end), anchored to its base. */
function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

export function DailyBars({ data }: { data: DayPoint[] }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(720);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const max = niceMax(Math.max(...data.map((d) => d.messages), 0));
  const ticks = [0, max / 2, max];
  const innerW = w - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;
  const band = innerW / Math.max(1, data.length);
  const barW = Math.max(3, Math.min(26, band * 0.66));
  const y = (v: number) => PAD.top + innerH - (v / max) * innerH;
  const every = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(innerW / 46))));
  const hd = hover !== null ? data[hover] : null;

  return (
    <div className="dr-chart">
      <div className="dr-legend" aria-hidden>
        <span><i className="dr-sw dr-sw--in" /> {t('Aligné DMARC')}</span>
        <span><i className="dr-sw dr-sw--out" /> {t('Non aligné')}</span>
      </div>
      <div className="dr-plot" ref={wrap}>
        <svg width={w} height={H} role="img" aria-label={t('Messages par jour, {n} jours, alignés et non alignés. Détail dans le tableau qui suit.', { n: data.length })}>
          {ticks.map((tk) => (
            <g key={tk}>
              <line x1={PAD.left} x2={w - PAD.right} y1={y(tk)} y2={y(tk)} className={tk === 0 ? 'dr-base' : 'dr-grid'} />
              <text x={PAD.left - 6} y={y(tk)} dy="0.32em" textAnchor="end" className="dr-tick">
                {fmtInt(tk)}
              </text>
            </g>
          ))}
          {data.map((d, i) => {
            const cx = PAD.left + band * i + band / 2;
            const x = cx - barW / 2;
            const ok = d.dmarcPass;
            const bad = d.messages - d.dmarcPass;
            const hOk = (ok / max) * innerH;
            const hBad = (bad / max) * innerH;
            const gap = ok > 0 && bad > 0 ? 2 : 0;
            const base = PAD.top + innerH;
            return (
              <g key={d.day} className={hover === i ? 'dr-day is-hover' : 'dr-day'}>
                {ok > 0 && (bad > 0 ? <rect x={x} y={base - hOk} width={barW} height={hOk} className="dr-in" /> : <path d={topRounded(x, base - hOk, barW, hOk, 4)} className="dr-in" />)}
                {bad > 0 && <path d={topRounded(x, base - hOk - gap - hBad, barW, Math.max(1, hBad), 4)} className="dr-out" />}
                {i % every === 0 && (
                  <text x={cx} y={H - 8} textAnchor="middle" className="dr-tick">
                    {dd(d.day)}
                  </text>
                )}
                <rect
                  x={PAD.left + band * i}
                  y={PAD.top}
                  width={band}
                  height={innerH}
                  className="dr-hit"
                  role="img"
                  tabIndex={i === 0 ? 0 : -1}
                  onKeyDown={(e) => {
                    // one tab stop for the whole chart, arrows move between days
                    const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
                    if (!dir) return;
                    e.preventDefault();
                    const hits = (e.currentTarget.ownerSVGElement?.querySelectorAll<SVGRectElement>('.dr-hit')) ?? [];
                    hits[Math.min(hits.length - 1, Math.max(0, i + dir))]?.focus();
                  }}
                  aria-label={t('{day} : {messages} messages, {ok} alignés, {bad} non alignés', { day: dd(d.day), messages: d.messages, ok, bad })}
                  onMouseEnter={() => setHover(i)}
                  onMouseLeave={() => setHover(null)}
                  onFocus={() => setHover(i)}
                  onBlur={() => setHover(null)}
                />
              </g>
            );
          })}
        </svg>
        {hd && hover !== null && (
          <div className="dr-tip" style={{ left: Math.min(w - 190, Math.max(0, PAD.left + band * hover + band / 2 - 95)) }} role="status">
            <strong>{dd(hd.day)}</strong> · {t('{n} messages', { n: hd.messages })}
            <br />
            {rich('<m>{ok}</m> alignés ({rate}), <m>{bad}</m> non alignés', { ok: hd.dmarcPass, rate: pct(hd.dmarcPass, hd.messages), bad: hd.messages - hd.dmarcPass }, { m: (c) => <span className="mono">{c}</span> })}
          </div>
        )}
      </div>
    </div>
  );
}

export function DailyTable({ data }: { data: DayPoint[] }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">{t('Jour')}</th>
            <th scope="col" className="num">{t('Rapports')}</th>
            <th scope="col" className="num">{t('Messages')}</th>
            <th scope="col" className="num">{t('Alignés')}</th>
            <th scope="col" className="num">{t('Non alignés')}</th>
            <th scope="col" className="num">{t('Taux')}</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.day}>
              <td className="mono">{ddFull(d.day)}</td>
              <td className="num mono">{fmtInt(d.reports)}</td>
              <td className="num mono">{fmtInt(d.messages)}</td>
              <td className="num mono">{fmtInt(d.dmarcPass)}</td>
              <td className={`num mono ${d.messages - d.dmarcPass > 0 ? 'out-text' : ''}`}>{fmtInt(d.messages - d.dmarcPass)}</td>
              <td className="num mono">{pct(d.dmarcPass, d.messages)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
