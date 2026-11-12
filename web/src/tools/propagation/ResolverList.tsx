// The list of resolvers (Signal, 2026-11-11), in its own scrolling panel beside the map: flag,
// operator, place and IP, the value served with the TTL left and the latency, a status mark. A
// resolver that is not up to date says why on its own line. Rows arrive live from skeletons.
// Groups: the big anycast resolvers first, then one per continent, with a sticky head.
import { memo, useSyncExternalStore } from 'react';
import { Skel } from '../../components/ui';
import { locale, t } from '../../lib/i18n';
import { countryName, fmtCount, fmtTtl } from '../dns/fmt';
import { shortReason } from './explain';
import { STATUS_LABEL } from './marks';
import { cleanProvider, countRows, displayName, rowStatus, ttlLeft, valueText, type AuthorityEvent, type Row, type RowStatus } from './model';

/** Colour family of a status: green up to date, amber a different answer, red no answer. */
export type Tone = 'ok' | 'warn' | 'out' | 'wait';
export const TONE: Record<RowStatus, Tone> = {
  fresh: 'ok',
  regional: 'ok',
  stale: 'warn',
  missing: 'warn',
  rewritten: 'warn',
  error: 'out',
  timeout: 'out',
  pending: 'wait',
};

/* one shared clock for every TTL countdown */
let now = Date.now();
const subs = new Set<() => void>();
let tick: ReturnType<typeof setInterval> | null = null;
function subscribe(cb: () => void) {
  subs.add(cb);
  tick ??= setInterval(() => {
    now = Date.now();
    subs.forEach((s) => s());
  }, 1000);
  return () => {
    subs.delete(cb);
    if (!subs.size && tick) {
      clearInterval(tick);
      tick = null;
    }
  };
}
const useNow = () => useSyncExternalStore(subscribe, () => now);

function TtlLeft({ row }: { row: Row }) {
  const clock = useNow();
  const left = ttlLeft(row.ev, clock);
  return left === null ? null : <>TTL {fmtTtl(left)}</>;
}

/** Flag of a country (flag-icons), or an empty frame when unknown. */
export function Flag({ cc, label }: { cc: string | null | undefined; label?: string }) {
  if (!cc || cc === '??' || !/^[a-z]{2}$/i.test(cc)) return <span className="flag flag--none" aria-hidden />;
  return label ? (
    <span className={`flag fi fi-${cc.toLowerCase()}`} role="img" aria-label={label} />
  ) : (
    <span className={`flag fi fi-${cc.toLowerCase()}`} aria-hidden />
  );
}

/** The status mark of a row: a tick, an exclamation, a cross or a waiting dot, with its word for screen readers. */
export function StatusTick({ status, uncertain, note }: { status: RowStatus; uncertain?: boolean; note?: string | null }) {
  const label = uncertain && status === 'stale' ? t('incertain') : t(STATUS_LABEL[status]);
  return (
    <span className={`pl-tick pl-tick--${TONE[status]}`} title={note ? t('{label} : {note}', { label, note }) : label}>
      <span className="visually-hidden">
        {note ? t('{label}. {note}', { label, note }) : label}
      </span>
    </span>
  );
}

interface RowProps {
  row: Row;
  ev: Row['ev'];
  remeasuring: boolean;
  authority?: AuthorityEvent;
  highlight: boolean;
  sameAsUpToDate: boolean;
  near: string | null;
  /** the small line shows the latency (list sorted by latency) instead of the TTL left */
  latency: boolean;
}

const ResolverRow = memo(
  function ResolverRow({ row, authority, highlight, sameAsUpToDate, near, latency }: RowProps) {
    const e = row.ev;
    const st = rowStatus(row);
    const i = row.info;
    const place = i.anycast ? (near ? t('anycast, près de {near}', { near }) : t('anycast, près de notre serveur')) : [i.city, countryName(i.country_code)].filter(Boolean).join(', ');
    const failed = st === 'error' || st === 'timeout';
    const reason = e ? shortReason(e, authority, sameAsUpToDate) : null;
    const value = e && !failed ? valueText(e) : '';
    const who = cleanProvider(i.provider) || displayName(i);
    return (
      <li
        id={`res-${i.ip}`}
        className={`pl-row pl-row--${TONE[st]} ${row.remeasuring ? 'pl-row--again' : ''} ${highlight ? 'pl-row--hl' : ''}`}
        aria-busy={!e || row.remeasuring || undefined}
      >
        <Flag cc={i.country_code} label={i.anycast ? t('opérateur : {country}', { country: countryName(i.country_code) }) : countryName(i.country_code)} />
        <span className="pl-who">
          <b title={displayName(i)}>{who}</b>
          <span>
            {place} · <span className="mono">{i.ip}</span>
          </span>
        </span>
        <span className="pl-val">
          {e ? (
            <span className="pl-v mono" title={value.includes('\n') ? value : undefined}>
              <b>{failed ? (e.rcode && e.rcode !== 'NOERROR' ? e.rcode : t('sans réponse')) : value.split('\n')[0] || t('vide')}</b>
              {value.includes('\n') && <span className="pl-more">+{value.split('\n').length - 1}</span>}
            </span>
          ) : (
            <Skel w="13ch" />
          )}
          <small
            className="mono"
            title={[e?.refreshAt ? t('Redemande la valeur vers {time}', { time: new Date(e.refreshAt).toLocaleTimeString(locale()) }) : '', i.latencyMs !== null ? t('latence {ms} ms', { ms: fmtCount(i.latencyMs) }) : ''].filter(Boolean).join(', ') || undefined}
          >
            {e && (latency || failed ? i.latencyMs !== null && `${fmtCount(i.latencyMs)} ms` : <TtlLeft row={row} />)}
          </small>
        </span>
        <StatusTick status={st} uncertain={e?.uncertain} note={TONE[st] === 'ok' ? reason : null} />
        {/* why a resolver is not up to date, on its own line; for an up to date one, in the tick's tooltip */}
        {reason && TONE[st] !== 'ok' && (
          <span className="pl-why">
            <span className={`pl-word pl-word--${TONE[st]}`}>{e?.uncertain && st === 'stale' ? t('incertain') : t(STATUS_LABEL[st])}</span> {reason}
          </span>
        )}
      </li>
    );
  },
  // rows are rebuilt on every batch: re-render only when what is shown changed
  (a, b) =>
    a.ev === b.ev && a.remeasuring === b.remeasuring && a.highlight === b.highlight && a.authority === b.authority &&
    a.sameAsUpToDate === b.sameAsUpToDate && a.near === b.near && a.latency === b.latency && a.row.info.ip === b.row.info.ip && a.row.info.city === b.row.info.city,
);

/** Countries of a group with a resolver really late (flags shown on its head). */
export function lateCountries(rows: Row[], isLate: (r: Row) => boolean): string[] {
  return [...new Set(rows.filter(isLate).map((r) => r.info.country_code).filter((x): x is string => !!x))].sort();
}

export function ResolverGroup({
  title,
  rows,
  authority,
  highlight,
  isGood,
  isLate = () => false,
  near = null,
  latency = false,
}: {
  title: string;
  rows: Row[];
  authority?: AuthorityEvent;
  highlight: string | null;
  isGood: (r: Row) => boolean;
  /** Real delay (not uncertain, not a TTL-stretching cache): its country flag goes on the head. */
  isLate?: (r: Row) => boolean;
  /** city of our server, where the anycast resolvers answer from */
  near?: string | null;
  latency?: boolean;
}) {
  if (!rows.length) return null;
  const c = countRows(rows);
  const ok = c.fresh + c.regional;
  const lateCc = lateCountries(rows, isLate);
  return (
    <section className="pl-group">
      <h3 className="pl-group__head">
        <span>{title}</span>
        {lateCc.length > 0 && (
          <span className="flags pl-group__late" role="img" aria-label={t('En retard : {countries}', { countries: lateCc.map(countryName).join(', ') })}>
            {lateCc.slice(0, 5).map((cc) => (
              <Flag key={cc} cc={cc} />
            ))}
          </span>
        )}
        <small>
          {c.pending
            ? t('{done} sur {total}', { done: fmtCount(c.total - c.pending), total: fmtCount(c.total) })
            : c.error > 0
              ? t('{ok} à jour sur {total}, {error} sans réponse', { ok: fmtCount(ok), total: fmtCount(c.total), error: fmtCount(c.error) })
              : t('{ok} à jour sur {total}', { ok: fmtCount(ok), total: fmtCount(c.total) })}
        </small>
      </h3>
      <ul className="pl-list">
        {rows.map((r) => (
          <ResolverRow key={r.info.ip} row={r} ev={r.ev} remeasuring={r.remeasuring} authority={authority} highlight={highlight === r.info.ip} sameAsUpToDate={isGood(r)} near={near} latency={latency} />
        ))}
      </ul>
    </section>
  );
}
