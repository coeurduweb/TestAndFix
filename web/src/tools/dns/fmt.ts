import { locale, t } from '../../lib/i18n';

// Formatting shared by the DNS lookup and propagation pages. Pure, unit tested in fmt.test.ts.

/** A TTL in seconds, read at a glance: "45 s", "4 min 53 s", "3 h", "2 h 05", "1 j 2 h". */
export function fmtTtl(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return '';
  const n = Math.max(0, Math.round(s));
  if (n < 60) return t('{n} s', { n });
  if (n < 3600) {
    const m = Math.floor(n / 60);
    const r = n % 60;
    return r ? t('{m} min {r} s', { m, r: String(r).padStart(2, '0') }) : t('{m} min', { m });
  }
  if (n < 86400) {
    const h = Math.floor(n / 3600);
    const m = Math.floor((n % 3600) / 60);
    return m ? t('{h} h {m}', { h, m: String(m).padStart(2, '0') }) : t('{h} h', { h });
  }
  const d = Math.floor(n / 86400);
  const h = Math.floor((n % 86400) / 3600);
  return h ? t('{d} j {h} h', { d, h }) : t('{d} j', { d });
}

/** Time until a future instant: "dans 12 s", "dans 3 min", "dans 2 h 10", "maintenant" when past. */
export function fmtIn(iso: string | number | null | undefined, now = Date.now()): string {
  if (iso === null || iso === undefined || iso === '') return '';
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return '';
  const s = Math.round((at - now) / 1000);
  if (s <= 0) return t('maintenant');
  if (s < 60) return t('dans {n} s', { n: s });
  const minutes = Math.round(s / 60);
  if (minutes < 60) return t('dans {n} min', { n: minutes });
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h < 24) return m ? t('dans {h} h {m}', { h, m: String(m).padStart(2, '0') }) : t('dans {h} h', { h });
  return t('dans {n} j', { n: Math.round(h / 24) });
}

/** Clock time of an instant, with the day when it is not today: "21:33", "11/11 à 02:10". */
export function fmtClock(iso: string | number | null | undefined, now = Date.now()): string {
  if (iso === null || iso === undefined || iso === '') return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const time = d.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' });
  const today = new Date(now);
  const sameDay = d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth() && d.getDate() === today.getDate();
  return sameDay ? time : t('{date} à {time}', { date: d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' }), time });
}

let regions: Intl.DisplayNames | null = null;
let regionsLocale = '';
/** French country name of an ISO 3166 code, the code itself when unknown. */
export function countryName(cc: string | null | undefined): string {
  if (!cc || cc === '??') return t('Pays inconnu');
  try {
    if (!regions || regionsLocale !== locale()) {
      regionsLocale = locale();
      regions = new Intl.DisplayNames([regionsLocale], { type: 'region' });
    }
    return regions.of(cc.toUpperCase()) ?? cc;
  } catch {
    return cc;
  }
}

/** "1 234" in French. */
export const fmtCount = (n: number) => new Intl.NumberFormat(locale()).format(n);

/** Percentage with at most one decimal: "96,9 %", "100 %". */
export function fmtPercent(p: number | null | undefined): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return '';
  return `${new Intl.NumberFormat(locale(), { maximumFractionDigits: 1 }).format(p)} %`;
}
