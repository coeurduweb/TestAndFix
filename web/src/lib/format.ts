import { locale, t } from './i18n';

// Formatters follow the interface language (i18n.tsx); they are built on use, the language being set before the first render.
const one = () => new Intl.NumberFormat(locale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const int = () => new Intl.NumberFormat(locale());

export const fmtScore = (n: number | undefined | null) => (n === undefined || n === null ? '' : one().format(n));
export const fmtInt = (n: number) => int().format(n);
export const fmtPenalty = (n: number) => one().format(Math.abs(n));

export function fmtDateTime(iso: string | number | undefined | null): string {
  if (iso === undefined || iso === null || iso === '') return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const day = d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit', year: 'numeric' });
  const time = d.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return t('{day} à {time}', { day, time });
}

export function fmtRelative(iso: string | number): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 5) return t("à l'instant");
  if (s < 60) return t('il y a {n} s', { n: s });
  const m = Math.round(s / 60);
  if (m < 60) return t('il y a {n} min', { n: m });
  const h = Math.round(m / 60);
  if (h < 24) return t('il y a {n} h', { n: h });
  return t('il y a {n} j', { n: Math.round(h / 24) });
}

export function fmtMs(ms: number | undefined): string {
  if (ms === undefined) return '';
  return ms < 1000 ? `${Math.round(ms)} ms` : `${one().format(ms / 1000)} s`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return t('{n} o', { n });
  if (n < 1024 * 1024) return t('{n} Ko', { n: one().format(n / 1024) });
  return t('{n} Mo', { n: one().format(n / 1024 / 1024) });
}

/** Score band: lab-report wording. */
export function scoreBand(score: number): 'ok' | 'mid' | 'low' {
  return score >= 9 ? 'ok' : score >= 6 ? 'mid' : 'low';
}

/** "3 jours": `one` and `many` are French words, translated; the language decides which form a count takes. */
export const plural = (n: number, one: string, many: string) =>
  `${fmtInt(n)} ${t(new Intl.PluralRules(locale()).select(n) === 'one' ? one : many)}`;
