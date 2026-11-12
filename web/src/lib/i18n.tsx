// Languages of the interface. Messages are written in French in the code and the French sentence is
// the key (gettext style): t('Mesurer à nouveau'), t('il y a {n} min', { n }). Each other language has
// a catalog in i18n/web.<lang>.json. A missing translation falls back to English, then to French.
//
// The language: the visitor's choice (localStorage), else the first browser language we support,
// else English. It is also written to the `lang` cookie so that the server writes its findings and
// verdicts in the same language.
import { Fragment, type ReactNode } from 'react';

/** The six most used content languages of the web (W3Techs, 12 November 2026), English first. */
export const LANGS = ['en', 'es', 'de', 'ja', 'fr', 'pt'] as const;
export type Lang = (typeof LANGS)[number];
/** Each language named in itself, for the switcher. */
export const LANG_NAMES: Record<Lang, string> = { en: 'English', es: 'Español', de: 'Deutsch', ja: '日本語', fr: 'Français', pt: 'Português' };

const STORAGE_KEY = 'lang';
const isLang = (v: unknown): v is Lang => typeof v === 'string' && (LANGS as readonly string[]).includes(v);

/** First supported language among the browser's, else English. */
export function detectLang(langs: readonly string[] = typeof navigator === 'undefined' ? [] : navigator.languages ?? [navigator.language]): Lang {
  for (const l of langs) {
    const primary = l?.toLowerCase().split('-')[0];
    if (isLang(primary)) return primary;
  }
  return 'en';
}

function stored(): Lang | undefined {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return isLang(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

type Catalog = Record<string, string>;
let lang: Lang = 'fr';
let cat: Catalog = {};
let en: Catalog = {};

export const currentLang = () => lang;
/** BCP 47 locale for Intl. */
export const locale = () => ({ en: 'en-GB', es: 'es-ES', de: 'de-DE', ja: 'ja-JP', fr: 'fr-FR', pt: 'pt-BR' })[lang];

const loaders = import.meta.glob<Catalog>('../../../i18n/web.*.json', { import: 'default' });
async function load(l: Lang): Promise<Catalog> {
  if (l === 'fr') return {};
  const f = loaders[`../../../i18n/web.${l}.json`];
  return f ? f().catch(() => ({})) : {};
}

function writeCookie(l: Lang) {
  try {
    document.cookie = `lang=${l}; path=/; max-age=${400 * 86400}; SameSite=Lax`;
  } catch {
    /* no cookie: the server falls back to Accept-Language */
  }
}

/** Load the language before the first render (main.tsx). */
export async function initI18n(forced?: Lang): Promise<Lang> {
  const l = forced ?? stored() ?? detectLang();
  const [c, e] = await Promise.all([load(l), l === 'en' ? Promise.resolve(null) : load('en')]);
  setCatalogs(l, c, e ?? c);
  writeCookie(l);
  document.documentElement.lang = l;
  return l;
}

/** For tests and initI18n. */
export function setCatalogs(l: Lang, c: Catalog, english: Catalog = {}) {
  lang = l;
  cat = c;
  en = english;
}

/** The visitor's choice: kept, then the page reloads in that language (findings come from the server). */
export function chooseLang(l: Lang) {
  try {
    localStorage.setItem(STORAGE_KEY, l);
  } catch {
    /* the cookie still carries it for this session */
  }
  writeCookie(l);
  location.reload();
}

export type TVars = Record<string, string | number | undefined | null>;

function interpolate(text: string, vars?: TVars): string {
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (m, k: string) => {
    const v = vars[k];
    return v === undefined || v === null ? m : typeof v === 'number' ? new Intl.NumberFormat(locale()).format(v) : v;
  });
}

const raw = (msgid: string) => (lang === 'fr' ? msgid : cat[msgid] || en[msgid] || msgid);

/** Translate a French message. Numbers in vars are formatted for the language. */
export function t(msgid: string, vars?: TVars): string {
  return interpolate(raw(msgid), vars);
}

/** Marks a French msgid for extraction where t() is applied later to a variable. */
export const msg = (s: string) => s;

/** "3 jours": `one` and `many` are French msgids with {n} ("{n} jour", "{n} jours"); Intl picks the form. */
export function tn(n: number, one: string, many: string, vars?: TVars): string {
  const form = new Intl.PluralRules(locale()).select(n) === 'one' ? one : many;
  return t(form, { n, ...vars });
}

/**
 * A message with markup: tags in the msgid are rendered by the given components, so translators
 * move them freely. rich('Expire le <b>{date}</b>', { date }, { b: (c) => <strong>{c}</strong> }).
 * Tags do not nest.
 */
export function rich(msgid: string, vars: TVars | undefined, tags: Record<string, (children: ReactNode) => ReactNode>): ReactNode {
  const text = interpolate(raw(msgid), vars);
  const out: ReactNode[] = [];
  const re = /<(\w+)>(.*?)<\/\1>/gs;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const render = tags[m[1]];
    out.push(<Fragment key={i++}>{render ? render(m[2]) : m[2]}</Fragment>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}
