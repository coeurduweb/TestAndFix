// Languages of the interface and of the texts the server writes (findings, verdicts, errors).
//
// Messages are written in French in the code and the French sentence is the key (gettext style):
// t('Domaine payé jusqu’au {date}', { date }). Each other language has a catalog in i18n/server.<lang>.json
// mapping the French sentence to its translation. A missing translation falls back to English, then
// to the French sentence, so a message is never empty.
//
// The language of a request: the `lang` cookie set by the interface (the visitor's choice or the
// detected language), else Accept-Language, else English. Mail reception has no request: the language
// is the one stored with the test address (mail/service.ts).
import { AsyncLocalStorage } from 'node:async_hooks';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance, FastifyRequest } from 'fastify';

/** The six most used content languages of the web (W3Techs, 12 November 2026), English first. */
export const LANGS = ['en', 'es', 'de', 'ja', 'fr', 'pt'] as const;
export type Lang = (typeof LANGS)[number];
export const LANG_COOKIE = 'lang';
const LOCALES: Record<Lang, string> = { en: 'en-GB', es: 'es-ES', de: 'de-DE', ja: 'ja-JP', fr: 'fr-FR', pt: 'pt-BR' };
/** Accept-Language sent to audited sites: the reader's language first, as a browser would. */
export function browserAcceptLanguage(): string {
  const loc = locale();
  const lang = currentLang();
  return lang === 'en' ? 'en-US,en;q=0.9' : `${loc},${lang};q=0.9,en-US;q=0.8,en;q=0.7`;
}
/** BCP 47 locale of the current language, for Intl (dates, numbers). */
export const locale = () => LOCALES[currentLang()];

let defaultLang: Lang = 'en';
/** Language outside any request (tests set French, the language the messages are written in). */
export function setDefaultLang(l: Lang) {
  defaultLang = l;
}

export const isLang = (v: unknown): v is Lang => typeof v === 'string' && (LANGS as readonly string[]).includes(v);

/** First supported language of an Accept-Language header, by quality. */
export function fromAcceptLanguage(header: string | undefined): Lang | undefined {
  if (!header) return undefined;
  const ranked = header
    .split(',')
    .map((part, i) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params.map((p) => p.trim()).find((p) => p.startsWith('q='));
      return { tag: tag.toLowerCase(), q: q ? Number(q.slice(2)) || 0 : 1, i };
    })
    .filter((x) => x.tag && x.q > 0)
    .sort((a, b) => b.q - a.q || a.i - b.i);
  for (const { tag } of ranked) {
    const primary = tag.split('-')[0];
    if (isLang(primary)) return primary;
  }
  return undefined;
}

export function langOfRequest(req: Pick<FastifyRequest, 'headers'> & { cookies?: Record<string, string | undefined> }): Lang {
  const c = req.cookies?.[LANG_COOKIE];
  if (isLang(c)) return c;
  return fromAcceptLanguage(req.headers['accept-language']) ?? defaultLang;
}

const als = new AsyncLocalStorage<{ lang: Lang }>();

export function currentLang(): Lang {
  return als.getStore()?.lang ?? defaultLang;
}

/** True inside a request (or withLang): false at SMTP reception and in background jobs. */
export function hasLangContext(): boolean {
  return als.getStore() !== undefined;
}

/** Run `fn` in a language (mail reception, background jobs). */
export function withLang<T>(lang: Lang | string | null | undefined, fn: () => T): T {
  return als.run({ lang: isLang(lang) ? lang : defaultLang }, fn);
}

/** Bind the language of every request, the way owner.ts binds the notebook. */
export function registerLang(app: FastifyInstance) {
  app.addHook('onRequest', (req, _reply, done) => {
    als.run({ lang: langOfRequest(req) }, done);
  });
  app.addHook('preValidation', (req, _reply, done) => {
    als.run({ lang: langOfRequest(req) }, done);
  });
}

// ---------- catalogs ----------

const here = path.dirname(fileURLToPath(import.meta.url));
const I18N_DIR = path.resolve(here, '..', '..', 'i18n');
type Catalog = Record<string, string>;
const catalogs = new Map<Lang, Catalog>();

export function catalog(lang: Lang): Catalog {
  let c = catalogs.get(lang);
  if (!c) {
    try {
      c = lang === 'fr' ? {} : (JSON.parse(fs.readFileSync(path.join(I18N_DIR, `server.${lang}.json`), 'utf8')) as Catalog);
    } catch {
      c = {};
    }
    catalogs.set(lang, c);
  }
  return c;
}

/** Marks a French msgid for extraction where it is translated later (t() is called on the variable). */
export const msg = (s: string) => s;

export type TVars = Record<string, string | number | undefined | null>;

/** Replace {name} with its value; an unknown name stays as written. */
export function interpolate(text: string, vars?: TVars): string {
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (m, k: string) => {
    const v = vars[k];
    return v === undefined || v === null ? m : String(v);
  });
}

/** Translate a French message into a language (the current one by default). */
export function tIn(lang: Lang, msgid: string, vars?: TVars): string {
  const text = lang === 'fr' ? msgid : catalog(lang)[msgid] || catalog('en')[msgid] || msgid;
  return interpolate(text, vars);
}

export function t(msgid: string, vars?: TVars): string {
  return tIn(currentLang(), msgid, vars);
}

/** Plural: `one` and `many` are French msgids ("jour", "jours"); Intl decides which form the language uses. */
export function tPlural(n: number, one: string, many: string, vars?: TVars): string {
  const lang = currentLang();
  const form = new Intl.PluralRules(lang).select(n) === 'one' ? one : many;
  return t(form, { n, ...vars });
}
