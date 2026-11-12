// Links and images of the body: form checks (shortener, misleading text, http, IP, port…) and a
// real visit of each one (HEAD then GET, redirects followed up to 10, 5 s per link, 6 at a time).
import net from 'node:net';
import { domainToUnicode } from 'node:url';
import { orgDomain } from '../received.js';
import { anchors, tags, urlsInText } from './html.js';
import { GMAIL_BLOCKED_EXT, SHORTENERS, T } from './thresholds.js';
import type { Fetcher, StepContext } from './types.js';
import { msg, t, tPlural } from '../../i18n.js';

/** http:, https:// or http:/// : a scheme without any host. */
const NO_HOST = /^https?:\/*$/i;

export interface LinkInfo {
  url: string;
  text?: string;
  source: 'html' | 'text';
  scheme: string;
  host?: string;
  shortener: boolean;
  mismatch?: string;
  check?: LinkCheck;
}

export interface LinkCheck {
  status?: number;
  finalUrl?: string;
  redirects: string[];
  contentType?: string;
  bytes?: number;
  /** technical detail (library message, error code) */
  error?: string;
  /** the same, said in French for the interface */
  reason?: string;
  ms: number;
}

export interface ImageInfo {
  src: string;
  alt?: string;
  host?: string;
  width?: string;
  height?: string;
  tracking: boolean;
  check?: LinkCheck;
}

function safeUrl(u: string): URL | undefined {
  try {
    return new URL(u);
  } catch {
    return undefined;
  }
}

const LOOKS_LIKE_URL = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?$/i;

function hostOf(u: string | undefined): string | undefined {
  return u ? safeUrl(u)?.hostname.toLowerCase().replace(/^\[|\]$/g, '') : undefined;
}

function isMixedScript(label: string): boolean {
  const latin = /\p{Script=Latin}/u.test(label);
  const other = /\p{Script=Cyrillic}|\p{Script=Greek}|\p{Script=Armenian}/u.test(label);
  return latin && other;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p, new Promise<T>((_r, rej) => (t = setTimeout(() => rej(new Error(`délai de ${ms / 1000} s dépassé`)), ms)))]);
  } finally {
    clearTimeout(t);
  }
}

const HTTP_REASON: Record<number, string> = {
  400: msg('requête refusée'),
  401: msg('connexion requise'),
  403: msg('accès refusé'),
  404: msg('page introuvable'),
  410: msg('page supprimée'),
  429: msg('trop de requêtes, le site limite les visites'),
  500: msg('erreur du serveur'),
  502: msg('passerelle en erreur'),
  503: msg('service indisponible'),
  504: msg('le serveur a mis trop de temps à répondre'),
};

/** "erreur HTTP 404 : page introuvable" */
export function httpReason(status: number): string {
  const r = HTTP_REASON[status] ?? (status >= 500 ? msg('erreur du serveur') : undefined);
  return r ? t('erreur HTTP {status} : {reason}', { status, reason: t(r) }) : t('erreur HTTP {status}', { status });
}

/** Technical detail of a failed visit and its French wording. */
export function describeFetchError(e: unknown): { error: string; reason: string } {
  const err = e as { message?: string; code?: string; cause?: { message?: string; code?: string } };
  const parts = [err?.message, err?.code, err?.cause?.code, err?.cause?.message].filter((x): x is string => !!x);
  const error = [...new Set(parts)].join(' : ') || t('erreur inconnue');
  const tx = `${error} ${err?.cause?.code ?? ''}`;
  let reason = t('le serveur n’a pas répondu correctement');
  const delay = /délai de (\d+) s dépassé/.exec(tx);
  if (delay) reason = t('pas de réponse en {n} s', { n: delay[1] });
  else if (/UNSAFE_TARGET|non publique refusée/.test(tx)) reason = t('adresse privée ou locale refusée (protection du serveur)');
  else if (/ECONNREFUSED/.test(tx)) reason = t('connexion refusée par le serveur');
  else if (/ENOTFOUND|EAI_AGAIN|ENODATA|NXDOMAIN/.test(tx)) reason = t('nom de domaine introuvable');
  else if (/ETIMEDOUT|TIMEOUT|timeout/i.test(tx)) reason = t('pas de réponse dans le délai');
  else if (/ECONNRESET|socket hang up|UND_ERR_SOCKET|other side closed/i.test(tx)) reason = t('connexion coupée par le serveur');
  else if (/CERT|certificate|SSL|TLS|self[- ]signed/i.test(tx)) reason = t('certificat HTTPS invalide');
  else if (/Protocole refusé/.test(tx)) reason = t('protocole non pris en charge');
  else if (/Invalid URL|ERR_INVALID_URL/.test(tx)) reason = t('adresse mal formée');
  else if (/redirections/.test(tx)) reason = error;
  return { error, reason };
}

/** Visit a URL: HEAD first, GET when HEAD is refused, redirects followed. */
export async function visit(fetcher: Fetcher, url: string, maxRedirects = T.linkMaxRedirects, timeoutMs = T.linkTimeoutMs): Promise<LinkCheck> {
  const started = performance.now();
  const redirects: string[] = [];
  let current = url;
  const run = async (): Promise<LinkCheck> => {
    for (let i = 0; i <= maxRedirects; i++) {
      type R = { status: number; headers: Record<string, string>; bytes?: number; failure?: unknown };
      const tryFetch = (m: 'HEAD' | 'GET') => fetcher(current, m).catch((e: unknown): R => ({ status: 0, headers: {}, failure: e })) as Promise<R>;
      let res = await tryFetch('HEAD');
      if (!res.status || [400, 403, 405, 501].includes(res.status)) {
        const g = await tryFetch('GET');
        if (g.status || !res.status) res = g;
      }
      if (!res.status) return { redirects, ...describeFetchError(res.failure ?? new Error(t('pas de réponse'))), ms: 0, finalUrl: current };
      const loc = res.headers.location;
      if (res.status >= 300 && res.status < 400 && loc) {
        const next = new URL(loc, current).toString();
        redirects.push(next);
        current = next;
        continue;
      }
      const len = Number(res.headers['content-length']);
      return {
        status: res.status,
        finalUrl: current,
        redirects,
        contentType: res.headers['content-type'],
        bytes: Number.isFinite(len) ? len : res.bytes,
        reason: res.status >= 400 ? httpReason(res.status) : undefined,
        ms: 0,
      };
    }
    const tooMany = t('plus de {n} redirections', { n: maxRedirects });
    return { finalUrl: current, redirects, error: tooMany, reason: tooMany, ms: 0 };
  };
  try {
    const out = await withTimeout(run(), timeoutMs);
    return { ...out, ms: Math.round(performance.now() - started) };
  } catch (e) {
    return { finalUrl: current, redirects, ...describeFetchError(e), ms: Math.round(performance.now() - started) };
  }
}

async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<void>) {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) await fn(items[i++]);
    }),
  );
}

export function collectLinks(html: string, text: string): LinkInfo[] {
  const out = new Map<string, LinkInfo>();
  const add = (href: string, t: string | undefined, source: 'html' | 'text') => {
    if (out.has(href)) return;
    const u = safeUrl(href);
    const scheme = u ? u.protocol.replace(/:$/, '').toLowerCase() : (/^([a-z][a-z0-9+.-]*):/i.exec(href)?.[1]?.toLowerCase() ?? '');
    const host = u && (scheme === 'http' || scheme === 'https') ? u.hostname.toLowerCase().replace(/^\[|\]$/g, '') : undefined;
    out.set(href, { url: href, text: t, source, scheme, host, shortener: !!host && SHORTENERS.has(host.replace(/^www\./, '')) });
  };
  // href="http:///" (scheme, no host) leads nowhere: counted with the empty links, not listed as a link
  if (html) for (const a of anchors(html)) if (!NO_HOST.test(a.href)) add(a.href, a.text || (a.hasImage ? '[image]' : ''), 'html');
  for (const u of urlsInText(text)) add(u, undefined, 'text');
  return [...out.values()];
}

export async function runLinks(sc: StepContext) {
  const { facts, deps, c } = sc;
  const html = facts.html?.text ?? '';
  const text = facts.text?.text ?? '';
  const links = collectLinks(html, text);
  const fromOrg = orgDomain(facts.fromDomain);
  const providerKey = facts.provider?.key;
  sc.data.links = links;

  const web = links.filter((l) => l.scheme === 'http' || l.scheme === 'https');
  const fetcher = deps.fetcher;
  if (fetcher && web.length) {
    const toCheck = web.slice(0, T.maxLinksChecked);
    if (web.length > toCheck.length) c.missing(t('Vérification des liens'), t('{total} liens : seuls les {n} premiers ont été visités', { total: web.length, n: toCheck.length }));
    await pool(toCheck, T.linkConcurrency, async (l) => {
      l.check = await visit(fetcher, l.url);
    });
  } else if (!fetcher && web.length) c.missing(t('Vérification des liens'), t('Visite des liens désactivée'));

  for (const l of links) {
    const v = { url: l.url };
    const u = safeUrl(l.url);
    if (['javascript', 'data', 'vbscript', 'file'].includes(l.scheme)) {
      c.add('links.unsafe_scheme', { vars: v, evidence: l.url.slice(0, 200), fallback: { title: t('Lien {url} : protocole dangereux'), family: 'links', severity: 'high', penalty: 1 } });
      continue;
    }
    if (!u || !l.host) continue;
    if (l.shortener) c.add('links.shortener', { vars: v, evidence: `${l.url}${l.check?.finalUrl && l.check.finalUrl !== l.url ? ` → ${l.check.finalUrl}` : ''}`, fallback: { title: t('Lien raccourci {url}'), family: 'links', severity: 'medium', penalty: 1 } });
    if (l.scheme === 'http') c.add('links.http_not_https', { vars: v, evidence: l.url, fallback: { title: t('Lien non chiffré (http) : {url}'), family: 'links', severity: 'low', penalty: 0.3 } });
    if (net.isIP(l.host)) c.add('links.ip_literal', { vars: v, evidence: l.url, fallback: { title: t('Lien vers une adresse IP : {url}'), family: 'links', severity: 'high', penalty: 1.5 } });
    if (u.port && !['80', '443', '8080'].includes(u.port)) c.add('links.nonstandard_port', { vars: v, evidence: l.url, fallback: { title: t('Lien sur un port inhabituel : {url}'), family: 'links', severity: 'medium', penalty: 0.5 } });
    if (u.username || u.password) c.add('links.userinfo_in_url', { vars: v, evidence: l.url, fallback: { title: t('Lien avec identifiant avant @ : {url}'), family: 'links', severity: 'high', penalty: 1.5 } });
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|\.(local|localhost|test|internal)$|(^|\.)(staging|preprod|recette|dev)\./i.test(l.host))
      c.add('links.localhost_or_staging', { vars: v, evidence: l.url, fallback: { title: t('Lien vers un serveur de test : {url}'), family: 'links', severity: 'medium', penalty: 0.5 } });
    if (l.host.split('.').some((x) => x.startsWith('xn--'))) {
      const uni = domainToUnicode(l.host);
      if (uni.split('.').some(isMixedScript))
        c.add('links.punycode_lookalike', { vars: { url: l.url, value: uni }, evidence: `${l.host} = ${uni}`, fallback: { title: t('Domaine qui imite un autre ({value})'), family: 'links', severity: 'medium', penalty: 0.7 } });
    }
    // displayed URL that leads elsewhere
    if (l.text && l.text !== '[image]') {
      const m = LOOKS_LIKE_URL.exec(l.text.trim());
      if (m) {
        const shown = orgDomain(m[1]);
        const target = orgDomain(l.host);
        const final = orgDomain(hostOf(l.check?.finalUrl));
        if (shown && target && shown !== target && shown !== final) {
          l.mismatch = m[1].toLowerCase();
          c.add('links.text_url_mismatch', {
            vars: { url: l.url, value: l.text },
            evidence: `${t('Texte affiché : {text}', { text: l.text })}\n${t('Cible : {url}', { url: l.url })}${l.check?.finalUrl && l.check.finalUrl !== l.url ? `\n${t('Arrivée : {url}', { url: l.check.finalUrl })}` : ''}`,
            fallback: { title: t('Le lien affiche {value} mais mène ailleurs'), family: 'links', severity: 'high', penalty: 1.5 },
          });
        }
      }
    }
    const path = u.pathname.toLowerCase();
    const ext = /\.([a-z0-9]{2,6})$/.exec(path)?.[1];
    const finalType = l.check?.contentType ?? '';
    if ((ext && GMAIL_BLOCKED_EXT.has(ext)) || /application\/(x-msdownload|x-msdos-program|x-ms-installer|vnd\.microsoft\.portable-executable|java-archive)/i.test(finalType))
      c.add('links.executable_target', { vars: { url: l.url, value: ext ?? finalType }, evidence: l.url, fallback: { title: t('Lien vers un fichier exécutable'), family: 'links', severity: 'high', penalty: 2 } });
    // open redirect: a query parameter that is itself an absolute URL on another domain
    for (const val of u.searchParams.values()) {
      if (/^https?:\/\//i.test(val)) {
        const other = orgDomain(hostOf(val));
        if (other && other !== orgDomain(l.host) && !(l.check?.finalUrl && orgDomain(hostOf(l.check.finalUrl)) === orgDomain(l.host))) {
          c.add('links.open_redirect', { vars: v, evidence: l.url.slice(0, 300), fallback: { title: t('Lien de redirection vers un autre site'), family: 'links', severity: 'medium', penalty: 0.7 } });
          break;
        }
      }
    }
    if (l.check) {
      const ch = l.check;
      if (ch.error || (ch.status !== undefined && ch.status >= 400))
        c.add('links.broken', {
          // links.yaml says « répond par une erreur {value} »
          vars: { url: l.url, value: ch.status && ch.status >= 400 ? `HTTP ${ch.status}` : t('de connexion ({reason})', { reason: ch.reason ?? t('aucune réponse') }) },
          evidence: `${l.url} : ${ch.reason ?? t('erreur HTTP {status}', { status: ch.status })}${ch.redirects.length ? ` ${tPlural(ch.redirects.length, 'après {n} redirection', 'après {n} redirections')}` : ''}`,
          fallback: { title: t('Lien cassé : {url}'), family: 'links', severity: 'medium', penalty: 0.5 },
        });
      if (ch.redirects.length > T.maxLinkRedirects)
        c.add('links.redirect_chain', { vars: { url: l.url, value: ch.redirects.length }, evidence: [l.url, ...ch.redirects].join('\n→ '), fallback: { title: t('{value} redirections avant la page finale'), family: 'links', severity: 'low', penalty: 0.3 } });
    }
  }
  const empty = html ? anchors(html).filter((a) => a.href === '' || a.href === '#' || NO_HOST.test(a.href)) : [];
  const emptyHref = empty.length;
  if (emptyHref)
    c.add('links.empty_href', {
      vars: { value: emptyHref },
      evidence: empty
        .slice(0, 5)
        .map((a) => `<a href="${a.href}"> : ${a.text ? t('sur le texte « {text} »', { text: a.text.slice(0, 60) }) : a.hasImage ? t('autour d’une image') : t('sans texte ni image, invisible dans le message')}`)
        .join('\n'),
      fallback: { title: t('{value} lien(s) sans destination'), family: 'links', severity: 'low', penalty: 0.1 },
    });
  if (web.length > T.maxLinks) c.add('links.too_many', { vars: { value: web.length }, fallback: { title: t('{value} liens dans le message'), family: 'links', severity: 'low', penalty: 0.3 } });
  if (links.length && links.every((l) => l.scheme === 'mailto')) c.add('links.mailto_only', { fallback: { title: t('Seulement des liens mailto'), family: 'links', severity: 'info', penalty: 0 } });
  if (facts.isBulk && web.length && fromOrg && !web.some((l) => orgDomain(l.host) === fromOrg || orgDomain(hostOf(l.check?.finalUrl)) === fromOrg))
    c.add('links.no_link_to_sender_domain', { fallback: { title: t('Aucun lien vers le site de {domain}'), family: 'links', severity: 'low', penalty: 0.3 } });
  if (web.length && !c.findings.some((f) => f.family === 'links' && f.penalty > 0))
    c.pass('links.ok', 'links', t('{n} lien(s) contrôlé(s)', { n: web.length }), fetcher ? t('tous répondent') : undefined);

  /* ---------------- images ---------------- */
  const imgs: ImageInfo[] = (html ? tags(html, ['img']) : []).map((tag) => ({
    src: tag.attrs.src ?? '',
    alt: tag.attrs.alt,
    host: hostOf(tag.attrs.src),
    width: tag.attrs.width,
    height: tag.attrs.height,
    tracking: (tag.attrs.width === '1' && tag.attrs.height === '1') || (tag.attrs.width === '0' && tag.attrs.height === '0') || /display\s*:\s*none/i.test(tag.attrs.style ?? ''),
  }));
  sc.data.images = imgs;
  const remote = imgs.filter((i) => /^https?:/i.test(i.src));
  if (fetcher && remote.length) {
    const uniq = [...new Map(remote.map((i) => [i.src, i])).values()].slice(0, T.maxImagesChecked);
    const results = new Map<string, LinkCheck>();
    await pool(uniq, T.linkConcurrency, async (i) => {
      results.set(i.src, await visit(fetcher, i.src));
    });
    for (const i of remote) i.check = results.get(i.src);
  }
  const content = imgs.filter((i) => !i.tracking);
  const noAlt = content.filter((i) => i.alt === undefined);
  if (noAlt.length)
    c.add('images.missing_alt', {
      vars: { value: noAlt.length },
      evidence: [`${tPlural(noAlt.length, '{n} image sans attribut alt', '{n} images sans attribut alt')} :`, ...noAlt.slice(0, 5).map((i) => i.src.slice(0, 120))].join('\n'), fallback: { title: t('{value} image(s) sans texte alternatif'), family: 'images', severity: 'low', penalty: 0.2 } });
  const httpImg = remote.filter((i) => i.src.toLowerCase().startsWith('http:'));
  if (httpImg.length) c.add('images.http_insecure', { vars: { url: httpImg[0].src }, evidence: httpImg.slice(0, 5).map((i) => i.src).join('\n'), fallback: { title: t('Images chargées en http'), family: 'images', severity: 'low', penalty: 0.3 } });
  const ipImg = remote.filter((i) => i.host && net.isIP(i.host));
  if (ipImg.length) c.add('images.ip_host', { vars: { url: ipImg[0].src }, fallback: { title: t('Image hébergée sur une adresse IP'), family: 'images', severity: 'medium', penalty: 0.7 } });
  const knownOrgs = new Set([fromOrg, ...web.map((l) => orgDomain(l.host))].filter(Boolean));
  const third = content.filter((i) => i.host && !net.isIP(i.host) && !knownOrgs.has(orgDomain(i.host)) && !providerKey);
  if (third.length) c.add('images.third_party_host', { vars: { url: third[0].src }, evidence: [...new Set(third.map((i) => i.host))].join(', '), fallback: { title: t('Images hébergées sur un autre domaine'), family: 'images', severity: 'low', penalty: 0.2 } });
  const broken = remote.filter((i) => i.check && (i.check.error || (i.check.status ?? 0) >= 400));
  const why = (i: ImageInfo) => i.check?.reason ?? (i.check?.status ? httpReason(i.check.status) : t('aucune réponse'));
  if (broken.length)
    c.add('images.unreachable', {
      // {status}: what the first image answers; the count goes to the evidence
      vars: { url: broken[0].src, status: why(broken[0]), value: broken[0].check?.status ?? why(broken[0]) },
      evidence: [`${tPlural(broken.length, '{n} image ne se charge pas', '{n} images ne se chargent pas')} :`, ...broken.slice(0, 5).map((i) => `${i.src} : ${why(i)}`)].join('\n'), fallback: { title: t('{value} image(s) inaccessible(s)'), family: 'images', severity: 'medium', penalty: 0.5 } });
  const wrongType = remote.filter((i) => i.check?.status === 200 && i.check.contentType && !/^image\//i.test(i.check.contentType));
  if (wrongType.length) c.add('images.wrong_content_type', { vars: { url: wrongType[0].src, value: wrongType[0].check?.contentType }, fallback: { title: t('Une image n’est pas servie comme image'), family: 'images', severity: 'low', penalty: 0.2 } });
  const heavy = remote.filter((i) => (i.check?.bytes ?? 0) > T.maxImageBytes);
  if (heavy.length) c.add('images.too_heavy', { vars: { url: heavy[0].src, value: t('{n} Ko', { n: Math.round((heavy[0].check?.bytes ?? 0) / 1024) }) }, fallback: { title: t('Image lourde ({value})'), family: 'images', severity: 'low', penalty: 0.3 } });
  if (remote.some((i) => !i.tracking && (i.check?.redirects.length ?? 0) > 0)) c.add('images.redirecting_src', { fallback: { title: t('Images servies après redirection'), family: 'images', severity: 'low', penalty: 0.1 } });
  if (imgs.some((i) => i.tracking)) c.add('images.tracking_pixel', { fallback: { title: t('Pixel de suivi'), family: 'images', severity: 'info', penalty: 0 } });
  if (facts.inline.length > T.maxInlineImages) c.add('images.inline_cid_many', { vars: { value: facts.inline.length }, fallback: { title: t('{value} images jointes au message'), family: 'images', severity: 'medium', penalty: 0.5 } });
  if (content.length && !c.findings.some((f) => f.family === 'images' && f.penalty > 0)) c.pass('images.ok', 'images', t('{n} image(s) correcte(s)', { n: content.length }));

  return { links, linkDomains: [...new Set(web.map((l) => l.host!).filter((h) => !net.isIP(h)))] };
}
