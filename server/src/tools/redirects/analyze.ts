// Findings of a redirect chain (knowledge/situations/redirects.yaml, family `redirects`).
// Every suggested fix is computed for the hosts of this chain: .htaccess (Apache) and nginx.
import { t, tPlural, msg } from '../../i18n.js';
import psl from 'psl';
import { pass, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import type { HttpExchange } from '../../lib/http-trace.js';
import type { Hop, TraceData } from './trace.js';

/** One year: minimum max-age of the HSTS preload list (hstspreload.org, submission requirements). */
export const HSTS_MIN_AGE = 31536000;
/** Googlebot reads the first 2 MB of an HTML file, uncompressed (Google Search Central, Googlebot). */
export const HEAVY_BYTES = 2 * 1024 * 1024;
/** Internal setting: a text body above this size sent without compression. */
export const COMPRESS_MIN = 10 * 1024;
/** Internal setting: whole chain slower than this. */
export const SLOW_TOTAL_MS = 3000;
/** web.dev: a good TTFB is 0.8 s or less. */
export const GOOD_TTFB_MS = 800;
export const CERT_SOON_DAYS = 14;

export const STATUS_TEXT: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 203: 'Non-Authoritative Information', 204: 'No Content', 206: 'Partial Content',
  300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 406: 'Not Acceptable', 408: 'Request Timeout',
  410: 'Gone', 418: "I'm a teapot", 429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};

const host = (u: string) => new URL(u).hostname.toLowerCase();
const scheme = (u: string) => new URL(u).protocol.replace(':', '');
const bareHost = (h: string) => h.replace(/^www\./, '');
export function registrable(h: string): string {
  return (psl.get(h) as string | null) ?? h;
}
const esc = (h: string) => h.replace(/\./g, '\\.');

const DOMAIN_MOVE = msg('changement de domaine');
/** Kind of change made by one redirect, when it looks like a permanent canonicalisation. */
export function permanentLooking(from: string, to: string): string | undefined {
  const a = new URL(from);
  const b = new URL(to);
  const samePath = a.pathname === b.pathname && a.search === b.search;
  if (a.protocol === 'http:' && b.protocol === 'https:' && a.hostname === b.hostname) return msg('passage de http à https');
  if (bareHost(a.hostname) === bareHost(b.hostname) && a.hostname !== b.hostname) return a.hostname.startsWith('www.') ? msg('retrait du www') : msg('ajout du www');
  // same path on another registrable domain: a domain move (a shortener or tracking hop changes the path)
  if (registrable(a.hostname) !== registrable(b.hostname) && samePath) return DOMAIN_MOVE;
  return undefined;
}

const LANG_PARAM = /^(locale|lang|language|hl|lc|lng|country|region|setlang|ln)$/i;
const LANG_SEG = /^\/[a-z]{2}(?:[-_][a-z]{2,4})?(?=\/|$)/i;

/**
 * A temporary redirect that only picks a language or region: same origin, and the target adds only
 * language parameters (?locale=fr-fr), or prefixes the path with /fr, /en-gb..., or the response
 * says Vary: Accept-Language. It is a negotiation: a 301 there would pin one language for everyone.
 */
export function isLanguageRedirect(h: Hop): boolean {
  if (!h.redirect || h.redirect.kind !== 'http' || ![302, 303, 307].includes(h.exchange.status ?? 0)) return false;
  let a: URL;
  let b: URL;
  try {
    a = new URL(h.url);
    b = new URL(h.redirect.to);
  } catch {
    return false;
  }
  if (a.origin !== b.origin) return false;
  const vary = getHeaderValue(h.exchange, 'vary');
  if (vary && /accept-language/i.test(vary)) return true;
  if (a.pathname === b.pathname) {
    const before = new URLSearchParams(a.search);
    const added = [...new URLSearchParams(b.search).keys()].filter((k) => !before.has(k));
    const kept = [...before.keys()].every((k) => new URLSearchParams(b.search).get(k) === before.get(k));
    return added.length > 0 && kept && added.every((k) => LANG_PARAM.test(k));
  }
  const m = LANG_SEG.exec(b.pathname);
  return !!m && !LANG_SEG.test(a.pathname) && (b.pathname.slice(m[0].length) || '/') === (a.pathname || '/') && a.search === b.search;
}

function getHeaderValue(ex: HttpExchange, name: string): string | undefined {
  return ex.rawHeaders.filter(([k]) => k.toLowerCase() === name).map(([, v]) => v).join(', ') || undefined;
}

/** WordPress seen in a header (X-Redirect-By, api.w.org Link, X-Pingback) or in the HTML. */
export function detectWordPress(hops: Hop[]): boolean {
  return hops.some((h) => {
    const ex = h.exchange;
    if (/wordpress/i.test(getHeaderValue(ex, 'x-redirect-by') ?? '') || /api\.w\.org/i.test(getHeaderValue(ex, 'link') ?? '') || /xmlrpc\.php/i.test(getHeaderValue(ex, 'x-pingback') ?? '') || /wordpress/i.test(getHeaderValue(ex, 'x-powered-by') ?? '')) return true;
    const t = ex.body?.isText && ex.body.mime?.includes('html') ? ex.body.text : undefined;
    return !!t && (/\/wp-(content|includes)\//i.test(t) || /<meta[^>]+name=["']generator["'][^>]+WordPress/i.test(t));
  });
}

/** Apache + nginx rules that send every variant to `target` (scheme + host) in one 301. */
export function canonicalRules(target: string, aliases: string[] = []): string {
  const tu = new URL(target);
  const h = tu.hostname;
  const names = [...new Set([bareHost(h), 'www.' + bareHost(h), ...aliases])];
  const others = names.filter((n) => n !== h);
  const https = tu.protocol === 'https:';
  return [
    t('# Apache (.htaccess à la racine du site, avant les règles du CMS)'),
    'RewriteEngine On',
    ...(https ? ['RewriteCond %{HTTPS} off [OR]'] : []),
    `RewriteCond %{HTTP_HOST} !^${esc(h)}$ [NC]`,
    `RewriteRule ^ ${tu.protocol}//${h}%{REQUEST_URI} [R=301,L]`,
    '',
    '# nginx',
    'server {',
    '    listen 80;',
    '    listen [::]:80;',
    `    server_name ${names.join(' ')};`,
    `    return 301 ${tu.protocol}//${h}$request_uri;`,
    '}',
    ...(https && others.length
      ? ['server {', '    listen 443 ssl;', '    listen [::]:443 ssl;', `    server_name ${others.join(' ')};`, '    ' + t('# mêmes ssl_certificate et ssl_certificate_key que le site'), `    return 301 https://${h}$request_uri;`, '}']
      : []),
  ].join('\n');
}

/** One URL → another, as a server rule. */
export function pathRule(from: string, to: string): string {
  const f = new URL(from);
  const path = f.pathname || '/';
  return [
    '# Apache (.htaccess)',
    path === '/' ? `RewriteEngine On\nRewriteRule ^$ ${to} [R=301,L]` : `Redirect 301 ${path} ${to}`,
    '',
    t('# nginx (dans le bloc server de {host})', { host: f.hostname }),
    `location = ${path} {`,
    `    return 301 ${to};`,
    '}',
  ].join('\n');
}

function hstsRule(maxAge = HSTS_MIN_AGE): string {
  return [
    t('# Apache (.htaccess ou VirtualHost *:443, module headers actif)'),
    `Header always set Strict-Transport-Security "max-age=${maxAge}; includeSubDomains"`,
    '',
    t('# nginx (bloc server en 443)'),
    `add_header Strict-Transport-Security "max-age=${maxAge}; includeSubDomains" always;`,
  ].join('\n');
}

export function statusLine(ex: HttpExchange): string {
  if (ex.status === undefined) return ex.error?.code ?? t('sans réponse');
  return `${ex.status} ${ex.statusText || STATUS_TEXT[ex.status] || ''}`.trim();
}

function chainText(hops: Hop[]): string {
  return hops
    .map((h) => {
      const how = h.redirect ? (h.redirect.kind === 'http' ? '' : h.redirect.kind === 'meta' ? ', meta refresh' : h.redirect.kind === 'js' ? ', JavaScript' : ', ' + t('en-tête Refresh')) : '';
      return `${h.index}. ${statusLine(h.exchange)}${how}  ${h.url}`;
    })
    .join('\n');
}

/** Public link shorteners: their redirects are set in the service account, not in a server config. */
export const SHORTENERS = new Set(['bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 't.ly', 'lnkd.in', 'shorturl.at', 'tiny.cc', 'rb.gy', 'v.gd', 's.id']);
const isShortener = (u: string) => SHORTENERS.has(host(u).replace(/^www\./, ''));

/** curl command that re-measures the same phases, to compare before and after a fix. */
function curlTiming(u: string): string {
  return `curl -o /dev/null -s -w 'dns %{time_namelookup} s, ${t('connexion')} %{time_connect} s, tls %{time_appconnect} s, ${t('premier octet')} %{time_starttransfer} s, total %{time_total} s\\n' -L '${u.replace(/'/g, "%27")}'`;
}

const fmtDays = (n: number) => tPlural(Math.abs(n), '{n} jour', '{n} jours', { n });
const fmtSec = (n: number) => (n >= 86400 ? t('{n} jours', { n: Math.round(n / 86400) }) : `${n} s`);
const fmtKo = (n: number) => t('{n} Ko', { n: Math.round(n / 1024) });

/** Normalised URL for canonical comparison (host case, default port, no fragment). */
function normUrl(u: string): string {
  const x = new URL(u);
  x.hash = '';
  return x.toString();
}

export function analyzeTrace(d: TraceData): Analysis {
  const issues: Issue[] = [];
  const passed: Analysis['passed'] = [];
  const unavailable: Analysis['unavailable'] = [];
  const F = 'redirects';
  const last = d.hops[d.hops.length - 1];
  const lastEx = last.exchange;
  const redirects = d.hops.filter((h) => h.redirect);
  const chain = chainText(d.hops);

  // ---- stop reasons
  if (d.stoppedBy === 'loop') {
    issues.push({ id: 'redirects.loop', vars: { url: d.start, value: d.hops.length }, evidence: `${chain}\n→ ${last.redirect?.to ?? ''} ${t('(déjà visitée)')}` });
  } else if (d.stoppedBy === 'max') {
    issues.push({ id: 'redirects.too_many', vars: { url: d.start, value: d.max }, evidence: `${chain}\n→ ${last.redirect?.to ?? ''}` });
  } else if (d.stoppedBy === 'unsafe') {
    issues.push({ id: 'redirects.private_target', vars: { url: last.url, ip: lastEx.ip }, evidence: lastEx.error?.message });
  } else if (d.stoppedBy === 'error') {
    issues.push({ id: 'redirects.unreachable', vars: { url: last.url, value: (lastEx.error?.message ?? d.stopDetail ?? '').replace(/\.$/, '') }, evidence: lastEx.error?.message ?? d.stopDetail });
  } else if (d.stoppedBy === 'final') passed.push(pass('redirects.no_loop', F, t('Aucune boucle'), tPlural(redirects.length, "{n} redirection suivie jusqu'au bout", "{n} redirections suivies jusqu'au bout")));

  // ---- length
  if (redirects.length > 2) {
    const target = d.final;
    // only scheme / www / domain changes: one canonical rule; otherwise one rule from the start URL
    const hostOnly = redirects.every((h) => h.redirect!.kind === 'http' && permanentLooking(h.url, h.redirect!.to));
    const suggested = d.stoppedBy !== 'final' ? undefined : hostOnly ? canonicalRules(target) : pathRule(d.start, target);
    issues.push({ id: 'redirects.chain_long', vars: { url: d.start, value: redirects.length, final: target }, evidence: chain, suggested });
  } else if (d.stoppedBy === 'final') passed.push(pass('redirects.chain_short', F, t('Chaîne courte'), redirects.length ? tPlural(redirects.length, '{n} redirection', '{n} redirections') : t('aucune redirection')));

  // ---- temporary where permanent
  const lang = redirects.filter(isLanguageRedirect);
  const temp = redirects.filter((h) => !lang.includes(h) && [302, 303, 307].includes(h.exchange.status ?? 0) && h.redirect!.kind === 'http' && permanentLooking(h.url, h.redirect!.to));
  if (lang.length)
    issues.push({ id: 'redirects.language_redirect', vars: { url: lang[0].url, target: lang[0].redirect!.to, status: lang[0].exchange.status }, evidence: lang.map((h) => `${statusLine(h.exchange)}  ${h.url} → ${h.redirect!.to}`).join('\n') });
  if (temp.length) {
    const h = temp[0];
    const why = permanentLooking(h.url, h.redirect!.to)!;
    const tu = new URL(h.redirect!.to);
    issues.push({
      id: 'redirects.temporary_for_permanent',
      vars: { url: h.url, status: h.exchange.status, value: t(why), target: h.redirect!.to },
      evidence: temp.map((x) => `${statusLine(x.exchange)}  ${x.url} → ${x.redirect!.to} (${t(permanentLooking(x.url, x.redirect!.to)!)})`).join('\n'),
      suggested: why === DOMAIN_MOVE ? domainMoveRule(h.url, h.redirect!.to) : canonicalRules(`${tu.protocol}//${tu.host}/`),
    });
  } else if (redirects.some((h) => h.redirect!.kind === 'http')) {
    passed.push(pass('redirects.permanent_ok', F, t('Type de redirection adapté'), redirects.map((h) => h.exchange.status).filter(Boolean).join(', ')));
  }

  // ---- final status
  const fs = lastEx.status;
  if (d.stoppedBy === 'final' && fs !== undefined) {
    if (fs >= 400) {
      if (redirects.length) {
        const permanent = redirects.some((h) => h.exchange.status === 301 || h.exchange.status === 308);
        issues.push({
          id: 'redirects.redirect_to_error',
          vars: { url: d.start, status: fs, final: d.final, value: permanent ? t('permanente') : t('temporaire') },
          evidence: chain,
          severity: permanent ? 'high' : 'medium',
          // a shortener's target is changed in the service account: no server rule to write
          suggested: fs < 500 && !isShortener(d.start) ? pathRule(d.start, `${new URL(d.final).origin}/nouvelle-page`) : undefined,
        });
      } else issues.push({
        id: 'redirects.final_error',
        vars: { url: d.final, status: fs },
        evidence: `${statusLine(lastEx)}  ${d.final}`,
        suggested: fs < 500 ? pathRule(d.final, `${new URL(d.final).origin}/nouvelle-page`) : undefined,
      });
    } else if (fs >= 200 && fs < 300) passed.push(pass('redirects.final_ok', F, t('La page finale répond'), statusLine(lastEx)));
    else if (fs >= 300 && fs < 400 && !last.redirect) issues.push({ id: 'redirects.redirect_without_location', vars: { url: d.final, status: fs }, evidence: statusLine(lastEx), suggested: pathRule(d.final, `${new URL(d.final).origin}/destination`) });
  }

  // ---- https
  const downgrade = redirects.find((h) => scheme(h.url) === 'https' && scheme(h.redirect!.to) === 'http');
  if (downgrade) issues.push({
    id: 'redirects.https_to_http',
    vars: { url: downgrade.url, target: downgrade.redirect!.to },
    evidence: `${statusLine(downgrade.exchange)}  ${downgrade.url} → ${downgrade.redirect!.to}`,
    suggested: isShortener(downgrade.url) ? undefined : pathRule(downgrade.url, downgrade.redirect!.to.replace(/^http:/, 'https:')),
  });
  if (d.stoppedBy === 'final' && scheme(d.final) === 'http') {
    const target = `https://${new URL(d.final).host}/`;
    issues.push({ id: 'redirects.http_not_redirected', vars: { url: d.final, domain: host(d.final) }, evidence: `${statusLine(lastEx)}  ${d.final}`, suggested: canonicalRules(target) });
  } else if (d.stoppedBy === 'final' && scheme(d.start) === 'http' && scheme(d.final) === 'https') {
    passed.push(pass('redirects.https_upgrade', F, t('http redirigé vers https'), `${d.start} → ${d.final}`));
  }

  // ---- HSTS on the final https page
  if (d.stoppedBy === 'final' && scheme(d.final) === 'https' && fs !== undefined && fs < 400) {
    const h = d.finalPage?.hsts;
    const dom = host(d.final);
    if (!h) issues.push({ id: 'redirects.hsts_missing', vars: { domain: dom, url: d.final }, suggested: hstsRule() });
    else if (h.maxAge === undefined || h.maxAge < HSTS_MIN_AGE)
      issues.push({ id: 'redirects.hsts_short', vars: { domain: dom, value: h.maxAge === undefined ? t('absent') : fmtSec(h.maxAge) }, evidence: `Strict-Transport-Security: ${h.raw}`, suggested: hstsRule() });
    else if (!h.includeSubDomains) issues.push({ id: 'redirects.hsts_no_subdomains', vars: { domain: dom }, evidence: `Strict-Transport-Security: ${h.raw}`, suggested: hstsRule(h.maxAge) });
    else passed.push(pass('redirects.hsts_ok', F, t('HSTS actif'), h.raw));
  }

  // ---- meta refresh, Refresh header, JavaScript
  const meta = redirects.find((h) => h.redirect!.kind === 'meta');
  if (meta) issues.push({ id: 'redirects.meta_refresh', vars: { url: meta.url, target: meta.redirect!.to, value: meta.redirect!.delay }, evidence: `<meta http-equiv="refresh" content="${meta.redirect!.raw}">`, suggested: pathRule(meta.url, meta.redirect!.to) });
  const refresh = redirects.find((h) => h.redirect!.kind === 'refresh');
  if (refresh) issues.push({ id: 'redirects.refresh_header', vars: { url: refresh.url, target: refresh.redirect!.to, value: refresh.redirect!.delay }, evidence: `Refresh: ${refresh.redirect!.raw}`, suggested: pathRule(refresh.url, refresh.redirect!.to) });
  const js = redirects.find((h) => h.redirect!.kind === 'js');
  if (js) issues.push({ id: 'redirects.js_redirect', vars: { url: js.url, target: js.redirect!.to }, evidence: js.redirect!.raw, suggested: pathRule(js.url, js.redirect!.to) });
  const jsSeen = d.hops.find((h) => h.jsSeen);
  if (jsSeen && !js) issues.push({ id: 'redirects.js_seen', vars: { url: jsSeen.url, target: jsSeen.jsSeen!.url }, evidence: jsSeen.jsSeen!.code });

  // ---- canonical and robots on the final page
  if (d.stoppedBy === 'final' && fs !== undefined && fs >= 200 && fs < 300 && lastEx.body?.mime?.includes('html') && d.method === 'GET') {
    const fp = d.finalPage;
    if (!fp?.canonicalRaw) issues.push({ id: 'redirects.canonical_missing', vars: { url: d.final }, suggested: `<link rel="canonical" href="${d.final}">` });
    else if (!fp.canonical) issues.push({ id: 'redirects.canonical_mismatch', vars: { url: d.final, target: fp.canonicalRaw }, evidence: fp.canonicalRaw });
    else {
      const a = new URL(normUrl(fp.canonical));
      const b = new URL(normUrl(d.final));
      const sameDoc = a.protocol === b.protocol && a.host === b.host && a.pathname === b.pathname;
      if (!sameDoc) issues.push({
        id: 'redirects.canonical_mismatch',
        vars: { url: d.final, target: fp.canonical },
        evidence: `${t('Page finale : {url}', { url: d.final })}\n${fp.canonicalSource === 'html' ? t('Canonique (balise link) : {value}', { value: fp.canonicalRaw }) : t('Canonique (en-tête Link) : {value}', { value: fp.canonicalRaw })}`,
        suggested: `<link rel="canonical" href="${d.final}">`,
      });
      else passed.push(pass('redirects.canonical_ok', F, t('Canonique conforme à la page finale'), fp.canonicalRaw + (a.search !== b.search ? ' ' + t('(paramètres de requête ignorés)') : '')));
      if (sameDoc && !/^https?:\/\//i.test(fp.canonicalRaw)) issues.push({ id: 'redirects.canonical_relative', vars: { url: d.final, value: fp.canonicalRaw }, evidence: fp.canonicalRaw, suggested: `<link rel="canonical" href="${fp.canonical}">` });
    }
    const noindex = fp?.robots.filter((r) => /noindex|\bnone\b/i.test(r)) ?? [];
    if (noindex.length) {
      const header = noindex.some((r) => r.startsWith('X-Robots-Tag'));
      const suggested = header
        ? `# Apache (.htaccess)\nHeader unset X-Robots-Tag\n\n${t('# nginx : retirez la ligne add_header X-Robots-Tag du bloc server')}`
        : '<meta name="robots" content="index, follow">';
      issues.push({ id: 'redirects.final_noindex', vars: { url: d.final }, evidence: noindex.join('\n'), suggested });
    }
  }

  // ---- certificates (each https host once)
  const seenHosts = new Set<string>();
  let certOk: string | undefined;
  for (const h of d.hops) {
    const tl = h.exchange.tls;
    if (!tl || seenHosts.has(h.exchange.host)) continue;
    seenHosts.add(h.exchange.host);
    const c = tl.cert;
    if (!tl.chainValid || !tl.nameValid || (c && c.daysLeft < 0)) {
      const reason = c && c.daysLeft < 0 ? t('expiré depuis {duration}', { duration: fmtDays(-c.daysLeft) }) : !tl.nameValid ? t('ne couvre pas {host} ({error})', { host: h.exchange.host, error: tl.nameError ?? '' }) : t('chaîne non reconnue ({error})', { error: tl.chainError ?? t('inconnue') });
      issues.push({ id: 'redirects.cert_invalid', vars: { domain: h.exchange.host, value: reason }, evidence: c ? `${t('Sujet : {value}', { value: c.subject })}\n${t('Émetteur : {value}', { value: c.issuer })}\n${t('Noms : {value}', { value: c.san.join(', ') })}\n${t("Valide jusqu'au {date}", { date: c.validTo.slice(0, 10) })}` : reason, suggested: certbotFor(h.exchange.host) });
    } else if (c && c.daysLeft < CERT_SOON_DAYS) {
      issues.push({ id: 'redirects.cert_expiring', vars: { domain: h.exchange.host, value: c.daysLeft }, evidence: `${t("Valide jusqu'au {date}", { date: c.validTo.slice(0, 10) })} (${fmtDays(c.daysLeft)})\n${t('Émetteur : {value}', { value: c.issuer })}`, suggested: `${t('# serveur avec certbot')}\nsudo certbot renew --cert-name ${bareHost(h.exchange.host)}\nsudo systemctl reload nginx   ${t('# ou apache2')}` });
    } else if (c) certOk ??= t('{host} : {duration} restants, {issuer}', { host: h.exchange.host, duration: fmtDays(c.daysLeft), issuer: c.issuerOrg ?? c.issuer });
  }
  if (certOk && !issues.some((i) => i.id.startsWith('redirects.cert'))) passed.push(pass('redirects.cert_ok', F, t('Certificats valides'), certOk));

  // ---- weight and compression of the final body
  const b = lastEx.body;
  if (b && d.method === 'GET' && d.stoppedBy === 'final') {
    const big = b.decodedSize >= HEAVY_BYTES || (b.truncated && b.isText);
    if (big && b.mime?.includes('html')) issues.push({ id: 'redirects.heavy_body', vars: { url: d.final, value: fmtKo(Math.max(b.decodedSize, b.size)) }, evidence: t('{size} reçus{enc}, {decoded} décompressés{cut}', { size: fmtKo(b.size), enc: b.contentEncoding ? ` (${b.contentEncoding})` : '', decoded: fmtKo(b.decodedSize), cut: b.truncated ? ', ' + t('lecture arrêtée à 2 Mo') : '' }) });
    const sentAE = d.hops[d.hops.length - 1].exchange.requestHeaders.some(([k]) => k.toLowerCase() === 'accept-encoding');
    if (b.isText && !b.contentEncoding && b.size >= COMPRESS_MIN && sentAE) issues.push({ id: 'redirects.uncompressed', vars: { url: d.final, value: fmtKo(b.size) }, evidence: t('Content-Encoding absent, {size} transférés', { size: fmtKo(b.size) }) });
    else if (b.contentEncoding) passed.push(pass('redirects.compressed', F, t('Réponse compressée'), t('{enc} : {size} transférés pour {decoded}', { enc: b.contentEncoding, size: fmtKo(b.size), decoded: fmtKo(b.decodedSize) })));
  }

  // ---- time
  const ttfb = lastEx.timings.wait;
  if (d.totalMs > SLOW_TOTAL_MS || ttfb > GOOD_TTFB_MS) {
    const parts = d.hops.map((h) => t('{index}. {total} ms (DNS {dns}, connexion {connect}, TLS {tls}, attente {wait})  {url}', { index: h.index, total: Math.round(h.exchange.timings.total), dns: Math.round(h.exchange.timings.dns), connect: Math.round(h.exchange.timings.connect), tls: Math.round(h.exchange.timings.tls), wait: Math.round(h.exchange.timings.wait), url: h.url }));
    issues.push({ id: 'redirects.slow', vars: { url: d.final, value: d.totalMs, ttfb: Math.round(ttfb) }, evidence: parts.join('\n'), severity: d.totalMs > SLOW_TOTAL_MS * 2 ? 'medium' : 'low', suggested: curlTiming(d.start) });
  } else if (d.stoppedBy === 'final') passed.push(pass('redirects.fast', F, t('Temps de réponse'), t('{total} ms au total, premier octet de la page finale en {ttfb} ms', { total: d.totalMs, ttfb: Math.round(ttfb) })));

  if (d.finalPage && d.finalPage.h2 === undefined && scheme(d.final) === 'https' && d.stoppedBy === 'final' && last.exchange.tls) unavailable.push({ source: t('Test HTTP/2'), reason: t('la seconde poignée de main TLS n’a pas abouti') });
  if (d.method === 'HEAD') unavailable.push({ source: t('Corps des pages'), reason: t('méthode HEAD : ni meta refresh, ni JavaScript, ni canonique dans le HTML ne peuvent être lus') });
  // WordPress steps (fix_by_provider.wordpress) only when the site is WordPress
  if (detectWordPress(d.hops)) for (const i of issues) i.provider ??= 'wordpress';
  return { issues, passed, unavailable };
}

function certbotFor(h: string): string {
  const b = bareHost(h);
  const names = registrable(b) === b ? `-d ${b} -d www.${b}` : `-d ${h}`;
  return `${t('# serveur avec certbot')}\nsudo certbot certonly --webroot -w /var/www/html ${names}\nsudo systemctl reload nginx   ${t('# ou apache2')}`;
}

function domainMoveRule(from: string, to: string): string {
  const f = new URL(from);
  const tu = new URL(to);
  const old = bareHost(f.hostname);
  return [
    t('# Apache (.htaccess de l’ancien domaine)'),
    'RewriteEngine On',
    `RewriteCond %{HTTP_HOST} ^(www\\.)?${esc(old)}$ [NC]`,
    `RewriteRule ^ ${tu.protocol}//${tu.host}%{REQUEST_URI} [R=301,L]`,
    '',
    '# nginx',
    'server {',
    '    listen 80;',
    '    listen 443 ssl;',
    `    server_name ${old} www.${old};`,
    `    return 301 ${tu.protocol}//${tu.host}$request_uri;`,
    '}',
  ].join('\n');
}

