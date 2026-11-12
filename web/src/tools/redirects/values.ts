// "Mesuré" and "Référence" of each finding row, read from the trace (or the variants).
import { fmtBytes, fmtMs } from '../../lib/format';
import { t, tn } from '../../lib/i18n';
import type { Finding } from '../../lib/types';
import { reasonOf, shortUrl, type TraceData, type VariantsData } from './model';

export interface RowValues {
  measured?: string;
  reference?: string;
}

const sec = (n?: number) => (n === undefined ? t('absent') : n >= 86400 ? tn(Math.round(n / 86400), '{n} jour', '{n} jours') : `${n} s`);

export function traceValues(f: Finding, d: TraceData): RowValues {
  const last = d.hops[d.hops.length - 1].exchange;
  const st = last.status;
  const statusText = st !== undefined ? `${st} ${reasonOf(st, last.statusText)}` : (last.error?.code ?? t('sans réponse'));
  const firstTemp = d.hops.find((h) => h.redirect?.kind === 'http' && [302, 303, 307].includes(h.exchange.status ?? 0));
  const cert = d.hops.find((h) => h.exchange.tls?.cert)?.exchange.tls?.cert;
  const fp = d.finalPage;
  switch (f.id) {
    case 'redirects.loop': return { measured: tn(d.hops.length, 'boucle après {n} requête', 'boucle après {n} requêtes'), reference: t('aucune boucle') };
    case 'redirects.too_many': return { measured: t('plus de {n} requêtes', { n: d.max }), reference: t('≤ 10 sauts (Google)') };
    case 'redirects.private_target': return { measured: last.ip ?? t('adresse privée'), reference: t('adresse publique') };
    case 'redirects.unreachable': return { measured: last.error?.code ?? t('sans réponse'), reference: t('réponse HTTP') };
    case 'redirects.chain_long': return { measured: tn(d.redirects, '{n} redirection', '{n} redirections'), reference: '≤ 2' };
    case 'redirects.temporary_for_permanent': return { measured: firstTemp ? String(firstTemp.exchange.status) : t('temporaire'), reference: t('301 ou 308') };
    case 'redirects.redirect_to_error':
    case 'redirects.final_error': return { measured: statusText, reference: '2xx' };
    case 'redirects.redirect_without_location': return { measured: t('{status} sans Location', { status: statusText }), reference: t('Location présente') };
    case 'redirects.https_to_http': return { measured: t('https puis http'), reference: t('https partout') };
    case 'redirects.http_not_redirected': return { measured: 'http', reference: 'https' };
    case 'redirects.hsts_missing': return { measured: t('absent'), reference: t('max-age ≥ 1 an') };
    case 'redirects.hsts_short': return { measured: sec(fp?.hsts?.maxAge), reference: '≥ 31536000 s' };
    case 'redirects.hsts_no_subdomains': return { measured: t('sans includeSubDomains'), reference: 'includeSubDomains' };
    case 'redirects.meta_refresh': return { measured: 'meta refresh', reference: t('301 serveur') };
    case 'redirects.refresh_header': return { measured: t('en-tête Refresh'), reference: t('301 serveur') };
    case 'redirects.js_redirect': return { measured: 'JavaScript', reference: t('301 serveur') };
    case 'redirects.language_redirect': {
      // the evidence lists each language hop as "<status line>  <from> → <to>": match a whole line end
      const lines = (f.evidence ?? '').split('\n');
      const h = d.hops.find((x) => x.redirect && lines.some((l) => l.endsWith(`  ${x.url} → ${x.redirect!.to}`)));
      return { measured: h ? t('{status} selon la langue', { status: h.exchange.status }) : t('selon la langue'), reference: t('temporaire attendu') };
    }
    case 'redirects.js_seen': return { measured: t('script repéré'), reference: t('non suivi') };
    case 'redirects.canonical_missing': return { measured: t('absente'), reference: t('URL finale') };
    case 'redirects.canonical_mismatch': return { measured: fp?.canonicalRaw ? shortUrl(fp.canonicalRaw) : t('autre adresse'), reference: shortUrl(d.final) };
    case 'redirects.canonical_relative': return { measured: fp?.canonicalRaw, reference: t('adresse absolue') };
    case 'redirects.final_noindex': return { measured: 'noindex', reference: t('indexable') };
    case 'redirects.cert_invalid': return { measured: t('refusé'), reference: t('valide') };
    case 'redirects.cert_expiring': return { measured: cert ? tn(cert.daysLeft, '{n} jour', '{n} jours') : t('bientôt'), reference: t('≥ 14 jours') };
    case 'redirects.heavy_body': return { measured: last.body ? fmtBytes(last.body.decodedSize) : undefined, reference: t('< 2 Mo') };
    case 'redirects.uncompressed': return { measured: t('aucune compression'), reference: t('gzip, br ou zstd') };
    case 'redirects.slow':
      return d.totalMs > 3000
        ? { measured: t('{time} au total', { time: fmtMs(d.totalMs) }), reference: '≤ 3 s' }
        : { measured: t('premier octet {time}', { time: fmtMs(last.timings.wait) }), reference: '≤ 800 ms' };
    default: return {};
  }
}

export function variantValues(f: Finding, d: VariantsData): RowValues {
  const bad = d.variants.filter((v) => !v.conform);
  switch (f.id) {
    case 'redirects.variants_diverge': return { measured: tn(new Set(d.variants.filter((v) => !v.error).map((v) => v.final)).size, '{n} adresse finale', '{n} adresses finales'), reference: t('1 seule') };
    case 'redirects.variant_extra_hops': return { measured: tn(Math.max(...d.variants.map((v) => v.effective ?? v.redirects)), '{n} redirection', '{n} redirections'), reference: t('≤ 1 par variante') };
    case 'redirects.temporary_for_permanent': return { measured: t('redirection temporaire'), reference: t('301 ou 308') };
    case 'redirects.http_not_redirected': return { measured: t('http servi'), reference: 'https' };
    case 'redirects.language_redirect': return { measured: t('selon la langue'), reference: t('temporaire attendu') };
    case 'redirects.variant_unreachable': return { measured: t('{n} sans réponse', { n: d.variants.filter((v) => v.error).length }), reference: t('toutes répondent') };
    default: return bad.length ? { measured: tn(bad.length, '{n} non conforme', '{n} non conformes') } : {};
  }
}
