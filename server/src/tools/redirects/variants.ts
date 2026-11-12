// Variants of a site (US-070): http://, https://, with and without www, traced together.
// They should all end on the same canonical URL, in one permanent redirect at most.
import { t } from '../../i18n.js';
import { mapLimit, pass, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import { analyzeTrace, canonicalRules, detectWordPress, isLanguageRedirect, permanentLooking, registrable, statusLine } from './analyze.js';
import { normalizeUrlInput, traceChain, type RedirectKind, type TraceData, type TraceOptions } from './trace.js';

export interface VariantRow {
  label: string;
  url: string;
  hops: { status?: number; url: string; kind?: RedirectKind; error?: string }[];
  final: string;
  finalStatus?: number;
  redirects: number;
  /** Redirects that count (language negotiation left out). */
  effective: number;
  language: number;
  temporary?: { url: string; status?: number; to: string };
  permanent: boolean;
  conform: boolean;
  reasons: string[];
  error?: string;
  ms: number;
}

export interface VariantsData {
  input: string;
  host: string;
  canonical?: string;
  allSame: boolean;
  conform: boolean;
  variants: VariantRow[];
}

export function variantUrls(input: string): { host: string; list: { label: string; url: string }[] } {
  const { url } = normalizeUrlInput(input);
  const u = new URL(url);
  const h = u.hostname;
  const bare = h.replace(/^www\./, '');
  const rest = u.pathname + u.search;
  const port = u.port ? `:${u.port}` : '';
  const withWww = registrable(bare) === bare;
  const hosts = withWww ? [bare, 'www.' + bare] : [h];
  const list = hosts.flatMap((x) =>
    ['http', 'https'].map((s) => ({ label: rest === '/' ? `${s}://${x}${port}` : `${s}://${x}${port}${rest}`, url: `${s}://${x}${port}${rest}` })),
  );
  return { host: bare, list };
}

function landingTrace(traces: { t?: TraceData }[], ok: (t?: TraceData) => boolean | undefined, canonical?: string): TraceData | undefined {
  return traces.find((x) => x.t && ok(x.t) && norm(x.t.final) === canonical)?.t;
}

const norm = (u: string) => {
  const x = new URL(u);
  x.hash = '';
  return x.toString();
};

export async function analyzeVariants(input: string, o: Omit<TraceOptions, 'onHop'> & { dnsFor?: () => TraceOptions['dns'] } = {}): Promise<Analysis & { data: VariantsData }> {
  const { host, list } = variantUrls(input);
  const traces = await mapLimit(list, 4, async (v) => {
    const t0 = performance.now();
    try {
      return { v, t: await traceChain(v.url, { ...o, dns: o.dnsFor?.() ?? o.dns, max: 10, light: true }), ms: Math.round(performance.now() - t0) };
    } catch (e) {
      return { v, err: (e as Error).message, ms: Math.round(performance.now() - t0) };
    }
  });
  const ok = (t?: TraceData) => t && t.stoppedBy === 'final' && (t.finalStatus ?? 0) >= 200 && (t.finalStatus ?? 0) < 300;
  // the canonical URL: where the https variant of the typed host lands, else the most common landing
  const typed = normalizeUrlInput(input).url;
  const httpsTyped = traces.find((x) => x.v.url === typed.replace(/^http:/, 'https:'));
  const counts = new Map<string, number>();
  for (const x of traces) if (ok(x.t)) counts.set(norm(x.t!.final), (counts.get(norm(x.t!.final)) ?? 0) + 1);
  const canonical = ok(httpsTyped?.t) && (counts.get(norm(httpsTyped!.t!.final)) ?? 0) >= Math.max(...counts.values())
    ? norm(httpsTyped!.t!.final)
    : [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];

  // the reference shown and used in the rules: the landing URL before the language negotiation
  // (https://github.com/, not https://github.com/?locale=fr-fr), which stays a temporary redirect
  const langToCanonical = traces.flatMap((x) => x.t?.hops ?? []).find((h) => isLanguageRedirect(h) && canonical && norm(h.redirect!.to) === canonical);
  const reference = langToCanonical ? norm(langToCanonical.url) : canonical;
  const targetText = langToCanonical ? t('{url}, la redirection de langue restant temporaire', { url: reference }) : reference;

  const rows: VariantRow[] = traces.map((x) => {
    const tr = x.t;
    if (!tr) return { label: x.v.label, url: x.v.url, hops: [], final: x.v.url, redirects: 0, effective: 0, language: 0, permanent: false, conform: false, reasons: [x.err ?? t('erreur')], error: x.err, ms: x.ms };
    const reasons: string[] = [];
    // a language negotiation (302 to ?locale=fr-fr, /fr/...) is neither an extra hop nor a fault
    const redirectHops = tr.hops.filter((h) => h.redirect && !isLanguageRedirect(h));
    const language = tr.hops.filter(isLanguageRedirect).length;
    const permanent = redirectHops.every((h) => h.redirect!.kind === 'http' && (h.exchange.status === 301 || h.exchange.status === 308));
    const temporary = redirectHops.find((h) => !(h.redirect!.kind === 'http' && (h.exchange.status === 301 || h.exchange.status === 308)));
    const last = tr.hops[tr.hops.length - 1];
    if (tr.stoppedBy !== 'final') reasons.push(tr.stopDetail ?? last.exchange.error?.message ?? tr.stoppedBy);
    else if (!ok(tr)) reasons.push(t('page finale {status}', { status: statusLine(last.exchange) }));
    if (canonical && ok(tr) && norm(tr.final) !== canonical) reasons.push(t('aboutit à {url}', { url: tr.final }));
    if (redirectHops.length > 1) reasons.push(t("{n} redirections au lieu d'une", { n: redirectHops.length }));
    if (!permanent) reasons.push(t('redirection non permanente'));
    return {
      label: x.v.label,
      url: x.v.url,
      hops: tr.hops.map((h) => ({ status: h.exchange.status, url: h.url, kind: h.redirect?.kind, error: h.exchange.status === undefined ? h.exchange.error?.message : undefined })),
      final: tr.final,
      finalStatus: tr.finalStatus,
      redirects: tr.redirects,
      effective: redirectHops.length,
      language,
      temporary: temporary ? { url: temporary.url, status: temporary.exchange.status, to: temporary.redirect!.to } : undefined,
      permanent,
      conform: reasons.length === 0,
      reasons,
      error: tr.stoppedBy === 'error' || tr.stoppedBy === 'unsafe' ? (last.exchange.error?.message ?? tr.stopDetail) : undefined,
      ms: x.ms,
    };
  });

  const issues: Issue[] = [];
  const passed: Analysis['passed'] = [];
  const reachable = rows.filter((r) => !r.error);
  const finals = new Set(traces.filter((x) => ok(x.t)).map((x) => norm(x.t!.final)));
  const table = rows.map((r) => `${r.label.padEnd(28)} ${r.hops.map((h) => h.status ?? t('erreur')).join(' → ')}  ${r.final}`).join('\n');
  const suggested = reference ? canonicalRules(reference) : undefined;
  if (finals.size > 1) issues.push({ id: 'redirects.variants_diverge', vars: { domain: host, value: finals.size, final: reference }, evidence: table, suggested });
  else if (finals.size === 1) passed.push(pass('redirects.variants_same', 'redirects', t('Toutes les variantes aboutissent à la même adresse'), targetText));
  const extra = reachable.filter((r) => r.effective > 1);
  if (extra.length) issues.push({ id: 'redirects.variant_extra_hops', vars: { domain: host, value: extra.map((r) => r.label).join(', '), final: reference, target: targetText }, evidence: table, suggested });
  const temp = reachable.filter((r) => !r.permanent);
  if (temp.length) {
    const h = temp[0].temporary;
    const kind = h && permanentLooking(h.url, h.to);
    issues.push({
      id: 'redirects.temporary_for_permanent',
      vars: { url: h?.url ?? temp[0].url, status: h?.status, value: kind ? t(kind) : t("renvoi d'une variante vers l'adresse de référence"), target: reference },
      evidence: table,
      suggested,
    });
  }
  const lang = traces.flatMap((x) => x.t?.hops.filter(isLanguageRedirect) ?? []);
  if (lang.length)
    issues.push({ id: 'redirects.language_redirect', vars: { url: lang[0].url, target: lang[0].redirect!.to, status: lang[0].exchange.status }, evidence: [...new Set(lang.map((h) => `${statusLine(h.exchange)}  ${h.url} → ${h.redirect!.to}`))].join('\n') });
  if (landingTrace(traces, ok, canonical) && detectWordPress(landingTrace(traces, ok, canonical)!.hops)) for (const i of issues) i.provider ??= 'wordpress';
  const httpStays = rows.find((r) => r.url.startsWith('http:') && !r.error && r.final.startsWith('http:'));
  if (httpStays) issues.push({ id: 'redirects.http_not_redirected', vars: { url: httpStays.url, domain: host }, evidence: table, suggested: reference ? canonicalRules(reference.replace(/^http:/, 'https:')) : undefined });
  const down = rows.filter((r) => r.error);
  if (down.length) issues.push({ id: 'redirects.variant_unreachable', vars: { domain: host, value: down.map((r) => r.label).join(', ') }, evidence: down.map((r) => `${r.label} : ${r.error}`).join('\n'), suggested });
  if (!issues.length) passed.push(pass('redirects.variants_ok', 'redirects', t('Une seule redirection permanente par variante'), t('{n} variantes conformes', { n: rows.length })));

  // certificate and HSTS of the canonical page, from the trace that lands there
  const landing = traces.find((x) => x.t && ok(x.t) && norm(x.t.final) === canonical)?.t;
  if (landing) {
    const a = analyzeTrace(landing);
    for (const i of a.issues) if (/^redirects\.(cert_|hsts_)/.test(i.id) && !issues.some((x) => x.id === i.id)) issues.push(i);
  }
  return {
    issues,
    passed,
    data: { input, host, canonical: reference, allSame: finals.size === 1 && down.length === 0, conform: rows.every((r) => r.conform), variants: rows },
  };
}
