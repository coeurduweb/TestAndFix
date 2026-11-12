// Whois of a domain from two parties, because their data can differ (the registry knows the
// registration as the registrar declared it; the registrar keeps its own dates, contacts, reseller):
//
//   registry   1. RDAP, base URL from the IANA bootstrap (RFC 9224)
//              2. WHOIS port 43 (RFC 3912), server from whois.iana.org; when RDAP failed, is
//                 rate-limited or the TLD has no RDAP. Each address of the server's name is tried.
//   registrar  1. RDAP at the URL given by the registry: links rel "related" (ICANN RDAP Technical
//                 Implementation Guide 2.2 §3.2), else the registrar's RDAP base URL (RDAP Response
//                 Profile 2.2 §2.4.6, or the IANA Registrar IDs registry from its IANA id)
//              2. WHOIS port 43 at the "Registrar WHOIS Server" given by the registry WHOIS answer;
//                 when the registry answered by RDAP, the registry WHOIS is read only to find it.
//
// gTLD registries and registrars are no longer required to run WHOIS since 28 January 2025
// (ICANN 2023 Global Amendments, https://www.icann.org/resources/pages/global-amendment-2023-en/):
// RDAP comes first, port 43 is the fallback and the only source for ccTLDs without RDAP.
// Every request goes through the shared PoliteLimiter (limiter.ts). A result is kept 10 minutes
// per notebook so that the same domain is not asked twice in a row (politeness, not a measure
// cache: the page says when it shows a kept answer, "Mesurer à nouveau" asks again).
import { domainToUnicode } from 'node:url';
import type { PassedCheck } from '../../tools/types.js';
import { daysBetween, issue, normalizeDomain, orgDomain, pass, type Analysis, type Issue, InvalidInputError } from '../email-auth/common.js';
import { isEpp, statusInfo } from './epp.js';
import { PoliteLimiter, RateLimitedError, RDAP_POLICY, sharedLimiter, WHOIS_POLICY, parseRetryAfter } from './limiter.js';
import { hostOf, parseWhoisText } from './parse.js';
import type { WhoisAnswer } from './port43.js';
import { parseRdapJson } from './rdap.js';
import { sharedDirectory, type Http, type WhoisDirectory } from './sources.js';
import type { Attempt, Contact, Divergence, Party, PartyRecord, WhoisMerged, WhoisReport, WhoisRow } from './types.js';
import { t } from '../../i18n.js';

export const RAW_MAX = 200 * 1024;
export const CACHE_TTL_MS = 10 * 60_000;
export const CACHE_MAX = 500;
export const BATCH_MAX = 100;
export const BATCH_CONCURRENCY = 4;

export class WhoisCache {
  private m = new Map<string, WhoisReport>();
  constructor(
    private readonly ttlMs = CACHE_TTL_MS,
    private readonly max = CACHE_MAX,
    private readonly now: () => number = Date.now,
  ) {}
  get(key: string): WhoisReport | undefined {
    const r = this.m.get(key);
    if (!r) return undefined;
    if (Date.parse(r.lookedUpAt) + this.ttlMs <= this.now()) {
      this.m.delete(key);
      return undefined;
    }
    return { ...structuredClone(r), cachedAt: r.lookedUpAt };
  }
  set(key: string, r: WhoisReport) {
    this.m.delete(key);
    this.m.set(key, structuredClone(r));
    while (this.m.size > this.max) this.m.delete(this.m.keys().next().value!);
  }
}

export const sharedCache = new WhoisCache();

export interface WhoisDeps {
  http: Http;
  whois43: (host: string, query: string) => Promise<WhoisAnswer>;
  limiter?: PoliteLimiter;
  directory?: WhoisDirectory;
  cache?: WhoisCache;
  /** Cache scope: the notebook, so that one browser never sees another's lookups. */
  scope?: string;
  /** Skip the kept answer (re-measure). */
  fresh?: boolean;
  now?: () => number;
  /** Longest wait accepted in a server's queue before moving to the other protocol. */
  maxWaitMs?: number;
  signal?: AbortSignal;
  /** A records of the name ([] when it has none); a rejection leaves the field out. DNS, so no Whois politeness applies. */
  resolveA?: (name: string) => Promise<string[]>;
}

const capRaw = (s: string) => (s.length > RAW_MAX ? { raw: s.slice(0, RAW_MAX), rawTruncated: true } : { raw: s });
const hostOfUrl = (u: string) => {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return u;
  }
};

class Run {
  attempts: Attempt[] = [];
  constructor(
    readonly name: string,
    readonly d: Required<Pick<WhoisDeps, 'limiter' | 'directory' | 'maxWaitMs'>> & WhoisDeps,
  ) {}

  private push(a: Attempt) {
    this.attempts.push(a);
  }

  /** One RDAP GET through the limiter, redirects followed (RFC 7480 §5.2), one retry after a failure. */
  async rdap(party: Party, url: string): Promise<{ rec?: PartyRecord; notFound?: boolean }> {
    const host = hostOfUrl(url);
    for (let attempt = 0; attempt < 2; attempt++) {
      const started = performance.now();
      let res: { status: number; headers: Record<string, string>; body: Buffer; url: string };
      try {
        res = await this.d.limiter.run(host, RDAP_POLICY, () => this.follow(url), this.d.maxWaitMs, this.d.signal);
      } catch (e) {
        if (e instanceof RateLimitedError) {
          this.push({ party, protocol: 'rdap', server: host, status: 'rate_limited', reason: e.message });
          return {};
        }
        this.d.limiter.penalize(host);
        if (attempt === 0 && this.canRetry(host, RDAP_POLICY.minIntervalMs)) continue;
        this.push({ party, protocol: 'rdap', server: host, status: 'error', reason: netReason(e), ms: ms(started) });
        return {};
      }
      if (res.status === 200) {
        let json: Record<string, unknown>;
        try {
          json = JSON.parse(res.body.toString('utf8')) as Record<string, unknown>;
        } catch {
          this.push({ party, protocol: 'rdap', server: host, status: 'error', reason: t('réponse qui n’est pas du JSON'), ms: ms(started) });
          return {};
        }
        this.d.limiter.succeed(host);
        this.push({ party, protocol: 'rdap', server: host, status: 'ok', ms: ms(started) });
        return {
          rec: { party, protocol: 'rdap', server: host, url: res.url, ...parseRdapJson(json, party), ...capRaw(JSON.stringify(json, null, 2)) },
        };
      }
      if (res.status === 404) {
        this.d.limiter.succeed(host);
        this.push({ party, protocol: 'rdap', server: host, status: 'not_found', reason: t('HTTP 404 : nom inconnu de ce serveur'), ms: ms(started) });
        return { notFound: true };
      }
      if (res.status === 429) {
        const wait = parseRetryAfter(res.headers['retry-after'], this.now());
        this.d.limiter.penalize(host, wait);
        this.push({
          party, protocol: 'rdap', server: host, status: 'rate_limited', ms: ms(started),
          reason: wait !== undefined ? t('HTTP 429 : trop de requêtes, nouvel essai permis dans {s} s', { s: Math.ceil(wait / 1000) }) : t('HTTP 429 : trop de requêtes'),
        });
        return {};
      }
      if (res.status >= 500) {
        this.d.limiter.penalize(host);
        if (attempt === 0 && this.canRetry(host, RDAP_POLICY.minIntervalMs)) continue;
      }
      this.push({ party, protocol: 'rdap', server: host, status: 'error', reason: `HTTP ${res.status}`, ms: ms(started) });
      return {};
    }
    return {};
  }

  private canRetry(host: string, interval: number) {
    return this.d.limiter.expectedWait(host, { minIntervalMs: interval }) <= Math.min(this.d.maxWaitMs, 20_000);
  }

  private async follow(url: string) {
    let current = url;
    for (let hop = 0; hop < 4; hop++) {
      const r = await this.d.http(current, { accept: 'application/rdap+json, application/json' });
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        current = new URL(r.headers.location, current).toString();
        continue;
      }
      return { ...r, url: current };
    }
    throw new Error('trop de redirections');
  }

  /** One WHOIS query through the limiter. */
  async whois(party: Party, host: string): Promise<{ rec?: PartyRecord; notFound?: boolean }> {
    const started = performance.now();
    for (let attempt = 0; attempt < 2; attempt++) {
      let ans: WhoisAnswer;
      try {
        ans = await this.d.limiter.run(host, WHOIS_POLICY, () => this.d.whois43(host, this.name), this.d.maxWaitMs, this.d.signal);
      } catch (e) {
        if (e instanceof RateLimitedError) {
          this.push({ party, protocol: 'whois', server: host, status: 'rate_limited', reason: e.message });
          return {};
        }
        this.d.limiter.penalize(host);
        if (attempt === 0 && this.canRetry(host, WHOIS_POLICY.minIntervalMs)) continue;
        this.push({ party, protocol: 'whois', server: host, status: 'error', reason: netReason(e), ms: ms(started) });
        return {};
      }
      const p = parseWhoisText(ans.text, party);
      const { notFound, rateLimited, ...fields } = p;
      if (rateLimited) {
        this.d.limiter.penalize(host);
        this.push({ party, protocol: 'whois', server: host, status: 'rate_limited', reason: t('le serveur signale trop de requêtes'), ms: ms(started) });
        return {};
      }
      this.d.limiter.succeed(host);
      if (notFound) {
        this.push({ party, protocol: 'whois', server: host, status: 'not_found', reason: t('le serveur ne connaît pas ce nom'), ms: ms(started) });
        return { notFound: true };
      }
      const useful = !!(fields.created || fields.expires || fields.registrar?.name || fields.status.length || fields.nameservers.length);
      const rec: PartyRecord = { party, protocol: 'whois', server: host, ...fields, ...capRaw(ans.text), ...(ans.truncated ? { rawTruncated: true } : {}) };
      if (!useful) {
        this.push({ party, protocol: 'whois', server: host, status: 'error', reason: t('réponse sans donnée lisible'), ms: ms(started) });
        return { rec: undefined };
      }
      this.push({ party, protocol: 'whois', server: host, status: 'ok', ms: ms(started) });
      return { rec };
    }
    return {};
  }

  now() {
    return (this.d.now ?? Date.now)();
  }

  /** WHOIS server of the TLD through whois.iana.org (cached by the directory). */
  async tldWhois(tld: string): Promise<string | null | undefined> {
    try {
      return await this.d.directory.tldWhoisServer(tld, async (host, q) => {
        const a = await this.d.limiter.run(host, WHOIS_POLICY, () => this.d.whois43(host, q), this.d.maxWaitMs, this.d.signal);
        return a.text;
      });
    } catch (e) {
      this.push({ party: 'registry', protocol: 'whois', server: 'whois.iana.org', status: e instanceof RateLimitedError ? 'rate_limited' : 'error', reason: t('serveur WHOIS du registre inconnu : {error}', { error: e instanceof RateLimitedError ? e.message : netReason(e) }) });
      return undefined;
    }
  }
}

const ms = (started: number) => Math.round(performance.now() - started);

function netReason(e: unknown): string {
  const m = (e as Error)?.message ?? String(e);
  const code = (e as { code?: string; cause?: { code?: string } })?.cause?.code ?? (e as { code?: string })?.code;
  if (/timeout|délai/i.test(m) || code === 'timeout' || code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return t('délai dépassé');
  if (code === 'ENOTFOUND' || /ENOTFOUND/.test(m)) return t('nom du serveur introuvable dans le DNS');
  if (code === 'ECONNREFUSED') return t('connexion refusée');
  if (code === 'UNSAFE_TARGET') return t('adresse non publique refusée');
  // the message of a network error can carry a URL: keep only short, known texts
  return /^[\p{L}\s’'()0-9-]{1,80}$/u.test(m) ? m : t('erreur réseau');
}

const day = (iso?: string) => iso?.slice(0, 10);
const LEGAL = /\b(sas|sarl|sa|inc|llc|ltd|limited|gmbh|corp|corporation|co|bv|ag|ehf|pty|srl|spa|ab|as|oy|plc|lp|kg|nv)\b/g;
export const sameRegistrar = (a: string, b: string) => {
  const n = (s: string) => s.toLowerCase().replace(/[.,]/g, ' ').replace(LEGAL, ' ').replace(/[^a-z0-9]+/g, '');
  return n(a) === n(b);
};
const statusSet = (l: string[]) => l.filter((s) => isEpp(s) && s !== 'ok').sort();

/** Fields where the registry and the registrar say different things. */
export function divergences(reg: PartyRecord, rar: PartyRecord): Divergence[] {
  const out: Divergence[] = [];
  const dates: [Divergence['field'], string, boolean?][] = [
    ['created', t('Création')],
    ['expires', t('Expiration')],
    ['updated', t('Dernière modification'), true],
  ];
  for (const [f, label, expected] of dates) {
    const a = reg[f as 'created'];
    const b = rar[f as 'created'];
    if (a && b && day(a) !== day(b)) out.push({ field: f, label, registry: a, registrar: b, ...(expected ? { expected } : {}) });
  }
  const sa = statusSet(reg.status);
  const sb = statusSet(rar.status);
  if (reg.status.length && rar.status.length && sa.join() !== sb.join()) out.push({ field: 'status', label: t('Statuts EPP'), registry: sa.join(', ') || t('aucun'), registrar: sb.join(', ') || t('aucun') });
  const ia = reg.registrar?.ianaId;
  const ib = rar.registrar?.ianaId;
  if (ia && ib && ia !== ib) out.push({ field: 'ianaId', label: t('Identifiant IANA'), registry: ia, registrar: ib });
  const na = reg.registrar?.name;
  const nb = rar.registrar?.name;
  if (na && nb && !(ia && ib && ia === ib) && !sameRegistrar(na, nb)) out.push({ field: 'registrar', label: t('Bureau d’enregistrement'), registry: na, registrar: nb });
  const nsa = [...reg.nameservers].sort();
  const nsb = [...rar.nameservers].sort();
  if (nsa.length && nsb.length && nsa.join() !== nsb.join()) out.push({ field: 'nameservers', label: t('Serveurs de noms'), registry: nsa.join(', '), registrar: nsb.join(', ') });
  if (reg.dnssec !== undefined && rar.dnssec !== undefined && reg.dnssec !== rar.dnssec)
    out.push({ field: 'dnssec', label: 'DNSSEC', registry: reg.dnssec ? t('signé') : t('non signé'), registrar: rar.dnssec ? t('signé') : t('non signé') });
  return out;
}

const visible = (c: Contact) => Number(!!c.name) + Number(!!c.org) + Number(!!c.email);

/** The view shown first: the registry for what it rules (dates, statuses, delegation), the registrar for contacts and reseller. */
export function merge(reg: PartyRecord | undefined, rar: PartyRecord | undefined, now: number): WhoisMerged {
  const created = reg?.created ?? rar?.created;
  const expires = reg?.expires ?? rar?.expires;
  const contacts: Contact[] = [];
  for (const role of ['registrant', 'admin', 'tech'] as const) {
    const a = rar?.contacts.find((c) => c.role === role);
    const b = reg?.contacts.find((c) => c.role === role);
    const pick = a && b ? (visible(b) > visible(a) ? b : a) : (a ?? b);
    if (pick) contacts.push(pick);
  }
  const registrar = reg?.registrar || rar?.registrar ? { ...(rar?.registrar ?? {}), ...stripEmpty(reg?.registrar ?? {}) } : undefined;
  const status = reg?.status.length ? reg.status : (rar?.status ?? []);
  return {
    statusDetails: status.map(statusInfo),
    created,
    updated: reg?.updated ?? rar?.updated,
    expires,
    ageDays: created ? daysBetween(now, Date.parse(created)) : undefined,
    expiresInDays: expires ? daysBetween(Date.parse(expires), now) : undefined,
    status,
    registryStatus: reg?.registryStatus ?? [],
    registrar,
    reseller: rar?.reseller ?? reg?.reseller,
    contacts,
    nameservers: reg?.nameservers.length ? reg.nameservers : (rar?.nameservers ?? []),
    dnssec: reg?.dnssec ?? rar?.dnssec,
  };
}

function stripEmpty<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== '')) as Partial<T>;
}

/** Look a domain up at its registry and its registrar. Never throws for a server failure. */
export async function lookupWhois(input: string, deps: WhoisDeps): Promise<WhoisReport> {
  const domain = normalizeDomain(input);
  const queried = orgDomain(domain);
  const tld = queried.split('.').pop()!;
  const cache = deps.cache;
  const key = `${deps.scope ?? ''}|${queried}`;
  if (cache && !deps.fresh) {
    const hit = cache.get(key);
    if (hit) return { ...hit, domain };
  }
  const now = (deps.now ?? Date.now)();
  // the A records run beside the Whois queries, which are much slower
  const aP = deps.resolveA ? deps.resolveA(queried).then((ips) => [...new Set(ips)], () => undefined) : Promise.resolve(undefined);
  const run = new Run(queried, { ...deps, limiter: deps.limiter ?? sharedLimiter, directory: deps.directory ?? sharedDirectory, maxWaitMs: deps.maxWaitMs ?? 15_000 });

  // ---- registry
  let registry: PartyRecord | undefined;
  let notFound = false;
  let base: string | null | undefined;
  try {
    base = await run.d.directory.rdapBase(deps.http, queried);
  } catch (e) {
    run.attempts.push({ party: 'registry', protocol: 'rdap', server: 'data.iana.org', status: 'error', reason: (e as Error).message });
  }
  if (base) {
    const r = await run.rdap('registry', `${base}domain/${queried}`);
    registry = r.rec;
    notFound = !!r.notFound;
  } else if (base === null) {
    run.attempts.push({ party: 'registry', protocol: 'rdap', server: 'data.iana.org', status: 'unsupported', reason: t('le registre de .{tld} n’a pas de service RDAP inscrit à l’IANA', { tld }) });
  }
  let registryWhoisHost: string | null | undefined;
  let registryWhoisRec: PartyRecord | undefined;
  if (!registry && !notFound) {
    registryWhoisHost = await run.tldWhois(tld);
    if (registryWhoisHost) {
      const r = await run.whois('registry', registryWhoisHost);
      registry = registryWhoisRec = r.rec;
      notFound = !!r.notFound;
    } else if (registryWhoisHost === null) {
      run.attempts.push({ party: 'registry', protocol: 'whois', server: 'whois.iana.org', status: 'unsupported', reason: t('l’IANA n’indique aucun serveur WHOIS pour .{tld}', { tld }) });
    }
  }

  // ---- registrar
  let registrar: PartyRecord | undefined;
  let registrarNotAnnounced = false;
  let registrarUnknown = false;
  if (registry && !notFound) {
    let rdapUrl = registry.registrarRdapUrl;
    const ianaId = registry.registrar?.ianaId;
    // 9994 to 9999 are reserved ids, 9994, 9998 and 9999 for a registry acting as registrar
    // (IANA Registrar IDs registry; RDAP Response Profile 2.2 §2.4.6 cites 9999)
    const accredited = !!ianaId && /^\d+$/.test(ianaId) && !(Number(ianaId) >= 9994 && Number(ianaId) <= 9999);
    if (!rdapUrl && registry.registrar?.rdapBase) rdapUrl = `${registry.registrar.rdapBase.replace(/\/?$/, '/')}domain/${queried}`;
    if (!rdapUrl && accredited) {
      try {
        const b = await run.d.directory.registrarRdapBase(deps.http, ianaId!);
        if (b) rdapUrl = `${b}domain/${queried}`;
      } catch (e) {
        run.attempts.push({ party: 'registrar', protocol: 'rdap', server: 'www.iana.org', status: 'error', reason: (e as Error).message });
      }
    }
    if (rdapUrl && hostOfUrl(rdapUrl) === registry.server) rdapUrl = undefined;
    let rdapSaidUnknown = false;
    if (rdapUrl) {
      const r = await run.rdap('registrar', rdapUrl);
      registrar = r.rec;
      // RDAP Response Profile 2.2 §2.11.1: a registrar answers 404 for a name it does not sponsor;
      // that answer is final, its WHOIS would say the same
      rdapSaidUnknown = !!r.notFound;
    }
    if (rdapSaidUnknown) registrarUnknown = true;
    else if (!registrar) {
      let host = registry.registrar?.whoisServer;
      // the registry answered by RDAP: its WHOIS names the registrar's WHOIS server
      if (!host && registry.protocol === 'rdap' && accredited) {
        registryWhoisHost ??= await run.tldWhois(tld);
        if (registryWhoisHost) {
          registryWhoisRec = (await run.whois('registry', registryWhoisHost)).rec;
          host = registryWhoisRec?.registrar?.whoisServer;
        }
      }
      if (host && host !== registry.server && host !== registryWhoisHost) {
        const r = await run.whois('registrar', host);
        registrar = r.rec;
        if (r.notFound) registrarUnknown = true;
      } else if (!rdapUrl) registrarNotAnnounced = true;
    }
  }

  const report: WhoisReport = {
    domain,
    queried,
    unicode: domainToUnicode(queried) || queried,
    tld,
    registry,
    registrar,
    attempts: run.attempts,
    merged: merge(registry, registrar, now),
    divergences: registry && registrar ? divergences(registry, registrar) : [],
    ...(notFound ? { notFound } : {}),
    ...(registrarNotAnnounced ? { registrarNotAnnounced } : {}),
    ...(registrarUnknown && !registrar ? { registrarUnknown } : {}),
    ...(await aP.then((a) => (a ? { a } : {}))),
    lookedUpAt: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  if (cache && (registry || notFound)) cache.set(key, report);
  return report;
}

const HOLD = ['clientHold', 'serverHold'];
const DELETING = ['pendingDelete', 'redemptionPeriod', 'pendingRestore'];

/** Findings of a report: same situations as the RDAP check (knowledge base), plus what is fine. */
export function whoisAnalysis(r: WhoisReport): Analysis & { data: WhoisReport } {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const unavailable: { source: string; reason: string }[] = [];
  const v = { domain: r.queried };
  const fail = (party: Party) =>
    r.attempts
      .filter((a) => a.party === party && a.status !== 'ok' && a.status !== 'not_found')
      .map((a) => `${a.server} (${a.protocol === 'rdap' ? 'RDAP' : 'WHOIS'}) : ${a.reason ?? a.status}`)
      .join(' ; ');
  if (r.notFound) {
    issues.push(issue('infrastructure.domain_not_registered', v));
    return { issues, passed, data: r };
  }
  if (!r.registry) unavailable.push({ source: 'whois-registre', reason: t('Registre non joint : {detail}', { detail: fail('registry') || t('aucune source') }) });
  if (r.registry && !r.registrar && !r.registrarNotAnnounced && !r.registrarUnknown)
    unavailable.push({ source: 'whois-bureau', reason: t('Bureau d’enregistrement non joint : {detail}', { detail: fail('registrar') || t('aucune source') }) });
  const m = r.merged;
  const st = m.status.join(', ');
  if (m.status.some((s) => HOLD.includes(s))) issues.push(issue('infrastructure.domain_hold', { ...v, value: st }, { evidence: st }));
  if (m.status.some((s) => DELETING.includes(s))) issues.push(issue('infrastructure.domain_pending_delete', { ...v, value: st }, { evidence: st }));
  if (m.expiresInDays !== undefined) {
    if (m.expiresInDays < 0) issues.push(issue('infrastructure.domain_expired', { ...v, value: m.expires }, { evidence: t('expiration : {date}', { date: m.expires }) }));
    else if (m.expiresInDays < 30) issues.push(issue('infrastructure.domain_expiring', { ...v, value: m.expiresInDays }, { evidence: t('expiration : {date}', { date: m.expires }) }));
    else passed.push(pass('rdap.expiration', 'infrastructure', t('Domaine payé jusqu’au {date}', { date: m.expires!.slice(0, 10) })));
  }
  if (m.ageDays !== undefined && m.ageDays < 30) issues.push(issue('reputation.domain_very_new', { ...v, value: m.ageDays }, { evidence: t('création : {date}', { date: m.created }) }));
  if (m.status.some((s) => statusInfo(s).kind === 'lock' && /Transfer/.test(s))) passed.push(pass('rdap.transfer_lock', 'infrastructure', t('Domaine verrouillé contre les transferts')));
  if (r.registry && r.registrar && !r.divergences.some((d) => !d.expected)) passed.push(pass('whois.sources_agree', 'infrastructure', t('Registre et bureau d’enregistrement concordent')));
  return { issues, passed, unavailable, data: r };
}

/** One table line. */
export function toRow(r: WhoisReport): WhoisRow {
  const src = (p?: PartyRecord) => (p ? `${p.protocol === 'rdap' ? 'RDAP' : 'WHOIS'} ${p.server}` : undefined);
  const failed = !r.registry && !r.notFound;
  return {
    domain: r.queried,
    unicode: r.unicode,
    ok: !!r.registry,
    ...(r.notFound ? { notFound: true } : {}),
    ...(failed ? { error: r.attempts.filter((a) => a.party === 'registry').map((a) => `${a.server} : ${a.reason ?? a.status}`).join(' ; ') || t('registre injoignable') } : {}),
    registrar: r.merged.registrar?.name,
    ianaId: r.merged.registrar?.ianaId,
    reseller: r.merged.reseller,
    created: r.merged.created,
    updated: r.merged.updated,
    expires: r.merged.expires,
    ageDays: r.merged.ageDays,
    expiresInDays: r.merged.expiresInDays,
    status: r.merged.status,
    registryStatus: r.merged.registryStatus,
    nameservers: r.merged.nameservers,
    dnssec: r.merged.dnssec,
    ...(r.a ? { a: r.a } : {}),
    contacts: r.merged.contacts,
    registrySource: src(r.registry),
    registrarSource: src(r.registrar) ?? (r.registrarNotAnnounced ? t('données tenues par le registre') : r.registrarUnknown ? t('nom non publié par le bureau') : r.registry ? t('injoignable') : undefined),
    divergences: r.divergences,
    ...(r.cachedAt ? { cachedAt: r.cachedAt } : {}),
  };
}

/** A pasted list: one name per line, comma, semicolon or space; deduplicated on the registrable name. */
export function parseDomainList(input: string[] | string): { domains: string[]; invalid: { value: string; reason: string }[]; duplicates: number } {
  const tokens = (Array.isArray(input) ? input : [input]).flatMap((s) => String(s ?? '').split(/[\s,;]+/)).map((s) => s.trim()).filter(Boolean);
  const domains: string[] = [];
  const invalid: { value: string; reason: string }[] = [];
  let duplicates = 0;
  for (const token of tokens) {
    try {
      const d = orgDomain(normalizeDomain(token));
      if (!d.includes('.')) throw new InvalidInputError('extension seule');
      if (domains.includes(d)) duplicates++;
      else domains.push(d);
    } catch (e) {
      invalid.push({ value: token.slice(0, 80), reason: e instanceof InvalidInputError && /extension/.test(e.message) ? t('une extension seule, pas un domaine') : t('ce n’est pas un nom de domaine') });
    }
  }
  return { domains, invalid, duplicates };
}

/** Several domains, a few at a time (each server's own queue keeps the pace), rows sent as they come. */
export async function lookupMany(
  domains: string[],
  one: (d: string) => Promise<WhoisReport>,
  opts: { onRow?: (row: WhoisRow) => void; signal?: AbortSignal; concurrency?: number } = {},
): Promise<WhoisRow[]> {
  const rows: WhoisRow[] = new Array(domains.length);
  let next = 0;
  const worker = async () => {
    while (next < domains.length && !opts.signal?.aborted) {
      const i = next++;
      let row: WhoisRow;
      try {
        row = toRow(await one(domains[i]));
      } catch {
        row = { domain: domains[i], unicode: domainToUnicode(domains[i]) || domains[i], ok: false, error: 'mesure impossible', status: [], registryStatus: [], nameservers: [], contacts: [], divergences: [] };
      }
      rows[i] = row;
      opts.onRow?.(row);
    }
  };
  await Promise.all(Array.from({ length: Math.min(opts.concurrency ?? BATCH_CONCURRENCY, domains.length) }, worker));
  return rows.filter(Boolean);
}
