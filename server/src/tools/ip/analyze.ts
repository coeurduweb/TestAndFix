// IP reputation (US-065, US-068): DNS blocklists, reverse DNS, network (Team Cymru, RIPEstat),
// AbuseIPDB, VirusTotal and OTX. Every source runs in parallel; each one reports as soon as it
// answers (onEvent), and a missing key, a spent quota or a source down ends up in `unavailable`.
import { t, tPlural, msg } from '../../i18n.js';
import type { DnsblHit, DnsblResolver } from '../../mail/dnsbl.js';
import { explain, scoreOf, sortFindings, type Finding } from '../../knowledge/engine.js';
import { issue, mapLimit, pass, toFindings, type Analysis, type Issue, type Resolver } from '../../lib/email-auth/common.js';
import { abuseIpdbCheck, type AbuseIpdbData } from '../../lib/reputation/abuseipdb.js';
import { cymru, cymruAsInfo, cymruOrigin, type CymruData } from '../../lib/reputation/cymru.js';
import {
  delistFix,
  ipListingSituations,
  isScoringOnly,
  queryLists,
  selectLists,
  type ListSelection,
} from '../../lib/reputation/dnsbl-lists.js';
import type { RateLimiter } from '../../lib/reputation/limiter.js';
import { otxIp, type OtxData } from '../../lib/reputation/otx.js';
import { ripestat, type RipestatData } from '../../lib/reputation/ripestat.js';
import { runSource, type ApiFetch, type SourceResult } from '../../lib/reputation/source.js';
import { vtIp, type VtIpData } from '../../lib/reputation/virustotal.js';
import type { PassedCheck } from '../types.js';
import { nonPublicRange, parseIp } from './input.js';
import { lookupPtr, type PtrData } from './ptr.js';

export interface IpDeps {
  /** DNS session of the action (PTR, Team Cymru). */
  dns: Resolver;
  /** A resolver per DNSBL lookup. */
  dnsblResolverFor: () => DnsblResolver;
  keys: { abuseIpdb: string; virusTotal: string };
  fetch?: ApiFetch;
  bases?: Partial<Record<'abuseipdb' | 'virustotal' | 'otx' | 'ripestat', string>>;
  vtLimiter?: RateLimiter;
  /** Lists to query (tests); default: live zones of research/dnsbl.json. */
  lists?: ListSelection;
  /** Turn off the HTTP sources (tests of the DNS part). */
  http?: boolean;
}

/** One source that answered, sent on the SSE stream as event `source`. */
export interface IpSourceEvent {
  /** 'dnsbl:<zone>', 'ptr', 'cymru', 'ripestat', 'abuseipdb', 'virustotal', 'otx'. */
  source: string;
  label: string;
  ok: boolean;
  ms: number;
  reason?: string;
  data?: unknown;
}

export interface DnsblListing extends DnsblHit {
  situation: string;
  /** Concrete delisting steps, with the list's link filled in. */
  procedure: string[];
}

export interface IpReport {
  ip: string;
  version: 4 | 6;
  public: boolean;
  /** For a non-public address: the range and what it is. */
  range?: { range: string; label: string };
  dnsbl?: {
    source: 'research' | 'fallback';
    queried: number;
    listed: DnsblListing[];
    /** Answers that are a refusal (127.255.255.x...), never a listing. */
    refused: DnsblHit[];
    errors: { zone: string; name: string; error?: string }[];
    clean: { zone: string; name: string; weight: string }[];
    /** Answers of scoring-only lists that cover almost every address (not shown as listings). */
    scoringOnly: DnsblHit[];
    skipped: { zone: string; name: string; reason: string }[];
  };
  ptr?: PtrData;
  network?: {
    asn?: number;
    asName?: string;
    prefix?: string;
    country?: string;
    registry?: string;
    allocated?: string;
    peers: number[];
    city?: string;
    abuseContacts: string[];
    announced?: boolean;
    visibility?: { seeing: number; total: number };
  };
  sources: {
    cymru?: CymruData;
    ripestat?: RipestatData;
    abuseipdb?: AbuseIpdbData;
    virustotal?: VtIpData;
    otx?: OtxData;
  };
}

const LABELS: Record<string, string> = {
  ptr: msg('Reverse DNS'),
  cymru: 'Team Cymru (ASN)',
  ripestat: 'RIPEstat',
  abuseipdb: 'AbuseIPDB',
  virustotal: 'VirusTotal',
  otx: 'OTX AlienVault',
};

export const IP_SOURCES = Object.entries(LABELS).map(([id, label]) => ({ id, label }));

/** Report for an address that is not public: no network request at all. */
export function privateReport(ip: string, version: 4 | 6, range: { range: string; label: string }): Analysis & { data: IpReport } {
  return {
    issues: [
      issue('ip.not_public', { ip, value: range.label }, {
        fallback: {
          title: t("L'adresse {ip} n'est pas une adresse publique"),
          why: t("{ip} est une {value}. Elle n'est pas joignable depuis Internet : aucune liste noire ni aucun service de réputation ne la connaît, et un serveur de messagerie ne peut pas envoyer depuis elle vers l'extérieur."),
          fix: [
            t("Cherchez l'adresse publique par laquelle vos messages sortent : elle figure dans l'en-tête Received ajouté par le premier serveur extérieur, ou sur la page de votre hébergeur."),
            t('Relancez la vérification avec cette adresse publique.'),
          ],
          family: 'ip',
          severity: 'info',
          penalty: 0,
        },
      }),
    ],
    passed: [],
    data: { ip, version, public: false, range, sources: {} },
  };
}

function listingIssues(h: DnsblHit): (Issue & { codes: string[] })[] {
  return ipListingSituations(h).map((s) => ({
    codes: s.codes,
    ...issue(
      s.id,
      { ip: h.target, list_name: h.name, delist_url: h.delistUrl, value: h.target },
      {
        severity: s.severity,
        penalty: s.penalty,
        evidence: `${h.query} → ${s.codes.join(', ')}${h.meaning ? ` (${h.meaning})` : ''}${h.txt ? `\n${h.txt}` : ''}`,
        fallback: {
          title: t("L'IP {ip} est inscrite sur {list_name}"),
          why: t('Les serveurs de messagerie qui consultent {list_name} refusent ou classent en indésirables les messages venant de cette adresse.'),
          fix: delistFix(h.zone, !!h.delistUrl),
          family: 'blacklist',
          severity: s.severity ?? 'medium',
          penalty: s.penalty ?? 0.5,
        },
      },
    ),
  }));
}

/** Domain of the examples when the domain behind an IP is unknown. */
const EXAMPLE_DOMAIN = 'exemple.fr';

function ptrIssues(p: PtrData, issues: Issue[], passed: PassedCheck[]) {
  const v = { ip: p.ip, ptr: p.names[0] };
  if (p.error && !p.names.length) {
    issues.push(issue('rdns.temperror', v, { evidence: `${p.query} : ${p.error}` }));
    return;
  }
  if (!p.names.length) {
    // The IP alone does not tell whose domain it serves: the entry's examples use mail.exemple.fr,
    // and the record to ask for is given with the reverse name computed from the measured IP.
    issues.push(
      issue(p.ip.includes(':') ? 'rdns.ipv6_missing' : 'rdns.missing', { ...v, domain: EXAMPLE_DOMAIN }, {
        evidence: `${p.query} → ${p.rcode}`,
        suggested: `${p.query}. IN PTR mail.${EXAMPLE_DOMAIN}.`,
      }),
    );
    return;
  }
  if (p.names.length > 1) issues.push(issue('rdns.multiple_ptr', { ...v, value: p.names.length }, { evidence: p.names.join('\n') }));
  const dead = p.fcrdns.filter((f) => !f.ips.length);
  if (dead.length) issues.push(issue('rdns.ptr_target_nxdomain', { ...v, ptr: dead[0].name }, { evidence: dead.map((d) => `${d.name} → ${t('aucune adresse')}`).join('\n') }));
  if (!p.confirmed && dead.length < p.fcrdns.length)
    issues.push(issue('rdns.fcrdns_mismatch', v, { evidence: p.fcrdns.map((f) => `${f.name} → ${f.ips.join(', ') || t('aucune adresse')}`).join('\n') }));
  if (p.confirmed) passed.push(pass('rdns.fcrdns', 'rdns', t('Reverse DNS confirmé (FCrDNS) : {name}', { name: p.confirmed }), `${p.query} → ${p.confirmed} → ${p.ip}`));
  if (p.generic === 'dynamic') issues.push(issue('rdns.generic_dynamic', v, { evidence: p.names[0] }));
  else if (p.generic === 'hosting') issues.push(issue('rdns.generic_hosting', v, { evidence: p.names[0] }));
}

function abuseIssues(a: AbuseIpdbData, issues: Issue[], passed: PassedCheck[]) {
  const evidence = `${t('Score de confiance {score} %, {reports} par {users} en {days} jours', { score: a.score, reports: tPlural(a.totalReports, '{n} signalement', '{n} signalements'), users: tPlural(a.distinctUsers, '{n} utilisateur', '{n} utilisateurs'), days: a.maxAgeDays })}${a.lastReportedAt ? `, ${t('dernier le {date}', { date: a.lastReportedAt.slice(0, 10) })}` : ''}\n${a.link}`;
  if (a.score >= 25 || a.totalReports > 0) {
    const sev = a.score >= 75 ? { severity: 'high' as const, penalty: 2 } : a.score >= 25 ? { severity: 'medium' as const, penalty: 1 } : { severity: 'low' as const, penalty: 0.3 };
    issues.push(
      issue('ip.abuseipdb_reported', { ip: a.ip, value: a.score, url: a.link }, {
        ...sev,
        evidence,
        fallback: {
          title: t("L'IP {ip} est signalée sur AbuseIPDB (score {value} %)"),
          why: t("Des administrateurs ont signalé {ip} pour des abus (spam, attaques, balayage de ports). Le score dit à quel point AbuseIPDB juge l'adresse abusive. Quelques signalements anciens sur une IP partagée sont fréquents ; un score élevé indique une activité récente et répétée."),
          fix: [
            t('Lisez les signalements sur {url} : la catégorie et les commentaires indiquent ce qui a été vu.'),
            t("Si l'adresse est à vous, cherchez la machine ou le compte compromis et corrigez la cause. Les signalements vieillissent et le score baisse seul ; AbuseIPDB ne propose pas de retrait sur simple demande."),
            t("Si l'adresse appartient à votre hébergeur ou à votre service d'envoi, transmettez-lui le lien."),
          ],
          family: 'ip',
          ...sev,
        },
      }),
    );
  } else passed.push(pass('ip.abuseipdb', 'ip', t('AbuseIPDB : aucun signalement en {days} jours', { days: a.maxAgeDays }), a.link));
}

function vtIssues(v: VtIpData, issues: Issue[], passed: PassedCheck[]) {
  const { malicious, suspicious } = v.stats;
  if (malicious >= 1 || suspicious >= 2) {
    const sev = malicious >= 3 ? { severity: 'high' as const, penalty: 1.5 } : { severity: 'medium' as const, penalty: 0.5 };
    issues.push(
      issue('ip.virustotal_flagged', { ip: v.ip, value: malicious, url: v.link }, {
        ...sev,
        evidence: `${tPlural(malicious, '{n} moteur « malveillant »', '{n} moteurs « malveillant »')}, ${t('{n} « suspect »', { n: suspicious })}${v.flagged.length ? ` : ${v.flagged.map((f) => `${f.engine} (${f.result ?? f.category})`).join(', ')}` : ''}\n${v.link}`,
        fallback: {
          title: t("{value} moteur(s) de VirusTotal classent l'IP {ip} comme malveillante"),
          why: t("VirusTotal agrège des dizaines de listes de sécurité. Un seul moteur isolé se trompe souvent ; plusieurs moteurs d'accord signalent en général un hébergement de contenu malveillant ou une machine compromise sur cette adresse."),
          fix: [
            t('Ouvrez {url} et lisez quels moteurs signalent l’adresse et pour quelle raison.'),
            t("Si l'adresse est à vous, cherchez un site piraté ou un fichier malveillant hébergé, supprimez-le, puis demandez une nouvelle analyse sur VirusTotal."),
            t("Pour un moteur qui se trompe, la demande de correction se fait auprès de l'éditeur de ce moteur, pas auprès de VirusTotal."),
          ],
          family: 'ip',
          ...sev,
        },
      }),
    );
  } else passed.push(pass('ip.virustotal', 'ip', t('VirusTotal : aucun moteur ne signale cette adresse'), v.link));
}

function otxIssues(o: OtxData, issues: Issue[], passed: PassedCheck[]) {
  if (o.validation.length) {
    passed.push(pass('ip.otx', 'ip', t('OTX AlienVault : adresse connue et marquée sûre ({validation})', { validation: o.validation.join(', ') }), o.link));
    return;
  }
  if (o.pulseCount > 0) {
    issues.push(
      issue('ip.otx_pulses', { ip: o.ip, value: o.pulseCount, url: o.link }, {
        evidence: `${tPlural(o.pulseCount, '{n} collection', '{n} collections')}${o.pulses.length ? ` : ${o.pulses.join(' ; ')}` : ''}\n${o.link}`,
        fallback: {
          title: t("L'IP {ip} figure dans {value} collection(s) d'indicateurs OTX"),
          why: t("Les collections d'OTX AlienVault sont publiées par des membres de la communauté. Y figurer est un indice à lire, pas un verdict : une adresse partagée ou ancienne apparaît souvent dans des collections sans rapport avec son usage actuel."),
          fix: [t('Ouvrez {url} et regardez la date et le sujet des collections : seules les collections récentes qui parlent de spam ou de logiciel malveillant comptent.')],
          family: 'ip',
          severity: 'info',
          penalty: 0,
        },
      }),
    );
  } else passed.push(pass('ip.otx', 'ip', t('OTX AlienVault : adresse absente des collections'), o.link));
}

function ripeIssues(r: RipestatData, issues: Issue[], passed: PassedCheck[]) {
  if (r.announced === false) {
    issues.push(
      issue('ip.prefix_not_announced', { ip: r.ip, value: r.prefix }, {
        evidence: t('RIPEstat prefix-overview : {prefix} non annoncé', { prefix: r.prefix ?? r.ip }),
        fallback: {
          title: t("Aucun réseau n'annonce l'adresse {ip} sur Internet"),
          why: t("Les tables de routage observées par RIPEstat ne contiennent aucune route vers {ip}. Une adresse non annoncée ne peut ni envoyer ni recevoir de courrier sur Internet : c'est souvent une faute de frappe ou une adresse rendue par son ancien titulaire."),
          fix: [t("Vérifiez l'adresse saisie et comparez-la à celle que donne votre hébergeur.")],
          family: 'ip',
          severity: 'low',
          penalty: 0,
        },
      }),
    );
  }
  if (r.abuseContacts.length) passed.push(pass('ip.abuse_contact', 'ip', t('Contact d’abus publié : {contacts}', { contacts: r.abuseContacts.join(', ') }), r.link));
}

export interface IpAnalyzeOptions {
  onEvent?: (e: IpSourceEvent) => void;
  signal?: AbortSignal;
}

export async function analyzeIp(input: string, deps: IpDeps, opts: IpAnalyzeOptions = {}): Promise<Analysis & { data: IpReport }> {
  const { ip, version } = parseIp(input);
  const range = nonPublicRange(ip);
  if (range) return privateReport(ip, version, range);
  return analyzePublicIp(ip, version, deps, opts);
}

/** Every source for a public IP (also used by the tests on 127.0.0.2, the DNSBL test point). */
export async function analyzePublicIp(ip: string, version: 4 | 6, deps: IpDeps, opts: IpAnalyzeOptions = {}): Promise<Analysis & { data: IpReport }> {
  const emit = (e: IpSourceEvent) => {
    if (!opts.signal?.aborted) opts.onEvent?.(e);
  };
  const selection = deps.lists ?? selectLists('ip', 'all');
  const http = deps.http !== false;
  const report: IpReport = { ip, version, public: true, sources: {} };

  const dnsblP = queryLists(deps.dnsblResolverFor, { ip }, selection.lists, {
    onHit: (h) => emit({ source: `dnsbl:${h.zone}`, label: h.name, ok: h.status !== 'error', ms: h.ms, reason: h.error, data: h }),
  });
  const track = async <T>(id: string, fn: () => Promise<T>, timeoutMs?: number): Promise<SourceResult<T>> => {
    const r = await runSource(id, t(LABELS[id]), fn, timeoutMs);
    emit({ source: id, label: r.label, ok: r.ok, ms: r.ms, reason: r.reason, data: r.data });
    return r;
  };
  const [hits, ptr, cy, ripe, abuse, vt, otx] = await Promise.all([
    dnsblP,
    track('ptr', () => lookupPtr(deps.dns, ip)),
    track('cymru', () => cymru(deps.dns, ip)),
    http ? track('ripestat', () => ripestat(ip, { fetch: deps.fetch, base: deps.bases?.ripestat })) : undefined,
    http ? track('abuseipdb', () => abuseIpdbCheck(ip, { key: deps.keys.abuseIpdb, fetch: deps.fetch, base: deps.bases?.abuseipdb })) : undefined,
    http ? track('virustotal', () => vtIp(ip, { key: deps.keys.virusTotal, fetch: deps.fetch, base: deps.bases?.virustotal, limiter: deps.vtLimiter }), 30000) : undefined,
    http ? track('otx', () => otxIp(ip, { fetch: deps.fetch, base: deps.bases?.otx })) : undefined,
  ]);

  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const unavailable: { source: string; reason: string }[] = [];

  // DNS blocklists
  const listedHits = hits.filter((h) => h.status === 'listed' && !isScoringOnly(h));
  const listed: DnsblListing[] = [];
  for (const h of listedHits) {
    for (const { codes, ...is } of listingIssues(h)) {
      issues.push(is);
      listed.push({ ...h, codes, situation: is.id, procedure: explain(is).fix });
    }
  }
  const refused = hits.filter((h) => h.status === 'refused');
  const errors = hits.filter((h) => h.status === 'error');
  const clean = hits.filter((h) => h.status === 'clean');
  for (const h of refused)
    issues.push(issue('blacklist.query_blocked', { ip, list_name: h.name, delist_url: h.delistUrl }, { evidence: `${h.query} → ${h.codes.join(', ')} (${h.meaning ?? t('requête refusée')})` }));
  if (refused.length) unavailable.push({ source: 'dnsbl', reason: tPlural(refused.length, '{n} liste a refusé la requête ({names}) : ce n’est pas une inscription', '{n} listes ont refusé la requête ({names}) : ce n’est pas une inscription', { names: refused.map((h) => h.name).join(', ') }) });
  if (errors.length) unavailable.push({ source: 'dnsbl', reason: tPlural(errors.length, '{n} liste sans réponse ({names})', '{n} listes sans réponse ({names})', { names: errors.map((h) => h.name).slice(0, 6).join(', ') }) });
  const cleanZones = new Set(clean.map((h) => h.zone));
  if (!listedHits.length && clean.length) passed.push(pass('blacklist.clean', 'blacklist', t('Absente des {n} listes noires qui ont répondu', { n: cleanZones.size }), clean.map((h) => h.name).join(', ')));
  else if (clean.length) passed.push(pass('blacklist.clean_partial', 'blacklist', t('Absente de {n} autres listes noires', { n: cleanZones.size }), clean.map((h) => h.name).join(', ')));
  if (selection.source === 'fallback') unavailable.push({ source: 'dnsbl', reason: t('catalogue research/dnsbl.json illisible : listes de repli seulement') });
  report.dnsbl = {
    source: selection.source,
    queried: selection.lists.length,
    listed,
    refused,
    errors: errors.map((h) => ({ zone: h.zone, name: h.name, error: h.error })),
    clean: clean.map((h) => ({ zone: h.zone, name: h.name, weight: h.weight })),
    scoringOnly: hits.filter((h) => h.status === 'listed' && isScoringOnly(h)),
    skipped: selection.skipped,
  };

  // Reverse DNS
  if (ptr.ok) {
    report.ptr = ptr.data;
    ptrIssues(ptr.data!, issues, passed);
  } else unavailable.push({ source: 'ptr', reason: ptr.reason! });

  // Network
  const network: NonNullable<IpReport['network']> = { peers: [], abuseContacts: [] };
  if (cy.ok) {
    report.sources.cymru = cy.data;
    const o = cy.data!.origins[0];
    const as = cy.data!.as.find((a) => a.asn === o?.asn);
    Object.assign(network, { asn: o?.asn, prefix: o?.prefix, country: o?.country, registry: o?.registry, allocated: o?.allocated, asName: as?.name, peers: cy.data!.peers });
    if (o) passed.push(pass('ip.asn', 'ip', t('Réseau AS{asn}{name}, préfixe {prefix}{country}', { asn: o.asn, name: as?.name ? ` ${as.name}` : '', prefix: o.prefix, country: o.country ? `, ${o.country}` : '' })));
    else unavailable.push({ source: 'cymru', reason: t('Team Cymru ne connaît aucun réseau annonçant cette adresse') });
  } else unavailable.push({ source: 'cymru', reason: cy.reason! });
  if (ripe?.ok) {
    const r = ripe.data!;
    report.sources.ripestat = r;
    network.city = r.city;
    network.country ??= r.country;
    network.abuseContacts = r.abuseContacts;
    network.announced = r.announced;
    network.prefix ??= r.prefix;
    network.asn ??= r.holders[0]?.asn;
    network.asName ??= r.holders[0]?.holder;
    network.visibility = version === 6 ? r.visibility?.v6 : r.visibility?.v4;
    ripeIssues(r, issues, passed);
    if (r.missing.length) unavailable.push({ source: 'ripestat', reason: t('réponse partielle de RIPEstat ({missing} sans réponse)', { missing: r.missing.join(', ') }) });
  } else if (ripe) unavailable.push({ source: 'ripestat', reason: ripe.reason! });
  report.network = network;

  // Keyed and community reputation sources
  if (abuse?.ok) {
    report.sources.abuseipdb = abuse.data;
    abuseIssues(abuse.data!, issues, passed);
  } else if (abuse) unavailable.push({ source: 'abuseipdb', reason: abuse.reason! });
  if (vt?.ok) {
    report.sources.virustotal = vt.data;
    vtIssues(vt.data!, issues, passed);
  } else if (vt) unavailable.push({ source: 'virustotal', reason: vt.reason! });
  if (otx?.ok) {
    report.sources.otx = otx.data;
    otxIssues(otx.data!, issues, passed);
  } else if (otx) unavailable.push({ source: 'otx', reason: otx.reason! });

  return { issues, passed, unavailable, data: report };
}

// ---------------------------------------------------------------------------------------------
// Batch (US-068): many IPs at once, major lists only, one row per address.

export interface IpBatchRow {
  ip: string;
  status: 'clean' | 'listed' | 'private' | 'error';
  /** Score out of 10 of the row (listings and reverse DNS). */
  score?: number;
  ptr?: string;
  fcrdns?: boolean;
  asn?: number;
  asName?: string;
  prefix?: string;
  country?: string;
  listed: { zone: string; name: string; weight: string; codes: string[]; meaning?: string; delistUrl?: string; situation: string }[];
  /** Number of "major" lists that list the address. */
  majorListed: number;
  refused: string[];
  errors: string[];
  /** For a non-public address. */
  range?: string;
  /** Findings of the row (same objects as a single check). */
  findings: Finding[];
}

export interface IpBatchData {
  count: number;
  lists: { zone: string; name: string }[];
  rows: IpBatchRow[];
  invalid: { value: string; reason: string }[];
  listedCount: number;
  privateCount: number;
}

export async function analyzeBatch(
  ips: string[],
  deps: IpDeps,
  opts: { invalid?: { value: string; reason: string }[]; onRow?: (r: IpBatchRow) => void; signal?: AbortSignal; concurrency?: number } = {},
): Promise<Analysis & { data: IpBatchData }> {
  const selection = deps.lists ?? selectLists('ip', 'major');
  const asNames = new Map<number, Promise<string | undefined>>();
  const asName = (asn: number) => {
    if (!asNames.has(asn)) asNames.set(asn, cymruAsInfo(deps.dns, asn).then((a) => a?.name).catch(() => undefined));
    return asNames.get(asn)!;
  };
  const rows = await mapLimit(ips, opts.concurrency ?? 8, async (ip): Promise<IpBatchRow> => {
    const base: IpBatchRow = { ip, status: 'clean', listed: [], majorListed: 0, refused: [], errors: [], findings: [] };
    if (opts.signal?.aborted) return { ...base, status: 'error', errors: [t('annulé')] };
    const range = nonPublicRange(ip);
    if (range) {
      const row = { ...base, status: 'private' as const, range: range.label, findings: toFindings(privateReport(ip, ip.includes(':') ? 6 : 4, range).issues) };
      opts.onRow?.(row);
      return row;
    }
    const [hits, ptr, origin] = await Promise.all([
      queryLists(deps.dnsblResolverFor, { ip }, selection.lists, { concurrency: 4, withTxt: false }),
      lookupPtr(deps.dns, ip).catch(() => undefined),
      cymruOrigin(deps.dns, ip).catch(() => undefined),
    ]);
    const issues: Issue[] = [];
    const listedHits = hits.filter((h) => h.status === 'listed' && !isScoringOnly(h));
    for (const h of listedHits) {
      for (const { codes, ...is } of listingIssues(h)) {
        issues.push(is);
        base.listed.push({ zone: h.zone, name: h.name, weight: h.weight, codes, meaning: h.meaning, delistUrl: h.delistUrl, situation: is.id });
      }
    }
    if (ptr) ptrIssues(ptr, issues, []);
    base.majorListed = new Set(listedHits.filter((h) => h.weight === 'major').map((h) => h.zone)).size;
    base.refused = hits.filter((h) => h.status === 'refused').map((h) => h.name);
    base.errors = hits.filter((h) => h.status === 'error').map((h) => h.name);
    base.ptr = ptr?.names[0];
    base.fcrdns = ptr ? !!ptr.confirmed : undefined;
    const o = origin?.[0];
    if (o) Object.assign(base, { asn: o.asn, prefix: o.prefix, country: o.country, asName: await asName(o.asn) });
    base.findings = sortFindings(toFindings(issues));
    base.score = scoreOf(base.findings);
    base.status = listedHits.length ? 'listed' : base.errors.length === hits.length && hits.length ? 'error' : 'clean';
    opts.onRow?.(base);
    return base;
  });
  const listedCount = rows.filter((r) => r.status === 'listed').length;
  const passed: PassedCheck[] = [];
  const checked = rows.filter((r) => r.status !== 'private').length;
  if (checked && !listedCount) passed.push(pass('blacklist.batch_clean', 'blacklist', t('Aucune des {n} adresses n’est sur les listes principales', { n: checked }), selection.lists.map((l) => l.name).join(', ')));
  const errors = rows.reduce((n, r) => n + r.errors.length, 0);
  const refused = rows.reduce((n, r) => n + r.refused.length, 0);
  const unavailable = [
    ...(errors ? [{ source: 'dnsbl', reason: tPlural(errors, '{n} interrogation de liste sans réponse', '{n} interrogations de liste sans réponse') }] : []),
    ...(refused ? [{ source: 'dnsbl', reason: tPlural(refused, '{n} requête refusée par une liste (ce n’est pas une inscription)', '{n} requêtes refusées par une liste (ce n’est pas une inscription)') }] : []),
  ];
  // The batch result carries no findings of its own: each row has its findings, the envelope
  // score is the mean of the rows.
  return {
    issues: [],
    passed,
    unavailable,
    data: {
      count: rows.length,
      lists: selection.lists.map((l) => ({ zone: l.zone, name: l.name })),
      rows,
      invalid: opts.invalid ?? [],
      listedCount,
      privateCount: rows.filter((r) => r.status === 'private').length,
    },
  };
}
