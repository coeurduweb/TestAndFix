// Phishing check of a link (US-066, US-067): the redirect chain followed live, the threat
// sources on the first and the last URL, domain lists on every domain of the chain, and the
// usual phishing signs (young domain, look-alike of a brand, homoglyphs, certificate, password
// or card form). Verdict "sûr" / "suspect" / "dangereux" with the main reason in one sentence.
import { t, tPlural, msg } from '../../i18n.js';
import net from 'node:net';
import path from 'node:path';
import { domainToUnicode } from 'node:url';
import type { DnsblHit, DnsblResolver } from '../../mail/dnsbl.js';
import { GMAIL_BLOCKED_EXT, SHORTENERS } from '../../mail/analyze/thresholds.js';
import { scoreOf, sortFindings, type Finding, type Severity } from '../../knowledge/engine.js';
import { InvalidInputError, issue, pass, toFindings, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import { domainListingSituation, queryLists, selectLists, type ListSelection } from '../../lib/reputation/dnsbl-lists.js';
import type { RateLimiter } from '../../lib/reputation/limiter.js';
import { openPhishCheck, type OpenPhishData } from '../../lib/reputation/openphish.js';
import { gsbThreatLabel, safeBrowsingLookup, type GsbData } from '../../lib/reputation/safebrowsing.js';
import { runSource, type ApiFetch, type SourceResult } from '../../lib/reputation/source.js';
import { urlhausHost, urlhausUrl, type UrlhausHostData, type UrlhausUrlData } from '../../lib/reputation/urlhaus.js';
import { urlscanSearch, type UrlscanData } from '../../lib/reputation/urlscan.js';
import { vtUrl, type VtUrlData } from '../../lib/reputation/virustotal.js';
import { orgDomain } from '../../lib/email-auth/common.js';
import type { PassedCheck } from '../types.js';
import { BRANDS, brandsInTitle, findLookalikes, isOfficial, punycodeLabels, type Lookalike } from './brands.js';
import { domainOf, followChain, hostOf, type ChainResult, type Hop, type HopFetch, type HostResolver } from './chain.js';
import type { PageFacts } from './page.js';
import { probeTls, type TlsInfo, type TlsProbe } from './tls.js';

export interface RdapAge {
  ageDays?: number;
  created?: string;
  registrar?: string;
  /** Why the age is unknown. */
  unavailable?: string;
  notRegistered?: boolean;
}

export interface LinkDeps {
  fetch: HopFetch;
  resolveHost: HostResolver;
  tlsProbe?: TlsProbe;
  rdap?: (domain: string) => Promise<RdapAge>;
  /** A resolver per DNSBL lookup; without it the domain lists are skipped. */
  dnsblResolverFor?: () => DnsblResolver;
  lists?: ListSelection;
  keys: { safeBrowsing: string; virusTotal: string; urlhaus: string };
  apiFetch?: ApiFetch;
  bases?: Partial<Record<'safebrowsing' | 'virustotal' | 'urlhaus' | 'urlscan', string>>;
  openPhishFeed?: string;
  vtLimiter?: RateLimiter;
  /** Submit an URL unknown to VirusTotal (it then becomes part of VirusTotal's public data). */
  submitToVirusTotal?: boolean;
  /** Turn off every HTTP threat source (tests of the chain). */
  http?: boolean;
  now?: number;
}

/** One step of the check, sent on the SSE stream as event `step`. */
export interface LinkStepEvent {
  /** 'hop' (one per hop, live), 'chain', 'rdap', 'tls', 'page', 'dnsbl', 'safebrowsing', 'virustotal', 'urlhaus', 'openphish', 'urlscan', 'heuristics'. */
  step: string;
  label: string;
  status: 'ok' | 'unavailable' | 'skipped';
  ms?: number;
  reason?: string;
  data?: unknown;
}

export const LINK_STEPS = [
  { id: 'chain', label: msg('Chaîne de redirections') },
  { id: 'rdap', label: msg('Âge des domaines (RDAP)') },
  { id: 'tls', label: msg('Certificat TLS') },
  { id: 'page', label: msg('Contenu de la page finale') },
  { id: 'dnsbl', label: msg('Listes de domaines (Spamhaus DBL, SURBL, URIBL)') },
  { id: 'safebrowsing', label: 'Google Safe Browsing' },
  { id: 'virustotal', label: 'VirusTotal' },
  { id: 'urlhaus', label: 'URLhaus' },
  { id: 'openphish', label: 'OpenPhish' },
  { id: 'urlscan', label: 'urlscan.io' },
  { id: 'heuristics', label: msg('Signes de phishing') },
];
const STEP_LABEL = Object.fromEntries(LINK_STEPS.map((s) => [s.id, s.label]));
const stepLabel = (id: string): string => (STEP_LABEL[id] ? t(STEP_LABEL[id]) : id);

export type Verdict = 'sûr' | 'suspect' | 'dangereux';

export interface LinkReport {
  /** URL as checked (scheme added when missing). */
  url: string;
  verdict: Verdict;
  level: 'safe' | 'suspicious' | 'dangerous';
  /** Main reason, one sentence. */
  reason: string;
  start: string;
  final: string;
  /** HTTP status of the last hop, or undefined when it did not answer (see finalError). */
  finalStatus?: number;
  finalError?: string;
  chain: { hops: Hop[]; stoppedBy?: ChainResult['stoppedBy']; jsRedirects: number; metaRefreshes: number; domains: string[] };
  domains: { domain: string; ageDays?: number; created?: string; registrar?: string; ageSource?: 'rdap' | 'urlscan.io'; unavailable?: string }[];
  tls: TlsInfo[];
  page?: Omit<PageFacts, 'cardHints'> & { cardHints: string[]; brandsInTitle: string[]; contentType?: string; bytes?: number; truncated?: boolean };
  lookalikes: Lookalike[];
  punycode: { host: string; label: string; unicode: string; mixedScripts: boolean }[];
  intel: {
    safebrowsing?: GsbData;
    virustotal?: VtUrlData[];
    urlhaus?: { urls: UrlhausUrlData[]; host?: UrlhausHostData };
    openphish?: OpenPhishData;
    urlscan?: UrlscanData[];
    dnsbl?: { queried: string[]; listed: DnsblHit[]; refused: DnsblHit[]; errors: { zone: string; target: string; error?: string }[]; clean: number };
  };
}

/** Sources that can say a link is malicious (urlscan.io's free search gives no verdict). */
const THREAT_SOURCES = new Set(['dnsbl', 'safebrowsing', 'virustotal', 'urlhaus', 'openphish']);

const UNSAFE_SCHEMES = ['javascript:', 'data:', 'file:', 'vbscript:'];

/** URL to check: scheme added when missing. Throws InvalidInputError. */
export function normalizeLinkInput(raw: string): { url: string; unsafe?: string } {
  let s = String(raw ?? '').trim();
  if (!s) throw new InvalidInputError(t('Lien vide.'));
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(s)?.[1]?.toLowerCase();
  if (scheme && UNSAFE_SCHEMES.includes(scheme + ':')) return { url: s.slice(0, 2000), unsafe: scheme + ':' };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s.replace(/^\/+/, '');
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new InvalidInputError(t('« {raw} » n’est pas un lien valide.', { raw }));
  }
  if (!['http:', 'https:'].includes(u.protocol)) throw new InvalidInputError(t('Protocole {protocol} non pris en charge : seuls http et https sont vérifiés.', { protocol: u.protocol }));
  if (!u.hostname) throw new InvalidInputError(t('« {raw} » n’a pas de nom d’hôte.', { raw }));
  return { url: u.toString() };
}

const sev = (severity: Severity, penalty: number) => ({ severity, penalty });

function intelIssues(r: LinkReport, issues: Issue[], passed: PassedCheck[]) {
  const gsb = r.intel.safebrowsing;
  if (gsb) {
    if (gsb.matches.length) {
      for (const m of gsb.matches)
        issues.push(
          issue('phishing.safe_browsing', { url: m.url, value: gsbThreatLabel(m.threatType) }, {
            evidence: `${m.url} : ${m.threatType} (${m.platformType})`,
            fallback: {
              title: t('Google Safe Browsing classe ce lien comme dangereux ({value})'),
              why: t("Google a confirmé que {url} sert à {value}. Chrome, Firefox et Safari affichent une page d'alerte rouge sur cette adresse."),
              fix: [
                t("N'ouvrez pas le lien et ne saisissez aucune information sur la page."),
                t("Si vous l'avez déjà fait, changez tout de suite le mot de passe concerné et prévenez votre banque si vous avez donné une carte."),
                t("Si le site est le vôtre, il a probablement été piraté : nettoyez-le, puis demandez un réexamen dans Google Search Console (rubrique Problèmes de sécurité)."),
              ],
              family: 'phishing',
              ...sev('critical', 4),
            },
          }),
        );
    } else passed.push(pass('phishing.safe_browsing', 'phishing', t('Google Safe Browsing : aucune menace connue'), gsb.checked.join('\n')));
  }
  for (const v of r.intel.virustotal ?? []) {
    if (!v.found) {
      passed.push(pass('phishing.virustotal_unknown', 'phishing', v.submitted ? t('VirusTotal : lien inconnu, soumis pour analyse (relancez dans une minute)') : t('VirusTotal : lien jamais analysé'), v.url));
      continue;
    }
    const m = v.stats?.malicious ?? 0;
    const s = v.stats?.suspicious ?? 0;
    if (m >= 2 || (m >= 1 && s >= 1) || s >= 2) {
      const strong = m >= 2;
      issues.push(
        issue('phishing.virustotal', { url: v.url, value: m }, {
          ...(strong ? sev('critical', 3) : sev('high', 1.5)),
          evidence: `${t('{malicious} malveillant, {suspicious} suspect', { malicious: m, suspicious: s })}${v.flagged.length ? ` : ${v.flagged.map((f) => `${f.engine} (${f.result ?? f.category})`).join(', ')}` : ''}${v.lastAnalysisDate ? `\n${t('analyse du {date}', { date: v.lastAnalysisDate.slice(0, 10) })}` : ''}\n${v.link}`,
          fallback: {
            title: t('{value} moteur(s) de VirusTotal signalent ce lien'),
            why: t('Plusieurs moteurs de sécurité indépendants classent {url} comme dangereux. Quand au moins deux moteurs sont d’accord, il s’agit rarement d’une erreur.'),
            fix: [t("N'ouvrez pas le lien."), t('Si le site est le vôtre, ouvrez la fiche VirusTotal pour voir les moteurs concernés, nettoyez le site, puis demandez une nouvelle analyse.')],
            family: 'phishing',
            ...(strong ? sev('critical', 3) : sev('high', 1.5)),
          },
        }),
      );
    } else if (m === 1 || s === 1) {
      issues.push(
        issue('phishing.virustotal_single', { url: v.url }, {
          evidence: `${v.flagged.map((f) => `${f.engine} (${f.result ?? f.category})`).join(', ')}\n${v.link}`,
          fallback: {
            title: t('Un seul moteur de VirusTotal signale ce lien'),
            why: t('Un moteur isolé sur plusieurs dizaines se trompe souvent. Ce signal ne suffit pas, mais il s’ajoute aux autres indices de ce rapport.'),
            fix: [t('Regardez la fiche VirusTotal : un moteur peu connu qui signale seul un site ancien est en général une fausse alerte.')],
            family: 'phishing',
            ...sev('low', 0.3),
          },
        }),
      );
    } else passed.push(pass('phishing.virustotal', 'phishing', t('VirusTotal : aucun moteur ne signale ce lien') + (v.stats ? ` (${t('{n} moteurs', { n: v.stats.harmless + v.stats.undetected })})` : ''), v.link));
  }
  const uh = r.intel.urlhaus;
  if (uh) {
    const listed = uh.urls.filter((u) => u.listed);
    for (const u of listed)
      issues.push(
        issue('phishing.urlhaus', { url: u.url, value: u.threat ?? 'logiciel malveillant' }, {
          ...(u.status === 'online' ? sev('critical', 3.5) : sev('high', 1.5)),
          evidence: `URLhaus : ${u.status ?? t('statut inconnu')}${u.threat ? `, ${u.threat}` : ''}${u.tags.length ? ` (${u.tags.join(', ')})` : ''}${u.dateAdded ? `, ${t('ajouté le {date}', { date: u.dateAdded.slice(0, 10) })}` : ''}${u.reference ? `\n${u.reference}` : ''}`,
          fallback: {
            title: t('Ce lien est recensé par URLhaus comme diffusant un logiciel malveillant'),
            why: t('URLhaus, tenu par abuse.ch, recense les adresses qui distribuent des logiciels malveillants. {url} y figure ({value}).'),
            fix: [t("N'ouvrez pas le lien et ne téléchargez rien."), t('Si un fichier a déjà été ouvert, lancez une analyse antivirus complète du poste concerné.')],
            family: 'phishing',
            ...(u.status === 'online' ? sev('critical', 3.5) : sev('high', 1.5)),
          },
        }),
      );
    if (!listed.length && uh.host?.listed && uh.host.onlineCount > 0)
      issues.push(
        issue('phishing.urlhaus_host', { domain: uh.host.host, value: uh.host.onlineCount }, {
          evidence: `${t('{n} adresse(s) connues sur {host}, dont {online} en ligne', { n: uh.host.urlCount, host: uh.host.host, online: uh.host.onlineCount })}\n${uh.host.urls.map((u) => `${u.url} (${u.status})`).join('\n')}`,
          fallback: {
            title: t("Le site {domain} héberge d'autres liens malveillants recensés par URLhaus"),
            why: t("Ce lien précis n'est pas recensé, mais {value} autre(s) adresse(s) du même site distribuent un logiciel malveillant en ce moment."),
            fix: [t("Évitez ce site tant que l'hébergeur ne l'a pas nettoyé.")],
            family: 'phishing',
            ...sev('high', 1.5),
          },
        }),
      );
    if (!listed.length && !(uh.host?.listed && uh.host.onlineCount > 0)) passed.push(pass('phishing.urlhaus', 'phishing', t('URLhaus : lien absent de la base'), uh.urls.map((u) => u.url).join('\n')));
  }
  const op = r.intel.openphish;
  if (op) {
    for (const u of op.exact)
      issues.push(
        issue('phishing.openphish', { url: u }, {
          evidence: t('présent dans le flux OpenPhish ({n} adresses, téléchargé le {date})', { n: op.feedSize, date: op.fetchedAt }),
          fallback: {
            title: t('Ce lien figure dans la liste de phishing OpenPhish'),
            why: t("OpenPhish publie les pages d'hameçonnage actives qu'il a détectées. {url} en fait partie."),
            fix: [t("N'ouvrez pas le lien et ne saisissez aucune information."), t('Si vous avez saisi un mot de passe, changez-le tout de suite, partout où vous l’utilisez.')],
            family: 'phishing',
            ...sev('critical', 4),
          },
        }),
      );
    for (const h of op.sameHost)
      issues.push(
        issue('phishing.openphish_host', { url: h.url, domain: hostOf(new URL(h.url)) }, {
          evidence: h.feedUrls.join('\n'),
          fallback: {
            title: t("D'autres pages du site {domain} figurent dans la liste OpenPhish"),
            why: t("Cette adresse précise n'est pas dans la liste, mais d'autres pages du même site y sont, ce qui arrive quand un site sert de base à une campagne d'hameçonnage."),
            fix: [t('Méfiez-vous de toute page de ce site qui demande un mot de passe ou un paiement.')],
            family: 'phishing',
            ...sev('high', 1.5),
          },
        }),
      );
    if (!op.exact.length && !op.sameHost.length) passed.push(pass('phishing.openphish', 'phishing', t('OpenPhish : absent des {n} pages d’hameçonnage actives du flux', { n: op.feedSize }), op.stale ?? t('flux du {date}', { date: op.fetchedAt })));
  }
  const dl = r.intel.dnsbl;
  if (dl) {
    for (const h of dl.listed) {
      const s = domainListingSituation(h);
      issues.push(
        issue(s.id, { url: h.target, domain: h.target, value: h.target, list_name: h.name, delist_url: h.delistUrl }, {
          severity: s.severity,
          penalty: s.penalty,
          evidence: `${h.query} → ${h.codes.join(', ')}${h.meaning ? ` (${h.meaning})` : ''}${h.txt ? `\n${h.txt}` : ''}`,
          fallback: { title: t('{value} est inscrit sur {list_name}'), family: 'links', severity: s.severity ?? 'medium', penalty: s.penalty ?? 1 },
        }),
      );
    }
    for (const h of dl.refused)
      issues.push(issue('blacklist.query_blocked', { domain: h.target, list_name: h.name, delist_url: h.delistUrl }, { evidence: `${h.query} → ${h.codes.join(', ')} (${h.meaning ?? t('requête refusée')})` }));
    if (!dl.listed.length && dl.clean) passed.push(pass('links.domain_lists', 'links', t('Domaines absents des listes de domaines ({list})', { list: dl.queried.join(', ') })));
  }
}

function heuristicIssues(r: LinkReport, chain: ChainResult, ages: Map<string, LinkReport['domains'][number]>, issues: Issue[], passed: PassedCheck[]) {
  const start = new URL(r.start);
  const final = new URL(r.final);
  const startHost = hostOf(start);
  const finalHost = hostOf(final);
  const v = (u: URL) => ({ url: u.toString(), domain: domainOf(hostOf(u)) });

  // User info before the host: https://paypal.com@evil.example/
  if (start.username || start.password)
    issues.push(issue('links.userinfo_in_url', { ...v(start), value: start.username }, { evidence: t('partie avant le @ : {user} ; vraie destination : {host}', { user: decodeURIComponent(start.username) + (start.password ? ':…' : ''), host: startHost }), ...sev('high', 2) }));
  for (const u of new Set([start.toString(), final.toString()])) {
    const x = new URL(u);
    const h = hostOf(x);
    if (net.isIP(h)) issues.push(issue('links.ip_literal', { ...v(x), value: h }, { evidence: u }));
    if (x.port && !['80', '443'].includes(x.port)) issues.push(issue('link.nonstandard_port', { ...v(x), value: x.port }, { evidence: u }));
  }
  const shortHop = chain.hops.find((h, i) => i < chain.hops.length - 1 && SHORTENERS.has(h.host.replace(/^www\./, '')));
  if (shortHop) issues.push(issue('link.shortener', { url: shortHop.url, domain: domainOf(finalHost) }, { evidence: `${shortHop.host} → ${finalHost}` }));
  else if (SHORTENERS.has(startHost.replace(/^www\./, '')))
    // destination unknown: the shortener hides it completely
    issues.push(issue('link.shortener', { url: r.start, domain: domainOf(finalHost) }, { evidence: t('{host} : la destination n’a pas pu être lue', { host: startHost }), ...sev('medium', 1) }));

  // Look-alikes and homoglyphs on every host of the chain
  for (const l of r.lookalikes) {
    const strong = l.kind === 'homoglyph' || l.kind === 'typo' || l.kind === 'subdomain' || !!l.phishingWord;
    const evidence = `${l.unicode ?? l.host} : ${t(KIND_TEXT[l.kind])} « ${l.matched} »${l.distance ? ` (${t('distance {n}', { n: l.distance })})` : ''}${l.phishingWord ? `, ${t('avec le mot « {word} »', { word: l.phishingWord })}` : ''} ; ${t('domaines officiels : {list}', { list: l.official.slice(0, 4).join(', ') })}`;
    if (l.kind === 'homoglyph' && (l.unicode || /xn--/.test(l.host))) {
      issues.push(issue('link.punycode_lookalike', { url: l.unicode ?? l.host, domain: l.official[0], value: l.brandName }, { evidence }));
      continue;
    }
    issues.push(
      issue('phishing.brand_lookalike', { url: l.host, domain: l.official[0], value: l.brandName }, {
        ...(strong ? sev('high', 2) : sev('medium', 0.7)),
        evidence,
        fallback: {
          title: t('Le domaine {url} imite celui de {value}'),
          why: t("Le nom ressemble à celui de {value} sans lui appartenir : c'est la ficelle la plus courante du phishing, qui compte sur une lecture rapide de l'adresse. Le site officiel est sur {domain}."),
          fix: [
            t("N'utilisez pas ce lien : tapez vous-même l'adresse officielle {domain} dans le navigateur, ou passez par l'application."),
            t("Si vous avez saisi un identifiant ou une carte sur cette page, changez le mot de passe et prévenez l'organisme concerné."),
          ],
          family: 'phishing',
          ...(strong ? sev('high', 2) : sev('medium', 0.7)),
        },
      }),
    );
  }
  for (const p of r.punycode.filter((x) => x.mixedScripts && !r.lookalikes.some((l) => l.host === x.host && l.kind === 'homoglyph')))
    issues.push(issue('link.punycode_lookalike', { url: p.unicode, domain: p.host }, { evidence: t('{label} = « {unicode} » : alphabets mélangés', { label: p.label, unicode: p.unicode }) }));

  // Deep sub-domains: login.paypal.com.secure.verify.example.ru
  for (const host of new Set(chain.hops.map((h) => h.host))) {
    if (net.isIP(host)) continue;
    const sub = host.split('.').length - orgDomain(host).split('.').length;
    if (sub >= 4)
      issues.push(
        issue('phishing.deep_subdomains', { url: host, domain: orgDomain(host), value: sub }, {
          evidence: host,
          fallback: {
            title: t("L'adresse {url} empile {value} niveaux de sous-domaines"),
            why: t("Un nom très long fait de nombreux sous-domaines sert souvent à placer un nom connu au début de l'adresse, là où on le lit, alors que le vrai domaine est à la fin : {domain}."),
            fix: [t("Lisez l'adresse de droite à gauche : le vrai propriétaire est {domain}.")],
            family: 'phishing',
            ...sev('low', 0.3),
          },
        }),
      );
  }

  // Chain shape
  const redirects = chain.hops.filter((h) => h.next).length;
  if (chain.stoppedBy === 'max_hops')
    issues.push(issue('link.redirect_chain', { url: r.start, value: redirects }, { evidence: t('{n} redirections, arrêt au maximum de {hops} sauts', { n: redirects, hops: chain.hops.length }), ...sev('medium', 1) }));
  else if (chain.stoppedBy === 'loop') issues.push(issue('link.redirect_chain', { url: r.start, value: redirects }, { evidence: t('boucle : {url} renvoie vers une adresse déjà visitée', { url: r.final }) }));
  else if (redirects > 3) issues.push(issue('link.redirect_chain', { url: r.start, value: redirects }, { evidence: chain.hops.map((h) => `${h.status ?? '?'} ${h.url}`).join('\n') }));
  const js = chain.hops.filter((h) => h.next === 'js');
  if (js.length)
    issues.push(
      issue('phishing.js_redirect', { url: js[0].url, value: js.length }, {
        evidence: js.map((h) => `${h.url} → ${h.location}`).join('\n'),
        fallback: {
          title: t('Le lien redirige par un script de la page'),
          why: t("Une page intermédiaire envoie le visiteur ailleurs par JavaScript au lieu d'une redirection normale. Les filtres qui ne lisent pas les scripts ne voient alors pas la vraie destination : la technique sert souvent à masquer une page d'hameçonnage."),
          fix: [t('Regardez la destination finale de la chaîne ci-dessus avant de faire confiance au lien.')],
          family: 'phishing',
          ...sev('low', 0.3),
        },
      }),
    );
  if (chain.stoppedBy === 'unsafe') {
    const last = chain.hops[chain.hops.length - 1];
    issues.push(issue('link.private_target', { url: last.url, domain: last.host }, { evidence: last.error }));
  }
  const last = chain.hops[chain.hops.length - 1];
  if (last && (last.error || (last.status !== undefined && last.status >= 400)) && chain.stoppedBy !== 'unsafe')
    issues.push(issue('link.unreachable', { url: last.url, value: last.error ?? `HTTP ${last.status}` }, { evidence: last.error ?? `HTTP ${last.status}` }));
  else if (last && !last.error && last.status && last.status < 400) passed.push(pass('links.reachable', 'links', tPlural(chain.hops.length, 'Page finale atteinte : HTTP {status} en {n} saut', 'Page finale atteinte : HTTP {status} en {n} sauts', { status: last.status }), r.final));

  // Downloads
  const ext = path.extname(final.pathname).slice(1).toLowerCase();
  const ct = (last?.contentType ?? '').toLowerCase();
  const disposition = chain.finalHeaders?.['content-disposition'] ?? '';
  const dispExt = /filename\*?=(?:UTF-8'')?["']?[^"';]*\.([a-z0-9_]{1,10})["']?/i.exec(disposition)?.[1]?.toLowerCase();
  const exe = /application\/(x-msdownload|x-msdos-program|x-ms-installer|vnd\.microsoft\.portable-executable|java-archive|x-dosexec|vnd\.android\.package-archive)/.test(ct)
    ? ct
    : dispExt && GMAIL_BLOCKED_EXT.has(dispExt)
      ? dispExt
      : !/html/.test(ct) && ext && GMAIL_BLOCKED_EXT.has(ext)
        ? ext
        : undefined;
  if (exe) issues.push(issue('links.executable_target', { url: r.final, domain: domainOf(finalHost), value: exe }, { evidence: `${r.final}\nContent-Type: ${ct || 'absent'}${disposition ? `\nContent-Disposition: ${disposition}` : ''}` }));

  if (final.protocol === 'http:' && last?.status && last.status < 400) issues.push(issue('links.http_not_https', { url: r.final }, { evidence: r.final }));

  // Domain age
  const finalDomain = domainOf(finalHost);
  for (const d of ages.values()) {
    if (d.ageDays === undefined) continue;
    if (d.ageDays < 30)
      issues.push(
        issue('link.domain_recent', { url: d.domain, domain: d.domain, value: tPlural(d.ageDays, '{n} jour', '{n} jours') }, {
          evidence: t('{domain} créé le {date} ({source})', { domain: d.domain, date: d.created?.slice(0, 10) ?? '?', source: d.ageSource ?? 'rdap' }) + (d.registrar ? `, ${t('bureau d’enregistrement {name}', { name: d.registrar })}` : ''),
        }),
      );
    else passed.push(pass('links.domain_age', 'links', t('{domain} existe depuis {age}', { domain: d.domain, age: Math.floor(d.ageDays / 365) >= 1 ? tPlural(Math.floor(d.ageDays / 365), '{n} an', '{n} ans') : t('{n} jours', { n: d.ageDays }) }), d.created));
  }

  // Certificates
  for (const tl of r.tls) {
    const tv = { url: `https://${tl.host}/`, domain: tl.host, value: tl.issuerOrg ?? tl.issuer };
    const ev = t('{host} ({ip}:{port}) : émis par {issuer} le {from}, expire le {to} ; noms : {names}', { host: tl.host, ip: tl.ip, port: tl.port, issuer: tl.issuerOrg ?? tl.issuer ?? '?', from: tl.validFrom?.slice(0, 10) ?? '?', to: tl.validTo?.slice(0, 10) ?? '?', names: tl.san.slice(0, 6).join(', ') || tl.subject || '?' }) + (tl.authorizationError ? ` ; ${tl.authorizationError}` : '');
    if (tl.error) continue;
    if (tl.expired) issues.push(issue('tls.web_cert_expired', tv, { evidence: ev, fallback: tlsFb(TLS_FALLBACK.expired) }));
    else if (tl.selfSigned) issues.push(issue('tls.web_cert_self_signed', tv, { evidence: ev, fallback: tlsFb(TLS_FALLBACK.selfSigned) }));
    else if (!tl.nameMatches) issues.push(issue('tls.web_cert_name_mismatch', tv, { evidence: ev, fallback: tlsFb(TLS_FALLBACK.nameMismatch) }));
    else if (!tl.authorized) issues.push(issue('tls.web_cert_untrusted', tv, { evidence: ev, fallback: tlsFb(TLS_FALLBACK.untrusted) }));
    else {
      const age = ages.get(domainOf(tl.host))?.ageDays;
      if (tl.freeCa && tl.ageDays !== undefined && tl.ageDays < 7 && age !== undefined && age < 90)
        issues.push(issue('tls.web_cert_recent_free', { ...tv, value: tPlural(tl.ageDays, '{n} jour', '{n} jours') }, { evidence: ev, fallback: tlsFb(TLS_FALLBACK.recentFree) }));
      passed.push(pass('tls.web_cert', 'tls', (tl.ageDays !== undefined ? tPlural(tl.ageDays, 'Certificat valide pour {host}, émis par {issuer} il y a {n} jour', 'Certificat valide pour {host}, émis par {issuer} il y a {n} jours', { host: tl.host, issuer: tl.issuerOrg ?? tl.issuer ?? t('une autorité reconnue') }) : t('Certificat valide pour {host}, émis par {issuer}', { host: tl.host, issuer: tl.issuerOrg ?? tl.issuer ?? t('une autorité reconnue') })), ev));
    }
  }

  // Final page: forms and brand named in the title
  const page = r.page;
  if (page) {
    const titleBrands = page.brandsInTitle
      .map((id) => BRAND_BY_ID.get(id)!)
      .filter((b) => b && !isOfficial(finalHost, b));
    const lookFinal = r.lookalikes.find((l) => l.host === finalHost);
    const young = ages.get(finalDomain)?.ageDays;
    const triggers: string[] = [];
    if (lookFinal) triggers.push(t('le domaine imite {brand}', { brand: lookFinal.brandName }));
    if (titleBrands.length) triggers.push(t('le titre cite {brands}', { brands: titleBrands.map((b) => b.name).join(', ') }));
    if (young !== undefined && young < 30) triggers.push(tPlural(young, 'le domaine a {n} jour', 'le domaine a {n} jours'));
    if (net.isIP(finalHost)) triggers.push(t("l'adresse est une IP"));
    if (r.punycode.some((p) => p.host === finalHost)) triggers.push(t('le domaine est écrit en caractères internationaux'));
    const asks = page.passwordForm && page.cardForm ? t('un mot de passe et une carte bancaire') : page.passwordForm ? t('un mot de passe') : page.cardForm ? t('une carte bancaire') : '';
    const formEvidence = [
      page.passwordForm ? t('champ <input type="password">') : '',
      ...page.cardHints,
      page.formActions.length ? t('envoi du formulaire vers : {list}', { list: page.formActions.join(', ') }) : '',
      page.title ? t('titre : « {title} »', { title: page.title }) : '',
    ]
      .filter(Boolean)
      .join('\n');
    if (asks && triggers.length)
      issues.push(
        issue('phishing.credential_form', { url: r.final, domain: finalDomain, value: asks }, {
          ...sev('critical', 3.5),
          evidence: `${triggers.join(' ; ')}\n${formEvidence}`,
          fallback: {
            title: t('La page demande {value} sur un site qui se fait passer pour un autre'),
            why: t("La page finale contient un formulaire qui demande {value}, et le site présente des signes d'usurpation. C'est la forme exacte d'une page d'hameçonnage : ce qui est saisi part chez l'auteur de la page."),
            fix: [
              t('Ne saisissez rien sur cette page.'),
              t("Si c'est déjà fait : changez le mot de passe sur le site officiel (et partout où vous l'utilisez), activez la double authentification, et appelez votre banque pour faire opposition si vous avez donné une carte."),
              t('Signalez la page sur https://www.phishing-initiative.fr/ ou à la plateforme PHAROS.'),
            ],
            family: 'phishing',
            ...sev('critical', 3.5),
          },
        }),
      );
    else if (asks)
      issues.push(
        issue('phishing.form_on_page', { url: r.final, domain: finalDomain, value: asks }, {
          evidence: formEvidence,
          fallback: {
            title: t('La page finale demande {value}'),
            why: t("Aucun autre signe d'usurpation n'a été relevé : beaucoup de sites légitimes ont une page de connexion. Vérifiez seulement que l'adresse affichée est bien celle du service que vous attendez ({domain})."),
            fix: [t('Avant de saisir quoi que ce soit, vérifiez le nom de domaine dans la barre d’adresse.')],
            family: 'phishing',
            ...sev('info', 0),
          },
        }),
      );
    if (titleBrands.length && !asks)
      issues.push(
        issue('phishing.title_brand_mismatch', { url: r.final, domain: finalDomain, value: titleBrands.map((b) => b.name).join(', ') }, {
          evidence: `titre : « ${page.title} » ; domaine : ${finalDomain}`,
          fallback: {
            title: t('Le titre de la page cite {value}, mais le site est {domain}'),
            why: t("Le titre de la page nomme une marque à laquelle le domaine n'appartient pas. C'est normal pour un article ou un comparatif ; pour une page de connexion ou de paiement, c'est un signe d'usurpation."),
            fix: [t("Si la page se présente comme celle de {value}, n'y saisissez rien et passez par le site officiel.")],
            family: 'phishing',
            ...sev('low', 0.3),
          },
        }),
      );
  }
}

const KIND_TEXT: Record<Lookalike['kind'], string> = {
  homoglyph: msg('caractères qui imitent'),
  typo: msg('faute de frappe sur'),
  subdomain: msg('nom de la marque placé en sous-domaine'),
  word: msg('nom de la marque utilisé comme mot du domaine'),
  contains: msg('nom de la marque inclus dans'),
};

const tlsFb = (f: (typeof TLS_FALLBACK)[keyof typeof TLS_FALLBACK]) => ({ ...f, title: t(f.title), why: t(f.why), fix: f.fix.map((x) => t(x)) });

const BRAND_BY_ID = new Map(BRANDS.map((b) => [b.id, b]));

const TLS_FALLBACK = {
  expired: {
    title: msg('Le certificat de {domain} a expiré'),
    why: msg("Le navigateur affiche une alerte de sécurité sur ce site. Un site d'entreprise suivi ne laisse pas expirer son certificat : le site est abandonné, ou ce n'est pas celui qu'il prétend être."),
    fix: [msg("Ne passez pas outre l'alerte du navigateur pour saisir des informations sur ce site.")],
    family: 'tls',
    severity: 'high' as const,
    penalty: 1.5,
  },
  selfSigned: {
    title: msg('Le certificat de {domain} est auto-signé'),
    why: msg("Aucune autorité reconnue ne garantit ce certificat : n'importe qui peut en fabriquer un. Le navigateur affiche une alerte de sécurité."),
    fix: [msg("Ne passez pas outre l'alerte du navigateur pour saisir des informations sur ce site.")],
    family: 'tls',
    severity: 'high' as const,
    penalty: 1.5,
  },
  nameMismatch: {
    title: msg("Le certificat présenté n'est pas celui de {domain}"),
    why: msg("Le serveur présente un certificat établi pour un autre nom. Le navigateur affiche une alerte : soit le site est mal configuré, soit l'adresse n'est pas celle du service attendu."),
    fix: [msg("Ne passez pas outre l'alerte du navigateur pour saisir des informations sur ce site.")],
    family: 'tls',
    severity: 'high' as const,
    penalty: 1.5,
  },
  untrusted: {
    title: msg("Le certificat de {domain} n'est pas reconnu"),
    why: msg('La chaîne de certificats ne remonte pas à une autorité reconnue (chaîne incomplète ou autorité inconnue). Certains navigateurs affichent une alerte.'),
    fix: [msg('Si le site est le vôtre, installez la chaîne complète fournie par votre autorité de certification.')],
    family: 'tls',
    severity: 'medium' as const,
    penalty: 1,
  },
  recentFree: {
    title: msg('Certificat gratuit émis il y a {value} pour un domaine récent'),
    why: msg("Un certificat gratuit est normal et sûr en soi. Mais un certificat de quelques jours sur un domaine de quelques semaines est le profil type d'un site monté pour une campagne de phishing : le cadenas du navigateur ne dit rien de l'honnêteté du site."),
    fix: [msg("Ne vous fiez pas au cadenas : vérifiez le nom de domaine lui-même.")],
    family: 'tls',
    severity: 'medium' as const,
    penalty: 0.7,
  },
};

function verdictOf(findings: Finding[], score: number, r: LinkReport, consulted: string[], unavailable: { source: string }[]): { verdict: Verdict; level: LinkReport['level']; reason: string } {
  const top = findings.find((f) => f.penalty > 0) ?? findings[0];
  if (findings.some((f) => f.severity === 'critical')) return { verdict: 'dangereux', level: 'dangerous', reason: sentence(findings.find((f) => f.severity === 'critical')!.title) };
  if (findings.some((f) => f.severity === 'high') || score < 7) return { verdict: 'suspect', level: 'suspicious', reason: sentence(top.title) };
  const missing = [...new Set(unavailable.filter((u) => THREAT_SOURCES.has(u.source)).map((u) => stepLabel(u.source)))];
  const reached = r.chain.hops.some((h) => h.status);
  const sources = consulted.length
    ? t('Aucune des {n} sources de réputation consultées ne signale ce lien', { n: consulted.length })
    : t('Aucune source de réputation n’a pu être consultée');
  const base = reached ? t('{sources} et aucun signe de phishing n’a été relevé', { sources }) : t('{sources}, et la page n’a pas pu être lue', { sources });
  return { verdict: 'sûr', level: 'safe', reason: missing.length ? `${base} (${t('non consultées : {list}', { list: missing.join(', ') })}).` : `${base}.` };
}

function sentence(s: string): string {
  const t = s.trim();
  return /[.!?]$/.test(t) ? t : t + '.';
}

export async function analyzeLink(raw: string, deps: LinkDeps, opts: { onStep?: (e: LinkStepEvent) => void; signal?: AbortSignal } = {}): Promise<Analysis & { data: LinkReport }> {
  const emit = (e: LinkStepEvent) => {
    if (!opts.signal?.aborted) opts.onStep?.(e);
  };
  const input = normalizeLinkInput(raw);
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const unavailable: { source: string; reason: string }[] = [];

  if (input.unsafe) {
    const data: LinkReport = {
      url: input.url,
      verdict: 'dangereux',
      level: 'dangerous',
      reason: '',
      start: input.url,
      final: input.url,
      chain: { hops: [], jsRedirects: 0, metaRefreshes: 0, domains: [] },
      domains: [],
      tls: [],
      lookalikes: [],
      punycode: [],
      intel: {},
    };
    issues.push(issue('links.unsafe_scheme', { url: input.url.slice(0, 80), value: input.unsafe }, { evidence: input.url.slice(0, 300), ...sev('critical', 3) }));
    const f = toFindings(issues);
    data.reason = sentence(f[0].title);
    return { issues, passed, data };
  }

  // 1. The chain, live
  const chain = await followChain(input.url, { fetch: deps.fetch, resolveHost: deps.resolveHost, onHop: (h) => emit({ step: 'hop', label: t('Saut {n}', { n: h.index }), status: 'ok', ms: h.ms, data: h }) });
  const report: LinkReport = {
    url: input.url,
    verdict: 'sûr',
    level: 'safe',
    reason: '',
    start: chain.start,
    final: chain.final,
    chain: {
      hops: chain.hops,
      stoppedBy: chain.stoppedBy,
      jsRedirects: chain.hops.filter((h) => h.next === 'js').length,
      metaRefreshes: chain.hops.filter((h) => h.next === 'meta').length,
      domains: [...new Set(chain.hops.map((h) => h.domain))],
    },
    domains: [],
    tls: [],
    lookalikes: [],
    punycode: [],
    intel: {},
  };
  const lastHop = chain.hops[chain.hops.length - 1];
  report.finalStatus = lastHop?.status;
  report.finalError = lastHop?.error;
  emit({ step: 'chain', label: stepLabel('chain'), status: 'ok', data: report.chain });

  const startHost = hostOf(new URL(report.start));
  const finalHost = hostOf(new URL(report.final));
  const urls = [...new Set([report.start, report.final])];
  const hosts = [...new Set(chain.hops.map((h) => h.host))];
  const named = hosts.filter((h) => !net.isIP(h));
  const http = deps.http !== false;
  const consulted: string[] = [];

  const step = async <T>(id: string, fn: () => Promise<T>, timeoutMs?: number): Promise<SourceResult<T>> => {
    const r = await runSource(id, stepLabel(id), fn, timeoutMs);
    emit({ step: id, label: r.label, status: r.ok ? 'ok' : 'unavailable', ms: r.ms, reason: r.reason, data: r.data });
    if (r.ok && THREAT_SOURCES.has(id)) consulted.push(id);
    else unavailable.push({ source: id, reason: r.reason! });
    return r;
  };
  const skip = (id: string, reason: string) => emit({ step: id, label: stepLabel(id), status: 'skipped', reason });

  // 2. Everything else in parallel
  const ageDomains = [...new Set([startHost, finalHost].filter((h) => !net.isIP(h)).map(domainOf))].slice(0, 3);
  const rdapP = deps.rdap
    ? step('rdap', async () => {
        const out: Record<string, RdapAge> = {};
        await Promise.all(ageDomains.map(async (d) => (out[d] = await deps.rdap!(d).catch((e: Error) => ({ unavailable: e.message })))));
        return out;
      })
    : (skip('rdap', t('non configuré')), undefined);
  const tlsTargets = chain.hops.filter((h, i, all) => h.url.startsWith('https:') && h.ip && !h.error && (i === all.length - 1 || h.host === startHost)).filter((h, i, all) => all.findIndex((x) => x.host === h.host) === i);
  const tlsP = tlsTargets.length
    ? step('tls', () => Promise.all(tlsTargets.map((h) => (deps.tlsProbe ?? probeTls)(h.host, h.ip!, h.port ?? 443))))
    : (skip('tls', report.final.startsWith('https:') ? t('page finale injoignable') : t('la page finale est en http, sans certificat')), undefined);
  const listSel = deps.lists ?? selectLists('domain', 'all');
  const dnsblTargets = [...new Set(named.map((h) => orgDomain(h)))].slice(0, 10);
  const dnsblP =
    deps.dnsblResolverFor && dnsblTargets.length
      ? step('dnsbl', async () => {
          const hits = (await Promise.all(dnsblTargets.map((d) => queryLists(deps.dnsblResolverFor!, { domain: d }, listSel.lists, { concurrency: 4 })))).flat();
          return {
            queried: dnsblTargets,
            listed: hits.filter((h) => h.status === 'listed'),
            refused: hits.filter((h) => h.status === 'refused'),
            errors: hits.filter((h) => h.status === 'error').map((h) => ({ zone: h.zone, target: h.target, error: h.error })),
            clean: hits.filter((h) => h.status === 'clean').length,
          };
        })
      : (skip('dnsbl', dnsblTargets.length ? t('non configuré') : t('aucun nom de domaine dans la chaîne')), undefined);
  const gsbP = http ? step('safebrowsing', () => safeBrowsingLookup(urls, { key: deps.keys.safeBrowsing, fetch: deps.apiFetch, base: deps.bases?.safebrowsing })) : undefined;
  const vtP = http
    ? step('virustotal', () => Promise.all(urls.map((u) => vtUrl(u, { key: deps.keys.virusTotal, fetch: deps.apiFetch, base: deps.bases?.virustotal, limiter: deps.vtLimiter, submit: deps.submitToVirusTotal }))), 40000)
    : undefined;
  const uhP = http
    ? step('urlhaus', async () => {
        const [list, host] = await Promise.all([
          Promise.all(urls.map((u) => urlhausUrl(u, { key: deps.keys.urlhaus, fetch: deps.apiFetch, base: deps.bases?.urlhaus }))),
          net.isIP(finalHost) || !deps.keys.urlhaus ? undefined : urlhausHost(finalHost, { key: deps.keys.urlhaus, fetch: deps.apiFetch, base: deps.bases?.urlhaus }),
        ]);
        return { urls: list, host };
      })
    : undefined;
  const opP = http ? step('openphish', () => openPhishCheck(chain.hops.map((h) => h.url), { fetch: deps.apiFetch, feedUrl: deps.openPhishFeed })) : undefined;
  const usP = http && named.length ? step('urlscan', () => Promise.all([...new Set([startHost, finalHost])].filter((h) => !net.isIP(h)).map((h) => urlscanSearch(h, { fetch: deps.apiFetch, base: deps.bases?.urlscan })))) : undefined;
  if (!http) for (const id of ['safebrowsing', 'virustotal', 'urlhaus', 'openphish', 'urlscan']) skip(id, t('sources externes désactivées'));

  const [rdap, tlsR, dnsbl, gsb, vt, uh, op, us] = await Promise.all([rdapP, tlsP, dnsblP, gsbP, vtP, uhP, opP, usP]);
  if (tlsR?.ok) report.tls = tlsR.data!;
  if (dnsbl?.ok) report.intel.dnsbl = dnsbl.data;
  if (gsb?.ok) report.intel.safebrowsing = gsb.data;
  if (vt?.ok) report.intel.virustotal = vt.data;
  if (uh?.ok) report.intel.urlhaus = uh.data;
  if (op?.ok) report.intel.openphish = op.data;
  if (us?.ok) report.intel.urlscan = us.data;
  if (dnsbl?.ok && dnsbl.data!.errors.length) unavailable.push({ source: 'dnsbl', reason: t('{n} interrogation(s) de liste sans réponse', { n: dnsbl.data!.errors.length }) });

  // Domain ages: RDAP first, urlscan.io's figure when the registry did not answer
  const ages = new Map<string, LinkReport['domains'][number]>();
  for (const d of ageDomains) {
    const a = rdap?.ok ? rdap.data![d] : undefined;
    const entry: LinkReport['domains'][number] = { domain: d, ageDays: a?.ageDays, created: a?.created, registrar: a?.registrar, ageSource: a?.ageDays !== undefined ? 'rdap' : undefined, unavailable: a?.unavailable };
    if (entry.ageDays === undefined) {
      const scan = report.intel.urlscan?.flatMap((u) => u.scans).find((s) => s.apexDomainAgeDays !== undefined && s.url.includes(d));
      if (scan) Object.assign(entry, { ageDays: scan.apexDomainAgeDays, ageSource: 'urlscan.io' as const });
    }
    if (entry.ageDays === undefined && entry.unavailable) unavailable.push({ source: 'rdap', reason: t('âge de {domain} inconnu : {reason}', { domain: d, reason: entry.unavailable }) });
    ages.set(d, entry);
  }
  report.domains = [...ages.values()];

  // Page facts
  if (chain.finalPage) {
    const last = chain.hops[chain.hops.length - 1];
    const { cardHints, ...facts } = chain.finalPage;
    report.page = { ...facts, cardHints, brandsInTitle: chain.finalPage.title ? brandsInTitle(chain.finalPage.title).map((b) => b.id) : [], contentType: last.contentType, bytes: last.bytes, truncated: last.truncated };
    emit({ step: 'page', label: stepLabel('page'), status: 'ok', data: report.page });
  } else {
    const last = chain.hops[chain.hops.length - 1];
    skip('page', !last || last.error ? t('la page finale n’a pas répondu') + (last?.error ? ` (${last.error})` : '') : t('la page finale n’est pas du HTML (HTTP {status}, {type})', { status: last.status, type: last.contentType ?? t('type non indiqué') }));
  }

  report.lookalikes = hosts.flatMap(findLookalikes);
  report.punycode = hosts.flatMap((h) => punycodeLabels(h).map((p) => ({ host: h, ...p })));

  intelIssues(report, issues, passed);
  heuristicIssues(report, chain, ages, issues, passed);
  if (!report.lookalikes.length && !report.punycode.some((p) => p.mixedScripts))
    passed.push(pass('phishing.no_lookalike', 'phishing', t('Aucun domaine de la chaîne n’imite une marque connue'), hosts.map((h) => domainToUnicode(h) || h).join(', ')));
  emit({ step: 'heuristics', label: stepLabel('heuristics'), status: 'ok', data: { lookalikes: report.lookalikes, punycode: report.punycode } });

  const findings = sortFindings(toFindings(issues));
  const v = verdictOf(findings, scoreOf(findings), report, consulted, unavailable);
  Object.assign(report, v);
  return { issues, passed, unavailable, data: report };
}
