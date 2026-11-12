// Which DNSBL zones the IP and link tools query, and how a listing becomes a situation.
// The lookups themselves are those of mail/dnsbl.ts (checkDnsbl), reused as is; this file only
// selects the zones, streams results list by list, and adds delisting procedures for the lists
// the knowledge base has no entry for.
import { checkDnsbl, loadDnsblLists, type DnsblHit, type DnsblList, type DnsblResolver } from '../../mail/dnsbl.js';
import { nodeStyleResolver, type ResolveSession } from '../../dns/iterative.js';
import { deadline, DeadlineError, mapLimit } from '../email-auth/common.js';
import type { Severity } from '../../knowledge/engine.js';
import { msg, t } from '../../i18n.js';

/**
 * Live zones of research/dnsbl.json that are NOT queried, with the reason (from the research
 * notes of 2026-11-10). Redundant zones would count one listing twice.
 */
export const SKIPPED_ZONES: Record<string, string> = {
  'sbl.spamhaus.org': msg('composante de Spamhaus ZEN, déjà interrogée'),
  'xbl.spamhaus.org': msg('composante de Spamhaus ZEN, déjà interrogée'),
  'pbl.spamhaus.org': msg('composante de Spamhaus ZEN, déjà interrogée'),
  'sbl-xbl.spamhaus.org': msg('ancienne zone combinée, redondante avec Spamhaus ZEN'),
  'cbl.abuseat.org': msg('alias de Spamhaus XBL, déjà couvert par ZEN'),
  'black.uribl.com': msg('sous-zone de multi.uribl.com, déjà interrogée'),
  'z.mailspike.net': msg('comprise dans bl.mailspike.net, déjà interrogée'),
  'dnsbl.justspam.org': msg('liste 1.1.1.1 au test du 2026-11-10 : liste suspecte, écartée'),
  'dnsbl.kempt.net': msg('seul le point de test est documenté'),
  'dnsbl.rymsho.ru': msg('politique d’usage inconnue'),
  'spam.spamrats.com': msg('les conditions de SpamRATS exigent une clé API, non configurée'),
  'dyna.spamrats.com': msg('les conditions de SpamRATS exigent une clé API, non configurée'),
  'noptr.spamrats.com': msg('les conditions de SpamRATS exigent une clé API, non configurée'),
  'auth.spamrats.com': msg('les conditions de SpamRATS exigent une clé API, non configurée'),
};

export interface ListSelection {
  lists: DnsblList[];
  skipped: { zone: string; name: string; reason: string }[];
  source: 'research' | 'fallback';
}

/** Zones to query. `major` keeps the lists weighted "major" only (ranges and batches). */
export function selectLists(type: 'ip' | 'domain', scope: 'all' | 'major' = 'all'): ListSelection {
  const { lists, source } = loadDnsblLists();
  const ofType = lists.filter((l) => l.type === type);
  const skipped = ofType.filter((l) => SKIPPED_ZONES[l.zone]).map((l) => ({ zone: l.zone, name: l.name, reason: t(SKIPPED_ZONES[l.zone]) }));
  const kept = ofType.filter((l) => !SKIPPED_ZONES[l.zone] && (scope === 'all' || l.weight === 'major'));
  return { lists: kept, skipped, source };
}

/**
 * A resolver per lookup with a deadline and one retry on a fresh session: a resolution can
 * stall inside a session when list name servers have no glue (same guard as tools/domain).
 */
export function guardedDnsblResolver(makeSession: () => ResolveSession, fresh: () => ResolveSession = makeSession, ms = 4000): () => DnsblResolver {
  return () => {
    const first = nodeStyleResolver(makeSession());
    return async (name, type) => {
      try {
        return await deadline(first(name, type), ms, name);
      } catch (e) {
        if (!(e instanceof DeadlineError)) throw e;
        return deadline(nodeStyleResolver(fresh())(name, type), ms * 2, name);
      }
    };
  };
}

/** Query each list for one target, calling onHit as soon as a list answers. */
export async function queryLists(
  resolverFor: () => DnsblResolver,
  target: { ip?: string; domain?: string },
  lists: DnsblList[],
  opts: { concurrency?: number; withTxt?: boolean; onHit?: (h: DnsblHit) => void } = {},
): Promise<DnsblHit[]> {
  const per = await mapLimit(lists, opts.concurrency ?? 16, async (list) => {
    const r = await checkDnsbl(resolverFor(), target.ip ? { ips: [target.ip] } : { domains: [target.domain!] }, { lists: [list], withTxt: opts.withTxt ?? true, concurrency: 1 });
    for (const h of r.results) opts.onHit?.(h);
    return r.results;
  });
  return per.flat();
}

/** Scoring-only answers: SPFBL .3/.4 cover almost every address (verified 2026-11-10). */
export function isScoringOnly(h: DnsblHit): boolean {
  return h.zone === 'dnsbl.spfbl.net' && h.codes.every((c) => c === '127.0.0.3' || c === '127.0.0.4');
}

export interface ListingSituation {
  id: string;
  codes: string[];
  severity?: Severity;
  penalty?: number;
}

/** Situations of an IP listing, one per distinct meaning (ZEN can answer SBL, XBL and PBL at once). */
export function ipListingSituations(h: DnsblHit): ListingSituation[] {
  const z = h.zone;
  const info = h.weight === 'info' ? { severity: 'info' as const, penalty: 0 } : {};
  if (z === 'zen.spamhaus.org') {
    const by = new Map<string, string[]>();
    for (const c of h.codes) {
      const id =
        c === '127.0.0.9'
          ? 'blacklist.spamhaus_drop'
          : c === '127.0.0.2'
            ? 'blacklist.spamhaus_sbl'
            : c === '127.0.0.3'
              ? 'blacklist.spamhaus_css'
              : /^127\.0\.0\.[4-7]$/.test(c)
                ? 'blacklist.spamhaus_xbl'
                : c === '127.0.0.10' || c === '127.0.0.11'
                  ? 'blacklist.spamhaus_pbl'
                  : 'blacklist.spamhaus_sbl';
      by.set(id, [...(by.get(id) ?? []), c]);
    }
    return [...by].map(([id, codes]) => ({ id, codes }));
  }
  const one = (id: string, extra: Partial<ListingSituation> = {}) => [{ id, codes: h.codes, ...info, ...extra }];
  if (z === 'b.barracudacentral.org') return one('blacklist.barracuda');
  if (z === 'bl.spamcop.net') return one('blacklist.spamcop');
  if (z === 'dnsbl-1.uceprotect.net') return one('blacklist.uceprotect_level1');
  // levels 2 and 3 target the whole network or the whole ASN: informative, never scored
  if (z === 'dnsbl-2.uceprotect.net') return one('blacklist.uceprotect_level2', { severity: 'info', penalty: 0 });
  if (z === 'dnsbl-3.uceprotect.net') return one('blacklist.uceprotect_level3', { severity: 'info', penalty: 0 });
  if (z === 'psbl.surriel.com') return one('blacklist.psbl');
  if (z === 'bl.mailspike.net' || z === 'z.mailspike.net') return one('blacklist.mailspike');
  if (z === 'rep.mailspike.net') return one('blacklist.mailspike', { severity: 'info', penalty: 0 });
  if (z.endsWith('dyna.spamrats.com')) return one('blacklist.spamrats_dyna');
  if (z.endsWith('noptr.spamrats.com')) return one('blacklist.spamrats_noptr');
  if (z.endsWith('spam.spamrats.com')) return one('blacklist.spamrats_spam');
  return one('blacklist.ip_listed', h.weight === 'major' ? { severity: 'high', penalty: 1.5 } : h.weight === 'minor' ? { severity: 'medium', penalty: 0.5 } : {});
}

/**
 * Situation of a domain listing on the link page (link.domain_listed, written for a link alone;
 * the links.* and blacklist.* entries talk about a received message). The gravity depends on
 * the list and the code, passed at top level.
 */
export function domainListingSituation(h: DnsblHit): ListingSituation {
  const z = h.zone;
  const id = 'link.domain_listed';
  if (isPhishingListing(h)) return { id, codes: h.codes, severity: 'critical', penalty: 3 };
  // a legitimate site abused (DBL 127.0.1.1xx), or URIBL grey/red only: weaker signals
  if (z === 'dbl.spamhaus.org' && h.codes.some((c) => /^127\.0\.1\.1\d\d$/.test(c))) return { id, codes: h.codes, severity: 'high', penalty: 1.5 };
  if (z === 'multi.uribl.com' && !h.codes.some((c) => (Number(c.split('.')[3]) & 2) === 2)) return { id, codes: h.codes, severity: 'low', penalty: 0.3 };
  if (h.weight === 'minor') return { id, codes: h.codes, severity: 'medium', penalty: 1 };
  if (h.weight === 'info') return { id, codes: h.codes, severity: 'info', penalty: 0 };
  return { id, codes: h.codes };
}

/** A domain listing that names phishing or malware explicitly (Spamhaus DBL .4/.5, SURBL PH/MW). */
export function isPhishingListing(h: DnsblHit): boolean {
  if (h.zone === 'dbl.spamhaus.org') return h.codes.some((c) => ['127.0.1.4', '127.0.1.5', '127.0.1.104', '127.0.1.105'].includes(c));
  if (h.zone === 'multi.surbl.org') return h.codes.some((c) => (Number(c.split('.')[3]) & (8 | 16)) !== 0);
  if (h.zone === 'multi.uribl.com') return h.codes.some((c) => (Number(c.split('.')[3]) & 2) === 2);
  return false;
}

/**
 * Delisting procedure for lists without an entry of their own in the knowledge base, written
 * from the research notes (research/dnsbl.json, read 2026-11-10). {delist_url} is filled later.
 */
/** Delisting steps for a listing, translated; `{delist_url}` and `{list_name}` are left for explain() to fill. */
export function delistFix(zone: string, hasUrl: boolean): string[] {
  const steps = DELIST_PROCEDURES[zone] ?? (hasUrl ? GENERIC_DELIST : [GENERIC_DELIST[0], msg('Suivez ensuite la procédure de retrait de {list_name}.')]);
  return steps.map((x) => t(x));
}

export const DELIST_PROCEDURES: Record<string, string[]> = {
  'all.s5h.net': [msg('Corrigez la cause de l’envoi indésirable, puis ouvrez la page de retrait depuis l’IP listée elle-même : le retrait est automatique ({delist_url}).')],
  'bl.nordspam.com': [msg('Corrigez la cause, puis demandez le retrait sur {delist_url}. Il est gratuit, mais la demande doit venir du titulaire du bloc d’adresses, avec la preuve que le problème est réglé.')],
  'rbl.0spam.org': [msg('Corrigez la cause, créez un compte sur {delist_url} et demandez le retrait. Il est gratuit, à raison d’une IP toutes les trois heures.')],
  'nbl.0spam.org': [msg('Cette liste vise des réseaux entiers. Signalez l’inscription à votre hébergeur, seul à pouvoir traiter le bloc : {delist_url}.')],
  'dnsbl.dronebl.org': [
    msg('DroneBL recense les machines compromises et les services ouverts aux abus (proxy, résolveur DNS, VPN). Fermez ou protégez le service en cause sur cette IP.'),
    msg('Demandez ensuite le retrait sur {delist_url}.'),
  ],
  'bl.blocklist.de': [
    msg('Cette liste recense les IP qui ont attaqué des serveurs dans les 48 dernières heures (connexions SSH, IMAP, SMTP en force). Cherchez la machine compromise ou le script en cause.'),
    msg('Une fois la cause supprimée, demandez le retrait sur {delist_url}.'),
  ],
  'ips.backscatterer.org': [
    msg('Cette liste vise les serveurs qui renvoient des avis de non-remise à de fausses adresses d’expéditeur. Réglez votre serveur pour refuser les messages pendant la session SMTP plutôt que d’envoyer un rebond après coup.'),
    msg('L’inscription dure quatre semaines ; la page {delist_url} explique les options.'),
  ],
  'backscatter.spameatingmonkey.net': [msg('Cette liste vise les rebonds envoyés à de fausses adresses. Refusez les messages pendant la session SMTP au lieu de renvoyer un rebond, puis consultez {delist_url}.')],
  'dnsbl.spfbl.net': [msg('SPFBL sert au calcul d’une note, pas au rejet. Consultez la fiche de l’IP sur {delist_url} pour la raison.')],
  'rep.mailspike.net': [msg('Mailspike donne une note de réputation. Corrigez la cause des envois indésirables ; la note remonte avec des envois propres. Fiche de l’IP : {delist_url}.')],
};

export const GENERIC_DELIST = [
  msg('Corrigez la cause (compte ou site compromis, liste d’adresses achetée, formulaire détourné) avant toute demande, sinon l’IP est réinscrite.'),
  msg('Demandez ensuite le retrait sur {delist_url}.'),
];
