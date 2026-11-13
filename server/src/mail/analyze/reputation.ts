// Blocklists (sending IP on IP lists, From / Return-Path / link domains on domain lists) and
// SpamAssassin, whose every rule becomes a finding explained by the knowledge base.
import { situationForSaRule } from '../../knowledge/engine.js';
import { checkDnsbl, type DnsblHit } from '../dnsbl.js';
import { spamdReport, type SpamdResult } from '../spamd.js';
import { isPublicIp } from '../../lib/net.js';
import { orgDomain } from '../received.js';
import { T } from './thresholds.js';
import type { StepContext } from './types.js';
import type { Severity } from '../../knowledge/engine.js';
import { t, tPlural } from '../../i18n.js';

/** Situation id for a listing of the sending IP. */
function ipListingId(h: DnsblHit): string {
  const z = h.zone;
  if (z === 'zen.spamhaus.org' || z === 'sbl.spamhaus.org' || z === 'sbl-xbl.spamhaus.org' || z === 'xbl.spamhaus.org' || z === 'pbl.spamhaus.org') {
    const codes = h.codes;
    if (codes.includes('127.0.0.9')) return 'blacklist.spamhaus_drop';
    if (codes.includes('127.0.0.2')) return 'blacklist.spamhaus_sbl';
    if (codes.includes('127.0.0.3')) return 'blacklist.spamhaus_css';
    if (codes.some((c) => /^127\.0\.0\.[4-7]$/.test(c))) return 'blacklist.spamhaus_xbl';
    if (codes.includes('127.0.0.10') || codes.includes('127.0.0.11')) return 'blacklist.spamhaus_pbl';
    return 'blacklist.spamhaus_sbl';
  }
  if (z === 'b.barracudacentral.org') return 'blacklist.barracuda';
  if (z === 'bl.spamcop.net') return 'blacklist.spamcop';
  if (z === 'dnsbl-1.uceprotect.net') return 'blacklist.uceprotect_level1';
  if (z === 'dnsbl-2.uceprotect.net') return 'blacklist.uceprotect_level2';
  if (z === 'dnsbl-3.uceprotect.net') return 'blacklist.uceprotect_level3';
  if (z === 'psbl.surriel.com') return 'blacklist.psbl';
  if (z === 'bl.mailspike.net' || z.endsWith('mailspike.net')) return 'blacklist.mailspike';
  if (z.endsWith('dyna.spamrats.com')) return 'blacklist.spamrats_dyna';
  if (z.endsWith('noptr.spamrats.com')) return 'blacklist.spamrats_noptr';
  if (z.endsWith('spam.spamrats.com')) return 'blacklist.spamrats_spam';
  return 'blacklist.ip_listed';
}

function domainListingId(h: DnsblHit, kind: 'sender' | 'link'): string {
  const z = h.zone;
  if (z === 'dbl.spamhaus.org') {
    if (h.codes.some((c) => /^127\.0\.1\.1\d\d$/.test(c))) return 'blacklist.spamhaus_dbl_abused';
    return kind === 'link' ? 'links.uribl_listed' : 'blacklist.spamhaus_dbl_sender';
  }
  if (z.endsWith('surbl.org')) return kind === 'link' ? 'links.uribl_listed' : 'blacklist.surbl';
  if (z.endsWith('uribl.com')) {
    if (z === 'multi.uribl.com' && !h.codes.some((c) => (Number(c.split('.')[3]) & 2) === 2)) return 'blacklist.uribl_grey_red';
    return kind === 'link' ? 'links.uribl_listed' : 'blacklist.uribl_black';
  }
  return kind === 'link' ? 'links.uribl_listed' : 'blacklist.domain_listed';
}

const WEIGHT_SEVERITY: Record<string, { severity: Severity; penalty: number }> = {
  major: { severity: 'high', penalty: 1.5 },
  minor: { severity: 'medium', penalty: 0.5 },
  info: { severity: 'low', penalty: 0.1 },
};

export async function runBlacklists(sc: StepContext, linkDomains: string[]) {
  const { facts, deps, c } = sc;
  if (deps.dnsbl === false) {
    c.missing(t('Listes noires'), t('Interrogation des listes désactivée'));
    return;
  }
  const ip = facts.ip && isPublicIp(facts.ip) ? facts.ip : undefined;
  if (!ip) c.missing(t('Listes noires (IP)'), facts.ip ? t("{ip} n'est pas une adresse publique", { ip: facts.ip }) : t("IP d'envoi inconnue"));
  const senderDomains = [...new Set([facts.fromDomain, facts.envelopeDomain].filter((d): d is string => !!d))];
  const senderOrgs = new Set(senderDomains.map((d) => orgDomain(d) ?? d));
  const links = [...new Set(linkDomains.map((d) => orgDomain(d) ?? d))].filter((d) => !senderOrgs.has(d)).slice(0, 20);
  const domains = [...new Set([...senderDomains, ...senderDomains.map((d) => orgDomain(d) ?? d), ...links])];
  const res = await checkDnsbl(deps.resolver, { ips: ip ? [ip] : [], domains }, { resolverFor: deps.dnsblResolver });
  const linkSet = new Set(links);
  const listed = res.results.filter((r) => r.status === 'listed');
  const refused = res.results.filter((r) => r.status === 'refused');
  const errors = res.results.filter((r) => r.status === 'error');
  sc.data.blacklists = {
    source: res.source,
    lists: res.lists,
    checked: res.results.length,
    listed,
    refused,
    errors: errors.map((e) => ({ zone: e.zone, target: e.target, error: e.error, reason: dnsReason(e.error) })),
    clean: res.results.filter((r) => r.status === 'clean').map((r) => ({ zone: r.zone, name: r.name, target: r.target, type: r.type })),
  };
  if (res.source === 'fallback') c.missing(t('Catalogue des listes'), t('research/dnsbl.json absent : listes de repli (Spamhaus, Barracuda, SpamCop, PSBL, Mailspike)'));
  for (const h of listed) {
    const isLink = h.type === 'domain' && linkSet.has(h.target) && !senderDomains.includes(h.target);
    const id = h.type === 'ip' ? ipListingId(h) : domainListingId(h, isLink ? 'link' : 'sender');
    const w = WEIGHT_SEVERITY[h.weight] ?? WEIGHT_SEVERITY.info;
    c.add(id, {
      vars: { list_name: h.name, delist_url: h.delistUrl, value: h.target, url: isLink ? h.target : undefined, domain: h.type === 'domain' && !isLink ? h.target : undefined },
      evidence: `${h.query} → ${h.codes.join(', ')}${h.meaning ? ` (${h.meaning})` : ''}${h.txt ? `\n${h.txt}` : ''}`,
      // the list weight decides the cost, whatever the base's default for this id
      severity: w.severity,
      penalty: w.penalty,
      fallback: {
        title: h.type === 'ip' ? t("L'IP {ip} est sur la liste {list_name}") : t('{value} est sur la liste {list_name}'),
        why: t('Les serveurs qui consultent cette liste refusent ou classent en spam les messages concernés.'),
        fix: h.delistUrl ? [t('Corrigez la cause (machine compromise, liste d’envoi achetée, formulaire abusé), puis demandez le retrait sur {delist_url}.')] : [t('Corrigez la cause, puis suivez la procédure de retrait de {list_name}.')],
        family: h.type === 'ip' || !isLink ? 'blacklist' : 'links',
        severity: w.severity,
        penalty: w.penalty,
      },
    });
  }
  for (const h of refused) {
    c.add('blacklist.query_blocked', {
      vars: { list_name: h.name, delist_url: h.delistUrl },
      evidence: `${h.query} → ${h.codes.join(', ')} (${h.meaning ?? t('requête refusée')})`,
      fallback: { title: t('La liste {list_name} a refusé de répondre'), family: 'blacklist', severity: 'info', penalty: 0 },
    });
  }
  if (errors.length)
    c.missing(
      t('Listes noires'),
      t('{count} sans réponse ({zones}) : ces listes ne sont pas comptées', {
        count: tPlural(errors.length, '{n} interrogation', '{n} interrogations'),
        zones: [...new Set(errors.map((e) => e.zone))].slice(0, 5).join(', '),
      }),
      errors.slice(0, 5).map((e) => `${e.zone} : ${e.error}`).join('\n'),
    );
  if (!listed.length) c.pass('blacklist.clean', 'blacklist', t('Absent des {n} listes interrogées', { n: new Set(res.results.filter((r) => r.status === 'clean').map((r) => r.zone)).size }), [ip, ...domains].filter(Boolean).join(', '));
}

/** Wording of a DNS lookup failure, in the current language. */
export function dnsReason(error: string | undefined): string {
  if (!error) return t('pas de réponse');
  if (/ETIMEOUT|timeout/i.test(error)) return t('pas de réponse dans le délai');
  if (/SERVFAIL/i.test(error)) return t('serveur DNS de la liste en erreur');
  if (/REFUSED/i.test(error)) return t('requête refusée par le serveur DNS de la liste');
  return t('erreur DNS');
}

function saPoints(score: number): string {
  return tPlural(score, '{n} point', '{n} points');
}

/**
 * Our points for a SpamAssassin score: half of it, at most 3, as research/scripts/sa_build.py gives
 * every rule that has its own entry. Until 2026-11-13 a rule without an entry cost its full score:
 * the same 1-point rule then cost 1 or 0.5 depending on whether it had been written up.
 */
export function saPenalty(score: number): number {
  return Math.max(0, Math.min(3, Math.round(score * 5) / 10));
}

function saSeverity(score: number): Severity {
  if (score >= 2.5) return 'high';
  if (score >= 1) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export async function runSpamassassin(sc: StepContext) {
  const { deps, facts, c } = sc;
  if (!deps.spamd) {
    c.missing('SpamAssassin', t('Non configuré pour cette analyse'));
    sc.data.spamassassin = { available: false };
    return;
  }
  let r: SpamdResult;
  try {
    r = await spamdReport(facts.input.raw, deps.spamd);
  } catch (e) {
    c.missing('SpamAssassin', t('spamd injoignable : la note est calculée sans SpamAssassin'), (e as Error).message);
    sc.data.spamassassin = { available: false, error: (e as Error).message };
    return;
  }
  sc.data.spamassassin = { available: true, score: r.score, threshold: r.threshold, isSpam: r.isSpam, rules: r.rules, ms: r.ms };
  // Rules explained by one entry share one cause (four HREF_EMPTY_* rules for one empty link): one
  // finding, which costs what its rules cost together (2026-11-13: a WooCommerce order email listed the
  // same empty link three times, as three raw rule names).
  const together = new Map<string, number>();
  for (const rule of r.rules) {
    const s = rule.score >= T.minSaScore ? situationForSaRule(rule.name) : undefined;
    if (s && (s.sa_rules?.length ?? 0) > 1) together.set(s.id, (together.get(s.id) ?? 0) + saPenalty(rule.score));
  }
  for (const rule of r.rules) {
    if (rule.score < 0) {
      c.pass(`sa.${rule.name.toLowerCase()}`, 'spamassassin', `${rule.name} (${rule.score})`, rule.description, 'spamassassin');
      continue;
    }
    if (rule.score < T.minSaScore) continue;
    // DKIM_SIGNED (+0.1) only marks a signature; DKIM_VALID (-0.1) cancels it when it verifies
    if (rule.name === 'DKIM_SIGNED' && r.rules.some((x) => x.name === 'DKIM_VALID')) continue;
    const s = situationForSaRule(rule.name);
    const id = s?.id ?? `sa.${rule.name.toLowerCase()}`;
    c.add(id, {
      vars: { rule: rule.name, rule_score: rule.score },
      evidence: `SpamAssassin ${rule.name} (${saPoints(rule.score)}) : ${rule.description}`,
      // a rule without its own entry costs half its SpamAssassin score, like the ones with an entry
      penalty: s ? (together.has(s.id) ? Math.min(3, Math.round(together.get(s.id)! * 10) / 10) : undefined) : saPenalty(rule.score),
      severity: s ? undefined : saSeverity(rule.score),
      section: s ? undefined : 'spamassassin',
      fallback: {
        title: t('Règle SpamAssassin {rule} ({points})', { rule: rule.name, points: saPoints(rule.score) }),
        why: rule.description,
        fix: [],
        family: 'spamassassin',
        severity: saSeverity(rule.score),
        penalty: saPenalty(rule.score),
      },
    });
  }
  if (r.score < r.threshold) c.pass('spamassassin.score', 'spamassassin', t('Score SpamAssassin {score} (seuil {threshold})', { score: r.score, threshold: r.threshold }), undefined, 'spamassassin');
}
