// A domain on the domain lists (US-067): Spamhaus DBL, SURBL, URIBL and the other live domain
// zones of research/dnsbl.json, for the name typed and its registrable domain.
import { t, tPlural } from '../../i18n.js';
import type { DnsblHit, DnsblResolver } from '../../mail/dnsbl.js';
import { issue, orgDomain, pass, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import { domainListingSituation, queryLists, selectLists, type ListSelection } from '../../lib/reputation/dnsbl-lists.js';
import type { PassedCheck } from '../types.js';

export interface DomainListsReport {
  domain: string;
  queried: string[];
  lists: { zone: string; name: string; weight: string }[];
  listed: DnsblHit[];
  refused: DnsblHit[];
  errors: { zone: string; target: string; error?: string }[];
  clean: { zone: string; name: string; target: string }[];
  skipped: { zone: string; name: string; reason: string }[];
}


export async function analyzeDomainLists(domain: string, resolverFor: () => DnsblResolver, opts: { lists?: ListSelection; onHit?: (h: DnsblHit) => void } = {}): Promise<Analysis & { data: DomainListsReport }> {
  const sel = opts.lists ?? selectLists('domain', 'all');
  const queried = [...new Set([domain, orgDomain(domain)])];
  const hits = (await Promise.all(queried.map((d) => queryLists(resolverFor, { domain: d }, sel.lists, { onHit: opts.onHit })))).flat();
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const listed = hits.filter((h) => h.status === 'listed');
  const refused = hits.filter((h) => h.status === 'refused');
  const errors = hits.filter((h) => h.status === 'error');
  for (const h of listed) {
    // link.domain_listed: written for a domain checked alone (the blacklist.* entries talk
    // about a domain cited in a message). Gravity from the list and the code.
    const s = domainListingSituation(h);
    const base = h.weight === 'minor' ? { severity: 'medium' as const, penalty: 0.5 } : h.weight === 'info' ? { severity: 'info' as const, penalty: 0 } : { severity: 'high' as const, penalty: 1.5 };
    // phishing or malware code: critical; URIBL grey or red only: low; otherwise by list weight
    const grade = s.severity === 'critical' || s.severity === 'low' ? { severity: s.severity, penalty: s.penalty ?? base.penalty } : base;
    issues.push(
      issue(s.id, { domain: h.target, value: h.target, list_name: h.name, delist_url: h.delistUrl }, {
        ...grade,
        evidence: `${h.query} → ${h.codes.join(', ')}${h.meaning ? ` (${h.meaning})` : ''}${h.txt ? `\n${h.txt}` : ''}`,
      }),
    );
  }
  for (const h of refused)
    issues.push(issue('blacklist.query_blocked', { domain: h.target, list_name: h.name, delist_url: h.delistUrl }, { evidence: `${h.query} → ${h.codes.join(', ')} (${h.meaning ?? t('requête refusée')})` }));
  const clean = hits.filter((h) => h.status === 'clean');
  if (!listed.length && clean.length) passed.push(pass('blacklist.domain_clean', 'blacklist', (queried.length > 1 ? t('{a} et {b} absents des {n} listes de domaines', { a: queried[0], b: queried[1], n: new Set(clean.map((h) => h.zone)).size }) : t('{a} absent des {n} listes de domaines', { a: queried[0], n: new Set(clean.map((h) => h.zone)).size })), [...new Set(clean.map((h) => h.name))].join(', ')));
  const unavailable = errors.length ? [{ source: 'dnsbl', reason: tPlural(errors.length, '{n} liste sans réponse ({names})', '{n} listes sans réponse ({names})', { names: [...new Set(errors.map((h) => h.name))].join(', ') }) }] : [];
  return {
    issues,
    passed,
    unavailable,
    data: {
      domain,
      queried,
      lists: sel.lists.map((l) => ({ zone: l.zone, name: l.name, weight: l.weight })),
      listed,
      refused,
      errors: errors.map((h) => ({ zone: h.zone, target: h.target, error: h.error })),
      clean: clean.map((h) => ({ zone: h.zone, name: h.name, target: h.target })),
      skipped: sel.skipped,
    },
  };
}
