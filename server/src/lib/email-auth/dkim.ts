// DKIM public keys (RFC 6376 §3.6.1, RFC 8301, RFC 8463): selector discovery over a list of
// common selectors, key parsing with node:crypto (real modulus length), flags and revocation.
import type { PassedCheck } from '../../tools/types.js';
import { createPublicKey, randomBytes } from 'node:crypto';
import { issue, lookupTxt, lookupType, mapLimit, norm, orgDomain, parseTags, pass, type Analysis, type Issue, type Resolver } from './common.js';
import { COMMON_SELECTORS, type KnownSelector } from './selectors.js';
import { t, tPlural } from '../../i18n.js';

export interface DkimKey {
  selector: string;
  name: string;
  /** Provider the selector is known for, from selectors.ts. */
  knownFor?: string[];
  record: string;
  /** CNAME chain followed to reach the key (delegated to an ESP). */
  cnames: string[];
  /** ESP recognized from the CNAME target. */
  cnameProvider?: string;
  version?: string;
  keyType: string;
  /** Real key size in bits (RSA modulus), 256 for Ed25519. */
  bits?: number;
  hashAlgorithms?: string[];
  serviceTypes?: string[];
  flags: string[];
  testing: boolean;
  strictSubdomains: boolean;
  revoked: boolean;
  notes?: string;
  error?: string;
  ttl?: number;
  /** true when the domain answers any selector (wildcard): the key may not be a real one. */
  wildcard?: boolean;
}

export interface DkimData {
  domain: string;
  /** Selectors actually queried. */
  tried: number;
  selectorsTried: string[];
  keys: DkimKey[];
  /** Selectors that answered something that is not a DKIM key. */
  other: { selector: string; record: string }[];
  /** Lookups that failed (timeout, SERVFAIL). */
  errors: { selector: string; error: string }[];
  wildcard: boolean;
  /** Selectors such as Amazon SES Easy DKIM tokens cannot be guessed. */
  limits: string[];
}

export interface DkimAnalysis extends Analysis {
  data: DkimData;
}

const CNAME_PROVIDERS: [RegExp, string][] = [
  [/\.onmicrosoft\.com$|\.dkim\.mail\.microsoft$/, 'microsoft_365'],
  [/(^|\.)dkim\.mcsv\.net$/, 'mailchimp'],
  [/(^|\.)mandrillapp\.com$/, 'mailchimp'],
  [/(^|\.)sendgrid\.net$/, 'sendgrid'],
  [/(^|\.)mailgun\.org$/, 'mailgun'],
  [/(^|\.)dkim\.amazonses\.com$/, 'amazon_ses'],
  [/(^|\.)protonmail\.ch$/, 'proton'],
  [/(^|\.)brevo\.com$|(^|\.)sendinblue\.com$/, 'brevo'],
  [/(^|\.)mailjet\.com$/, 'mailjet'],
  [/(^|\.)fmhosted\.com$/, 'fastmail'],
  [/(^|\.)mtasv\.net$/, 'postmark'],
  [/(^|\.)sparkpostmail\.com$/, 'sparkpost'],
  [/(^|\.)hubspotemail\.net$/, 'hubspot'],
  [/(^|\.)zendesk\.com$/, 'zendesk'],
  [/(^|\.)custdkim\.salesforce\.com$|(^|\.)exacttarget\.com$/, 'salesforce'],
  [/(^|\.)dkim\.mail\.ovh\.net$/, 'ovh'],
  [/(^|\.)dkim\.ionos\.com$/, 'ionos'],
  [/(^|\.)gandimail\.net$/, 'gandi'],
  [/(^|\.)mlsend\.com$/, 'mailerlite'],
  [/(^|\.)dkim\d?\.mailgun\.com$/, 'mailgun'],
  [/(^|\.)klaviyo\.com$/, 'klaviyo'],
];

export function cnameProvider(target: string): string | undefined {
  for (const [re, key] of CNAME_PROVIDERS) if (re.test(target)) return key;
  return undefined;
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Real size of a DKIM public key (p= value). Throws when the key cannot be parsed. */
export function keyBits(p: string, keyType: string): number {
  const der = Buffer.from(p.replace(/\s+/g, ''), 'base64');
  if (!der.length) throw new Error(t('clé vide'));
  if (keyType === 'ed25519') {
    if (der.length !== 32) throw new Error(t('clé Ed25519 de {n} octets au lieu de 32', { n: der.length }));
    createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, der]), format: 'der', type: 'spki' });
    return 256;
  }
  let key;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    // some panels publish a bare PKCS#1 RSAPublicKey
    key = createPublicKey({ key: der, format: 'der', type: 'pkcs1' });
  }
  if (key.asymmetricKeyType !== 'rsa') throw new Error(t('type de clé {type} annoncé comme rsa', { type: key.asymmetricKeyType }));
  return key.asymmetricKeyDetails?.modulusLength ?? 0;
}

export function isDkimRecord(txt: string): boolean {
  return /^\s*v\s*=\s*DKIM1\b/i.test(txt) || /(^|;)\s*p\s*=/i.test(txt);
}

export function parseDkimKey(selector: string, domain: string, record: string): DkimKey {
  const { tags, errors } = parseTags(record);
  const get = (n: string) => tags.find((t) => t.name === n)?.value;
  const key: DkimKey = {
    selector,
    name: `${selector}._domainkey.${domain}`,
    record,
    cnames: [],
    version: get('v'),
    keyType: (get('k') ?? 'rsa').toLowerCase(),
    flags: (get('t') ?? '').split(':').map((s) => s.trim().toLowerCase()).filter(Boolean),
    testing: false,
    strictSubdomains: false,
    revoked: false,
    notes: get('n'),
  };
  key.testing = key.flags.includes('y');
  key.strictSubdomains = key.flags.includes('s');
  const h = get('h');
  if (h !== undefined) key.hashAlgorithms = h.split(':').map((s) => s.trim().toLowerCase()).filter(Boolean);
  const s = get('s');
  if (s !== undefined) key.serviceTypes = s.split(':').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const errs: string[] = [];
  if (errors.length) errs.push(t('balise illisible : {value}', { value: errors.join(', ') }));
  if (key.version !== undefined && (key.version !== 'DKIM1' || tags[0]?.name !== 'v')) errs.push(t('v=DKIM1 doit être la première balise'));
  const p = get('p');
  if (p === undefined) errs.push(t('balise p= absente'));
  else if (p.trim() === '') key.revoked = true;
  else if (!['rsa', 'ed25519'].includes(key.keyType)) errs.push(t('type de clé k={type} inconnu', { type: key.keyType }));
  else {
    try {
      key.bits = keyBits(p, key.keyType);
    } catch (e) {
      errs.push(t('clé publique illisible : {error}', { error: (e as Error).message }));
    }
  }
  if (errs.length) key.error = errs.join(' ; ');
  return key;
}

export interface DkimOptions {
  /** Selectors to check in addition to (or instead of, with only=true) the common list. */
  selectors?: string[];
  only?: boolean;
  concurrency?: number;
}

const SELECTOR_RE = /^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_][a-z0-9_-]{0,62})*$/i;

export function validSelector(s: string): boolean {
  return SELECTOR_RE.test(s);
}

export async function analyzeDkim(dns: Resolver, domain: string, opts: DkimOptions = {}): Promise<DkimAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const userSel = (opts.selectors ?? []).map((s) => s.trim().toLowerCase().replace(/\._domainkey.*$/, '')).filter(validSelector);
  const list: KnownSelector[] = [];
  const index = new Map<string, KnownSelector>();
  const add = (k: KnownSelector) => {
    const prev = index.get(k.selector);
    if (prev) {
      for (const p of k.providers) if (!prev.providers.includes(p)) prev.providers.push(p);
      return;
    }
    const copy = { ...k, providers: [...k.providers] };
    index.set(k.selector, copy);
    list.push(copy);
  };
  for (const s of userSel) add({ selector: s, providers: [], source: 'saisie' });
  if (!opts.only || !userSel.length) for (const k of COMMON_SELECTORS) add(k);

  const probe = `check-${randomBytes(5).toString('hex')}`;
  const [wild, ...results] = await Promise.all([
    lookupTxt(dns, `${probe}._domainkey.${domain}`),
    mapLimit(list, opts.concurrency ?? 20, async (k) => ({ k, txt: await lookupTxt(dns, `${k.selector}._domainkey.${domain}`) })),
  ]).then(([w, r]) => [w, ...r] as const);
  const wildcard = (wild as Awaited<ReturnType<typeof lookupTxt>>).records.some(isDkimRecord);

  const keys: DkimKey[] = [];
  const dangling: { selector: string; target: string; chain: string[] }[] = [];
  const other: DkimData['other'] = [];
  const errors: DkimData['errors'] = [];
  for (const { k, txt } of results as { k: KnownSelector; txt: Awaited<ReturnType<typeof lookupTxt>> }[]) {
    if (txt.error) {
      errors.push({ selector: k.selector, error: txt.error });
      continue;
    }
    const dk = txt.records.filter(isDkimRecord);
    if (txt.cnames.length && txt.rcode === 'NXDOMAIN') {
      dangling.push({ selector: k.selector, target: txt.cnames.at(-1)!, chain: txt.cnames });
      continue;
    }
    if (!dk.length) {
      if (txt.records.length) other.push({ selector: k.selector, record: txt.records.join(' | ') });
      continue;
    }
    if (dk.length > 1) issues.push(issue('dkim.multiple_key_records', { domain, dkim_domain: domain, selector: k.selector, value: dk.length }, { evidence: dk.join('\n') }));
    const key = parseDkimKey(k.selector, domain, dk[0]);
    key.cnames = txt.cnames;
    key.ttl = txt.ttl;
    // A CNAME names the real provider: it wins over the guess from the selector list
    // (s1/s2 are SendGrid's defaults, but cnn.com points them to Salesforce).
    if (txt.cnames.length) {
      key.cnameProvider = cnameProvider(txt.cnames.at(-1)!);
      key.knownFor = key.cnameProvider ? [key.cnameProvider] : undefined;
    } else key.knownFor = k.providers.length ? k.providers : undefined;
    if (wildcard) key.wildcard = true;
    keys.push(key);
  }

  for (const key of keys) {
    const v = { domain, dkim_domain: domain, selector: key.selector, value: key.bits };
    const ev = `${key.name} : ${key.record.length > 160 ? key.record.slice(0, 160) + '…' : key.record}`;
    if (key.error) {
      issues.push(issue('dkim.key_syntax_error', { ...v, value: key.error }, { evidence: ev }));
      continue;
    }
    if (key.revoked) {
      // A revoked key is the normal leftover of a rotation (gmail.com keeps four of them):
      // no penalty when a valid key exists; otherwise the base penalty, counted once only.
      const valid = keys.some((k) => !k.revoked && !k.error);
      const first = keys.find((k) => k.revoked) === key;
      issues.push(issue('dkim.key_revoked', v, { evidence: ev, ...(valid || !first ? { severity: 'info' as const, penalty: 0 } : {}) }));
      continue;
    }
    if (key.keyType === 'rsa' && key.bits !== undefined) {
      if (key.bits < 1024) issues.push(issue('dkim.key_below_1024', v, { evidence: ev }));
      else if (key.bits < 2048) issues.push(issue('dkim.key_1024', v, { evidence: ev }));
      else passed.push(pass(`dkim.key_size.${key.selector}`, 'dkim', t('Clé {selector} : RSA {bits} bits', { selector: key.selector, bits: key.bits })));
    } else if (key.keyType === 'ed25519') {
      passed.push(pass(`dkim.key_size.${key.selector}`, 'dkim', t('Clé {selector} : Ed25519', { selector: key.selector })));
      if (keys.every((k) => k.keyType === 'ed25519' && !k.revoked)) issues.push(issue('dkim.ed25519_only', v, { evidence: ev }));
    }
    if (key.testing) issues.push(issue('dkim.key_testing_flag', v, { evidence: ev }));
    if (key.hashAlgorithms && !key.hashAlgorithms.includes('sha256')) issues.push(issue('dkim.key_algorithm_mismatch', { ...v, value: key.hashAlgorithms.join(':') }, { evidence: ev }));
    if (key.serviceTypes && !key.serviceTypes.includes('*') && !key.serviceTypes.includes('email'))
      issues.push(issue('dkim.key_service_type', { ...v, value: key.serviceTypes.join(':') }, { evidence: ev }));
  }

  if (dangling.length) {
    const host = await dnsHostOf(dns, domain);
    for (const d of dangling) issues.push(danglingIssue(domain, d, keys, host));
  }

  const active = keys.filter((k) => !k.revoked && !k.error);
  if (active.length) passed.push(pass('dkim.found', 'dkim', tPlural(active.length, '{n} clé DKIM publiée', '{n} clés DKIM publiées'), active.map((k) => k.selector).join(', ')));
  if (!keys.length) {
    if (userSel.length) issues.push(issue('dkim.key_not_found', { domain, dkim_domain: domain, selector: userSel.join(', ') }));
    else issues.push(issue('dkim.selector_not_discovered', { domain, dkim_domain: domain, value: list.length }));
  } else if (userSel.length) {
    const missing = userSel.filter((s) => !keys.some((k) => k.selector === s));
    if (missing.length) issues.push(issue('dkim.key_not_found', { domain, dkim_domain: domain, selector: missing.join(', ') }));
  }
  if (wildcard && keys.length) issues.push(issue('dkim.wildcard', { domain, dkim_domain: domain }, { evidence: t('{name} répond aussi', { name: `${probe}._domainkey.${domain}` }) }));

  const unavailable = errors.length
    ? [{ source: 'dns', reason: tPlural(errors.length, '{n} sélecteur sans réponse DNS : {list}', '{n} sélecteurs sans réponse DNS : {list}', { list: errors.map((e) => e.selector).join(', ') }) }]
    : undefined;
  return {
    issues,
    passed,
    unavailable,
    data: {
      domain,
      tried: list.length,
      selectorsTried: list.map((k) => k.selector),
      keys,
      other,
      errors,
      wildcard,
      limits: [
        t('Un sélecteur absent de la liste ne peut pas être deviné : saisissez-le (il figure dans l’en-tête DKIM-Signature, balise s=, d’un message envoyé).'),
        t('Amazon SES (Easy DKIM) publie trois sélecteurs uniques à chaque identité : ils ne peuvent pas être découverts.'),
        t('OVHcloud (ovhmo<numéro>-selector1, ovhex…, ovhemp…), Zoho, Postmark (sélecteurs horodatés) et les sélecteurs personnalisés de SendGrid ne sont pas devinables.'),
      ],
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Dangling CNAME: steps chosen from the provider named by the target and the DNS host named by
// the NS records (review of 2026-11-10: cnn.com, zone at Route 53, target at Microsoft 365, was
// told to switch a Cloudflare proxy off and pointed at the Amazon SES documentation).

export const PROVIDER_LABEL: Record<string, string> = {
  microsoft_365: 'Microsoft 365', mailchimp: 'Mailchimp', sendgrid: 'SendGrid', mailgun: 'Mailgun', amazon_ses: 'Amazon SES',
  proton: 'Proton Mail', brevo: 'Brevo', mailjet: 'Mailjet', fastmail: 'Fastmail', postmark: 'Postmark', sparkpost: 'SparkPost',
  hubspot: 'HubSpot', zendesk: 'Zendesk', klaviyo: 'Klaviyo', ovh: 'OVHcloud', ionos: 'IONOS', gandi: 'Gandi',
  mailerlite: 'MailerLite', salesforce: 'Salesforce',
};

const DNS_HOSTS: [RegExp, string, string][] = [
  [/\.awsdns-\d+\./, 'aws_route53', 'Amazon Route 53'],
  [/\.ns\.cloudflare\.com$/, 'cloudflare_dns', 'Cloudflare'],
  [/\.ovh\.(net|ca)$|\.anycast\.me$/, 'ovh', 'OVHcloud'],
  [/\.gandi\.net$/, 'gandi', 'Gandi'],
  [/\.o2switch\.net$/, 'o2switch', 'o2switch'],
  [/\.ui-dns\.(com|org|de|biz)$/, 'ionos', 'IONOS'],
  [/\.domaincontrol\.com$/, 'godaddy', 'GoDaddy'],
  [/\.azure-dns\.(com|net|org|info)$/, 'azure_dns', 'Azure DNS'],
  [/\.googledomains\.com$/, 'google_cloud_dns', 'Google Cloud DNS'],
  [/\.nsone\.net$/, 'ns1', 'NS1'],
  [/\.registrar-servers\.com$/, 'namecheap', 'Namecheap'],
  [/\.infomaniak\.ch$/, 'infomaniak', 'Infomaniak'],
  [/\.dns-parking\.com$/, 'hostinger', 'Hostinger'],
  [/\.akam\.net$/, 'akamai', 'Akamai'],
  [/\.ultradns\.(com|net|org|biz|info|co\.uk)$/, 'ultradns', 'UltraDNS'],
];

export interface DnsHost {
  key?: string;
  label?: string;
  ns: string[];
}

export async function dnsHostOf(dns: Resolver, domain: string): Promise<DnsHost> {
  const r = await lookupType(dns, orgDomain(domain), 'NS');
  return dnsHostFromNs(r.data.map((x) => norm(String(x))));
}

/**
 * The DNS host(s) named by the NS records, each with its own name servers. A zone served by two
 * hosts names both (2026-11-12: github.com, on NS1 and Route 53, was described as "Amazon Route 53
 * (identified by its nameservers dns1.p08.nsone.net…)", the NS1 servers). `key` is the first host
 * found, for the provider-specific steps.
 */
export function dnsHostFromNs(ns: string[]): DnsHost {
  const found = DNS_HOSTS.map(([re, key, label]) => ({ key, label, ns: ns.filter((n) => re.test(n)) })).filter((h) => h.ns.length);
  if (!found.length) return { ns };
  const label = found.length === 1 ? found[0].label : t('{a} et {b}', { a: found.slice(0, -1).map((h) => h.label).join(', '), b: found[found.length - 1].label });
  // one or two servers of each host, so that each name is backed by its own servers
  const shown = found.flatMap((h) => h.ns.slice(0, found.length > 1 ? 1 : 2));
  return { key: found[0].key, label, ns: shown };
}

const MS_DOC = 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure';

function danglingIssue(domain: string, d: { selector: string; target: string; chain: string[] }, keys: DkimKey[], host: DnsHost): Issue {
  // Texts live in knowledge/situations/dkim.yaml (dkim.selector_cname_dangling and
  // dkim.standby_selector_dangling). The code only picks the provider steps that were detected
  // (ESP from the CNAME target, DNS host from the NS) and passes the context severity.
  const provider = cnameProvider(d.target);
  const label = provider ? PROVIDER_LABEL[provider] ?? provider : undefined;
  const twin = provider ? keys.find((k) => k.cnameProvider === provider && !k.revoked && !k.error) : undefined;
  const refs = ['https://www.rfc-editor.org/rfc/rfc6376#section-6.1.2'];
  if (provider === 'microsoft_365') refs.push(MS_DOC);
  if (host.key === 'cloudflare_dns') refs.push('https://developers.cloudflare.com/dns/proxy-status/');
  const vars = {
    domain,
    dkim_domain: domain,
    selector: d.selector,
    value: d.target,
    provider: label ?? t('le service d’envoi qui a demandé ce CNAME'),
    dns_host: host.label ? t('{host} (reconnu à ses serveurs de noms {ns})', { host: host.label, ns: host.ns.slice(0, 2).join(', ') }) : t('votre hébergeur DNS'),
    twin: twin?.selector,
  };
  const evidence = `${d.selector}._domainkey.${domain} → ${d.chain.join(' → ')} : NXDOMAIN${twin ? `\n${t('{name} → {target} : clé valide ({bits} bits)', { name: `${twin.selector}._domainkey.${domain}`, target: twin.cnames.at(-1), bits: twin.bits })}` : ''}`;
  return issue(twin ? 'dkim.standby_selector_dangling' : 'dkim.selector_cname_dangling', vars, {
    evidence,
    provider,
    alsoProviders: host.key === 'cloudflare_dns' ? ['cloudflare_dns'] : undefined,
    references: refs,
    ...(twin ? { severity: 'medium' as const, penalty: 0.5 } : { severity: 'high' as const, penalty: 1.5 }),
  });
}
