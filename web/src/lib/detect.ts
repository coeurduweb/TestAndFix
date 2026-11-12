// Universal input: guess what was pasted and rank the tools that can take it.
// Pure function, unit tested. No network.
import { t } from './i18n';

export type InputKind =
  | 'empty'
  | 'email'
  | 'ip'
  | 'ip-list'
  | 'domain-list'
  | 'cidr'
  | 'url'
  | 'domain'
  | 'dkim-name'
  | 'dmarc-name'
  | 'dns-query'
  | 'headers'
  | 'eml'
  | 'dmarc-xml'
  | 'spf-record'
  | 'dmarc-record'
  | 'dkim-record'
  | 'bimi-record'
  | 'text';

export interface Action {
  tool: string;
  /** Route to open, input already encoded. */
  path: string;
  label: string;
  /** What will be checked, shown under the label. */
  hint?: string;
  score: number;
}

export interface Detection {
  kind: InputKind;
  value: string;
  /** Normalised domain when one applies. */
  domain?: string;
  actions: Action[];
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^(([0-9a-f]{1,4}:){1,7}:?([0-9a-f]{1,4}:?){0,7}|::1?)$/i;
const DOMAIN = /^(?=.{1,253}$)((?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$/i;
const EMAIL = /^[^\s@<>"]+@([^\s@<>"]+)$/;
const RR_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY', 'TLSA', 'HTTPS', 'SVCB', 'NAPTR'];

export const isIp = (s: string) => IPV4.test(s) || (s.includes(':') && IPV6.test(s));

/** Tolerant domain extraction: strips scheme, path, port, trailing dot, "www." kept. */
export function toDomain(raw: string): string | undefined {
  let s = raw.trim().toLowerCase();
  if (!s) return undefined;
  s = s.replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  try {
    // IDN to ASCII via the URL parser
    s = new URL(`http://${s}`).hostname;
  } catch {
    return undefined;
  }
  return DOMAIN.test(s) ? s : undefined;
}

const enc = encodeURIComponent;

function domainActions(d: string, base = 1): Action[] {
  return [
    { tool: 'domain', path: `/domaine/${enc(d)}`, label: t('Scanner le domaine'), hint: t('MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DNSSEC, listes noires'), score: base },
    { tool: 'spf', path: `/spf/${enc(d)}`, label: t('Vérifier le SPF'), score: base - 0.1 },
    { tool: 'dmarc', path: `/dmarc/${enc(d)}`, label: t('Vérifier le DMARC'), score: base - 0.11 },
    { tool: 'dkim', path: `/dkim/${enc(d)}`, label: t('Trouver les clés DKIM'), score: base - 0.12 },
    { tool: 'propagation', path: `/propagation/${enc(d)}`, label: t('Suivre la propagation'), score: base - 0.13 },
    { tool: 'dns', path: `/dns/${enc(d)}`, label: t('Recherche DNS'), score: base - 0.14 },
    { tool: 'bimi', path: `/bimi/${enc(d)}`, label: t('Vérifier le BIMI'), score: base - 0.15 },
    { tool: 'mta-sts', path: `/mta-sts/${enc(d)}`, label: t('Vérifier MTA-STS et TLS-RPT'), score: base - 0.16 },
    { tool: 'rdap', path: `/whois/${enc(d)}`, label: t('Whois : registre et bureau d’enregistrement'), hint: t('Dates, statuts, contacts, écarts entre les deux'), score: base - 0.19 },
    { tool: 'ip', path: `/ip/${enc(d)}`, label: t('Réputation du domaine'), hint: t('Listes noires du domaine, de ses IP web et de ses MX'), score: base - 0.11 },
    { tool: 'subdomains', path: `/sous-domaines/${enc(d)}`, label: t('Trouver les sous-domaines'), hint: t('Certificats publiés (Certificate Transparency)'), score: base - 0.18 },
    { tool: 'smtp', path: `/smtp/${enc(d)}`, label: t('Tester les serveurs SMTP'), score: base - 0.21 },
    { tool: 'redirects', path: `/redirections?url=${enc(d)}`, label: t('Suivre les redirections du site'), hint: t('http, https, www et sans www comparés'), score: base - 0.17 },
  ];
}

export function detect(raw: string): Detection {
  const value = raw.replace(/\r\n/g, '\n');
  const txt = value.trim();
  if (!txt) return { kind: 'empty', value: txt, actions: [] };
  const lines = txt.split('\n');

  // Multi-line content first: headers, raw message, DMARC XML, IP lists
  if (/<feedback[\s>]/i.test(txt) && /<record[\s>]/i.test(txt)) {
    return { kind: 'dmarc-xml', value: txt, actions: [{ tool: 'dmarc-reports', path: '/rapports-dmarc', label: t('Analyser ce rapport DMARC'), score: 1 }] };
  }
  if (lines.length > 2) {
    const headerLines = lines.filter((l) => /^[A-Za-z][A-Za-z0-9-]{1,60}:\s/.test(l));
    const hasMailHeaders = headerLines.some((l) => /^(received|from|to|subject|message-id|dkim-signature|return-path|authentication-results|date):/i.test(l));
    if (hasMailHeaders && headerLines.length >= 2) {
      const hasBody = /\n\n[\s\S]*\S/.test(txt);
      return {
        kind: hasBody ? 'eml' : 'headers',
        value: txt,
        actions: [{ tool: 'mail', path: '/mail/analyse', label: hasBody ? t('Analyser ce message') : t('Analyser ces en-têtes'), hint: t('Authentification, parcours, listes noires, SpamAssassin'), score: 1 }],
      };
    }
    const ips = lines.map((l) => l.trim()).filter(Boolean);
    if (ips.length > 1 && ips.every((l) => isIp(l) || /^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(l))) {
      return { kind: 'ip-list', value: ips.join('\n'), actions: [{ tool: 'ip', path: `/ip?liste=${enc(ips.join(','))}`, label: t('Réputation de {n} adresses', { n: ips.length }), score: 1 }] };
    }
  }

  // several domain names (lines, commas, semicolons or spaces): the Whois table
  const tokens = txt.split(/[\s,;]+/).filter(Boolean);
  if (tokens.length > 1 && tokens.every((tok) => !/[@/:=]/.test(tok) && !isIp(tok) && !!toDomain(tok))) {
    const names = [...new Set(tokens.map((tok) => toDomain(tok)!.replace(/^www\./, '')))];
    if (names.length > 1) {
      const shown = names.slice(0, 100);
      return {
        kind: 'domain-list',
        value: names.join('\n'),
        actions: [
          {
            tool: 'rdap',
            path: `/whois?liste=${shown.map(enc).join(',')}`,
            label: t('Whois de {n} domaines', { n: names.length }),
            hint: names.length > 100 ? t('Les 100 premiers, en tableau exportable') : t('Registre et bureau d’enregistrement, en tableau exportable'),
            score: 1,
          },
        ],
      };
    }
  }

  // DNS records pasted as text
  if (/^"?v=spf1\b/i.test(txt)) return { kind: 'spf-record', value: txt.replace(/^"|"$/g, ''), actions: [{ tool: 'spf', path: `/spf?enregistrement=${enc(txt.replace(/^"|"$/g, ''))}`, label: t('Analyser cet enregistrement SPF'), score: 1 }] };
  if (/^"?v=DMARC1\b/i.test(txt)) return { kind: 'dmarc-record', value: txt, actions: [{ tool: 'dmarc', path: `/dmarc?enregistrement=${enc(txt.replace(/^"|"$/g, ''))}`, label: t('Analyser cet enregistrement DMARC'), score: 1 }] };
  if (/^"?v=DKIM1\b/i.test(txt)) return { kind: 'dkim-record', value: txt, actions: [{ tool: 'dkim', path: `/dkim?enregistrement=${enc(txt.replace(/^"|"$/g, ''))}`, label: t('Analyser cette clé DKIM'), score: 1 }] };
  if (/^"?v=BIMI1\b/i.test(txt)) return { kind: 'bimi-record', value: txt, actions: [{ tool: 'bimi', path: `/bimi?enregistrement=${enc(txt.replace(/^"|"$/g, ''))}`, label: t('Analyser cet enregistrement BIMI'), score: 1 }] };

  const one = txt.split(/\s+/);
  // "MX example.fr" or "example.fr MX"
  if (one.length === 2) {
    const [a, b] = one;
    const typeFirst = RR_TYPES.includes(a.toUpperCase()) ? a : RR_TYPES.includes(b.toUpperCase()) ? b : undefined;
    const name = typeFirst === a ? b : a;
    const d = typeFirst ? toDomain(name) ?? (isIp(name) ? name : undefined) : undefined;
    if (typeFirst && d) {
      const type = typeFirst.toUpperCase();
      return {
        kind: 'dns-query',
        value: txt,
        domain: d,
        actions: [
          { tool: 'dns', path: `/dns/${enc(d)}?type=${type}`, label: t('Recherche {type} de {d}', { type, d }), hint: t('Réponse des serveurs autoritaires'), score: 1 },
          { tool: 'propagation', path: `/propagation/${enc(d)}?type=${type}`, label: t('Propagation {type} de {d}', { type, d }), score: 0.95 },
        ],
      };
    }
  }

  if (one.length === 1) {
    const s = one[0];
    if (/^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(s)) {
      return { kind: 'cidr', value: s, actions: [{ tool: 'ip', path: `/ip/${enc(s)}`, label: t('Réputation de la plage {s}', { s }), score: 1 }] };
    }
    if (isIp(s)) {
      return {
        kind: 'ip',
        value: s,
        actions: [
          { tool: 'ip', path: `/ip/${enc(s)}`, label: t('Réputation de cette IP'), hint: t('Listes noires, AbuseIPDB, VirusTotal, ASN, reverse DNS'), score: 1 },
          { tool: 'dns', path: `/dns/${enc(s)}?type=PTR`, label: t('Reverse DNS (PTR)'), score: 0.8 },
        ],
      };
    }
    if (/^https?:\/\//i.test(s) || /^www\.[^\s]+\/.+/i.test(s)) {
      const d = toDomain(s);
      return {
        kind: 'url',
        value: s,
        domain: d,
        actions: [
          { tool: 'link', path: `/lien?url=${enc(s)}`, label: t('Vérifier ce lien'), hint: t('Phishing, logiciels malveillants, âge du domaine'), score: 1 },
          { tool: 'redirects', path: `/redirections?url=${enc(s)}`, label: t('Suivre les redirections'), hint: t('Statut, en-têtes et corps de chaque saut'), score: 0.95 },
          ...(d ? domainActions(d, 0.7).slice(0, 3) : []),
        ],
      };
    }
    const email = EMAIL.exec(s.replace(/^mailto:/i, ''));
    if (email) {
      const d = toDomain(email[1]);
      if (d) {
        return {
          kind: 'email',
          value: s,
          domain: d,
          actions: [
            { tool: 'domain', path: `/domaine/${enc(d)}`, label: t('Scanner {d}', { d }), hint: t("Tout ce qui fait arriver les mails de cette adresse"), score: 1 },
            ...domainActions(d, 0.9).slice(1),
          ],
        };
      }
    }
    const lower = s.toLowerCase().replace(/\.$/, '');
    const dk = /^([a-z0-9_.-]+)\._domainkey\.(.+)$/.exec(lower);
    if (dk && toDomain(dk[2])) {
      const d = toDomain(dk[2])!;
      return { kind: 'dkim-name', value: s, domain: d, actions: [{ tool: 'dkim', path: `/dkim/${enc(d)}?selecteur=${enc(dk[1])}`, label: t('Clé DKIM « {selector} » de {d}', { selector: dk[1], d }), score: 1 }] };
    }
    const dm = /^_dmarc\.(.+)$/.exec(lower);
    if (dm && toDomain(dm[1])) {
      const d = toDomain(dm[1])!;
      return { kind: 'dmarc-name', value: s, domain: d, actions: [{ tool: 'dmarc', path: `/dmarc/${enc(d)}`, label: t('DMARC de {d}', { d }), score: 1 }] };
    }
    const d = toDomain(s);
    if (d) return { kind: 'domain', value: s, domain: d, actions: domainActions(d) };
    // a bare word ("gmail"): offer the usual endings instead of a dead end
    if (/^[a-z0-9][a-z0-9-]{0,62}$/i.test(s) && !/^\d+$/.test(s)) {
      const w = s.toLowerCase();
      return {
        kind: 'text',
        value: s,
        actions: ['com', 'fr'].map((tld, i) => ({
          tool: 'domain', path: `/domaine/${w}.${tld}`, label: t('Scanner {name}', { name: `${w}.${tld}` }), hint: t('Domaine complété'), score: 0.6 - i * 0.05,
        })),
      };
    }
  }
  return { kind: 'text', value: txt, actions: [] };
}
