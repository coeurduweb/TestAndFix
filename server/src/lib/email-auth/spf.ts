// SPF (RFC 7208): full tree expansion with lookup accounting, every syntax and policy defect,
// flattened authorized networks, a corrected record, and a real check_host() evaluation of one IP.
import type { PassedCheck } from '../../tools/types.js';
import ipaddr from 'ipaddr.js';
import net from 'node:net';
import {
  issue,
  lookupAddresses,
  lookupMx,
  lookupTxt,
  lookupType,
  norm,
  pass,
  splitTxt,
  txtStrings,
  type Analysis,
  type Issue,
  type Resolver,
} from './common.js';
import { t, tPlural } from '../../i18n.js';

export const SPF_LOOKUP_LIMIT = 10; // RFC 7208 §4.6.4
export const SPF_VOID_LIMIT = 2; // RFC 7208 §4.6.4
export const SPF_MX_LIMIT = 10; // RFC 7208 §4.6.4
export const SPF_PTR_LIMIT = 10; // RFC 7208 §4.6.4

const MECHANISMS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'] as const;
type MechName = (typeof MECHANISMS)[number];
type Qualifier = '+' | '-' | '~' | '?';
const DNS_MECHS = new Set<string>(['include', 'a', 'mx', 'ptr', 'exists']);

export interface SpfTerm {
  raw: string;
  kind: 'mechanism' | 'modifier' | 'invalid';
  qualifier?: Qualifier;
  name: string;
  /** domain-spec, ip network or modifier value */
  value?: string;
  cidr4?: number;
  cidr6?: number;
  error?: string;
  /** Language independent class of `error`, for the checks that must not read the text. */
  errorKind?: 'unknown_mechanism' | 'dns' | 'mx_limit';
}

const QUAL_RESULT: Record<Qualifier, SpfResult> = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

export type SpfResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'permerror' | 'temperror';

// ---------------------------------------------------------------------------------------------
// Parsing

const TOPLABEL = /^([a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])$/i;
const MACRO_EXPAND = /%(\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}|%|_|-)/gi;

/** RFC 7208 §8.1 domain-spec: macro-string domain-end. Returns an error message or undefined. */
export function checkDomainSpec(spec: string): string | undefined {
  if (!spec) return t('domaine vide');
  if (!/^[\x21-\x7e]+$/.test(spec)) return t('caractère non autorisé');
  const stripped = spec.replace(MACRO_EXPAND, '');
  if (stripped.includes('%')) return t('macro mal formée');
  if (spec !== stripped && /%\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}\.?$/i.test(spec)) return undefined; // ends with a macro
  const s = spec.replace(/\.$/, '');
  const labels = s.split('.');
  if (labels.length < 2) return t('un nom de domaine complet est attendu (avec au moins un point)');
  const top = labels[labels.length - 1];
  if (!TOPLABEL.test(top)) return net.isIPv4(s) ? t('une adresse IP est écrite là où un nom de domaine est attendu') : t('extension de domaine invalide');
  return undefined;
}

export function parseTerm(raw: string): SpfTerm {
  const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
  if (mod) {
    const name = mod[1].toLowerCase();
    const value = mod[2];
    const tm: SpfTerm = { raw, kind: 'modifier', name, value };
    if ((name === 'redirect' || name === 'exp') && checkDomainSpec(value)) tm.error = checkDomainSpec(value);
    return tm;
  }
  const m = /^([+\-~?]?)([a-z][a-z0-9_.-]*)(.*)$/i.exec(raw);
  if (!m) return { raw, kind: 'invalid', name: raw, error: t('terme illisible') };
  const qualifier = (m[1] || '+') as Qualifier;
  const name = m[2].toLowerCase();
  const rest = m[3];
  const tm: SpfTerm = { raw, kind: 'mechanism', qualifier, name };
  if (!(MECHANISMS as readonly string[]).includes(name)) {
    return { ...tm, kind: 'invalid', error: t('mécanisme inconnu'), errorKind: 'unknown_mechanism' };
  }
  const mech = name as MechName;
  if (mech === 'all') {
    if (rest) tm.error = t('all ne prend pas d’argument');
    return tm;
  }
  if (mech === 'include' || mech === 'exists') {
    if (!rest.startsWith(':')) {
      tm.error = t('{mech} exige un domaine ({mech}:exemple.com)', { mech });
      return tm;
    }
    tm.value = rest.slice(1);
    tm.error = checkDomainSpec(tm.value);
    return tm;
  }
  if (mech === 'ip4' || mech === 'ip6') {
    if (!rest.startsWith(':')) {
      tm.error = t('{mech} exige une adresse ({mech}:…)', { mech });
      return tm;
    }
    const [addr, cidr, extra] = rest.slice(1).split('/');
    tm.value = addr;
    const max = mech === 'ip4' ? 32 : 128;
    if (extra !== undefined) tm.error = t('préfixe mal formé');
    else if (mech === 'ip4' ? !net.isIPv4(addr) : !net.isIPv6(addr)) tm.error = t('adresse {version} invalide', { version: mech === 'ip4' ? 'IPv4' : 'IPv6' });
    else if (cidr !== undefined) {
      if (!/^(0|[1-9]\d{0,2})$/.test(cidr) || Number(cidr) > max) tm.error = t('préfixe /{cidr} invalide', { cidr });
      else if (mech === 'ip4') tm.cidr4 = Number(cidr);
      else tm.cidr6 = Number(cidr);
    }
    return tm;
  }
  // a, mx, ptr: [":" domain-spec] [dual-cidr-length] (ptr: no cidr)
  const dm = /^(?::([^/]*))?(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(rest);
  if (!dm) {
    tm.error = t('argument mal formé');
    return tm;
  }
  if (dm[1] !== undefined) {
    tm.value = dm[1];
    tm.error = checkDomainSpec(dm[1]);
  }
  if (dm[2] !== undefined) {
    if (mech === 'ptr' || Number(dm[2]) > 32) tm.error = t('préfixe /{cidr} invalide', { cidr: dm[2] });
    else tm.cidr4 = Number(dm[2]);
  }
  if (dm[3] !== undefined) {
    if (mech === 'ptr' || Number(dm[3]) > 128) tm.error = t('préfixe //{cidr} invalide', { cidr: dm[3] });
    else tm.cidr6 = Number(dm[3]);
  }
  return tm;
}

export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseRecord(record: string): { terms: SpfTerm[]; versionError?: string } {
  const parts = record.trim().split(/\s+/);
  const versionError = /^v=spf1$/i.test(parts[0] ?? '') ? undefined : t('le record doit commencer par v=spf1');
  return { terms: parts.slice(1).filter(Boolean).map(parseTerm), versionError };
}

// ---------------------------------------------------------------------------------------------
// Macros (RFC 7208 §7)

export interface MacroContext {
  ip?: string;
  sender?: string;
  domain: string;
  helo?: string;
}

export function hasMacro(spec: string): boolean {
  return /%\{/.test(spec);
}

/** Letters that can be expanded without knowing the connecting IP or the sender. */
function staticMacro(spec: string): boolean {
  return [...spec.matchAll(/%\{([a-z])/gi)].every((m) => 'd'.includes(m[1].toLowerCase()));
}

export function expandMacros(spec: string, mc: MacroContext, exp = false): string {
  const sender = mc.sender && mc.sender.includes('@') ? mc.sender : `postmaster@${mc.sender || mc.domain}`;
  const at = sender.lastIndexOf('@');
  const local = sender.slice(0, at) || 'postmaster';
  const sdomain = sender.slice(at + 1);
  const ipDotted = () => {
    if (!mc.ip) return '';
    if (net.isIPv4(mc.ip)) return mc.ip;
    const hex = ipaddr.parse(mc.ip).toNormalizedString().split(':').map((p) => p.padStart(4, '0')).join('');
    return hex.split('').join('.');
  };
  return spec.replace(MACRO_EXPAND, (whole, body: string) => {
    if (body === '%') return '%';
    if (body === '_') return ' ';
    if (body === '-') return '%20';
    const m = /^\{([a-z])(\d*)(r?)([.\-+,/_=]*)\}$/i.exec(body)!;
    const letter = m[1];
    const l = letter.toLowerCase();
    let v: string;
    switch (l) {
      case 's': v = sender; break;
      case 'l': v = local; break;
      case 'o': v = sdomain; break;
      case 'd': v = mc.domain; break;
      case 'i': v = ipDotted(); break;
      case 'p': v = 'unknown'; break;
      case 'v': v = mc.ip && net.isIPv6(mc.ip) ? 'ip6' : 'in-addr'; break;
      case 'h': v = mc.helo || mc.domain; break;
      case 'c': v = exp ? mc.ip ?? '' : whole; break;
      case 'r': v = exp ? 'unknown' : whole; break;
      case 't': v = exp ? String(Math.floor(Date.now() / 1000)) : whole; break;
      default: v = whole;
    }
    const delims = m[4] || '.';
    let parts = v.split(new RegExp(`[${delims.replace(/[-\\\]]/g, '\\$&')}]`));
    if (m[3]) parts = parts.reverse();
    if (m[2]) {
      const n = Number(m[2]);
      if (n > 0) parts = parts.slice(-n);
    }
    let out = parts.join('.');
    if (letter !== l) out = encodeURIComponent(out);
    return out;
  });
}

// ---------------------------------------------------------------------------------------------
// Networks

function inNetwork(ip: string, network: string, prefix?: number): boolean {
  try {
    const a = ipaddr.process(ip);
    const n = ipaddr.parse(network);
    if (a.kind() !== n.kind()) return false;
    const bits = prefix ?? (a.kind() === 'ipv4' ? 32 : 128);
    return a.match(n, bits);
  } catch {
    return false;
  }
}

function cidrString(ip: string, prefix?: number): string {
  const full = net.isIPv4(ip) ? 32 : 128;
  if (prefix === undefined || prefix === full) return ip;
  try {
    const [addr] = ipaddr.parseCIDR(`${ip}/${prefix}`);
    const bytes = addr.toByteArray();
    const bitsTotal = bytes.length * 8;
    for (let i = prefix; i < bitsTotal; i++) bytes[i >> 3] &= ~(0x80 >> (i & 7));
    return `${ipaddr.fromByteArray(bytes).toString()}/${prefix}`;
  } catch {
    return `${ip}/${prefix}`;
  }
}

// ---------------------------------------------------------------------------------------------
// Tree expansion (static: no connecting IP)

export interface SpfTermNode {
  term: string;
  mechanism: string;
  qualifier?: Qualifier;
  kind: SpfTerm['kind'];
  /** Domain the mechanism queries, after static macro expansion. */
  target?: string;
  /** DNS lookups this term costs against the limit of 10 (children not included). */
  lookups: number;
  /** Void lookups (NXDOMAIN or empty answer) caused by this term. */
  voids: number;
  /** Running total of lookups once this term is evaluated (in evaluation order). */
  cumulative?: number;
  /** true when this term is the one that crosses the limit of 10. */
  overLimit?: boolean;
  /** Networks this term authorizes (ip4/ip6/a/mx). */
  networks?: string[];
  mx?: { host: string; ips: string[] }[];
  child?: SpfNode;
  error?: string;
  errorKind?: 'unknown_mechanism' | 'dns' | 'mx_limit';
  note?: string;
}

export interface SpfNode {
  domain: string;
  record?: string;
  /** All v=spf1 records seen at this name (more than one is a permerror). */
  records: string[];
  status: 'ok' | 'none' | 'multiple' | 'nxdomain' | 'temperror' | 'loop' | 'skipped';
  error?: string;
  terms: SpfTermNode[];
  ttl?: number;
}

export interface SpfData {
  domain: string;
  record?: string;
  records: string[];
  /** All TXT records of the name, for context. */
  txt: string[];
  source: 'dns' | 'input';
  tree: SpfNode;
  lookupCount: number;
  voidCount: number;
  lookupLimit: number;
  voidLimit: number;
  /** Authorized networks, flattened from the whole tree (only "+" paths). */
  ipv4: string[];
  ipv6: string[];
  /** Mechanisms that cannot be flattened (ptr, exists, macros). */
  dynamic: string[];
  allQualifier?: Qualifier;
  includes: string[];
  providers: string[];
  responseSize: number;
  suggested?: string;
  /** The suggested record split in 255-octet strings, when it is longer. */
  suggestedSplit?: string;
  suggestedLookupCount?: number;
}

export interface SpfAnalysis extends Analysis {
  data: SpfData;
}

interface WalkCtx {
  dns: Resolver;
  root: string;
  ipv4: Set<string>;
  ipv6: Set<string>;
  dynamic: Set<string>;
  includes: Set<string>;
  budget: { lookups: number };
}

const HARD_CAP = 40; // stop expanding after this many lookups (display only)

async function walkNode(
  ctx: WalkCtx,
  domain: string,
  ancestors: string[],
  authorized: boolean,
  given?: { record: string },
): Promise<SpfNode> {
  const node: SpfNode = { domain, records: [], status: 'ok', terms: [] };
  if (ancestors.includes(domain)) {
    node.status = 'loop';
    node.error = `boucle : ${[...ancestors, domain].join(' → ')}`;
    return node;
  }
  if (ctx.budget.lookups > HARD_CAP) {
    node.status = 'skipped';
    return node;
  }
  let record: string;
  if (given) {
    record = given.record;
    node.records = [record];
  } else {
    const txt = await lookupTxt(ctx.dns, domain);
    node.ttl = txt.ttl;
    if (txt.error) {
      node.status = 'temperror';
      node.error = txt.error;
      return node;
    }
    if (txt.rcode === 'NXDOMAIN') {
      node.status = 'nxdomain';
      return node;
    }
    node.records = txt.records.filter(isSpfRecord);
    if (!node.records.length) {
      node.status = 'none';
      return node;
    }
    if (node.records.length > 1) node.status = 'multiple';
    record = node.records[0];
  }
  node.record = record;
  const { terms } = parseRecord(record);
  const hasAll = terms.some((tm) => tm.kind === 'mechanism' && tm.name === 'all');
  const path = [...ancestors, domain];

  node.terms = await Promise.all(
    terms.map(async (tm): Promise<SpfTermNode> => {
      const tn: SpfTermNode = { term: tm.raw, mechanism: tm.name, qualifier: tm.qualifier, kind: tm.kind, lookups: 0, voids: 0, error: tm.error, errorKind: tm.errorKind };
      if (tm.kind === 'invalid' || tm.error) return tn;
      const ok = authorized && (tm.qualifier ?? '+') === '+';
      if (tm.kind === 'modifier') {
        if (tm.name === 'redirect') {
          if (hasAll) {
            tn.note = t('ignoré : un mécanisme all est présent (RFC 7208 §6.1)');
            return tn;
          }
          tn.lookups = 1;
          ctx.budget.lookups++;
          const target = resolveSpec(tm.value!, domain);
          if (!target) {
            tn.note = t('dépend de l’expéditeur ou de l’IP : non déplié');
            ctx.dynamic.add(tm.raw);
            return tn;
          }
          tn.target = target;
          tn.child = await walkNode(ctx, target, path, authorized);
          if (['none', 'nxdomain'].includes(tn.child.status)) tn.voids = 1;
        }
        return tn;
      }
      const spec = tm.value ? resolveSpec(tm.value, domain) : domain;
      if (DNS_MECHS.has(tm.name)) {
        tn.lookups = 1;
        ctx.budget.lookups++;
      }
      if (tm.value && !spec) {
        tn.note = t('dépend de l’expéditeur ou de l’IP : non déplié');
        ctx.dynamic.add(tm.raw);
        return tn;
      }
      tn.target = spec ?? domain;
      switch (tm.name) {
        case 'ip4':
        case 'ip6': {
          const n = cidrString(tm.value!, tm.name === 'ip4' ? tm.cidr4 : tm.cidr6);
          tn.networks = [n];
          if (ok) (tm.name === 'ip4' ? ctx.ipv4 : ctx.ipv6).add(n);
          return tn;
        }
        case 'a': {
          const r = await lookupAddresses(ctx.dns, tn.target);
          if (r.error) {
            tn.error = t('requête DNS en échec ({rcode})', { rcode: r.rcode });
            tn.errorKind = 'dns';
          }
          else if (!r.ips.length) tn.voids = 1;
          tn.networks = r.ips.map((ip) => cidrString(ip, net.isIPv4(ip) ? tm.cidr4 : tm.cidr6));
          if (ok) for (const n of tn.networks) (n.includes(':') ? ctx.ipv6 : ctx.ipv4).add(n);
          return tn;
        }
        case 'mx': {
          const r = await lookupMx(ctx.dns, tn.target);
          if (r.error) {
            tn.error = t('requête DNS en échec ({rcode})', { rcode: r.rcode });
            tn.errorKind = 'dns';
            return tn;
          }
          const hosts = r.mx.filter((m) => m.exchange && m.exchange !== '.');
          if (!hosts.length) tn.voids = 1;
          if (hosts.length > SPF_MX_LIMIT) {
            tn.error = t('{n} serveurs MX, la limite est {limit}', { n: hosts.length, limit: SPF_MX_LIMIT });
            tn.errorKind = 'mx_limit';
          }
          tn.mx = await Promise.all(
            hosts.slice(0, SPF_MX_LIMIT).map(async (m) => {
              const a = await lookupAddresses(ctx.dns, m.exchange);
              if (!a.ips.length && !a.error) tn.voids++;
              return { host: m.exchange, ips: a.ips };
            }),
          );
          tn.networks = tn.mx.flatMap((m) => m.ips.map((ip) => cidrString(ip, net.isIPv4(ip) ? tm.cidr4 : tm.cidr6)));
          if (ok) for (const n of tn.networks) (n.includes(':') ? ctx.ipv6 : ctx.ipv4).add(n);
          return tn;
        }
        case 'ptr':
          tn.note = t('dépend du nom inverse de chaque IP : non déplié');
          ctx.dynamic.add(tm.raw);
          return tn;
        case 'exists': {
          const r = await lookupType(ctx.dns, tn.target, 'A');
          if (!r.error && !r.data.length) tn.voids = 1;
          tn.note = r.data.length ? t('le nom existe') : t('le nom n’existe pas');
          return tn;
        }
        case 'include': {
          ctx.includes.add(tn.target);
          tn.child = await walkNode(ctx, tn.target, path, ok);
          if (['none', 'nxdomain'].includes(tn.child.status)) tn.voids = 1;
          return tn;
        }
        default:
          return tn;
      }
    }),
  );
  return node;
}

/** Expand a domain-spec when it only uses %{d}; undefined when it depends on the IP or sender. */
function resolveSpec(spec: string, domain: string): string | undefined {
  if (!hasMacro(spec)) return norm(spec);
  if (!staticMacro(spec)) return undefined;
  return norm(expandMacros(spec, { domain }));
}

/** Walk the tree in evaluation order (terms, then redirect) and assign running lookup totals. */
function accountLookups(node: SpfNode, state = { lookups: 0, voids: 0 }): { lookups: number; voids: number } {
  const ordered = [
    ...node.terms.filter((tm) => !(tm.kind === 'modifier' && tm.mechanism === 'redirect')),
    ...node.terms.filter((tm) => tm.kind === 'modifier' && tm.mechanism === 'redirect'),
  ];
  for (const tm of ordered) {
    const before = state.lookups;
    state.lookups += tm.lookups;
    state.voids += tm.voids;
    tm.cumulative = state.lookups;
    if (before <= SPF_LOOKUP_LIMIT && state.lookups > SPF_LOOKUP_LIMIT) tm.overLimit = true;
    if (tm.child) accountLookups(tm.child, state);
  }
  return state;
}

function* allNodes(node: SpfNode): Generator<{ node: SpfNode; parent?: SpfTermNode }> {
  yield { node };
  for (const tm of node.terms) if (tm.child) for (const x of allNodes(tm.child)) yield { node: x.node, parent: x.parent ?? tm };
}

// Well-known include targets, to label the providers found (used for provider-specific fixes).
const PROVIDER_INCLUDES: [RegExp, string][] = [
  [/(^|\.)_spf\.google\.com$/, 'google_workspace'],
  [/(^|\.)spf\.protection\.outlook\.com$/, 'microsoft_365'],
  [/(^|\.)servers\.mcsv\.net$/, 'mailchimp'],
  [/(^|\.)spf\.mandrillapp\.com$/, 'mailchimp'],
  [/(^|\.)sendgrid\.net$/, 'sendgrid'],
  [/(^|\.)mailgun\.org$/, 'mailgun'],
  [/(^|\.)amazonses\.com$/, 'amazon_ses'],
  [/(^|\.)(spf\.)?(sendinblue|brevo)\.com$/, 'brevo'],
  [/(^|\.)spf\.mailjet\.com$/, 'mailjet'],
  [/(^|\.)zoho\.(com|eu|in|com\.au)$/, 'zoho'],
  [/(^|\.)protonmail\.ch$/, 'proton'],
  [/(^|\.)mx\.ovh\.com$|(^|\.)ovh\.net$/, 'ovh'],
  [/(^|\.)spf\.mtasv\.net$/, 'postmark'],
  [/(^|\.)sparkpostmail\.com$/, 'sparkpost'],
  [/(^|\.)infomaniak\.ch$/, 'infomaniak'],
  [/(^|\.)_spf\.perfora\.net$|(^|\.)_spf\.kundenserver\.de$|(^|\.)ionos\./, 'ionos'],
  [/(^|\.)_mailcust\.gandi\.net$|(^|\.)gandi\.net$/, 'gandi'],
  [/(^|\.)hubspotemail\.net$/, 'hubspot'],
  [/(^|\.)_spf\.salesforce\.com$|(^|\.)exacttarget\.com$/, 'salesforce'],
];

export function providersOf(includes: Iterable<string>): string[] {
  const out = new Set<string>();
  for (const inc of includes) for (const [re, key] of PROVIDER_INCLUDES) if (re.test(inc)) out.add(key);
  return [...out];
}

export interface SpfCheckOptions {
  /** Test this record instead of the published one (may contain "..." "..." quoted strings). */
  record?: string;
}

/** Parse a record pasted as in a zone file ("part1" "part2") into its strings. */
export function parsePastedRecord(input: string): { value: string; strings: string[] } {
  const s = input.trim();
  if (/^".*"$/s.test(s)) {
    const strings = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
    return { value: strings.join(''), strings };
  }
  return { value: s, strings: [s] };
}

export async function analyzeSpf(dns: Resolver, domain: string, opts: SpfCheckOptions = {}): Promise<SpfAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const ctx: WalkCtx = { dns, root: domain, ipv4: new Set(), ipv6: new Set(), dynamic: new Set(), includes: new Set(), budget: { lookups: 0 } };

  let txtAll: string[] = [];
  let responseSize = 0;
  let pastedStrings: string[] | undefined;
  let tree: SpfNode;
  if (opts.record) {
    const p = parsePastedRecord(opts.record);
    pastedStrings = p.strings;
    tree = await walkNode(ctx, domain, [], true, { record: p.value });
  } else {
    const txt = await lookupTxt(dns, domain);
    txtAll = txt.records;
    responseSize = txt.responseSize;
    if (txt.error) {
      tree = { domain, records: [], status: 'temperror', error: txt.error, terms: [] };
    } else if (txt.rcode === 'NXDOMAIN') {
      tree = { domain, records: [], status: 'nxdomain', terms: [] };
    } else {
      const spf = txt.records.filter(isSpfRecord);
      tree = spf.length ? await walkNode(ctx, domain, [], true) : { domain, records: [], status: 'none', terms: [] };
      // a record "v=spf1" broken across strings without the joining rules stays valid; nothing to check
    }
  }
  const counts = accountLookups(tree);
  // obsolete SPF RR type 99 (RFC 7208 §3.1), Sender ID records, MX of the domain
  const [t99, mxr] = opts.record
    ? [{ data: [] as unknown[] }, undefined]
    : await Promise.all([lookupType(dns, domain, 'SPF' as never), lookupMx(dns, domain)]);
  const type99 = t99.data.map((d) => (Buffer.isBuffer(d) ? decodeCharStrings(d) : txtStrings(d).join('')));
  const senderId = txtAll.filter((tm) => /^spf2\.0\//i.test(tm.trim()));
  const record = tree.record;
  const vars = { domain, envelope_domain: domain, spf_record: record, lookup_count: counts.lookups, value: undefined as string | number | undefined };

  // --- record-level checks
  if (tree.status === 'temperror') {
    issues.push(issue('spf.temperror', { domain, envelope_domain: domain }, { evidence: tree.error }));
  } else if (tree.status === 'nxdomain') {
    issues.push(issue('spf.domain_nxdomain', { domain, envelope_domain: domain }));
  } else if (tree.status === 'none') {
    const near = txtAll.find((tm) => /^\s*"?v\s*=\s*spf/i.test(tm) || /^spf1?\b/i.test(tm) || /^v=spf[^1]/i.test(tm));
    if (near) issues.push(issue('spf.version_invalid', { domain, envelope_domain: domain, value: near }, { evidence: near }));
    else if (type99.length) issues.push(issue('spf.type99_only', { domain, envelope_domain: domain }, { evidence: type99.join('\n') }));
    else issues.push(issue('spf.missing', { domain, envelope_domain: domain }, { suggested: `v=spf1 mx ~all` }));
  } else {
    passed.push(pass('spf.present', 'spf', t('Enregistrement SPF publié'), record));
    if (type99.length) issues.push(issue('spf.type99_leftover', { domain, envelope_domain: domain }, { evidence: type99.join('\n') }));
    if (tree.status === 'multiple') {
      issues.push(issue('spf.multiple_records', { ...vars, value: tree.records.length }, { evidence: tree.records.join('\n') }));
    } else passed.push(pass('spf.single_record', 'spf', t('Un seul enregistrement SPF')));
  }

  if (record) {
    // walk every record of the tree
    for (const { node } of allNodes(tree)) {
      const where = node.domain === domain ? domain : node.domain;
      if (node !== tree && node.status === 'multiple')
        issues.push(issue('spf.include_permerror', { domain, envelope_domain: domain, value: where }, { evidence: node.records.join('\n') }));
      if (node.status === 'loop') issues.push(issue('spf.include_loop', { domain, envelope_domain: domain, value: where }, { evidence: node.error }));
      if (node !== tree && node.status === 'temperror') issues.push(issue('spf.temperror', { domain, envelope_domain: domain, value: where }, { evidence: node.error }));
      for (const tm of node.terms) {
        if (tm.kind === 'invalid' && tm.errorKind === 'unknown_mechanism')
          issues.push(issue('spf.unknown_mechanism', { domain, envelope_domain: domain, value: tm.term }, { evidence: node === tree ? tm.term : `${where} : ${tm.term}` }));
        else if (tm.error && (tm.kind === 'invalid' || (tm.errorKind !== 'dns' && tm.errorKind !== 'mx_limit')))
          issues.push(issue('spf.syntax_error', { domain, envelope_domain: domain, value: `${tm.term} : ${tm.error}` }, { evidence: node === tree ? tm.term : `${where} : ${tm.term}` }));
        if (tm.errorKind === 'dns') issues.push(issue('spf.temperror', { domain, envelope_domain: domain, value: `${where} : ${tm.term}` }, { evidence: tm.error }));
        if (tm.errorKind === 'mx_limit') issues.push(issue('spf.mx_too_many_addresses', { domain, envelope_domain: domain, value: tm.term }, { evidence: tm.error }));
        if (tm.mechanism === 'ptr' && tm.kind === 'mechanism' && !tm.error)
          issues.push(issue('spf.ptr_mechanism', { domain, envelope_domain: domain }, { evidence: node === tree ? tm.term : `${where} : ${tm.term}` }));
        if (tm.child && tm.mechanism === 'include' && ['none', 'nxdomain'].includes(tm.child.status))
          issues.push(issue('spf.include_no_spf', { domain, envelope_domain: domain, value: tm.target }, { evidence: `${where} : ${tm.term}` }));
        if (tm.child && tm.mechanism === 'redirect' && ['none', 'nxdomain'].includes(tm.child.status))
          issues.push(issue('spf.redirect_target_invalid', { domain, envelope_domain: domain, value: tm.target }, { evidence: `${where} : ${tm.term}` }));
      }
    }
    const { terms, versionError } = parseRecord(record);
    if (versionError) issues.push(issue('spf.syntax_error', { domain, envelope_domain: domain, value: versionError }, { evidence: record }));
    const mechs = terms.filter((tm) => tm.kind === 'mechanism');
    const allIdx = terms.findIndex((tm) => tm.kind === 'mechanism' && tm.name === 'all');
    const all = allIdx >= 0 ? terms[allIdx] : undefined;
    const redirect = terms.find((tm) => tm.kind === 'modifier' && tm.name === 'redirect');
    const dupMods = ['redirect', 'exp'].filter((n) => terms.filter((tm) => tm.kind === 'modifier' && tm.name === n).length > 1);
    for (const n of dupMods) issues.push(issue('spf.syntax_error', { domain, envelope_domain: domain, value: t('le modificateur {name}= apparaît plusieurs fois', { name: n }) }, { evidence: record }));
    if (all) {
      if (all.qualifier === '+') issues.push(issue('spf.plus_all', vars, { evidence: all.raw }));
      else if (all.qualifier === '?') issues.push(issue('spf.neutral_all', vars, { evidence: all.raw }));
      else passed.push(pass('spf.all_policy', 'spf', t('Politique finale {raw}', { raw: all.raw }), all.qualifier === '-' ? t('échec strict des sources non autorisées') : t('échec doux des sources non autorisées')));
      const after = terms.slice(allIdx + 1).filter((tm) => tm.kind === 'mechanism' || (tm.kind === 'modifier' && tm.name === 'redirect'));
      if (after.length) issues.push(issue('spf.terms_after_all', { domain, envelope_domain: domain, value: after.map((tm) => tm.raw).join(' ') }, { evidence: record }));
      if (redirect) issues.push(issue('spf.redirect_with_all', { domain, envelope_domain: domain, value: redirect.raw }, { evidence: record }));
    } else if (!redirect) {
      issues.push(issue('spf.no_all', vars, { evidence: record }));
    } else passed.push(pass('spf.redirect', 'spf', t('Politique déléguée par {raw}', { raw: redirect.raw })));
    const seen = new Map<string, number>();
    for (const tm of mechs) seen.set(tm.raw.toLowerCase().replace(/^\+/, ''), (seen.get(tm.raw.toLowerCase().replace(/^\+/, '')) ?? 0) + 1);
    const dups = [...seen].filter(([, n]) => n > 1).map(([k]) => k);
    if (dups.length) issues.push(issue('spf.duplicate_terms', { domain, envelope_domain: domain, value: dups.join(', ') }, { evidence: record }));
    for (const tm of terms) if (tm.kind === 'modifier' && !['redirect', 'exp'].includes(tm.name))
      issues.push(issue('spf.unknown_modifier', { domain, envelope_domain: domain, value: tm.raw }, { evidence: tm.raw, severity: 'info' }));

    const exp = terms.find((tm) => tm.kind === 'modifier' && tm.name === 'exp');
    if (exp) issues.push(issue('spf.exp_modifier', { ...vars, value: exp.raw }, { evidence: exp.raw }));
    const macroTerms = [...allNodes(tree)].flatMap(({ node }) => node.terms.filter((tm) => tm.term.includes('%{')).map((tm) => tm.term));
    if (macroTerms.length) issues.push(issue('spf.macros', { ...vars, value: macroTerms.join(' ') }, { evidence: macroTerms.join('\n') }));
    const broad = terms.filter((tm) => tm.kind === 'mechanism' && (tm.qualifier ?? '+') === '+' && ((tm.name === 'ip4' && tm.cidr4 !== undefined && tm.cidr4 < 16) || (tm.name === 'ip6' && tm.cidr6 !== undefined && tm.cidr6 < 32)));
    if (broad.length) issues.push(issue('spf.range_too_broad', { ...vars, value: broad.map((tm) => tm.raw).join(' ') }, { evidence: broad.map((tm) => tm.raw).join(' ') }));
    if (mxr && !mxr.error && (mxr.mx.length === 0 || mxr.mx.every((m) => m.exchange === '' || m.exchange === '.')) && all && all.qualifier !== '-')
      issues.push(issue('spf.non_sending_domain_open', { ...vars, value: all.raw }, { evidence: record, suggested: 'v=spf1 -all' }));
    // limits
    if (counts.lookups > SPF_LOOKUP_LIMIT) issues.push(issue('spf.lookup_limit', vars, { evidence: lookupEvidence(tree) }));
    else if (counts.lookups >= SPF_LOOKUP_LIMIT - 1) issues.push(issue('spf.lookup_limit_near', vars, { evidence: lookupEvidence(tree) }));
    else passed.push(pass('spf.lookup_limit', 'spf', t('{n} requêtes DNS sur {limit} autorisées', { n: counts.lookups, limit: SPF_LOOKUP_LIMIT })));
    if (counts.voids > SPF_VOID_LIMIT) issues.push(issue('spf.void_lookup_limit', { ...vars, value: counts.voids }));
    else passed.push(pass('spf.void_lookups', 'spf', tPlural(counts.voids, '{n} requête sans réponse sur {limit} tolérées', '{n} requêtes sans réponse sur {limit} tolérées', { limit: SPF_VOID_LIMIT })));

    // sizes
    if (pastedStrings) {
      const long = pastedStrings.filter((s) => Buffer.byteLength(s) > 255);
      if (long.length) issues.push(issue('spf.string_too_long', { domain, envelope_domain: domain, value: Buffer.byteLength(long[0]) }, { suggested: splitTxt(parsePastedRecord(opts.record!).value) }));
    }
    if (responseSize > 512) issues.push(issue('spf.dns_response_too_large', { domain, envelope_domain: domain, value: responseSize }, { evidence: t('{n} enregistrements TXT sur {domain}', { n: txtAll.length, domain }) }));
  }

  if (senderId.length) issues.push(issue('spf.sender_id_record', { domain, envelope_domain: domain }, { evidence: senderId.join('\n') }));
  const ipv4 = [...ctx.ipv4];
  const ipv6 = [...ctx.ipv6];
  const data: SpfData = {
    domain,
    record,
    records: tree.records,
    txt: txtAll,
    source: opts.record ? 'input' : 'dns',
    tree,
    lookupCount: counts.lookups,
    voidCount: counts.voids,
    lookupLimit: SPF_LOOKUP_LIMIT,
    voidLimit: SPF_VOID_LIMIT,
    ipv4,
    ipv6,
    dynamic: [...ctx.dynamic],
    allQualifier: record ? (parseRecord(record).terms.find((tm) => tm.kind === 'mechanism' && tm.name === 'all')?.qualifier) : undefined,
    includes: [...ctx.includes],
    providers: providersOf(ctx.includes),
    responseSize,
  };

  if (record) {
    const sug = suggestSpf(tree, counts.lookups);
    if (sug && sug.record.toLowerCase() !== record.toLowerCase().trim().replace(/\s+/g, ' ')) {
      data.suggested = sug.record;
      data.suggestedLookupCount = sug.lookups;
      if (Buffer.byteLength(sug.record) > 255) data.suggestedSplit = splitTxt(sug.record);
      // attach the suggestion to the record-level findings
      for (const i of issues) if (!i.suggested && SUGGESTABLE.has(i.id)) i.suggested = sug.record;
    }
  }
  return { issues, passed, data };
}

/** Raw RDATA made of <length><bytes> character-strings (unknown record types). */
function decodeCharStrings(b: Buffer): string {
  const out: string[] = [];
  for (let i = 0; i < b.length; ) {
    const n = b[i];
    out.push(b.subarray(i + 1, i + 1 + n).toString('utf8'));
    i += n + 1;
  }
  return out.join('');
}

const SUGGESTABLE = new Set([
  'spf.multiple_records', 'spf.plus_all', 'spf.neutral_all', 'spf.no_all', 'spf.ptr_mechanism', 'spf.unknown_mechanism',
  'spf.syntax_error', 'spf.include_no_spf', 'spf.terms_after_all', 'spf.redirect_with_all', 'spf.duplicate_terms',
  'spf.lookup_limit',
]);

function lookupEvidence(tree: SpfNode): string {
  const lines: string[] = [];
  const visit = (n: SpfNode, depth: number) => {
    for (const tm of n.terms) {
      if (!tm.lookups) continue;
      lines.push(`${'  '.repeat(depth)}${tm.term} (total ${tm.cumulative})${tm.overLimit ? `  ${t('← limite dépassée ici')}` : ''}`);
      if (tm.child) visit(tm.child, depth + 1);
    }
  };
  visit(tree, 0);
  return lines.join('\n');
}

/**
 * Corrected record: one record, invalid/dangerous terms dropped, a single all at the end,
 * own a/mx flattened to ip4/ip6 when the lookup budget is exceeded.
 */
export function suggestSpf(tree: SpfNode, lookups: number): { record: string; lookups: number } | undefined {
  if (!tree.record) return undefined;
  const termNodes = new Map<string, SpfTermNode>();
  for (const tm of tree.terms) termNodes.set(tm.term, tm);
  const all: SpfTerm[] = [];
  for (const rec of tree.records) all.push(...parseRecord(rec).terms);
  const out: string[] = [];
  const seen = new Set<string>();
  let allQ: Qualifier | undefined;
  let redirect: string | undefined;
  let exp: string | undefined;
  let cost = lookups;
  const flatten = lookups > SPF_LOOKUP_LIMIT;
  for (const tm of all) {
    if (tm.kind === 'invalid' || tm.error) continue;
    if (tm.kind === 'modifier') {
      if (tm.name === 'redirect') redirect ??= tm.raw;
      else if (tm.name === 'exp') exp ??= tm.raw;
      continue;
    }
    if (tm.name === 'all') {
      const q = tm.qualifier!;
      if (!allQ || (q === '-' && allQ !== '-')) allQ = q;
      continue;
    }
    const node = termNodes.get(tm.raw);
    if (tm.name === 'ptr') {
      cost -= node?.lookups ?? 1;
      continue;
    }
    if (tm.name === 'include' && node?.child && ['none', 'nxdomain', 'loop'].includes(node.child.status)) {
      cost -= node.lookups;
      continue;
    }
    const key = tm.raw.toLowerCase().replace(/^\+/, '');
    if (seen.has(key)) {
      cost -= node?.lookups ?? (DNS_MECHS.has(tm.name) ? 1 : 0);
      continue;
    }
    seen.add(key);
    if (flatten && (tm.name === 'a' || tm.name === 'mx') && node?.networks?.length && (!tm.value || norm(tm.value) === tree.domain) && tm.qualifier === '+') {
      for (const n of node.networks) {
        const term = `${n.includes(':') ? 'ip6' : 'ip4'}:${n}`;
        if (!seen.has(term)) {
          seen.add(term);
          out.push(term);
        }
      }
      cost -= 1;
      continue;
    }
    out.push(tm.qualifier === '+' ? tm.raw.replace(/^\+/, '') : tm.raw);
  }
  if (!allQ || allQ === '+' || allQ === '?') {
    if (!(redirect && !allQ)) allQ = '~';
  }
  const parts = ['v=spf1', ...out];
  if (allQ) parts.push(`${allQ}all`);
  else if (redirect) parts.push(redirect);
  if (exp) parts.push(exp);
  return { record: parts.join(' '), lookups: Math.max(0, cost) };
}

// ---------------------------------------------------------------------------------------------
// check_host() (RFC 7208 §4) for one IP

export interface SpfEvalStep {
  depth: number;
  domain: string;
  term: string;
  outcome: 'match' | 'no-match' | 'error' | 'info';
  detail?: string;
}

export interface SpfEvalResult {
  ip: string;
  domain: string;
  sender: string;
  result: SpfResult;
  /** Mechanism of the evaluated domain's record that decided (its qualifier gives the result). */
  mechanism?: { term: string; domain: string; record?: string };
  /** Full path to the matching term through include/redirect, outermost first. */
  chain: { term: string; domain: string }[];
  reason: string;
  lookups: number;
  voids: number;
  steps: SpfEvalStep[];
}

class SpfAbort extends Error {
  constructor(public result: 'permerror' | 'temperror', message: string) {
    super(message);
  }
}

interface EvalCtx {
  dns: Resolver;
  ip: string;
  sender: string;
  helo?: string;
  lookups: number;
  voids: number;
  steps: SpfEvalStep[];
}

function countLookup(ctx: EvalCtx) {
  ctx.lookups++;
  if (ctx.lookups > SPF_LOOKUP_LIMIT) throw new SpfAbort('permerror', t('plus de {limit} requêtes DNS (RFC 7208 §4.6.4)', { limit: SPF_LOOKUP_LIMIT }));
}
function countVoid(ctx: EvalCtx) {
  ctx.voids++;
  if (ctx.voids > SPF_VOID_LIMIT) throw new SpfAbort('permerror', t('plus de {limit} requêtes DNS sans réponse (RFC 7208 §4.6.4)', { limit: SPF_VOID_LIMIT }));
}

async function addrOf(ctx: EvalCtx, name: string, v6: boolean): Promise<string[]> {
  const r = await lookupType(ctx.dns, name, v6 ? 'AAAA' : 'A');
  if (r.error) throw new SpfAbort('temperror', t('requête DNS {type} {name} en échec', { type: v6 ? 'AAAA' : 'A', name }));
  return r.data.map(String);
}

type HostOut = { result: SpfResult; mechanism?: SpfEvalResult['mechanism']; reason: string; chain?: SpfEvalResult['chain'] };

async function checkHost(ctx: EvalCtx, domain: string, depth: number): Promise<HostOut> {
  const d = norm(domain);
  if (checkDomainSpec(d)) return { result: 'none', reason: t('{domain} n’est pas un nom de domaine valide', { domain: d }) };
  const txt = await lookupTxt(ctx.dns, d);
  if (txt.error) return { result: 'temperror', reason: t('requête TXT {domain} en échec', { domain: d }) };
  const recs = txt.records.filter(isSpfRecord);
  if (!recs.length) return { result: 'none', reason: t('aucun SPF sur {domain}', { domain: d }) };
  if (recs.length > 1) return { result: 'permerror', reason: t('{n} enregistrements SPF sur {domain}', { n: recs.length, domain: d }) };
  const record = recs[0];
  const { terms } = parseRecord(record);
  const bad = terms.find((tm) => tm.kind === 'invalid' || tm.error);
  if (bad) return { result: 'permerror', reason: t('terme invalide « {term} » dans le SPF de {domain}', { term: bad.raw, domain: d }), mechanism: { term: bad.raw, domain: d, record } };
  const mods = terms.filter((tm) => tm.kind === 'modifier');
  if (mods.filter((tm) => tm.name === 'redirect').length > 1 || mods.filter((tm) => tm.name === 'exp').length > 1)
    return { result: 'permerror', reason: t('modificateur répété dans le SPF de {domain}', { domain: d }) };
  const v6 = net.isIPv6(ipaddr.process(ctx.ip).toString());
  const mc = { ip: ctx.ip, sender: ctx.sender, domain: d, helo: ctx.helo };
  const step = (term: string, outcome: SpfEvalStep['outcome'], detail?: string) => ctx.steps.push({ depth, domain: d, term, outcome, detail });

  for (const tm of terms) {
    if (tm.kind !== 'mechanism') continue;
    const target = tm.value !== undefined ? norm(expandMacros(tm.value, mc)) : d;
    const prefix = v6 ? tm.cidr6 : tm.cidr4;
    let matched = false;
    let detail: string | undefined;
    let inner: SpfEvalResult['chain'] = [];
    switch (tm.name) {
      case 'all':
        matched = true;
        break;
      case 'ip4':
      case 'ip6':
        matched = inNetwork(ctx.ip, tm.value!, tm.name === 'ip4' ? tm.cidr4 : tm.cidr6);
        break;
      case 'a': {
        countLookup(ctx);
        const ips = await addrOf(ctx, target, v6);
        if (!ips.length) countVoid(ctx);
        matched = ips.some((ip) => inNetwork(ctx.ip, ip, prefix));
        detail = ips.length ? ips.join(', ') : t('aucune adresse');
        break;
      }
      case 'mx': {
        countLookup(ctx);
        const r = await lookupMx(ctx.dns, target);
        if (r.error) throw new SpfAbort('temperror', t('requête MX {target} en échec', { target }));
        const hosts = r.mx.filter((m) => m.exchange && m.exchange !== '.');
        if (!hosts.length) countVoid(ctx);
        if (hosts.length > SPF_MX_LIMIT) throw new SpfAbort('permerror', t('{target} a plus de {limit} MX', { target, limit: SPF_MX_LIMIT }));
        for (const h of hosts) {
          const ips = await addrOf(ctx, h.exchange, v6);
          if (!ips.length) countVoid(ctx);
          if (ips.some((ip) => inNetwork(ctx.ip, ip, prefix))) {
            matched = true;
            detail = `${h.exchange} (${ips.join(', ')})`;
            break;
          }
        }
        detail ??= hosts.map((h) => h.exchange).join(', ') || t('aucun MX');
        break;
      }
      case 'ptr': {
        countLookup(ctx);
        const rev = await lookupType(ctx.dns, reverseOf(ctx.ip), 'PTR');
        if (!rev.data.length) countVoid(ctx);
        const names = rev.data.map((x) => norm(String(x))).slice(0, SPF_PTR_LIMIT);
        for (const n of names) {
          const ips = await addrOf(ctx, n, v6).catch(() => [] as string[]);
          const validated = ips.some((ip) => inNetwork(ctx.ip, ip));
          if (validated && (n === target || n.endsWith('.' + target))) {
            matched = true;
            detail = n;
            break;
          }
        }
        detail ??= names.join(', ') || t('aucun nom inverse');
        break;
      }
      case 'exists': {
        countLookup(ctx);
        const r = await lookupType(ctx.dns, target, 'A');
        if (r.error) throw new SpfAbort('temperror', t('requête A {target} en échec', { target }));
        if (!r.data.length) countVoid(ctx);
        matched = r.data.length > 0;
        detail = target;
        break;
      }
      case 'include': {
        countLookup(ctx);
        const sub = await checkHost(ctx, target, depth + 1);
        if (sub.result === 'pass') {
          matched = true;
          inner = sub.chain ?? [];
        } else if (sub.result === 'temperror') {
          throw new SpfAbort('temperror', sub.reason);
        } else if (sub.result === 'permerror' || sub.result === 'none') {
          throw new SpfAbort('permerror', sub.result === 'none' ? t('include:{target} ne publie aucun SPF', { target }) : sub.reason);
        }
        detail = `${target} : ${sub.result}`;
        break;
      }
    }
    step(tm.raw, matched ? 'match' : 'no-match', detail);
    if (matched) {
      const result = QUAL_RESULT[tm.qualifier!];
      return { result, mechanism: { term: tm.raw, domain: d, record }, reason: t('{term} dans le SPF de {domain}', { term: tm.raw, domain: d }), chain: [{ term: tm.raw, domain: d }, ...inner] };
    }
  }
  const redirect = mods.find((tm) => tm.name === 'redirect');
  if (redirect) {
    countLookup(ctx);
    const target = norm(expandMacros(redirect.value!, mc));
    step(redirect.raw, 'info', target);
    const sub = await checkHost(ctx, target, depth + 1);
    if (sub.result === 'none') return { result: 'permerror', reason: t('redirect={target} ne publie aucun SPF', { target }), mechanism: { term: redirect.raw, domain: d, record } };
    return { ...sub, chain: [{ term: redirect.raw, domain: d }, ...(sub.chain ?? [])] };
  }
  return { result: 'neutral', reason: t('aucun mécanisme du SPF de {domain} ne correspond et il n’y a pas de all', { domain: d }) };
}

function reverseOf(ip: string): string {
  const a = ipaddr.process(ip);
  if (a.kind() === 'ipv4') return a.toByteArray().reverse().join('.') + '.in-addr.arpa';
  const hex = (a as ipaddr.IPv6).toNormalizedString().split(':').map((p) => p.padStart(4, '0')).join('');
  return hex.split('').reverse().join('.') + '.ip6.arpa';
}

export async function evaluateSpf(
  dns: Resolver,
  input: { ip: string; domain: string; sender?: string; helo?: string },
): Promise<SpfEvalResult> {
  const ip = ipaddr.process(input.ip).toString();
  const sender = input.sender?.includes('@') ? input.sender : `postmaster@${input.domain}`;
  const ctx: EvalCtx = { dns, ip, sender, helo: input.helo, lookups: 0, voids: 0, steps: [] };
  let out: HostOut;
  try {
    out = await checkHost(ctx, input.domain, 0);
  } catch (e) {
    if (e instanceof SpfAbort) out = { result: e.result, reason: e.message };
    else out = { result: 'temperror', reason: (e as Error).message };
  }
  return { ip, domain: input.domain, sender, ...out, chain: out.chain ?? [], lookups: ctx.lookups, voids: ctx.voids, steps: ctx.steps };
}
