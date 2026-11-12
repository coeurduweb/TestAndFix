// DMARC generator model (RFC 9989, May 2026: pct, rf and ri are gone; t= and np= are new).
// Builds the record, lists the authorisations external report addresses need (RFC 9990 §4),
// reads an existing record back, and picks the next policy step. Pure, unit tested.
import { t } from '../../lib/i18n';
import { parseMailto, sameOrg } from '../gen-spf/txt';

export type Policy = 'none' | 'quarantine' | 'reject';
export type Align = 'r' | 's';
export type FoOpt = '0' | '1' | 'd' | 's';

export interface DmarcModel {
  p: Policy;
  /** '' : inherits p. */
  sp: Policy | '';
  /** '' : inherits sp, then p. */
  np: Policy | '';
  adkim: Align;
  aspf: Align;
  /** Testing mode (RFC 9989 §4.7): the policy is applied one step lower. */
  t: boolean;
  /** Addresses as typed (mailto: optional). */
  rua: string[];
  ruf: string[];
  fo: FoOpt[];
}

export const POLICIES: Policy[] = ['none', 'quarantine', 'reject'];
export const strength = (p: Policy) => POLICIES.indexOf(p);

export function defaultModel(domain?: string): DmarcModel {
  return { p: 'none', sp: '', np: '', adkim: 'r', aspf: 'r', t: false, rua: domain ? [`dmarc@${domain}`] : [], ruf: [], fo: [] };
}

const uris = (xs: string[]) =>
  xs.map(parseMailto).flatMap((r) => ('uri' in r ? [r.uri] : []));

/** Tags in the usual order; defaults are left out (adkim=r, aspf=r, fo=0, t=n). */
export function buildDmarc(m: DmarcModel): string {
  const tags = ['v=DMARC1', `p=${m.p}`];
  if (m.sp && m.sp !== m.p) tags.push(`sp=${m.sp}`);
  if (m.np && m.np !== (m.sp || m.p)) tags.push(`np=${m.np}`);
  if (m.adkim === 's') tags.push('adkim=s');
  if (m.aspf === 's') tags.push('aspf=s');
  if (m.t && m.p !== 'none') tags.push('t=y');
  const rua = uris(m.rua);
  if (rua.length) tags.push(`rua=${rua.join(',')}`);
  const ruf = uris(m.ruf);
  if (ruf.length) {
    tags.push(`ruf=${ruf.join(',')}`);
    const fo = m.fo.filter((x) => x !== '0');
    if (fo.length) tags.push(`fo=${fo.join(':')}`);
  }
  return tags.join('; ');
}

export interface Authorization {
  address: string;
  reportDomain: string;
  /** TXT name the owner of the report domain must publish. */
  name: string;
  value: 'v=DMARC1';
}

/** RFC 9990 §4: an address outside the organisation of `domain` needs its owner's consent. */
export function externalAuthorizations(domain: string, addresses: string[]): Authorization[] {
  const out: Authorization[] = [];
  for (const a of addresses) {
    const r = parseMailto(a);
    if (!('uri' in r) || !r.uri.startsWith('mailto:')) continue;
    if (sameOrg(r.domain, domain)) continue;
    if (out.some((x) => x.reportDomain === r.domain)) continue;
    out.push({ address: r.address, reportDomain: r.domain, name: `${domain}._report._dmarc.${r.domain}`, value: 'v=DMARC1' });
  }
  return out;
}

/** Existing record → model, unknown or removed tags (pct, ri, rf) listed apart. */
export function parseDmarc(record: string, domain?: string): { model: DmarcModel; dropped: string[] } {
  const model = defaultModel();
  const dropped: string[] = [];
  const kv = record
    .replace(/^"|"$/g, '')
    .split(';')
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => {
      const i = x.indexOf('=');
      return i < 0 ? [x.toLowerCase(), ''] : [x.slice(0, i).trim().toLowerCase(), x.slice(i + 1).trim()];
    });
  const pol = (v: string): Policy | undefined => (POLICIES.includes(v.toLowerCase() as Policy) ? (v.toLowerCase() as Policy) : undefined);
  for (const [k, v] of kv) {
    if (k === 'v') continue;
    else if (k === 'p') model.p = pol(v) ?? 'none';
    else if (k === 'sp') model.sp = pol(v) ?? '';
    else if (k === 'np') model.np = pol(v) ?? '';
    else if (k === 'adkim') model.adkim = v.toLowerCase() === 's' ? 's' : 'r';
    else if (k === 'aspf') model.aspf = v.toLowerCase() === 's' ? 's' : 'r';
    else if (k === 't') model.t = v.toLowerCase() === 'y';
    else if (k === 'rua' || k === 'ruf') {
      const list = v.split(',').map((u) => u.trim().replace(/^mailto:/i, '').replace(/!\d+[kmgt]?$/i, '')).filter(Boolean);
      model[k] = list;
    } else if (k === 'fo') model.fo = v.split(':').map((x) => x.trim()).filter((x): x is FoOpt => ['0', '1', 'd', 's'].includes(x));
    else dropped.push(v ? `${k}=${v}` : k);
  }
  if (!model.rua.length && domain) model.rua = [];
  return { model, dropped };
}

export interface PolicyAdvice {
  policy: Policy;
  /** One sentence: why this step now. */
  reason: string;
  /** Where the advice comes from. */
  basis: 'none-published' | 'published' | 'reports' | 'unread';
}

/**
 * Next step from what is published, refined by the stored aggregate reports when there are some
 * (server recommendation, measured on the reports).
 */
export function advise(published: Policy | null, reports?: { target: Policy; headline: string } | null, read = true): PolicyAdvice {
  if (!read)
    return { policy: 'none', reason: t("DNS non lu : partez de none si rien n'est publié ; sinon montez d'un cran depuis la politique en place, quand les rapports le permettent."), basis: 'unread' };
  if (reports) return { policy: reports.target, reason: reports.headline, basis: 'reports' };
  if (!published) return { policy: 'none', reason: t("Aucun DMARC publié : commencez en observation, lisez les rapports quelques semaines, puis montez d'un cran."), basis: 'none-published' };
  if (published === 'none')
    return { policy: 'quarantine', reason: t('p=none est publié : passez à quarantine une fois les rapports sans envoi légitime non aligné.'), basis: 'published' };
  if (published === 'quarantine') return { policy: 'reject', reason: t('p=quarantine est publié : passez à reject après quelques semaines de rapports sans anomalie.'), basis: 'published' };
  return { policy: 'reject', reason: t('p=reject est déjà la politique la plus protectrice : gardez-la.'), basis: 'published' };
}

/** The three steps of the progressive plan, with the settings of `m`. */
export function plan(m: DmarcModel): { policy: Policy; record: string }[] {
  return POLICIES.map((p) => ({ policy: p, record: buildDmarc({ ...m, p, t: false }) }));
}
