// SPF generator state: selected services, addresses, kept terms. Serialised in the URL so that a
// composed record can be shared or reopened; filled from the live DNS when the session allows it.
import { buildSpf, cleanIncludeTarget, emptyModel, parseSpfRecord, type AllQualifier, type BuiltSpf, type SpfInclude } from './spf-build';
import { t } from '../../lib/i18n';
import { providerByKey, providerOfInclude, providersFromMx, SPF_PROVIDERS } from './providers';

export interface Sel {
  key: string;
  on: boolean;
  /** How it got there: read in the published SPF, guessed from the MX, chosen. */
  via: 'spf' | 'mx' | 'user';
  /** Evidence for detected ones (MX host, include read). */
  evidence?: string;
  /** Service whose include normally lives elsewhere, added to this record anyway. */
  forced?: boolean;
  /** Account-specific include (HubSpot). */
  account?: string;
  /** Optional second include (Gandi web hosting). */
  extra?: boolean;
  /** Include actually used when it is a legitimate variant (mx.ovh.ca). */
  variant?: string;
  /** Lookups read from the live SPF tree. */
  dnsCost?: number;
}

export interface GenState {
  sels: Sel[];
  custom: SpfInclude[];
  ip4: string[];
  ip6: string[];
  a: boolean;
  mx: boolean;
  others: string[];
  all: AllQualifier;
  noMail: boolean;
  /** Notes about what the prefill changed (alias replaced...). */
  notes: string[];
}

export const initialState = (): GenState => ({ sels: [], custom: [], ip4: [], ip6: [], a: false, mx: false, others: [], all: '~', noMail: false, notes: [] });

/** Includes contributed by the selected services. */
export function selIncludes(s: Sel): SpfInclude[] {
  const p = providerByKey(s.key);
  if (!p || !s.on) return [];
  const out: SpfInclude[] = [];
  if (p.accountInclude) {
    const t = s.account ? cleanIncludeTarget(s.account) : undefined;
    if (t && p.accountInclude.pattern.test(t)) out.push({ domain: t, cost: s.dnsCost ?? 1, source: s.dnsCost !== undefined ? 'dns' : 'estimated', providerKey: p.key });
  } else if (p.include && (!p.elsewhere || s.forced)) {
    const domain = s.variant ?? p.include;
    out.push({ domain, cost: s.dnsCost ?? p.cost ?? 1, source: s.dnsCost !== undefined ? 'dns' : p.cost !== undefined ? 'reference' : 'estimated', providerKey: p.key });
  }
  if (p.extra && s.extra) out.push({ domain: p.extra.include, cost: p.extra.cost, source: 'reference', providerKey: p.key });
  return out;
}

export function build(st: GenState): BuiltSpf {
  return buildSpf({
    ...emptyModel(),
    ip4: st.ip4,
    ip6: st.ip6,
    a: st.a,
    mx: st.mx,
    includes: [...st.sels.flatMap(selIncludes), ...st.custom],
    others: st.others,
    all: st.all,
    noMail: st.noMail,
  });
}

/* ---------- live SPF tree (server shape) ---------- */
export interface TreeTerm {
  term: string;
  mechanism: string;
  target?: string;
  lookups: number;
  child?: { terms: TreeTerm[] };
}
/** Lookups of a term, its nested includes included. */
export function treeCost(t: TreeTerm, depth = 0): number {
  if (depth > 12) return t.lookups;
  return t.lookups + (t.child?.terms ?? []).reduce((n, c) => n + treeCost(c, depth + 1), 0);
}

/** State from the published record and the MX hosts. */
export function fromDns(record: string | undefined, tree: TreeTerm[] | undefined, mx: string[]): GenState {
  const st = initialState();
  const costs = new Map<string, number>();
  for (const t of tree ?? []) if (t.mechanism === 'include' && t.target) costs.set(t.target.toLowerCase(), treeCost(t));
  if (record) {
    const p = parseSpfRecord(record);
    st.ip4 = p.ip4;
    st.ip6 = p.ip6;
    st.a = p.a;
    st.mx = p.mx;
    st.others = p.others;
    st.all = p.all === '-' ? '-' : '~';
    if (p.all && p.all !== '-' && p.all !== '~') st.notes.push(p.all === '+' ? t('La règle finale publiée ({all}all) est remplacée par ~all : +all autorise tout le monde.', { all: p.all }) : t('La règle finale publiée ({all}all) est remplacée par ~all : ?all n’affirme rien.', { all: p.all }));
    for (const inc of p.includes) {
      const prov = providerOfInclude(inc);
      const dnsCost = costs.get(inc);
      if (!prov) {
        st.custom.push({ domain: inc, cost: dnsCost ?? 1, source: dnsCost !== undefined ? 'dns' : 'estimated' });
        continue;
      }
      const existing = st.sels.find((s) => s.key === prov.key);
      if (prov.extra?.include === inc) {
        if (existing) existing.extra = true;
        else st.sels.push({ key: prov.key, on: true, via: 'spf', evidence: `include:${inc}`, extra: true });
        continue;
      }
      if (existing) {
        st.notes.push(t('include:{inc} fait double emploi avec include:{existing} ({name}) : retiré, il coûtait une requête.', { inc, existing: existing.variant ?? prov.include, name: prov.name }));
        continue;
      }
      const sel: Sel = { key: prov.key, on: true, via: 'spf', evidence: `include:${inc}`, dnsCost };
      if (prov.accountInclude) sel.account = inc;
      else if (prov.aliases?.includes(inc)) {
        sel.dnsCost = undefined;
        st.notes.push(t('include:{inc} remplacé par include:{official}, la valeur officielle actuelle de {name}.', { inc, official: prov.include, name: prov.name }));
      } else if (inc !== prov.include) sel.variant = inc;
      if (prov.elsewhere) sel.forced = true;
      st.sels.push(sel);
    }
  }
  for (const { provider, host } of providersFromMx(mx)) {
    if (st.sels.some((s) => s.key === provider.key)) continue;
    st.sels.push({ key: provider.key, on: true, via: 'mx', evidence: `MX ${host.replace(/\.$/, '')}` });
  }
  return st;
}

/* ---------- URL ---------- */
const csv = (xs: string[]) => xs.join(',');
const list = (v: string | null) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : []);

export function toParams(st: GenState): Record<string, string> {
  const out: Record<string, string> = {};
  const on = st.sels.filter((s) => s.on);
  if (on.length)
    out.s = csv(on.map((s) => [s.key, s.forced ? '!' : '', s.extra ? '+' : '', s.variant ? `=${s.variant}` : '', s.account ? `=${s.account}` : ''].join('')));
  if (st.custom.length) out.inc = csv(st.custom.map((c) => c.domain));
  if (st.ip4.length || st.ip6.length) out.ip = csv([...st.ip4, ...st.ip6]);
  if (st.others.length) out.o = st.others.join(' ');
  if (st.a) out.a = '1';
  if (st.mx) out.mx = '1';
  if (st.all === '-') out.all = '-';
  if (st.noMail) out.nm = '1';
  return out;
}

export const STATE_PARAMS = ['s', 'inc', 'ip', 'o', 'a', 'mx', 'all', 'nm'];

export function fromParams(p: URLSearchParams): GenState | null {
  if (!STATE_PARAMS.some((k) => p.has(k))) return null;
  const st = initialState();
  for (const raw of list(p.get('s'))) {
    const m = /^([a-z0-9_]+)(!?)(\+?)(?:=(.+))?$/.exec(raw);
    if (!m || !providerByKey(m[1])) continue;
    const prov = providerByKey(m[1])!;
    const sel: Sel = { key: m[1], on: true, via: 'user', forced: !!m[2], extra: !!m[3] };
    if (m[4]) {
      if (prov.accountInclude) sel.account = m[4];
      else if (providerOfInclude(m[4])?.key === prov.key) sel.variant = m[4];
    }
    st.sels.push(sel);
  }
  for (const inc of list(p.get('inc'))) {
    const t = cleanIncludeTarget(inc);
    if (t) st.custom.push({ domain: t, cost: 1, source: 'estimated' });
  }
  for (const ip of list(p.get('ip'))) (ip.includes(':') ? st.ip6 : st.ip4).push(ip);
  st.others = (p.get('o') ?? '').split(/\s+/).filter(Boolean);
  st.a = p.get('a') === '1';
  st.mx = p.get('mx') === '1';
  st.all = p.get('all') === '-' ? '-' : '~';
  st.noMail = p.get('nm') === '1';
  return st;
}

/** Frequent services offered as one-click chips when not selected. */
export const FREQUENT = ['google_workspace', 'microsoft_365', 'brevo', 'ovh', 'o2switch', 'mailjet', 'infomaniak', 'sendgrid'];

export const ALL_KEYS = SPF_PROVIDERS.map((p) => p.key);
