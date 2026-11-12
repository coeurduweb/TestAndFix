// BIMI: default._bimi record, SVG logo (SVG Tiny PS profile), VMC/CMC certificate, DMARC prerequisite.
import type { PassedCheck } from '../../tools/types.js';
import { X509Certificate, createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import type { SafeFetchResult } from '../net.js';
import { httpGet } from './http.js';
import { issue, lookupTxt, orgDomain, parseTags, pass, type Analysis, type Issue, type Resolver } from './common.js';
import { analyzeDmarc, type DmarcData } from './dmarc.js';
import { t } from '../../i18n.js';

export interface SvgCheck {
  url: string;
  status?: number;
  contentType?: string;
  bytes?: number;
  sha256?: string;
  error?: string;
  baseProfile?: string;
  version?: string;
  title?: string;
  viewBox?: string;
  square?: boolean;
  /** Violations of the SVG Tiny PS profile (MUST). */
  problems: string[];
  /** Recommendations of the draft, Google or the BIMI Group (SHOULD). */
  warnings: string[];
  /** Subset of `warnings` about the size or shape of the logo (language independent). */
  sizeWarnings?: string[];
}

export interface VmcCheck {
  url: string;
  status?: number;
  error?: string;
  certificates: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    san: string[];
    fingerprint256: string;
    ca: boolean;
  }[];
  /** Leaf certificate type, from its extended key usage and policies. */
  kind?: 'VMC' | 'CMC' | 'inconnu';
  /** subject:markType (Registered Mark, Prior Use Mark…). */
  markType?: string;
  markPolicy?: boolean;
  bimiEku?: boolean;
  /** Logo embedded in the certificate (logotype extension), decoded. */
  logotype?: { found: boolean; sha256?: string; matchesSvg?: boolean };
  coversDomain?: boolean;
  /** Each certificate signed by the next one in the file. */
  chainLinked?: boolean;
  expired?: boolean;
  daysLeft?: number;
  problems: string[];
}

export interface BimiData {
  domain: string;
  selector: string;
  name: string;
  foundAt?: string;
  inherited: boolean;
  record?: string;
  records: string[];
  logoUrl?: string;
  authorityUrl?: string;
  declined: boolean;
  svg?: SvgCheck;
  vmc?: VmcCheck;
  dmarc?: Pick<DmarcData, 'record' | 'policy' | 'effectivePolicy' | 'subdomainPolicy' | 'pct' | 'foundAt'>;
  dmarcEligible?: boolean;
}

export interface BimiAnalysis extends Analysis {
  data: BimiData;
}

export const SVG_MAX_BYTES = 32 * 1024;

// draft-svg-tiny-ps-abrotman-13 §2.3: image, switch, multimedia, interactivity, linking,
// scripting and animation MUST NOT be present.
const FORBIDDEN_ELEMENTS = [
  'script', 'handler', 'listener', 'image', 'switch', 'video', 'audio', 'animation', 'a',
  'animate', 'animatemotion', 'animatetransform', 'animatecolor', 'set', 'discard',
];
// §2.3: SHOULD be absent; when present MUST have this value.
const RESTRICTED_ATTRS: Record<string, string> = {
  zoomAndPan: 'disable',
  externalResourcesRequired: 'false',
  focusable: 'false',
  snapshotTime: 'none',
  playbackOrder: 'all',
  timelineBegin: 'onLoad',
};

/** Static checks of the SVG Tiny Portable/Secure profile, without a full XML parser. */
export function checkSvgTinyPs(svgText: string): Omit<SvgCheck, 'url'> {
  const out: Omit<SvgCheck, 'url'> = { problems: [], warnings: [], sizeWarnings: [] };
  const text = svgText.replace(/<!--[\s\S]*?-->/g, '');
  if (/<!DOCTYPE[^>]*\[/i.test(text) || /<!ENTITY/i.test(text)) out.problems.push(t('déclaration DOCTYPE ou ENTITY interne'));
  const root = /<svg\b([^>]*)>/i.exec(text);
  if (!root) {
    out.problems.push(t('aucun élément <svg> racine'));
    return out;
  }
  const attrs = root[1];
  const attr = (n: string, where = attrs) => new RegExp(`(?:^|\\s)${n}\\s*=\\s*(["'])(.*?)\\1`, 'i').exec(where)?.[2];
  out.baseProfile = attr('baseProfile');
  out.version = attr('version');
  out.viewBox = attr('viewBox');
  if (out.baseProfile !== 'tiny-ps') out.problems.push(out.baseProfile ? t('baseProfile="{value}" au lieu de "tiny-ps"', { value: out.baseProfile }) : t('attribut baseProfile="tiny-ps" absent'));
  if (out.version !== '1.2') out.problems.push(out.version ? t('version="{value}" au lieu de "1.2"', { value: out.version }) : t('attribut version="1.2" absent'));
  if (attr('xmlns') !== 'http://www.w3.org/2000/svg') out.problems.push(t('espace de noms xmlns="http://www.w3.org/2000/svg" absent'));
  if (attr('x') !== undefined || attr('y') !== undefined) out.problems.push(t('attributs x= ou y= sur l’élément <svg> racine'));
  const titles = [...text.matchAll(/<title\b[^>]*>([\s\S]*?)<\/title>/gi)];
  out.title = titles[0]?.[1].trim();
  if (!out.title) out.problems.push(t('élément <title> absent ou vide'));
  else {
    if (titles.length > 1) out.problems.push(t('plusieurs éléments <title>'));
    if (out.title.length > 64) out.warnings.push(t('titre de {n} caractères (64 au plus recommandés)', { n: out.title.length }));
  }
  const desc = /<desc\b[^>]*>([\s\S]*?)<\/desc>/i.exec(text);
  if (desc && !desc[1].trim()) out.problems.push(t('élément <desc> vide'));
  if (!desc) out.warnings.push(t('élément <desc> absent (Google recommande de l’ajouter)'));
  for (const el of FORBIDDEN_ELEMENTS) {
    if (new RegExp(`<(?:[a-z]+:)?${el}[\\s>/]`, 'i').test(text)) out.problems.push(t('élément <{el}> interdit', { el }));
  }
  for (const [name, value] of Object.entries(RESTRICTED_ATTRS)) {
    for (const m of text.matchAll(new RegExp(`\\s${name}\\s*=\\s*(["'])(.*?)\\1`, 'gi')))
      if (m[2] !== value) out.problems.push(t('{name}="{found}" (seule la valeur "{value}" est permise)', { name, found: m[2], value }));
  }
  if (/\son[a-z]+\s*=/i.test(text)) out.problems.push(t('attribut d’événement (onload, onclick…)'));
  const hrefs = [...text.matchAll(/(?:xlink:)?href\s*=\s*(["'])(.*?)\1/gi)].map((m) => m[2]);
  const external = hrefs.filter((h) => !h.startsWith('#'));
  if (external.length) out.problems.push(t('référence externe : {value}', { value: external.slice(0, 3).join(', ') }));
  if (/url\(\s*['"]?(?!#)/i.test(text)) out.problems.push(t('url() vers une ressource externe dans un style'));
  if (out.viewBox) {
    const vb = out.viewBox.trim().split(/[\s,]+/).map(Number);
    if (vb.length === 4 && vb.every(Number.isFinite)) out.square = Math.abs(vb[2] - vb[3]) < 1e-6;
  } else {
    const w = Number.parseFloat(attr('width') ?? '');
    const h = Number.parseFloat(attr('height') ?? '');
    if (Number.isFinite(w) && Number.isFinite(h)) out.square = w === h;
  }
  if (out.square === false) {
    const w = t('logo non carré (viewBox {viewBox}) : Google et le BIMI Group recommandent un carré', { viewBox: out.viewBox ?? t('absente') });
    out.warnings.push(w);
    out.sizeWarnings!.push(w);
  }
  if (/%\s*$/.test(attr('width') ?? '') || /%\s*$/.test(attr('height') ?? '')) {
    const w = t('dimensions en pourcentage : Gmail demande des pixels absolus');
    out.warnings.push(w);
    out.sizeWarnings!.push(w);
  }
  return out;
}

// --- certificates

const OID_BIMI_EKU = Buffer.from('06082b0601050507031f', 'hex'); // 1.3.6.1.5.5.7.3.31
const OID_LOGOTYPE = Buffer.from('06082b060105050701' + '0c', 'hex'); // 1.3.6.1.5.5.7.1.12
const OID_MARK_POLICY = Buffer.from('060a2b06010401839e5f0101', 'hex'); // 1.3.6.1.4.1.53087.1.1
const OID_MARK_TYPE = Buffer.from('060a2b06010401839e5f010d', 'hex'); // 1.3.6.1.4.1.53087.1.13

// BIMI Group, Minimum Security Requirements for Issuance of Mark Certificates v1.8, §7.1.4
const MARK_TYPES: Record<string, 'VMC' | 'CMC'> = {
  'registered mark': 'VMC',
  'government mark': 'VMC',
  'prior use mark': 'CMC',
  'modified registered mark': 'CMC',
  'provisional mark': 'CMC',
};

/** Value of the subject:markType attribute (a string right after its OID in the DER). */
export function markTypeOf(der: Buffer): string | undefined {
  const i = der.indexOf(OID_MARK_TYPE);
  if (i < 0) return undefined;
  const p = i + OID_MARK_TYPE.length;
  const tag = der[p];
  const len = der[p + 1];
  if (![0x0c, 0x13, 0x16].includes(tag) || len >= 0x80) return undefined;
  return der.subarray(p + 2, p + 2 + len).toString('utf8');
}

function derContains(der: Buffer, needle: Buffer): boolean {
  return der.indexOf(needle) >= 0;
}

/** Extract the SVG embedded as a data: URI in the logotype extension (RFC 3709, RFC 6170). */
export function extractLogotype(der: Buffer): Buffer | undefined {
  const s = der.toString('latin1');
  const m = /data:image\/svg\+xml;base64,([A-Za-z0-9+/=]+)/.exec(s);
  if (!m) return undefined;
  const raw = Buffer.from(m[1], 'base64');
  try {
    return raw[0] === 0x1f && raw[1] === 0x8b ? gunzipSync(raw) : raw;
  } catch {
    return undefined;
  }
}

export function splitPem(pem: string): string[] {
  return [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map((m) => m[0]);
}

export function checkVmc(pem: string, domain: string, svgSha?: string, now = Date.now()): Omit<VmcCheck, 'url'> {
  const out: Omit<VmcCheck, 'url'> = { certificates: [], problems: [] };
  const blocks = splitPem(pem);
  if (!blocks.length) {
    out.problems.push(t('aucun certificat PEM dans le fichier'));
    return out;
  }
  let certs: X509Certificate[];
  try {
    certs = blocks.map((b) => new X509Certificate(b));
  } catch (e) {
    out.problems.push(t('certificat illisible : {error}', { error: (e as Error).message }));
    return out;
  }
  out.certificates = certs.map((c) => ({
    subject: c.subject.replace(/\n/g, ', '),
    issuer: c.issuer.replace(/\n/g, ', '),
    validFrom: new Date(c.validFrom).toISOString(),
    validTo: new Date(c.validTo).toISOString(),
    serialNumber: c.serialNumber,
    san: (c.subjectAltName ?? '').split(',').map((x) => x.trim()).filter((x) => x.startsWith('DNS:')).map((x) => x.slice(4).toLowerCase()),
    fingerprint256: c.fingerprint256,
    ca: c.ca,
  }));
  const leaf = certs.find((c) => !c.ca) ?? certs[0];
  const der = leaf.raw;
  out.bimiEku = derContains(der, OID_BIMI_EKU);
  if (!out.bimiEku) out.problems.push(t('le certificat n’a pas l’usage étendu BIMI (1.3.6.1.5.5.7.3.31)'));
  const hasLogo = derContains(der, OID_LOGOTYPE);
  const logo = hasLogo ? extractLogotype(der) : undefined;
  out.logotype = { found: !!logo };
  if (logo) {
    out.logotype.sha256 = createHash('sha256').update(logo).digest('hex');
    if (svgSha) out.logotype.matchesSvg = out.logotype.sha256 === svgSha;
  } else out.problems.push(t('aucun logo intégré au certificat (extension logotype)'));
  out.markType = markTypeOf(der);
  out.markPolicy = derContains(der, OID_MARK_POLICY);
  out.kind = (out.markType ? MARK_TYPES[out.markType.toLowerCase()] : undefined) ?? 'inconnu';
  if (!out.markPolicy) out.problems.push(t('politique « Mark Certificate General Policy » (1.3.6.1.4.1.53087.1.1) absente'));
  const leafInfo = out.certificates[certs.indexOf(leaf)];
  const vt = Date.parse(leafInfo.validTo);
  out.daysLeft = Math.floor((vt - now) / 86400000);
  out.expired = vt < now || Date.parse(leafInfo.validFrom) > now;
  if (out.expired) out.problems.push(t('certificat hors de sa période de validité ({from} au {to})', { from: leafInfo.validFrom.slice(0, 10), to: leafInfo.validTo.slice(0, 10) }));
  out.coversDomain = leafInfo.san.some((s) => s === domain || s === orgDomain(domain) || (s.startsWith('*.') && domain.endsWith(s.slice(1))));
  if (!out.coversDomain) out.problems.push(t('le certificat ne couvre pas {domain} (SAN : {san})', { domain, san: leafInfo.san.join(', ') || t('aucun') }));
  let linked = true;
  for (let i = 0; i < certs.length - 1; i++) {
    try {
      if (!certs[i].checkIssued(certs[i + 1]) || !certs[i].verify(certs[i + 1].publicKey)) linked = false;
    } catch {
      linked = false;
    }
  }
  out.chainLinked = certs.length > 1 ? linked : undefined;
  if (certs.length === 1) out.problems.push(t('le fichier ne contient que le certificat final, sans la chaîne de l’autorité'));
  else if (!linked) out.problems.push(t('les certificats du fichier ne forment pas une chaîne'));
  return out;
}

async function follow(fetcher: Fetcher, url: string, maxBytes: number): Promise<SafeFetchResult> {
  let current = url;
  for (let hop = 0; hop < 4; hop++) {
    const r = await fetcher(current, maxBytes);
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      const next = new URL(r.headers.location, current);
      if (next.protocol !== 'https:') throw new Error(t('redirection vers {protocol} refusée', { protocol: next.protocol }));
      current = next.toString();
      continue;
    }
    return r;
  }
  throw new Error(t('trop de redirections'));
}

export type Fetcher = (url: string, maxBytes: number) => Promise<SafeFetchResult>;

export interface BimiOptions {
  selector?: string;
  fetcher?: Fetcher;
  session?: Resolver;
  now?: number;
}

export async function analyzeBimi(dns: Resolver, domain: string, opts: BimiOptions = {}): Promise<BimiAnalysis> {
  const selector = (opts.selector ?? 'default').toLowerCase();
  const fetcher: Fetcher = opts.fetcher ?? ((url, maxBytes) => httpGet(url, { session: opts.session, maxBytes }));
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const name = `${selector}._bimi.${domain}`;
  const data: BimiData = { domain, selector, name, inherited: false, records: [], declined: false };
  const org = orgDomain(domain);
  const [own, dmarc] = await Promise.all([lookupTxt(dns, name), analyzeDmarc(dns, domain)]);
  let txt = own;
  data.foundAt = name;
  let recs = txt.records.filter((r) => /^v\s*=\s*BIMI1\b/i.test(r.trim()));
  if (!recs.length && org !== domain && !txt.error) {
    const up = await lookupTxt(dns, `${selector}._bimi.${org}`);
    const upRecs = up.records.filter((r) => /^v\s*=\s*BIMI1\b/i.test(r.trim()));
    if (upRecs.length) {
      txt = up;
      recs = upRecs;
      data.inherited = true;
      data.foundAt = `${selector}._bimi.${org}`;
    }
  }
  data.records = recs;
  const d = dmarc.data;
  data.dmarc = { record: d.record, policy: d.policy, effectivePolicy: d.effectivePolicy, subdomainPolicy: d.subdomainPolicy, pct: d.pct, foundAt: d.foundAt };
  // draft-brand-indicators-for-message-identification-15 §4.1 and receiver steps 7 to 9:
  // quarantine with pct=100 or reject, on the From domain and the organizational domain, sp not none.
  const spNone = d.tags.some((t) => t.name === 'sp' && !t.implicit && t.value.trim().toLowerCase() === 'none');
  let orgPolicy = d.inherited || org === domain ? d.policy : undefined;
  if (!d.inherited && org !== domain) orgPolicy = (await analyzeDmarc(dns, org)).data.policy;
  data.dmarcEligible =
    !!d.effectivePolicy && d.effectivePolicy !== 'none' && !(d.effectivePolicy === 'quarantine' && d.pct !== 100) && !spNone && orgPolicy !== 'none' && orgPolicy !== undefined;
  if (txt.error) return { issues, passed, unavailable: [{ source: 'dns', reason: t('{name} : {error}', { name, error: txt.error }) }], data };
  if (!recs.length) {
    data.foundAt = undefined;
    // bimi.missing tells "your DMARC is enforced": only true when it is (base entry, detect.signal)
    const suggested = `v=BIMI1; l=https://${domain}/bimi/logo.svg; a=https://${domain}/bimi/certificat.pem`;
    if (data.dmarcEligible) issues.push(issue('bimi.missing', { domain }, { suggested }));
    else issues.push(issue('bimi.missing_dmarc_not_enforced', { domain, value: dmarcSummary(d) }));
    return { issues, passed, data };
  }
  if (recs.length > 1) issues.push(issue('bimi.syntax_invalid', { domain, value: recs.length }, { evidence: recs.join('\n') }));
  const record = recs[0];
  data.record = record;
  const ev = `${data.foundAt} : ${record}`;
  const { tags, errors } = parseTags(record);
  const get = (n: string) => tags.find((t) => t.name === n)?.value.trim();
  if (errors.length || tags[0]?.name !== 'v' || tags[0].value !== 'BIMI1')
    issues.push(issue('bimi.syntax_invalid', { domain, value: errors.length ? t('balise illisible « {value} »', { value: errors.join(' ; ') }) : t('v=BIMI1 doit être la première balise') }, { evidence: ev }));
  data.logoUrl = get('l') || undefined;
  data.authorityUrl = get('a') || undefined;
  data.declined = get('l') === '' && !data.authorityUrl;
  if (data.declined) {
    issues.push(issue('bimi.declined', { domain }, { evidence: ev }));
    return { issues, passed, data };
  }
  const dev = d.record ? `${d.foundAt} : ${d.record}` : t('aucun DMARC');
  const dv = { domain, dmarc_record: d.record, value: dmarcSummary(d) };
  if (!d.effectivePolicy || d.effectivePolicy === 'none' || orgPolicy === 'none' || orgPolicy === undefined) issues.push(issue('bimi.dmarc_not_enforced', dv, { evidence: dev }));
  else if (d.effectivePolicy === 'quarantine' && d.pct !== 100) issues.push(issue('bimi.dmarc_pct_below_100', dv, { evidence: dev }));
  if (spNone) issues.push(issue('bimi.dmarc_subdomain_none', dv, { evidence: dev }));
  if (data.dmarcEligible) passed.push(pass('bimi.dmarc', 'bimi', d.effectivePolicy === 'quarantine' ? t('DMARC compatible BIMI ({policy}, pct=100)', { policy: d.effectivePolicy }) : t('DMARC compatible BIMI ({policy})', { policy: d.effectivePolicy })));

  // SVG
  if (!data.logoUrl) issues.push(issue('bimi.syntax_invalid', { domain, value: t('balise l= absente ou vide') }, { evidence: ev }));
  else if (!/^https:\/\//i.test(data.logoUrl)) issues.push(issue('bimi.logo_not_https', { domain, url: data.logoUrl }, { evidence: ev }));
  let svgSha: string | undefined;
  if (data.logoUrl && /^https:\/\//i.test(data.logoUrl)) {
    const svg: SvgCheck = { url: data.logoUrl, problems: [], warnings: [] };
    data.svg = svg;
    try {
      const r = await follow(fetcher, data.logoUrl, SVG_MAX_BYTES * 4);
      svg.status = r.status;
      svg.contentType = r.headers['content-type'];
      svg.bytes = r.body.length;
      if (r.status !== 200) {
        svg.error = `HTTP ${r.status}`;
        issues.push(issue('bimi.logo_unreachable', { domain, url: data.logoUrl, value: svg.error }, { evidence: `${data.logoUrl} : ${svg.error}` }));
      } else {
        let body = r.body;
        if (body[0] === 0x1f && body[1] === 0x8b) {
          try {
            body = gunzipSync(body);
          } catch {
            /* keep raw */
          }
        }
        svgSha = createHash('sha256').update(body).digest('hex');
        svg.sha256 = svgSha;
        Object.assign(svg, checkSvgTinyPs(body.toString('utf8')), { url: data.logoUrl, status: r.status, contentType: svg.contentType, bytes: svg.bytes, sha256: svgSha });
        if (r.truncated || body.length > SVG_MAX_BYTES) {
          const w = t('fichier de {size} Ko décompressé, au-delà des {max} Ko recommandés', { size: Math.round(body.length / 1024), max: SVG_MAX_BYTES / 1024 });
          svg.warnings.push(w);
          (svg.sizeWarnings ??= []).push(w);
        }
        const profile = svg.problems.filter((p) => /baseProfile|version=|xmlns|<title>/.test(p));
        const content = svg.problems.filter((p) => !profile.includes(p));
        if (profile.length) issues.push(issue('bimi.svg_not_tiny_ps', { domain, url: data.logoUrl, value: profile.join(' ; ') }, { evidence: profile.join('\n') }));
        if (content.length) issues.push(issue('bimi.svg_forbidden_content', { domain, url: data.logoUrl, value: content.join(' ; ') }, { evidence: content.join('\n') }));
        const sizeW = svg.warnings.filter((w) => svg.sizeWarnings?.includes(w));
        const otherW = svg.warnings.filter((w) => !sizeW.includes(w));
        if (sizeW.length) issues.push(issue('bimi.logo_size', { domain, url: data.logoUrl, value: sizeW.join(' ; ') }, { evidence: sizeW.join('\n') }));
        if (otherW.length) issues.push(issue('bimi.svg_recommendation', { domain, url: data.logoUrl, value: otherW.join(' ; ') }, { evidence: otherW.join('\n') }));
        if (!svg.problems.length) passed.push(pass('bimi.svg', 'bimi', t('Logo SVG conforme au profil SVG Tiny PS'), t('{size} Ko', { size: Math.round(svg.bytes! / 102.4) / 10 })));
      }
    } catch (e) {
      svg.error = (e as Error).message;
      issues.push(issue('bimi.logo_unreachable', { domain, url: data.logoUrl, value: svg.error }, { evidence: `${data.logoUrl} : ${svg.error}` }));
    }
  }

  // certificate
  if (!data.authorityUrl) {
    issues.push(issue('bimi.no_certificate', { domain }, { evidence: ev }));
  } else if (!/^https:\/\//i.test(data.authorityUrl)) {
    issues.push(issue('bimi.certificate_invalid', { domain, url: data.authorityUrl, value: t('l’URL a= doit être en https') }, { evidence: ev }));
  } else {
    const vmc: VmcCheck = { url: data.authorityUrl, certificates: [], problems: [] };
    data.vmc = vmc;
    try {
      const r = await follow(fetcher, data.authorityUrl, 512 * 1024);
      vmc.status = r.status;
      if (r.status !== 200) {
        vmc.error = `HTTP ${r.status}`;
        issues.push(issue('bimi.certificate_invalid', { domain, url: data.authorityUrl, value: vmc.error }, { evidence: `${data.authorityUrl} : ${vmc.error}` }));
      } else {
        Object.assign(vmc, checkVmc(r.body.toString('utf8'), data.inherited ? org : domain, svgSha, opts.now), { url: data.authorityUrl, status: r.status });
        if (vmc.logotype?.matchesSvg === false)
          issues.push(issue('bimi.certificate_logo_mismatch', { domain, url: data.logoUrl }, { evidence: `${t('SHA-256 du logo du certificat : {hash}', { hash: vmc.logotype.sha256 })}\n${t('SHA-256 du fichier l= : {hash}', { hash: svgSha })}` }));
        if (vmc.problems.length) issues.push(issue('bimi.certificate_invalid', { domain, url: data.authorityUrl, value: vmc.problems.join(' ; ') }, { evidence: vmc.problems.join('\n') }));
        if (vmc.kind === 'CMC') issues.push(issue('bimi.cmc_no_checkmark', { domain, value: vmc.markType }, { evidence: `markType : ${vmc.markType}` }));
        if (!vmc.problems.length) passed.push(pass('bimi.vmc', 'bimi', t('Certificat de marque lisible et cohérent'), vmc.certificates[0]?.issuer));
      }
    } catch (e) {
      vmc.error = (e as Error).message;
      issues.push(issue('bimi.certificate_invalid', { domain, url: data.authorityUrl, value: vmc.error }, { evidence: `${data.authorityUrl} : ${vmc.error}` }));
    }
  }
  return { issues, passed, data };
}

function dmarcSummary(d: DmarcData): string {
  if (!d.record) return t('aucun enregistrement DMARC');
  return t('politique {policy}, pct={pct}', { policy: d.effectivePolicy ?? t('absente'), pct: d.pct });
}
