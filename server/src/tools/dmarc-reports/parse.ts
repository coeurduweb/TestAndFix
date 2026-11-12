// Extraction (xml / gz / zip) and parsing of DMARC aggregate reports (RFC 7489 appendix C).
import { t } from '../../i18n.js';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { unzipSync } from 'fflate';
import { XMLParser } from 'fast-xml-parser';

export const MAX_XML_BYTES = 40 * 1024 * 1024;

export interface AuthDkim {
  domain: string;
  selector: string;
  result: string;
}
export interface AuthSpf {
  domain: string;
  scope: string;
  result: string;
}
export interface ReportRecord {
  ip: string;
  count: number;
  disposition: 'none' | 'quarantine' | 'reject' | string;
  /** policy_evaluated: DMARC-aligned DKIM / SPF result. */
  dkimAligned: boolean;
  spfAligned: boolean;
  headerFrom: string;
  envelopeFrom: string;
  dkim: AuthDkim[];
  spf: AuthSpf[];
  reasons: string[];
  /** Reverse DNS of `ip`, filled at upload time (null: none or not looked up). */
  ptr?: string | null;
}
export interface PolicyPublished {
  domain: string;
  p: string;
  sp: string;
  np: string;
  adkim: string;
  aspf: string;
  pct: number | null;
  testing: string;
}
export interface ParsedReport {
  orgName: string;
  email: string;
  reportId: string;
  /** Epoch ms. */
  dateBegin: number;
  dateEnd: number;
  policy: PolicyPublished;
  records: ReportRecord[];
  messages: number;
}

export class ReportError extends Error {}

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
  processEntities: true,
  isArray: (name) => ['record', 'dkim', 'spf', 'reason'].includes(name),
});

const str = (v: unknown): string => (v === undefined || v === null || typeof v === 'object' ? '' : String(v).trim());
const arr = <T>(v: T | T[] | undefined): T[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const lc = (v: unknown) => str(v).toLowerCase();
const num = (v: unknown): number => {
  const n = Number.parseInt(str(v), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};
function epochMs(v: unknown): number {
  const n = Number.parseInt(str(v), 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e12 ? n : n * 1000; // some generators emit milliseconds
}

type Obj = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Parse one XML document into a report. Throws ReportError with a message in French. */
export function parseReportXml(xml: string): ParsedReport {
  let doc: Obj;
  try {
    doc = parser.parse(xml.replace(/^﻿/, '')) as Obj;
  } catch {
    throw new ReportError(t("Ce fichier n'est pas un XML lisible."));
  }
  const fb = doc?.feedback as Obj | undefined;
  if (!fb || typeof fb !== 'object') throw new ReportError(t("Ce XML n'est pas un rapport DMARC agrégé (balise feedback absente)."));
  const meta = (fb.report_metadata ?? {}) as Obj;
  const pol = (fb.policy_published ?? {}) as Obj;
  const domain = lc(pol.domain);
  if (!domain) throw new ReportError(t('Rapport sans domaine (policy_published/domain).'));
  const range = (meta.date_range ?? {}) as Obj;
  const records: ReportRecord[] = [];
  for (const rec of arr<Obj>(fb.record)) {
    const row = (rec.row ?? {}) as Obj;
    const ev = (row.policy_evaluated ?? {}) as Obj;
    const ids = (rec.identifiers ?? rec.identities ?? {}) as Obj;
    const auth = (rec.auth_results ?? {}) as Obj;
    const ip = lc(row.source_ip);
    if (!ip) continue;
    records.push({
      ip,
      count: num(row.count),
      disposition: lc(ev.disposition) || 'none',
      dkimAligned: lc(arr(ev.dkim)[0]) === 'pass', // dkim/spf are forced to arrays for auth_results
      spfAligned: lc(arr(ev.spf)[0]) === 'pass',
      headerFrom: lc(ids.header_from) || domain,
      envelopeFrom: lc(ids.envelope_from),
      dkim: arr<Obj>(auth.dkim).map((d) => ({ domain: lc(d.domain), selector: str(d.selector), result: lc(d.result) })),
      spf: arr<Obj>(auth.spf).map((s) => ({ domain: lc(s.domain), scope: lc(s.scope), result: lc(s.result) })),
      reasons: arr<Obj>(ev.reason).map((r) => lc(r?.type)).filter(Boolean),
    });
  }
  const pct = Number.parseInt(str(pol.pct), 10);
  return {
    orgName: lc(meta.org_name),
    email: lc(meta.email),
    reportId: str(meta.report_id),
    dateBegin: epochMs(range.begin),
    dateEnd: epochMs(range.end),
    policy: {
      domain,
      p: lc(pol.p) || 'none',
      sp: lc(pol.sp),
      np: lc(pol.np),
      adkim: lc(pol.adkim) || 'r',
      aspf: lc(pol.aspf) || 'r',
      pct: Number.isFinite(pct) ? pct : null,
      testing: lc(pol.testing),
    },
    records,
    messages: records.reduce((n, r) => n + r.count, 0),
  };
}

/** Stable identity for a report with no report_id. */
export function contentId(xml: string): string {
  return 'sha1:' + crypto.createHash('sha1').update(xml).digest('hex');
}

export interface ExtractedXml {
  /** Display name: the file, or `archive.zip/inner.xml`. */
  name: string;
  xml?: string;
  error?: string;
}

const isGzip = (b: Uint8Array) => b.length > 2 && b[0] === 0x1f && b[1] === 0x8b;
const isZip = (b: Uint8Array) => b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5) && (b[3] === 4 || b[3] === 6);

/** At most this many documents per uploaded file. */
export const MAX_DOCUMENTS = 500;

/**
 * Turn an uploaded file (xml, gz, zip, zip of gz) into XML documents. Never throws.
 * One budget for the whole file, counted on the bytes really decompressed, nested archives included
 * (code review of 2026-11-12: a zip of small gzip bombs passed a cap that only counted the zip's
 * declared sizes, then each .gz expanded to 40 MB on its own).
 */
export function extractXml(name: string, buf: Buffer, depth = 0, budget = { bytes: MAX_XML_BYTES, docs: MAX_DOCUMENTS }): ExtractedXml[] {
  try {
    if (isGzip(buf)) {
      if (budget.bytes <= 0) throw new Error(t('zip trop volumineux une fois décompressé'));
      let inner: Buffer;
      try {
        inner = zlib.gunzipSync(buf, { maxOutputLength: budget.bytes });
      } catch (e) {
        if ((e as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') throw new Error(t('zip trop volumineux une fois décompressé'));
        throw e;
      }
      budget.bytes -= inner.length;
      return depth < 2 ? extractXml(name, inner, depth + 1, budget) : [{ name, error: t('Archives imbriquées trop profondes.') }];
    }
    if (isZip(buf)) {
      if (depth >= 2) return [{ name, error: t('Archives imbriquées trop profondes.') }];
      let declared = 0;
      const files = unzipSync(new Uint8Array(buf), {
        filter: (f) => {
          if (f.name.endsWith('/') || f.name.startsWith('__MACOSX/') || /(^|\/)\.[^/]*$/.test(f.name)) return false;
          declared += f.originalSize;
          if (declared > budget.bytes) throw new Error(t('zip trop volumineux une fois décompressé'));
          return true;
        },
      });
      const out: ExtractedXml[] = [];
      const names = Object.keys(files);
      if (!names.length) return [{ name, error: t("L'archive ne contient aucun fichier.") }];
      // the declared sizes can lie: count what was really decompressed
      const real = names.reduce((n, k) => n + files[k].length, 0);
      if (real > budget.bytes) throw new Error(t('zip trop volumineux une fois décompressé'));
      budget.bytes -= real;
      for (const n of names) {
        if (--budget.docs < 0) throw new Error(t('trop de fichiers dans l’archive'));
        for (const e of extractXml(n, Buffer.from(files[n]), depth + 1, budget)) out.push({ ...e, name: `${name}/${e.name}` });
      }
      return out;
    }
    const text = buf.toString('utf8');
    if (!/<\s*feedback[\s>]|<\?xml/i.test(text.slice(0, 4096)) && !text.includes('<feedback')) {
      return [{ name, error: t('Format non reconnu : ni XML, ni .gz, ni .zip contenant du XML.') }];
    }
    return [{ name, xml: text }];
  } catch (e) {
    const msg = (e as Error).message;
    return [{ name, error: t('Fichier illisible ({msg}).', { msg }) }];
  }
}
