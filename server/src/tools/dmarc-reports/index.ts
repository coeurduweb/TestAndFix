// DMARC aggregate report analyzer: upload (xml / gz / zip), storage, per-source verdicts, aggregate view.
import { t } from '../../i18n.js';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { newId, saveResult, type DB } from '../../db.js';
import { scoreOf } from '../../knowledge/engine.js';
import { isPublicIp, reverseName } from '../../lib/net.js';
import { days, now } from '../../lib/time.js';
import { currentOwnerId } from '../../owner.js';
import type { CheckResult, ServerTool, ToolContext } from '../types.js';
import { aggregate, buildFindings, recommend, type Aggregate, type Recommendation, type StoredReport } from './analyze.js';
import { contentId, extractXml, parseReportXml, ReportError, type ParsedReport } from './parse.js';

export const RETENTION_DAYS = 90;
const MAX_PTR_LOOKUPS = 200;
const PTR_CONCURRENCY = 8;

export interface FileOutcome {
  file: string;
  status: 'imported' | 'duplicate' | 'error';
  error?: string;
  id?: string;
  domain?: string;
  orgName?: string;
  reportId?: string;
  dateBegin?: string;
  dateEnd?: string;
  messages?: number;
  sources?: number;
}

export interface UploadData {
  files: FileOutcome[];
  summary: { files: number; imported: number; duplicates: number; errors: number; messages: number };
  /** Domain with the most messages among the files read (imported or duplicate). */
  domain: string | null;
  aggregate: Aggregate | null;
  recommendation: Recommendation | null;
}

export interface QueryData {
  domain: string | null;
  aggregate: Aggregate | null;
  recommendation: Recommendation | null;
  findings: CheckResult['findings'];
  passed: CheckResult['passed'];
  score: number | null;
  reports: { id: string; orgName: string; reportId: string; dateBegin: string | null; dateEnd: string | null; messages: number }[];
}

interface InputFile {
  name: string;
  buf: Buffer;
  error?: string;
}

async function ptrLookup(ctx: ToolContext, ips: string[]): Promise<{ ptr: Map<string, string | null>; failed: number }> {
  const session = ctx.dns();
  const ptr = new Map<string, string | null>();
  let failed = 0;
  const queue = ips.filter(isPublicIp).slice(0, MAX_PTR_LOOKUPS);
  const worker = async () => {
    for (let ip = queue.shift(); ip; ip = queue.shift()) {
      try {
        const r = await session.resolve(reverseName(ip), 'PTR');
        const a = r.answers.find((x) => x.type === 'PTR');
        ptr.set(ip, a ? String(a.data).replace(/\.$/, '').toLowerCase() : null);
      } catch {
        failed++;
        ptr.set(ip, null);
      }
    }
  };
  await Promise.all(Array.from({ length: PTR_CONCURRENCY }, worker));
  return { ptr, failed };
}

/** Reports of one notebook (owner.ts). */
function loadRows(db: DB, ownerId: string | null, domain?: string, from?: number, to?: number): StoredReport[] {
  const where: string[] = ['owner_id = ?'];
  const args: (string | number | null)[] = [ownerId];
  if (domain) { where.push('domain = ?'); args.push(domain.toLowerCase()); }
  if (from !== undefined) { where.push('date_begin >= ?'); args.push(from); }
  if (to !== undefined) { where.push('date_begin <= ?'); args.push(to); }
  const sql = `SELECT id, created_at, domain, data FROM dmarc_reports WHERE ${where.join(' AND ')} ORDER BY date_begin`;
  const rows = db.prepare(sql).all(...args) as { id: string; created_at: number; domain: string; data: string }[];
  const out: StoredReport[] = [];
  for (const r of rows) {
    try {
      out.push({ id: r.id, createdAt: r.created_at, domain: r.domain, report: JSON.parse(r.data) as ParsedReport });
    } catch {
      /* a corrupted row is skipped, never fatal */
    }
  }
  return out;
}

function mainDomain(rows: StoredReport[]): string | null {
  const m = new Map<string, number>();
  for (const r of rows) m.set(r.domain, (m.get(r.domain) ?? 0) + r.report.messages);
  return [...m.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
}

function analysisFor(rows: StoredReport[], domain: string | null) {
  if (!domain) return { aggregate: null, recommendation: null, findings: [], passed: [], score: null as number | null };
  const agg = aggregate(rows, domain);
  const { findings, passed } = buildFindings(agg);
  return { aggregate: agg, recommendation: recommend(agg), findings, passed, score: scoreOf(findings) as number | null };
}

/** Accepts 2026-10-01, an ISO date-time or epoch ms. `endOfDay` makes a bare date inclusive. */
function parseDate(v: unknown, endOfDay: boolean): number | undefined | 'invalid' {
  if (v === undefined || v === '') return undefined;
  const s = String(v).trim();
  if (/^\d{12,}$/.test(s)) return Number(s);
  const t = Date.parse(s);
  if (Number.isNaN(t)) return 'invalid';
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && endOfDay ? t + days(1) - 1 : t;
}

async function readInputs(app: FastifyInstance, req: import('fastify').FastifyRequest): Promise<InputFile[]> {
  void app;
  const files: InputFile[] = [];
  if (req.isMultipart()) {
    for await (const part of req.parts()) {
      if (part.type !== 'file') continue;
      const name = part.filename || 'rapport';
      try {
        const buf = await part.toBuffer();
        if ((part.file as { truncated?: boolean }).truncated) files.push({ name, buf, error: t('Fichier trop volumineux (30 Mo maximum).') });
        else files.push({ name, buf });
      } catch (e) {
        files.push({ name, buf: Buffer.alloc(0), error: t('Lecture impossible ({msg}).', { msg: (e as Error).message }) });
      }
    }
  } else if (Buffer.isBuffer(req.body) && req.body.length) {
    files.push({ name: t('corps de la requête'), buf: req.body });
  } else if (typeof req.body === 'string' && req.body.length) {
    files.push({ name: t('corps de la requête'), buf: Buffer.from(req.body) });
  }
  return files;
}

/** Upload into the notebook of the request being served; the duplicate check is per notebook. */
export async function processUpload(ctx: ToolContext, inputs: InputFile[], ownerId: string | null = currentOwnerId()): Promise<CheckResult<UploadData>> {
  const started = Date.now();
  const outcomes: FileOutcome[] = [];
  const fresh: { outcome: FileOutcome; report: ParsedReport }[] = [];
  const touched: { domain: string; messages: number }[] = [];
  const seen = new Set<string>();
  const exists = ctx.db.prepare('SELECT id FROM dmarc_reports WHERE owner_id = ? AND org_name = ? AND report_id = ?');

  for (const input of inputs) {
    if (input.error) { outcomes.push({ file: input.name, status: 'error', error: input.error }); continue; }
    for (const part of extractXml(input.name, input.buf)) {
      if (part.error || !part.xml) { outcomes.push({ file: part.name, status: 'error', error: part.error ?? 'Fichier vide.' }); continue; }
      try {
        const report = parseReportXml(part.xml);
        const reportId = report.reportId || contentId(part.xml);
        report.reportId = reportId;
        const outcome: FileOutcome = {
          file: part.name, status: 'imported', domain: report.policy.domain, orgName: report.orgName, reportId,
          dateBegin: report.dateBegin ? new Date(report.dateBegin).toISOString() : undefined,
          dateEnd: report.dateEnd ? new Date(report.dateEnd).toISOString() : undefined,
          messages: report.messages, sources: new Set(report.records.map((r) => r.ip)).size,
        };
        touched.push({ domain: report.policy.domain, messages: report.messages });
        const key = `${report.orgName}\u0000${reportId}`;
        const dup = exists.get(ownerId, report.orgName, reportId) as { id: string } | undefined;
        if (dup || seen.has(key)) {
          outcomes.push({ ...outcome, status: 'duplicate', id: dup?.id });
          continue;
        }
        seen.add(key);
        outcomes.push(outcome);
        fresh.push({ outcome, report });
      } catch (e) {
        outcomes.push({ file: part.name, status: 'error', error: e instanceof ReportError ? e.message : `Rapport illisible (${(e as Error).message}).` });
      }
    }
  }

  // One DNS session for the whole upload; the biggest sources first when we have to cap.
  const unavailable: { source: string; reason: string }[] = [];
  if (fresh.length) {
    const vol = new Map<string, number>();
    for (const f of fresh) for (const r of f.report.records) vol.set(r.ip, (vol.get(r.ip) ?? 0) + r.count);
    const ips = [...vol.entries()].sort((a, b) => b[1] - a[1]).map(([ip]) => ip);
    const { ptr, failed } = await ptrLookup(ctx, ips);
    if (failed) unavailable.push({ source: t('DNS inverse (PTR)'), reason: t('{n} adresse(s) sans réponse du DNS : le fournisseur de ces sources est déduit du seul DKIM.', { n: failed }) });
    if (ips.filter(isPublicIp).length > MAX_PTR_LOOKUPS) unavailable.push({ source: t('DNS inverse (PTR)'), reason: t('Seules les {n} sources les plus volumineuses ont été interrogées.', { n: MAX_PTR_LOOKUPS }) });
    const insert = ctx.db.prepare(
      'INSERT OR IGNORE INTO dmarc_reports(id, created_at, domain, org_name, report_id, date_begin, date_end, messages, data, owner_id) VALUES(?,?,?,?,?,?,?,?,?,?)',
    );
    const tx = ctx.db.transaction(() => {
      for (const f of fresh) {
        for (const r of f.report.records) r.ptr = ptr.get(r.ip) ?? null;
        const id = newId();
        const res = insert.run(id, now(), f.report.policy.domain, f.report.orgName, f.report.reportId, f.report.dateBegin, f.report.dateEnd, f.report.messages, JSON.stringify(f.report), ownerId);
        if (res.changes) f.outcome.id = id;
        else f.outcome.status = 'duplicate';
      }
    });
    tx();
  }

  const totals = new Map<string, number>();
  for (const t of touched) totals.set(t.domain, (totals.get(t.domain) ?? 0) + t.messages);
  const domain = [...totals.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
  const rows = domain ? loadRows(ctx.db, ownerId, domain) : [];
  const an = analysisFor(rows, domain);
  const imported = outcomes.filter((o) => o.status === 'imported');
  const data: UploadData = {
    files: outcomes,
    summary: {
      files: outcomes.length,
      imported: imported.length,
      duplicates: outcomes.filter((o) => o.status === 'duplicate').length,
      errors: outcomes.filter((o) => o.status === 'error').length,
      messages: imported.reduce((n, o) => n + (o.messages ?? 0), 0),
    },
    domain,
    aggregate: an.aggregate,
    recommendation: an.recommendation,
  };
  const result: CheckResult<UploadData> = {
    tool: 'dmarc-reports',
    input: domain ?? '',
    measuredAt: new Date().toISOString().slice(0, 19) + 'Z',
    findings: an.findings,
    passed: an.passed,
    unavailable: unavailable.length ? unavailable : undefined,
    data,
    ms: Date.now() - started,
  };
  if (an.score !== null && an.aggregate && an.aggregate.messages > 0) result.score = an.score;
  if (domain && imported.length) {
    try {
      result.resultId = saveResult('dmarc-reports', domain, data, { score: result.score ?? null, ownerId }, ctx.db);
    } catch {
      /* history is best effort */
    }
  }
  return result;
}

export const tool: ServerTool = {
  id: 'dmarc-reports',
  async register(app: FastifyInstance, ctx: ToolContext) {
    const raw = ['application/xml', 'text/xml', 'application/gzip', 'application/x-gzip', 'application/zip', 'application/x-zip-compressed', 'application/octet-stream'];
    app.addContentTypeParser(raw, { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

    app.post('/api/dmarc-reports/upload', async (req, reply: FastifyReply) => {
      let inputs: InputFile[];
      try {
        inputs = await readInputs(app, req);
      } catch (e) {
        return reply.code(400).send({ error: 'bad_upload', message: t('Dépôt illisible ({msg}).', { msg: (e as Error).message }) });
      }
      if (!inputs.length) return reply.code(400).send({ error: 'no_file', message: t('Aucun fichier reçu : déposez des rapports .xml, .gz ou .zip.') });
      return processUpload(ctx, inputs, req.owner?.ownerId ?? null);
    });

    app.get('/api/dmarc-reports', async (req, reply) => {
      const q = req.query as { domain?: string; from?: string; to?: string };
      const from = parseDate(q.from, false);
      const to = parseDate(q.to, true);
      if (from === 'invalid' || to === 'invalid') return reply.code(400).send({ error: 'bad_date', message: t('Dates attendues au format AAAA-MM-JJ.') });
      let rows = loadRows(ctx.db, req.owner?.ownerId ?? null, q.domain?.trim() || undefined, from, to);
      const domain = q.domain?.trim().toLowerCase() || mainDomain(rows);
      rows = domain ? rows.filter((r) => r.domain === domain) : [];
      const an = analysisFor(rows, domain);
      const body: QueryData = {
        domain,
        aggregate: an.aggregate,
        recommendation: an.recommendation,
        findings: an.findings,
        passed: an.passed,
        score: an.aggregate && an.aggregate.messages > 0 ? an.score : null,
        reports: rows.map((r) => ({
          id: r.id, orgName: r.report.orgName, reportId: r.report.reportId, messages: r.report.messages,
          dateBegin: r.report.dateBegin ? new Date(r.report.dateBegin).toISOString() : null,
          dateEnd: r.report.dateEnd ? new Date(r.report.dateEnd).toISOString() : null,
        })),
      };
      return body;
    });

    app.get('/api/dmarc-reports/domains', async (req) => {
      const rows = ctx.db
        .prepare(
          'SELECT domain, COUNT(*) AS reports, COALESCE(SUM(messages),0) AS messages, MIN(date_begin) AS dmin, MAX(date_end) AS dmax FROM dmarc_reports WHERE owner_id = ? GROUP BY domain ORDER BY messages DESC',
        )
        .all(req.owner?.ownerId ?? null) as { domain: string; reports: number; messages: number; dmin: number | null; dmax: number | null }[];
      return {
        domains: rows.map((r) => ({
          domain: r.domain, reports: r.reports, messages: r.messages,
          from: r.dmin ? new Date(r.dmin).toISOString() : null,
          to: r.dmax ? new Date(r.dmax).toISOString() : null,
        })),
      };
    });

    app.delete('/api/dmarc-reports/:id', async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = ctx.db.prepare('DELETE FROM dmarc_reports WHERE id = ? AND owner_id = ?').run(id, req.owner?.ownerId ?? null);
      if (!res.changes) return reply.code(404).send({ error: 'not_found', message: t('Rapport introuvable.') });
      return { deleted: true, id };
    });
  },
};
