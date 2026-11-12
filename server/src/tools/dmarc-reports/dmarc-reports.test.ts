import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyInstance } from 'fastify';
import multipart from '@fastify/multipart';
import { zipSync, strToU8 } from 'fflate';
import { beforeEach, describe, expect, it } from 'vitest';
import { openDb } from '../../db.js';
import { bindOwner } from '../../owner.js';
import type { ToolContext } from '../types.js';
import { aggregate, recommend } from './analyze.js';
import { extractXml, parseReportXml } from './parse.js';
import { tool } from './index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n: string) => fs.readFileSync(path.join(here, 'fixtures', n), 'utf8');

const PTR: Record<string, string> = {
  '209.85.220.41': 'mail-sor-f41.google.com',
  '77.32.148.12': 'mail-77.sendinblue.com',
};
let lookups = 0;
let sessions = 0;

function makeCtx(): ToolContext {
  return {
    db: openDb(':memory:'),
    config: {} as ToolContext['config'],
    dns: () => {
      sessions++;
      return {
        resolve: async (name: string) => {
          lookups++;
          const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$/.exec(name);
          const ip = m ? `${m[4]}.${m[3]}.${m[2]}.${m[1]}` : '';
          if (ip === '45.83.12.9') throw new Error('timeout');
          const ptr = PTR[ip];
          return { name, type: 'PTR', rcode: 'NOERROR', answers: ptr ? [{ name, type: 'PTR', data: ptr + '.' }] : [], cnames: [], trace: [], ms: 1 };
        },
      } as unknown as ReturnType<ToolContext['dns']>;
    },
  };
}

function multipartBody(files: { name: string; data: Buffer }[]) {
  const b = '----dmarctest';
  const parts: Buffer[] = [];
  for (const f of files) {
    parts.push(Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="files"; filename="${f.name}"\r\nContent-Type: application/octet-stream\r\n\r\n`), f.data, Buffer.from('\r\n'));
  }
  parts.push(Buffer.from(`--${b}--\r\n`));
  return { payload: Buffer.concat(parts), headers: { 'content-type': `multipart/form-data; boundary=${b}` } };
}

function report(opts: { org: string; id: string; begin: number; p?: string; rows: { ip: string; n: number; dkim: 'pass' | 'fail'; spf: 'pass' | 'fail' }[] }) {
  const recs = opts.rows
    .map(
      (r) => `<record><row><source_ip>${r.ip}</source_ip><count>${r.n}</count><policy_evaluated><disposition>none</disposition><dkim>${r.dkim}</dkim><spf>${r.spf}</spf></policy_evaluated></row><identifiers><header_from>long.example</header_from></identifiers><auth_results><dkim><domain>long.example</domain><result>${r.dkim}</result><selector>s</selector></dkim><spf><domain>long.example</domain><result>${r.spf}</result></spf></auth_results></record>`,
    )
    .join('');
  return `<?xml version="1.0"?><feedback><report_metadata><org_name>${opts.org}</org_name><report_id>${opts.id}</report_id><date_range><begin>${opts.begin}</begin><end>${opts.begin + 86399}</end></date_range></report_metadata><policy_published><domain>long.example</domain><p>${opts.p ?? 'none'}</p><pct>100</pct></policy_published>${recs}</feedback>`;
}

describe('parsing', () => {
  it('reads the Google format', () => {
    const r = parseReportXml(fx('google.xml'));
    expect(r.orgName).toBe('google.com');
    expect(r.reportId).toBe('13265348472014816557');
    expect(r.policy).toMatchObject({ domain: 'exemple-atelier.fr', p: 'none', pct: 100 });
    expect(r.records).toHaveLength(4);
    expect(r.messages).toBe(223);
    expect(r.records[0]).toMatchObject({ ip: '209.85.220.41', count: 120, dkimAligned: true, spfAligned: true });
    expect(r.records[3].reasons).toEqual(['forwarded']);
    expect(r.dateBegin).toBe(1760918400000);
  });
  it('reads the Microsoft format (default namespace, upper-case domain, scope)', () => {
    const r = parseReportXml(fx('microsoft.xml'));
    expect(r.orgName).toBe('outlook.com');
    expect(r.policy.domain).toBe('exemple-atelier.fr');
    expect(r.records[1].envelopeFrom).toBe('bounce.brevo.com');
    expect(r.records[1].spf[0]).toMatchObject({ domain: 'bounce.brevo.com', scope: 'mfrom', result: 'pass' });
  });
  it('tolerates a prefixed namespace (DMARCbis style) and a single record', () => {
    const xml = `<dmarc:feedback xmlns:dmarc="urn:ietf:params:xml:ns:dmarc-2.0"><dmarc:version>2.0</dmarc:version><dmarc:report_metadata><dmarc:org_name>yahoo</dmarc:org_name><dmarc:report_id>1</dmarc:report_id><dmarc:date_range><dmarc:begin>1760918400</dmarc:begin><dmarc:end>1761004799</dmarc:end></dmarc:date_range></dmarc:report_metadata><dmarc:policy_published><dmarc:domain>a.fr</dmarc:domain><dmarc:p>reject</dmarc:p><dmarc:np>reject</dmarc:np><dmarc:testing>n</dmarc:testing></dmarc:policy_published><dmarc:record><dmarc:row><dmarc:source_ip>2a00:1450:4864::1</dmarc:source_ip><dmarc:count>3</dmarc:count><dmarc:policy_evaluated><dmarc:disposition>reject</dmarc:disposition><dmarc:dkim>fail</dmarc:dkim><dmarc:spf>fail</dmarc:spf></dmarc:policy_evaluated></dmarc:row><dmarc:identifiers><dmarc:header_from>a.fr</dmarc:header_from></dmarc:identifiers><dmarc:auth_results><dmarc:spf><dmarc:domain>a.fr</dmarc:domain><dmarc:result>none</dmarc:result></dmarc:spf></dmarc:auth_results></dmarc:record></dmarc:feedback>`;
    const r = parseReportXml(xml);
    expect(r.policy).toMatchObject({ p: 'reject', np: 'reject', testing: 'n' });
    expect(r.records).toHaveLength(1);
    expect(r.records[0]).toMatchObject({ ip: '2a00:1450:4864::1', count: 3, disposition: 'reject' });
  });
  it('rejects non DMARC content with a French message', () => {
    expect(() => parseReportXml(fx('invalid.xml'))).toThrow(/feedback/);
  });
  it('extracts xml, gz, zip and zip of gz, and reports corrupted files without throwing', () => {
    const g = fx('google.xml');
    expect(extractXml('a.xml', Buffer.from(g))[0].xml).toBe(g);
    expect(extractXml('a.xml.gz', zlib.gzipSync(g))[0].xml).toBe(g);
    const zip = Buffer.from(zipSync({ 'a.xml': strToU8(g), 'sub/b.xml.gz': zlib.gzipSync(fx('microsoft.xml')), '__MACOSX/x': strToU8('x') }));
    const out = extractXml('r.zip', zip);
    expect(out.map((o) => o.name)).toEqual(['r.zip/a.xml', 'r.zip/sub/b.xml.gz']);
    expect(out.every((o) => o.xml)).toBe(true);
    const bad = extractXml('bad.gz', Buffer.concat([zlib.gzipSync(g).subarray(0, 40), Buffer.from('garbage')]));
    expect(bad[0].error).toMatch(/illisible/);
  });
});

describe('HTTP routes', () => {
  let app: FastifyInstance;
  let ctx: ToolContext;
  beforeEach(async () => {
    lookups = 0;
    sessions = 0;
    ctx = makeCtx();
    app = Fastify();
    // every request in one notebook (isolation between notebooks: isolation.test.ts)
    bindOwner(app, () => ({ ownerId: 'o-test', deviceId: 'd-test' }));
    await app.register(multipart, { limits: { fileSize: 30 * 1024 * 1024, files: 50 } });
    await app.register(async (scope) => tool.register!(scope, ctx));
  });

  const upload = async () => {
    const files = [
      { name: 'google.com!exemple-atelier.fr!1760918400!1761004799.xml', data: Buffer.from(fx('google.xml')) },
      { name: 'corrompu.xml.gz', data: Buffer.concat([zlib.gzipSync(fx('google.xml')).subarray(0, 30), Buffer.from('xxxx')]) },
      { name: 'outlook.com!exemple-atelier.fr.xml.gz', data: zlib.gzipSync(fx('microsoft.xml')) },
      { name: 'invalide.xml', data: Buffer.from(fx('invalid.xml')) },
      { name: 'lot.zip', data: Buffer.from(zipSync({ 'google-again.xml': strToU8(fx('google.xml')) })) },
    ];
    const { payload, headers } = multipartBody(files);
    return app.inject({ method: 'POST', url: '/api/dmarc-reports/upload', payload, headers });
  };

  it('imports valid files, isolates errors, dedups and enriches sources', async () => {
    const res = await upload();
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.tool).toBe('dmarc-reports');
    const byFile = Object.fromEntries(body.data.files.map((f: { file: string; status: string }) => [f.file, f.status]));
    expect(byFile['google.com!exemple-atelier.fr!1760918400!1761004799.xml']).toBe('imported');
    expect(byFile['corrompu.xml.gz']).toBe('error');
    expect(byFile['outlook.com!exemple-atelier.fr.xml.gz']).toBe('imported');
    expect(byFile['invalide.xml']).toBe('error');
    expect(byFile['lot.zip/google-again.xml']).toBe('duplicate');
    expect(body.data.summary).toMatchObject({ files: 5, imported: 2, duplicates: 1, errors: 2, messages: 323 });
    expect(sessions).toBe(1);

    expect(body.data.domain).toBe('exemple-atelier.fr');
    const agg = body.data.aggregate;
    expect(agg.messages).toBe(323);
    const src = Object.fromEntries(agg.bySource.map((s: { ip: string }) => [s.ip, s]));
    expect(src['209.85.220.41']).toMatchObject({ verdict: 'aligned', ptr: 'mail-sor-f41.google.com', provider: { key: 'google_workspace' } });
    expect(src['77.32.148.12']).toMatchObject({ verdict: 'legit_unaligned', provider: { key: 'brevo' }, messages: 120 });
    expect(src['45.83.12.9']).toMatchObject({ verdict: 'spoofing', provider: null });
    expect(src['51.158.22.7']).toMatchObject({ verdict: 'forwarding' });
    // DMARC pass: 120 + 9 + 60 = 189 of 323 messages
    expect(agg.dmarcPass).toBe(189);
    expect(agg.rates.dmarc).toBe(58.5);
    expect(agg.byProvider.map((p: { key: string }) => p.key)).toContain('brevo');
    expect(agg.byOrg.map((o: { org: string }) => o.org).sort()).toEqual(['google.com', 'outlook.com']);
    expect(agg.byDay.map((d: { day: string }) => d.day)).toEqual(['2025-10-20', '2025-10-21']);
    expect(agg.dispositions.none).toBe(323);

    const ids = body.findings.map((f: { id: string }) => f.id);
    expect(ids).toContain('dmarc-report.legit_unaligned');
    expect(ids).toContain('dmarc-report.spoofing');
    expect(ids).toContain('dmarc-report.forwarding');
    const fix = body.findings.find((f: { id: string }) => f.id === 'dmarc-report.legit_unaligned');
    expect(fix.fix.join(' ')).toContain('include:spf.brevo.com');
    expect(fix.fix.join(' ')).toMatch(/DKIM/);
    for (const f of body.findings) expect(JSON.stringify(f)).not.toMatch(/[—–]/);
    expect(body.unavailable?.[0].source).toMatch(/PTR/);
    expect(body.data.recommendation.target).toBe('none');
    expect(body.data.recommendation.change).toBe(false);
    expect(typeof body.score).toBe('number');

    const again = (await upload()).json();
    expect(again.data.summary.imported).toBe(0);
    expect(again.data.summary.duplicates).toBe(3);
    expect(ctx.db.prepare('SELECT COUNT(*) c FROM dmarc_reports').get()).toEqual({ c: 2 });
  });

  it('accepts a raw XML body and a raw gzip body', async () => {
    const r1 = await app.inject({ method: 'POST', url: '/api/dmarc-reports/upload', payload: fx('microsoft.xml'), headers: { 'content-type': 'application/xml' } });
    expect(r1.json().data.summary.imported).toBe(1);
    const r2 = await app.inject({ method: 'POST', url: '/api/dmarc-reports/upload', payload: zlib.gzipSync(fx('google.xml')), headers: { 'content-type': 'application/gzip' } });
    expect(r2.json().data.summary.imported).toBe(1);
    const r3 = await app.inject({ method: 'POST', url: '/api/dmarc-reports/upload', payload: '', headers: { 'content-type': 'application/xml' } });
    expect(r3.statusCode).toBe(400);
  });

  it('serves the aggregate, domains and deletion', async () => {
    await upload();
    const dom = (await app.inject({ url: '/api/dmarc-reports/domains' })).json();
    expect(dom.domains).toEqual([
      { domain: 'exemple-atelier.fr', reports: 2, messages: 323, from: '2025-10-20T00:00:00.000Z', to: '2025-10-21T23:59:59.000Z' },
    ]);
    const all = (await app.inject({ url: '/api/dmarc-reports?domain=exemple-atelier.fr' })).json();
    expect(all.aggregate.messages).toBe(323);
    expect(all.reports).toHaveLength(2);
    const day2 = (await app.inject({ url: '/api/dmarc-reports?domain=exemple-atelier.fr&from=2025-10-21&to=2025-10-21' })).json();
    expect(day2.aggregate.messages).toBe(100);
    const none = (await app.inject({ url: '/api/dmarc-reports?domain=autre.fr' })).json();
    expect(none.aggregate.messages).toBe(0);
    expect((await app.inject({ url: '/api/dmarc-reports?from=pas-une-date' })).statusCode).toBe(400);
    const id = all.reports[0].id;
    expect((await app.inject({ method: 'DELETE', url: `/api/dmarc-reports/${id}` })).json()).toEqual({ deleted: true, id });
    expect((await app.inject({ method: 'DELETE', url: `/api/dmarc-reports/${id}` })).statusCode).toBe(404);
    expect((await app.inject({ url: '/api/dmarc-reports/domains' })).json().domains[0].reports).toBe(1);
  });
});

describe('policy recommendation', () => {
  const build = (p: string, nDays: number, extra: { ip: string; n: number; dkim: 'pass' | 'fail'; spf: 'pass' | 'fail' }[] = []) => {
    const rows = [];
    for (let i = 0; i < nDays; i++) {
      const xml = report({ org: 'google.com', id: `r${i}`, begin: 1760918400 + i * 86400, p, rows: [{ ip: '209.85.220.41', n: 50, dkim: 'pass', spf: 'pass' }, ...extra] });
      const parsed = parseReportXml(xml);
      for (const r of parsed.records) r.ptr = PTR[r.ip] ?? null;
      rows.push({ id: `r${i}`, createdAt: 0, domain: 'long.example', report: parsed });
    }
    return aggregate(rows, 'long.example');
  };
  it('stays in none when the sample is too small', () => {
    const rec = recommend(build('none', 2));
    expect(rec).toMatchObject({ target: 'none', change: false });
  });
  it('suggests quarantine after 14 clean days', () => {
    const rec = recommend(build('none', 15, [{ ip: '45.83.12.9', n: 3, dkim: 'fail', spf: 'fail' }]));
    expect(rec).toMatchObject({ target: 'quarantine', change: true });
    expect(rec.reasons.join(' ')).toMatch(/42 message|45 message|\d+ message\(s\) d'usurpation/);
    expect(rec.figures.spoofingMessages).toBe(45);
  });
  it('blocks the move while a legitimate source is unaligned', () => {
    const rec = recommend(build('none', 15, [{ ip: '77.32.148.12', n: 10, dkim: 'fail', spf: 'fail' }]));
    expect(rec).toMatchObject({ target: 'none', change: false });
    expect(rec.figures.legitUnalignedMessages).toBe(150);
  });
  it('suggests reject after 28 clean days in quarantine', () => {
    expect(recommend(build('quarantine', 30))).toMatchObject({ target: 'reject', change: true });
    expect(recommend(build('quarantine', 20))).toMatchObject({ target: 'quarantine', change: false });
    expect(recommend(build('reject', 30))).toMatchObject({ target: 'reject', change: false });
  });
});
