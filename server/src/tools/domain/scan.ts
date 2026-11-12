// Domain scanner (US-040): every check in parallel on one ResolveSession, each section delivered
// as soon as it is ready (for the SSE stream), then a /10 score over all findings.
import { t, msg } from '../../i18n.js';
import type { ResolveSession } from '../../dns/iterative.js';
import type { AuthorityResolver } from '../../lib/email-auth/common.js';
import { scoreOf, sortFindings, type Finding } from '../../knowledge/engine.js';
import { deadline, orgDomain, toFindings, type Analysis } from '../../lib/email-auth/common.js';
import { analyzeBimi } from '../../lib/email-auth/bimi.js';
import { analyzeDkim } from '../../lib/email-auth/dkim.js';
import { analyzeDmarc } from '../../lib/email-auth/dmarc.js';
import { analyzeDnssec } from '../../lib/email-auth/dnssec.js';
import { analyzeMtaSts } from '../../lib/email-auth/mtasts.js';
import { analyzeMx, type MxData } from '../../lib/email-auth/mx.js';
import { analyzeRdap } from '../../lib/email-auth/rdap.js';
import { measuredAt } from '../../lib/email-auth/report.js';
import { analyzeSmtp } from '../../lib/email-auth/smtp-probe.js';
import { analyzeSpf } from '../../lib/email-auth/spf.js';
import type { CheckResult, PassedCheck } from '../types.js';
import { analyzeBlacklists, analyzeCaa, analyzeNs, analyzeSoa } from './infra.js';

export const SECTIONS = [
  { id: 'mx', title: msg('Serveurs MX') },
  { id: 'spf', title: 'SPF' },
  { id: 'dkim', title: 'DKIM' },
  { id: 'dmarc', title: 'DMARC' },
  { id: 'bimi', title: 'BIMI' },
  { id: 'mta-sts', title: msg('MTA-STS et TLS-RPT') },
  { id: 'dnssec', title: 'DNSSEC' },
  { id: 'ns', title: msg('Serveurs de noms') },
  { id: 'soa', title: 'SOA' },
  { id: 'caa', title: 'CAA' },
  { id: 'blacklist', title: msg('Listes noires des MX') },
  { id: 'smtp', title: msg('Connexion SMTP aux MX') },
  { id: 'rdap', title: msg('Enregistrement du domaine') },
] as const;

export type SectionId = (typeof SECTIONS)[number]['id'];

export interface ScanSection {
  id: SectionId;
  title: string;
  /** ok: nothing to fix; warning: low/medium findings; error: high/critical; unavailable: not measured. */
  status: 'ok' | 'info' | 'warning' | 'error' | 'unavailable';
  findings: Finding[];
  passed: PassedCheck[];
  unavailable?: { source: string; reason: string }[];
  data: unknown;
  ms: number;
  /** Highest overall score this section allows (bogus DNSSEC). */
  scoreCap?: number;
}

export interface ScanData {
  domain: string;
  sections: ScanSection[];
  /** Count of findings by severity. */
  counts: Record<string, number>;
  /** false when the name does not exist in the DNS (NXDOMAIN): only MX (existence) and RDAP are measured. */
  exists: boolean;
}

function statusOf(findings: Finding[], unavailable: unknown[] | undefined, hasPassed: boolean): ScanSection['status'] {
  if (findings.some((f) => f.severity === 'critical' || f.severity === 'high')) return 'error';
  if (findings.some((f) => f.severity === 'medium' || f.severity === 'low')) return 'warning';
  if (!findings.length && !hasPassed && unavailable?.length) return 'unavailable';
  return findings.length ? 'info' : 'ok';
}

export async function scanDomain(
  session: AuthorityResolver,
  domain: string,
  opts: { ehloName?: string; onSection?: (s: ScanSection) => void; signal?: AbortSignal; makeSession?: () => ResolveSession; sectionTimeoutMs?: number } = {},
): Promise<CheckResult<ScanData>> {
  const started = performance.now();
  const sections: ScanSection[] = [];
  const title = (id: SectionId) => t(SECTIONS.find((s) => s.id === id)!.title);
  const run = async (id: SectionId, fn: () => Promise<Analysis & { data: unknown }>): Promise<ScanSection> => {
    const t0 = performance.now();
    let s: ScanSection;
    try {
      const a = await deadline(fn(), opts.sectionTimeoutMs ?? 25000, title(id));
      const findings = sortFindings(toFindings(a.issues));
      s = { id, title: title(id), status: statusOf(findings, a.unavailable, a.passed.length > 0), findings, passed: a.passed, unavailable: a.unavailable?.length ? a.unavailable : undefined, data: a.data, ms: Math.round(performance.now() - t0), ...(a.scoreCap !== undefined ? { scoreCap: a.scoreCap } : {}) };
    } catch (e) {
      s = { id, title: title(id), status: 'unavailable', findings: [], passed: [], unavailable: [{ source: id, reason: (e as Error).message }], data: null, ms: Math.round(performance.now() - t0) };
    }
    sections.push(s);
    if (!opts.signal?.aborted) opts.onSection?.(s);
    return s;
  };

  // A name that does not exist would otherwise be measured on its parent zone (.fr) and score 10.
  const probe = await deadline(session.resolve(domain, 'SOA'), opts.sectionTimeoutMs ?? 25000, t('existence du domaine')).catch(() => undefined);
  if (probe?.rcode === 'NXDOMAIN') {
    const notMeasured = (id: SectionId) => {
      const s: ScanSection = { id, title: title(id), status: 'unavailable', findings: [], passed: [], unavailable: [{ source: id, reason: t('Non mesuré : {domain} n’existe pas dans le DNS.', { domain }) }], data: null, ms: 0 };
      sections.push(s);
      if (!opts.signal?.aborted) opts.onSection?.(s);
    };
    await Promise.all([run('mx', () => analyzeMx(session, domain)), run('rdap', () => analyzeRdap(domain, { session }))]);
    for (const s of SECTIONS) if (s.id !== 'mx' && s.id !== 'rdap') notMeasured(s.id);
    return finish(false);
  }

  const mxP = run('mx', () => analyzeMx(session, domain));
  const nsP = run('ns', () => analyzeNs(session, domain));
  await Promise.all([
    mxP,
    nsP,
    run('spf', () => analyzeSpf(session, domain)),
    run('dkim', () => analyzeDkim(session, domain)),
    run('dmarc', () => analyzeDmarc(session, domain)),
    run('bimi', () => analyzeBimi(session, domain, { session })),
    run('mta-sts', () => analyzeMtaSts(session, domain, { session })),
    run('dnssec', () => analyzeDnssec(session, domain)),
    nsP.then((ns) => run('soa', () => analyzeSoa(session, (ns.data as { zone?: string } | null)?.zone ?? orgDomain(domain)))),
    run('caa', () => analyzeCaa(session, domain, orgDomain(domain))),
    mxP.then((mx) =>
      run('blacklist', () => {
        const hosts = ((mx.data as MxData | null)?.hosts ?? []).slice(0, 5);
        const ips = [...new Set(hosts.flatMap((h) => h.ipv4.slice(0, 2)))];
        return analyzeBlacklists(session, ips, [orgDomain(domain)], opts.makeSession);
      }),
    ),
    run('smtp', () => analyzeSmtp(session, domain, { ehloName: opts.ehloName })),
    run('rdap', () => analyzeRdap(domain, { session })),
  ]);

  return finish(true);

  function finish(exists: boolean): CheckResult<ScanData> {
    // keep the canonical order whatever the arrival order
    sections.sort((a, b) => SECTIONS.findIndex((s) => s.id === a.id) - SECTIONS.findIndex((s) => s.id === b.id));
    const findings = sortFindings(sections.flatMap((s) => s.findings));
    const counts: Record<string, number> = {};
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    const unavailable = sections.flatMap((s) => (s.unavailable ?? []).map((u) => ({ source: `${s.id}: ${u.source}`, reason: u.reason })));
    return {
      tool: 'domain',
      input: domain,
      measuredAt: measuredAt(),
      // a domain that does not exist gets 0, whatever was measured
      score: exists ? Math.min(scoreOf(findings), ...sections.map((s) => s.scoreCap ?? 10)) : 0,
      findings,
      passed: sections.flatMap((s) => s.passed),
      unavailable: unavailable.length ? unavailable : undefined,
      data: { domain, sections, counts, exists },
      ms: Math.round(performance.now() - started),
    };
  }
}
