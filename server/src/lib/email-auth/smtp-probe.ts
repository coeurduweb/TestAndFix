// SMTP probe of an MX on port 25: banner, EHLO, STARTTLS, negotiated TLS version, certificate.
// The probe never sends MAIL FROM: it says hello, upgrades to TLS, says hello again and quits.
import net from 'node:net';
import tls from 'node:tls';
import { reverseName } from '../net.js';
import { issue, lookupAddresses, lookupMx, lookupType, pass, type Analysis, type Issue, type Resolver } from './common.js';
import type { PassedCheck } from '../../tools/types.js';
import { t, msg } from '../../i18n.js';

export interface SmtpCert {
  subject?: string;
  altNames: string[];
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysLeft?: number;
  fingerprint256?: string;
  selfSigned: boolean;
  /** Chain verified against the system trust store. */
  trusted: boolean;
  trustError?: string;
  /** Host name matches the certificate. */
  nameMatches: boolean;
  nameError?: string;
}

export interface SmtpProbe {
  host: string;
  ip: string;
  port: number;
  /** Outcome of the probe. */
  status: 'ok' | 'timeout' | 'refused' | 'error';
  error?: string;
  connectMs?: number;
  bannerMs?: number;
  totalMs?: number;
  banner?: string;
  ehlo?: string[];
  extensions: string[];
  starttls: boolean;
  tls?: {
    ok: boolean;
    error?: string;
    protocol?: string;
    cipher?: string;
    ms?: number;
    cert?: SmtpCert;
    ehloAfter?: string[];
  };
  transcript: string[];
}

export interface ProbeOptions {
  port?: number;
  timeoutMs?: number;
  ehloName?: string;
}

class LineReader {
  private buf = '';
  private waiters: ((l: string[] | Error) => void)[] = [];
  private lines: string[] = [];
  constructor(private sock: net.Socket | tls.TLSSocket) {
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => this.push(d));
  }
  private push(d: string) {
    this.buf += d;
    let i: number;
    while ((i = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, '');
      this.buf = this.buf.slice(i + 1);
      this.lines.push(line);
      // a reply ends with "ddd " (space after the code) or a bare code
      if (/^\d{3}( |$)/.test(line)) {
        const reply = this.lines;
        this.lines = [];
        this.waiters.shift()?.(reply);
      }
    }
  }
  fail(e: Error) {
    for (const w of this.waiters.splice(0)) w(e);
  }
  next(timeoutMs: number): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.waiters.indexOf(cb);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(Object.assign(new Error(t('délai de réponse dépassé')), { code: 'ETIMEDOUT' }));
      }, timeoutMs);
      const cb = (r: string[] | Error) => {
        clearTimeout(timer);
        if (r instanceof Error) reject(r);
        else resolve(r);
      };
      this.waiters.push(cb);
    });
  }
}

function connect(ip: string, port: number, timeoutMs: number): Promise<{ sock: net.Socket; ms: number }> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const sock = net.createConnection({ host: ip, port });
    const timer = setTimeout(() => {
      sock.destroy();
      reject(Object.assign(new Error(t('aucune réponse sur le port {port} après {ms} ms', { port, ms: timeoutMs })), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    sock.once('connect', () => {
      clearTimeout(timer);
      resolve({ sock, ms: Math.round(performance.now() - started) });
    });
    sock.once('error', (e) => {
      clearTimeout(timer);
      sock.destroy();
      reject(e);
    });
  });
}

function certInfo(host: string, s: tls.TLSSocket): SmtpCert | undefined {
  const c = s.getPeerCertificate(false);
  if (!c || !Object.keys(c).length) return undefined;
  const altNames = (c.subjectaltname ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter((x) => x.startsWith('DNS:'))
    .map((x) => x.slice(4));
  const nameErr = tls.checkServerIdentity(host, c);
  const validTo = c.valid_to ? new Date(c.valid_to) : undefined;
  const subj = c.subject as unknown as Record<string, string> | undefined;
  const iss = c.issuer as unknown as Record<string, string> | undefined;
  const fmt = (o?: Record<string, string>) => (o ? Object.entries(o).map(([k, v]) => `${k}=${v}`).join(', ') : undefined);
  const authErr = s.authorizationError ? String(s.authorizationError) : undefined;
  return {
    subject: fmt(subj),
    altNames,
    issuer: fmt(iss),
    validFrom: c.valid_from ? new Date(c.valid_from).toISOString() : undefined,
    validTo: validTo?.toISOString(),
    daysLeft: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : undefined,
    fingerprint256: c.fingerprint256,
    selfSigned: authErr === 'DEPTH_ZERO_SELF_SIGNED_CERT' || authErr === 'SELF_SIGNED_CERT_IN_CHAIN' || (fmt(subj) === fmt(iss) && !s.authorized),
    trusted: s.authorized,
    trustError: authErr,
    nameMatches: !nameErr,
    nameError: nameErr?.message,
  };
}

export async function probeSmtp(host: string, ip: string, opts: ProbeOptions = {}): Promise<SmtpProbe> {
  const port = opts.port ?? 25;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const ehloName = opts.ehloName ?? 'testandfix.localhost';
  const out: SmtpProbe = { host, ip, port, status: 'ok', extensions: [], starttls: false, transcript: [] };
  const started = performance.now();
  let sock: net.Socket | tls.TLSSocket | undefined;
  try {
    const c = await connect(ip, port, timeoutMs);
    sock = c.sock;
    out.connectMs = c.ms;
    let reader = new LineReader(sock);
    sock.on('error', (e) => reader.fail(e));
    sock.on('close', () => reader.fail(new Error(t('connexion fermée par le serveur'))));
    const send = (line: string) => {
      out.transcript.push(`C: ${line}`);
      sock!.write(line + '\r\n');
    };
    const read = async () => {
      const r = await reader.next(timeoutMs);
      for (const l of r) out.transcript.push(`S: ${l}`);
      return r;
    };
    const banner = await read();
    out.bannerMs = Math.round(performance.now() - started);
    out.banner = banner.join('\n');
    if (!banner.at(-1)!.startsWith('220')) throw new Error(t('bannière inattendue : {line}', { line: banner.at(-1) }));
    send(`EHLO ${ehloName}`);
    const ehlo = await read();
    out.ehlo = ehlo;
    if (!ehlo.at(-1)!.startsWith('250')) throw new Error(t('EHLO refusé : {line}', { line: ehlo.at(-1) }));
    out.extensions = ehlo.slice(1).map((l) => l.slice(4).trim().toUpperCase());
    out.starttls = out.extensions.some((e) => e === 'STARTTLS');
    if (out.starttls) {
      send('STARTTLS');
      const r = await read();
      if (!r.at(-1)!.startsWith('220')) {
        out.tls = { ok: false, error: t('STARTTLS refusé : {line}', { line: r.at(-1) }) };
      } else {
        const tlsStart = performance.now();
        const plain = sock as net.Socket;
        plain.removeAllListeners('data');
        const secure = await new Promise<tls.TLSSocket>((resolve, reject) => {
          const s = tls.connect({ socket: plain, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, minVersion: 'TLSv1' });
          const timer = setTimeout(() => {
            s.destroy();
            reject(new Error(t('négociation TLS trop longue')));
          }, timeoutMs);
          s.once('secureConnect', () => {
            clearTimeout(timer);
            resolve(s);
          });
          s.once('error', (e) => {
            clearTimeout(timer);
            reject(e);
          });
        }).catch((e: Error) => {
          out.tls = { ok: false, error: t('négociation TLS en échec : {error}', { error: e.message }) };
          return undefined;
        });
        if (secure) {
          sock = secure;
          out.tls = {
            ok: true,
            protocol: secure.getProtocol() ?? undefined,
            cipher: secure.getCipher()?.name,
            ms: Math.round(performance.now() - tlsStart),
            cert: certInfo(host, secure),
          };
          out.transcript.push(`-- TLS ${out.tls.protocol} ${out.tls.cipher}`);
          reader = new LineReader(secure);
          secure.on('error', (e) => reader.fail(e));
          send(`EHLO ${ehloName}`);
          const e2 = await read().catch(() => undefined);
          if (e2) out.tls.ehloAfter = e2;
        }
      }
    }
    if (sock && !sock.destroyed) {
      send('QUIT');
      await read().catch(() => undefined);
    }
  } catch (e) {
    const err = e as Error & { code?: string };
    out.status = err.code === 'ETIMEDOUT' ? 'timeout' : err.code === 'ECONNREFUSED' ? 'refused' : 'error';
    out.error = err.message;
  } finally {
    sock?.destroy();
    out.totalMs = Math.round(performance.now() - started);
  }
  return out;
}

/**
 * Is outbound port 25 usable from this machine? Connects to a reference MX: a timeout there
 * means the port is filtered locally (ISP, cloud provider), not that the target is down.
 */
export interface ReferenceMx {
  name: string;
  /** Who runs it, shown in the evidence (Gmail, iCloud). */
  label: string;
  ip: string;
}

export async function port25Reachable(refs: ReferenceMx[], timeoutMs = 5000): Promise<{ reachable: boolean; detail: string }> {
  const attempts = await Promise.all(
    refs.slice(0, 2).map((r) => {
      const who = `${r.name} (${t(r.label)}, ${r.ip})`;
      return connect(r.ip, 25, timeoutMs).then(
        (c) => {
          c.sock.destroy();
          return { ok: true, detail: t('{who} joignable en {ms} ms', { who, ms: c.ms }) };
        },
        (e: Error) => ({ ok: false, detail: `${who} : ${e.message}` }),
      );
    }),
  );
  const ok = attempts.find((a) => a.ok);
  return ok ? { reachable: true, detail: ok.detail } : { reachable: false, detail: attempts.map((a) => a.detail).join(' ; ') || t('aucune adresse de référence') };
}

// ---------------------------------------------------------------------------------------------
// Analysis of every MX of a domain


/** Reference MX used to tell "port 25 filtered here" from "this MX is down". */
export const REFERENCE_MX: { name: string; label: string }[] = [
  { name: 'gmail-smtp-in.l.google.com', label: msg('MX de référence Gmail') },
  { name: 'mx1.mail.icloud.com', label: msg('MX de référence iCloud') },
];

export interface SmtpData {
  domain: string;
  port25: { reachable: boolean; detail: string };
  mx: { host: string; preference: number; ips: string[] }[];
  probes: SmtpProbe[];
}

export interface SmtpAnalysis extends Analysis {
  data: SmtpData;
}

export interface SmtpAnalysisOptions extends ProbeOptions {
  /** Probe only this host instead of the MX of the domain. */
  host?: string;
  /** Injected for tests. */
  probe?: typeof probeSmtp;
  reachability?: typeof port25Reachable;
  /** Probe at most this many addresses. */
  maxTargets?: number;
}

export const UNAVAILABLE_PORT25 = msg('Le port 25 sortant est bloqué sur cette machine : la connexion SMTP aux MX est non vérifiable depuis cette machine.');

export async function analyzeSmtp(dns: Resolver, domain: string, opts: SmtpAnalysisOptions = {}): Promise<SmtpAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const hosts = opts.host
    ? [{ exchange: opts.host.toLowerCase().replace(/\.$/, ''), preference: 0 }]
    : (await lookupMx(dns, domain)).mx.filter((m) => m.exchange && m.exchange !== '.');
  const [mx, refIps] = await Promise.all([
    Promise.all(hosts.map(async (h) => ({ host: h.exchange, preference: h.preference, ips: (await lookupAddresses(dns, h.exchange, ['A'])).ips }))),
    Promise.all(REFERENCE_MX.map((h) => lookupAddresses(dns, h.name, ['A']).then((r) => (r.ips[0] ? { ...h, ip: r.ips[0] } : undefined)))),
  ]);
  const data: SmtpData = { domain, port25: { reachable: false, detail: '' }, mx, probes: [] };
  data.port25 = await (opts.reachability ?? port25Reachable)(refIps.filter((x): x is ReferenceMx => !!x), Math.min(opts.timeoutMs ?? 5000, 5000));
  if (!data.port25.reachable) {
    return { issues, passed, unavailable: [{ source: 'smtp', reason: `${t(UNAVAILABLE_PORT25)} (${data.port25.detail})` }], data };
  }
  if (!mx.length) return { issues, passed, data };
  const targets = mx.flatMap((m) => m.ips.slice(0, 2).map((ip) => ({ host: m.host, ip }))).slice(0, opts.maxTargets ?? 6);
  const probe = opts.probe ?? probeSmtp;
  data.probes = await Promise.all(targets.map((t) => probe(t.host, t.ip, opts)));
  const ok = data.probes.filter((p) => p.status === 'ok');
  if (!ok.length) {
    issues.push(issue('mx.unreachable', { domain }, { evidence: data.probes.map((p) => `${p.host} (${p.ip}) : ${p.error}`).join('\n') }));
    return { issues, passed, data };
  }
  passed.push(pass('smtp.reachable', 'mx', t('{ok} MX sur {total} répondent sur le port 25', { ok: ok.length, total: data.probes.length })));
  for (const p of data.probes) {
    const v = { domain, ip: p.ip, value: p.host };
    const ev = `${p.host} (${p.ip})`;
    if (p.status !== 'ok') {
      issues.push(issue('mx.host_unreachable', v, { evidence: `${ev} : ${p.error}` }));
      continue;
    }
    const bannerHost = /^220[ -](\S+)/.exec(p.banner ?? '')?.[1]?.toLowerCase().replace(/\.$/, '');
    const ptrNames = bannerHost && bannerHost !== p.host ? (await lookupType(dns, reverseName(p.ip), 'PTR')).data.map((x) => String(x).toLowerCase().replace(/\.$/, '')) : [];
    if (bannerHost && /\./.test(bannerHost) && bannerHost !== p.host && !ptrNames.includes(bannerHost))
      issues.push(issue('infrastructure.smtp_banner_mismatch', { ...v, value: bannerHost }, { evidence: `${ev} : ${p.banner?.split('\n')[0]}` }));
    if (!p.starttls) {
      issues.push(issue('tls.mx_no_starttls', v, { evidence: `${ev} : ${p.extensions.join(', ')}` }));
      continue;
    }
    if (!p.tls?.ok) {
      issues.push(issue('tls.mx_starttls_broken', { ...v, value: p.tls?.error }, { evidence: `${ev} : ${p.tls?.error}` }));
      continue;
    }
    if (p.tls.protocol && ['TLSv1', 'TLSv1.1', 'SSLv3'].includes(p.tls.protocol))
      issues.push(issue('tls.mx_old_version_only', { ...v, value: p.tls.protocol }, { evidence: `${ev} : ${p.tls.protocol}` }));
    const c = p.tls.cert;
    if (c) {
      if (c.daysLeft !== undefined && c.daysLeft < 0) issues.push(issue('tls.mx_cert_expired', { ...v, value: c.validTo }, { evidence: `${ev} : ${t('expiré le {date}', { date: c.validTo })}` }));
      else if (c.daysLeft !== undefined && c.daysLeft < 14) issues.push(issue('tls.mx_cert_expiring', { ...v, value: c.daysLeft }, { evidence: `${ev} : ${t('expire le {date}', { date: c.validTo })}` }));
      if (c.selfSigned) issues.push(issue('tls.mx_cert_self_signed', v, { evidence: `${ev} : ${c.trustError}` }));
      else if (!c.trusted && c.trustError && /UNABLE_TO_GET_ISSUER|UNABLE_TO_VERIFY_LEAF/.test(c.trustError))
        issues.push(issue('tls.mx_cert_chain_incomplete', { ...v, value: c.trustError }, { evidence: `${ev} : ${c.trustError}` }));
      if (!c.nameMatches) issues.push(issue('tls.mx_cert_name_mismatch', { ...v, value: c.altNames.join(', ') }, { evidence: `${ev} : ${c.nameError}` }));
      if (c.trusted && c.nameMatches && (c.daysLeft ?? 0) >= 14) passed.push(pass(`smtp.cert.${p.host}`, 'tls', t('Certificat valide sur {host}', { host: p.host }), t('{protocol}, expire le {date}', { protocol: p.tls.protocol, date: c.validTo?.slice(0, 10) })));
    }
  }
  return { issues, passed, data };
}
