// Certificate of an HTTPS host, read by a TLS handshake on the address the chain resolved
// (a public one only: checked here before connecting). Nothing is sent after the handshake.
import { t } from '../../i18n.js';
import net from 'node:net';
import tls from 'node:tls';
import { isPublicIp } from '../../lib/net.js';

export interface TlsInfo {
  host: string;
  ip: string;
  port: number;
  protocol?: string;
  /** The chain validates against the system's trusted roots. */
  authorized: boolean;
  authorizationError?: string;
  subject?: string;
  san: string[];
  issuer?: string;
  issuerOrg?: string;
  validFrom?: string;
  validTo?: string;
  /** Days since the certificate was issued. */
  ageDays?: number;
  daysLeft?: number;
  expired: boolean;
  selfSigned: boolean;
  nameMatches: boolean;
  /** Issued by a free automated authority (Let's Encrypt, ZeroSSL...). */
  freeCa: boolean;
  fingerprint256?: string;
  error?: string;
}

export type TlsProbe = (host: string, ip: string, port: number) => Promise<TlsInfo>;

const FREE_CA = /let'?s encrypt|zerossl|buypass|cpanel|google trust services|ssl\.com|actalis/i;

const iso = (d: string | undefined) => {
  const t = d ? Date.parse(d) : NaN;
  return Number.isNaN(t) ? undefined : new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');
};

export function describeCert(host: string, ip: string, port: number, cert: tls.PeerCertificate, authorized: boolean, authorizationError: string | undefined, protocol: string | null, now = Date.now()): TlsInfo {
  const subject = (cert.subject as unknown as Record<string, string> | undefined)?.CN;
  const issuerObj = cert.issuer as unknown as Record<string, string> | undefined;
  const san = (cert.subjectaltname ?? '')
    .split(',')
    .map((s) => s.trim().replace(/^(DNS|IP Address):/i, ''))
    .filter(Boolean);
  const from = Date.parse(cert.valid_from);
  const to = Date.parse(cert.valid_to);
  const selfSigned =
    authorizationError === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    authorizationError === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    (!!issuerObj && !!cert.subject && JSON.stringify(issuerObj) === JSON.stringify(cert.subject));
  let nameMatches = false;
  try {
    nameMatches = tls.checkServerIdentity(host, cert) === undefined;
  } catch {
    nameMatches = false;
  }
  return {
    host,
    ip,
    port,
    protocol: protocol ?? undefined,
    authorized,
    authorizationError: authorizationError || undefined,
    subject,
    san: san.slice(0, 50),
    issuer: issuerObj?.CN,
    issuerOrg: issuerObj?.O,
    validFrom: iso(cert.valid_from),
    validTo: iso(cert.valid_to),
    ageDays: Number.isNaN(from) ? undefined : Math.floor((now - from) / 86400000),
    daysLeft: Number.isNaN(to) ? undefined : Math.floor((to - now) / 86400000),
    expired: !Number.isNaN(to) && to < now,
    selfSigned,
    nameMatches,
    freeCa: FREE_CA.test(`${issuerObj?.O ?? ''} ${issuerObj?.CN ?? ''}`),
    fingerprint256: cert.fingerprint256,
  };
}

export const probeTls: TlsProbe = (host, ip, port) =>
  new Promise((resolve) => {
    const base = { host, ip, port, authorized: false, san: [], expired: false, selfSigned: false, nameMatches: false, freeCa: false };
    if (!isPublicIp(ip)) return resolve({ ...base, error: t('Adresse non publique refusée : {ip}', { ip }) });
    const socket = tls.connect({ host: ip, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: 8000 });
    const done = (r: TlsInfo) => {
      socket.destroy();
      resolve(r);
    };
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.valid_to) return done({ ...base, error: t('aucun certificat présenté') });
      const err = socket.authorizationError ? String((socket.authorizationError as Error & { code?: string }).code ?? socket.authorizationError) : undefined;
      done(describeCert(host, ip, port, cert, socket.authorized, err, socket.getProtocol()));
    });
    socket.once('timeout', () => done({ ...base, error: t('pas de réponse TLS en 8 s') }));
    socket.once('error', (e) => done({ ...base, error: e.message }));
  });
