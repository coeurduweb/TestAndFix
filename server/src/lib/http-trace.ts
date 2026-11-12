// Low-level HTTP client for the redirect tracer (US-069): one request, everything measured.
//
// - node:http / node:https with `agent: false`: a new connection per request, nothing reused,
//   nothing cached; `Cache-Control: no-cache` and `Pragma: no-cache` always sent.
// - The host name is resolved by the iterative resolver (from the root, no cache) and the IP is
//   checked with isPublicIp() BEFORE connecting, at every call, so a redirect towards a private
//   address is refused like the first URL (SSRF protection). The socket connects to that IP, with
//   the right SNI and Host header.
// - Records the exact request head sent, the status line, the raw response headers in the order
//   and case received, the body (2 MB kept, real size counted), its decoded text, the timings
//   (DNS, connection, TLS, first byte, download) and the TLS session with its certificate.
//
// Test seam: `network` replaces resolution and the IP check (a local test server lives on
// 127.0.0.1). It is honoured only under Vitest (process.env.VITEST) and throws anywhere else, so
// the protection can never be switched off in production.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { isPublicIp, UnsafeTargetError } from './net.js';
import { t } from '../i18n.js';

export const BODY_LIMIT = 2 * 1024 * 1024;
/** Bytes counted (not kept) past BODY_LIMIT to report the real size. */
const COUNT_LIMIT = 16 * 1024 * 1024;
export const HOP_TIMEOUT_MS = 10000;

export interface AddressResolver {
  resolve(name: string, type: 'A' | 'AAAA'): Promise<{ answers: { type: string; data: unknown }[]; cnames?: string[] }>;
}

export interface NetworkSeam {
  lookup(host: string): Promise<{ ip: string; cnames?: string[] }>;
  isAllowed(ip: string): boolean;
}

export interface TraceRequestOptions {
  method?: 'GET' | 'HEAD';
  /** Header pairs in the order to send them (case kept). Host, Connection and no-cache are added. */
  headers?: [string, string][];
  /** Iterative resolver of the current user action (ResolveSession or GuardedResolver). */
  dns?: AddressResolver;
  timeoutMs?: number;
  maxBody?: number;
  signal?: AbortSignal;
  /** Tests only (see header comment). */
  network?: NetworkSeam;
}

export interface CertInfo {
  subject: string;
  subjectOrg?: string;
  issuer: string;
  issuerOrg?: string;
  san: string[];
  validFrom: string;
  validTo: string;
  daysLeft: number;
  serial?: string;
  fingerprint256?: string;
  keyBits?: number;
  /** Subjects from the leaf to the root, as sent by the server. */
  chain: string[];
}

export interface TlsInfo {
  protocol?: string;
  cipher?: string;
  alpn?: string;
  /** Chain verified against Node's root store. */
  chainValid: boolean;
  chainError?: string;
  nameValid: boolean;
  nameError?: string;
  cert?: CertInfo;
}

export interface BodyInfo {
  /** Bytes received on the wire (compressed), counted up to 16 MB. */
  size: number;
  /** false when counting stopped before the end. */
  sizeComplete: boolean;
  /** More than 2 MB received: only the first 2 MB are kept. */
  truncated: boolean;
  contentEncoding?: string;
  /** Size after decompression of the kept part. */
  decodedSize: number;
  decodeError?: string;
  contentType?: string;
  mime?: string;
  charset?: string;
  charsetSource?: 'header' | 'meta' | 'bom' | 'default';
  isText: boolean;
  /** Decoded text (for text types). */
  text?: string;
  /** First 256 bytes in hex, for binary bodies. */
  hexPreview?: string;
}

export interface Timings {
  dns: number;
  connect: number;
  tls: number;
  /** Request sent to first byte of the response. */
  wait: number;
  download: number;
  total: number;
}

export interface HttpExchange {
  url: string;
  method: 'GET' | 'HEAD';
  host: string;
  /** Exact request head written to the socket: request line, then headers. */
  requestLine: string;
  requestHeaders: [string, string][];
  ip?: string;
  port: number;
  cnames?: string[];
  httpVersion?: string;
  status?: number;
  statusText?: string;
  /** Response headers in the order and case received. */
  rawHeaders: [string, string][];
  body?: BodyInfo;
  timings: Timings;
  tls?: TlsInfo;
  error?: { code: string; message: string };
}

const round = (n: number) => Math.max(0, Math.round(n * 10) / 10);

function seamOrDefault(o: TraceRequestOptions): NetworkSeam {
  if (o.network) {
    if (!process.env.VITEST) throw new Error('network seam is for tests only');
    return o.network;
  }
  const dns = o.dns;
  return {
    async lookup(host) {
      if (!dns) throw new Error('no resolver');
      const cnames: string[] = [];
      for (const type of ['A', 'AAAA'] as const) {
        let r;
        try {
          r = await dns.resolve(host, type);
        } catch (e) {
          if (type === 'AAAA') throw e;
          continue;
        }
        cnames.push(...(r.cnames ?? []));
        const ip = r.answers.find((a) => a.type === type)?.data as string | undefined;
        if (ip) return { ip, cnames: [...new Set(cnames)] };
      }
      throw Object.assign(new Error(t("Le nom {host} n'a aucune adresse IP (A ni AAAA).", { host })), { code: 'ENOTFOUND', own: true });
    },
    isAllowed: isPublicIp,
  };
}

/** Header value as text: header bytes are latin1 on the wire; UTF-8 sequences are restored. */
export function headerText(v: string): string {
  if (!/[\x80-\xff]/.test(v)) return v;
  const b = Buffer.from(v, 'latin1');
  const u = b.toString('utf8');
  return u.includes('�') ? v : u;
}

function pairs(raw: string[]): [string, string][] {
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i], headerText(raw[i + 1])]);
  return out;
}

export function getHeader(h: [string, string][], name: string): string | undefined {
  const n = name.toLowerCase();
  return h.find(([k]) => k.toLowerCase() === n)?.[1];
}
export function getHeaders(h: [string, string][], name: string): string[] {
  const n = name.toLowerCase();
  return h.filter(([k]) => k.toLowerCase() === n).map(([, v]) => v);
}

/* ---------- body decoding ---------- */

const TEXT_MIME = /^(text\/|application\/(json|ld\+json|xml|xhtml\+xml|javascript|ecmascript|x-javascript|rss\+xml|atom\+xml|manifest\+json|problem\+json)|image\/svg\+xml)|\+json$|\+xml$/i;

function decompress(buf: Buffer, enc: string | undefined): { data: Buffer; error?: string } {
  const e = (enc ?? '').trim().toLowerCase();
  if (!e || e === 'identity') return { data: buf };
  try {
    if (e === 'gzip' || e === 'x-gzip') return { data: zlib.gunzipSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH }) };
    if (e === 'deflate') {
      // "deflate" is zlib-wrapped per RFC 9110, but some servers send raw deflate
      try {
        return { data: zlib.inflateSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH }) };
      } catch {
        return { data: zlib.inflateRawSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH }) };
      }
    }
    if (e === 'br') return { data: zlib.brotliDecompressSync(buf, { finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH }) };
    if (e === 'zstd' && typeof (zlib as { zstdDecompressSync?: unknown }).zstdDecompressSync === 'function')
      return { data: (zlib as unknown as { zstdDecompressSync: (b: Buffer) => Buffer }).zstdDecompressSync(buf) };
    return { data: buf, error: t("Encodage {encoding} non pris en charge pour l'affichage.", { encoding: e }) };
  } catch (err) {
    return { data: buf, error: t('Décompression {encoding} impossible : {error}', { encoding: e, error: (err as Error).message }) };
  }
}

/** Accept-Encoding we can decode. */
export const ACCEPT_ENCODING =
  typeof (zlib as { zstdDecompressSync?: unknown }).zstdDecompressSync === 'function' ? 'gzip, deflate, br, zstd' : 'gzip, deflate, br';

function sniffMime(b: Buffer): string | undefined {
  const head = b.subarray(0, 512).toString('latin1').replace(/^﻿|^\xef\xbb\xbf/, '').trimStart().toLowerCase();
  if (head.startsWith('<!doctype html') || head.startsWith('<html') || /^<(head|body|meta|script|title)\b/.test(head)) return 'text/html';
  if (head.startsWith('<?xml')) return 'application/xml';
  if (head.startsWith('{') || head.startsWith('[')) return 'application/json';
  if (head.startsWith('%pdf')) return 'application/pdf';
  if (b.subarray(0, 512).includes(0)) return 'application/octet-stream';
  return b.length ? 'text/plain' : undefined;
}

function decodeText(data: Buffer, mime: string | undefined, headerCharset: string | undefined): Pick<BodyInfo, 'text' | 'charset' | 'charsetSource'> {
  let charset = headerCharset?.toLowerCase();
  let source: BodyInfo['charsetSource'] = charset ? 'header' : undefined;
  if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) {
    charset = 'utf-8';
    source = 'bom';
  } else if (data[0] === 0xff && data[1] === 0xfe) {
    charset = 'utf-16le';
    source = 'bom';
  } else if (data[0] === 0xfe && data[1] === 0xff) {
    charset = 'utf-16be';
    source = 'bom';
  }
  if (!charset && mime === 'text/html') {
    const head = data.subarray(0, 2048).toString('latin1');
    const m = /<meta[^>]+charset\s*=\s*["']?\s*([\w.:-]+)/i.exec(head);
    if (m) {
      charset = m[1].toLowerCase();
      source = 'meta';
    }
  }
  if (!charset) {
    charset = 'utf-8';
    source = 'default';
  }
  let dec: TextDecoder;
  try {
    dec = new TextDecoder(charset);
  } catch {
    dec = new TextDecoder('utf-8');
  }
  return { text: dec.decode(data), charset, charsetSource: source };
}

export function analyzeBody(raw: Buffer, info: { size: number; sizeComplete: boolean; truncated: boolean }, contentType?: string, contentEncoding?: string): BodyInfo {
  const { data, error } = decompress(raw, contentEncoding);
  const [mimePart, ...params] = (contentType ?? '').split(';');
  let mime = mimePart.trim().toLowerCase() || undefined;
  const headerCharset = params.map((p) => /^\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(p)?.[1]).find(Boolean);
  const sniffed = sniffMime(data);
  if (!mime) mime = sniffed;
  const isText = !error && !!mime && (TEXT_MIME.test(mime) || (mime === 'application/octet-stream' ? false : sniffed?.startsWith('text/') === true && !mime.startsWith('image/')));
  const out: BodyInfo = {
    ...info,
    contentEncoding: contentEncoding?.trim() || undefined,
    decodedSize: data.length,
    decodeError: error,
    contentType,
    mime,
    isText,
  };
  if (isText) Object.assign(out, decodeText(data.subarray(0, BODY_LIMIT * 4), mime, headerCharset));
  else if (data.length) out.hexPreview = data.subarray(0, 256).toString('hex').replace(/(..)/g, '$1 ').trim();
  return out;
}

/* ---------- TLS ---------- */

function nameOf(x: tls.Certificate | undefined): { cn: string; o?: string } {
  if (!x) return { cn: '' };
  const cn = Array.isArray(x.CN) ? x.CN[0] : x.CN;
  const o = Array.isArray(x.O) ? x.O[0] : x.O;
  return { cn: cn ?? o ?? '', o };
}

export function certInfo(peer: tls.DetailedPeerCertificate, now = Date.now()): CertInfo {
  const chain: string[] = [];
  const seen = new Set<string>();
  let c: tls.DetailedPeerCertificate | undefined = peer;
  while (c && c.fingerprint256 && !seen.has(c.fingerprint256) && chain.length < 8) {
    seen.add(c.fingerprint256);
    chain.push(nameOf(c.subject).cn || t('(sans nom)'));
    c = c.issuerCertificate;
  }
  const to = new Date(peer.valid_to).getTime();
  return {
    subject: nameOf(peer.subject).cn,
    subjectOrg: nameOf(peer.subject).o,
    issuer: nameOf(peer.issuer).cn,
    issuerOrg: nameOf(peer.issuer).o,
    san: (peer.subjectaltname ?? '').split(/,\s*/).filter(Boolean).map((s) => s.replace(/^DNS:/, '').replace(/^IP Address:/, '')),
    validFrom: new Date(peer.valid_from).toISOString(),
    validTo: new Date(to).toISOString(),
    daysLeft: Math.floor((to - now) / 86400000),
    serial: peer.serialNumber,
    fingerprint256: peer.fingerprint256,
    keyBits: (peer as { bits?: number }).bits,
    chain,
  };
}

function tlsInfo(s: tls.TLSSocket, host: string): TlsInfo {
  const peer = s.getPeerCertificate(true);
  const has = peer && Object.keys(peer).length > 0;
  let nameError: string | undefined;
  if (has) {
    const err = tls.checkServerIdentity(host, peer);
    nameError = err?.message;
  } else nameError = t('aucun certificat présenté');
  const authErr = s.authorizationError ? String((s.authorizationError as Error).message ?? s.authorizationError) : undefined;
  return {
    protocol: s.getProtocol() ?? undefined,
    cipher: s.getCipher()?.standardName ?? s.getCipher()?.name,
    alpn: typeof s.alpnProtocol === 'string' ? s.alpnProtocol : undefined,
    chainValid: s.authorized,
    chainError: s.authorized ? undefined : authErr,
    nameValid: !nameError,
    nameError,
    cert: has ? certInfo(peer) : undefined,
  };
}

/* ---------- request ---------- */

const FORBIDDEN = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'upgrade', 'te', 'keep-alive', 'proxy-connection']);
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Validate user-supplied extra headers: valid names, no CR/LF, no hop-by-hop headers. */
export function cleanHeaders(list: [string, string][]): [string, string][] {
  const out: [string, string][] = [];
  for (const [k, v] of list) {
    const name = String(k).trim();
    const value = String(v ?? '').trim();
    if (!name) continue;
    if (!TOKEN.test(name)) throw new UnsafeTargetError(t("Nom d'en-tête invalide : {name}", { name: name.slice(0, 40) }));
    if (/[\r\n\0]/.test(value)) throw new UnsafeTargetError(t("Valeur d'en-tête invalide pour {name}", { name }));
    if (FORBIDDEN.has(name.toLowerCase())) throw new UnsafeTargetError(t("L'en-tête {name} est géré par l'outil et ne peut pas être remplacé.", { name }));
    out.push([name, value]);
  }
  return out;
}

function parseHead(head: string): { line: string; headers: [string, string][] } {
  const lines = head.split('\r\n').filter(Boolean);
  const headers: [string, string][] = [];
  for (const l of lines.slice(1)) {
    const i = l.indexOf(':');
    if (i > 0) headers.push([l.slice(0, i), l.slice(i + 1).trim()]);
  }
  return { line: lines[0] ?? '', headers };
}

function errCode(e: unknown): string {
  if (e instanceof UnsafeTargetError) return 'UNSAFE_TARGET';
  return ((e as { code?: string }).code ?? 'ERROR').toString();
}

function errText(e: unknown, host: string, port: number): string {
  const code = errCode(e);
  const m = (e as Error).message ?? String(e);
  switch (code) {
    case 'ECONNREFUSED': return t('Connexion refusée par {host}:{port}.', { host, port });
    case 'ECONNRESET': return t('Connexion coupée par le serveur {host}.', { host });
    case 'ETIMEDOUT': case 'TIMEOUT': return t('Pas de réponse de {host} en {s} s.', { host, s: HOP_TIMEOUT_MS / 1000 });
    case 'EHOSTUNREACH': case 'ENETUNREACH': return t('Adresse de {host} injoignable depuis le serveur de check.', { host });
    case 'ENOTFOUND': case 'NXDOMAIN': return (e as { own?: boolean }).own ? m : t("Le nom {host} n'existe pas ou n'a pas d'adresse.", { host });
    case 'EPROTO': case 'ERR_SSL_WRONG_VERSION_NUMBER': return t('Négociation TLS impossible avec {host} : {error}', { host, error: m });
    case 'HPE_INVALID_CONSTANT': case 'HPE_INVALID_HEADER_TOKEN': return t('Réponse HTTP mal formée de {host} : {error}', { host, error: m });
    default: return m;
  }
}

export async function traceRequest(url: string, o: TraceRequestOptions = {}): Promise<HttpExchange> {
  const u = new URL(url);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new UnsafeTargetError(t('Protocole non suivi : {protocol}', { protocol: u.protocol }));
  const secure = u.protocol === 'https:';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const port = u.port ? Number(u.port) : secure ? 443 : 80;
  const method = o.method ?? 'GET';
  const timeout = o.timeoutMs ?? HOP_TIMEOUT_MS;
  const seam = seamOrDefault(o);
  const t0 = performance.now();
  const ex: HttpExchange = {
    url: u.toString(),
    method,
    host,
    requestLine: '',
    requestHeaders: [],
    port,
    rawHeaders: [],
    timings: { dns: 0, connect: 0, tls: 0, wait: 0, download: 0, total: 0 },
  };
  const hostHeader = u.port ? `${u.hostname}:${u.port}` : u.hostname;
  const sendHeaders: [string, string][] = [['Host', hostHeader], ...(o.headers ?? [])];
  if (!sendHeaders.some(([k]) => k.toLowerCase() === 'cache-control')) sendHeaders.push(['Cache-Control', 'no-cache']);
  if (!sendHeaders.some(([k]) => k.toLowerCase() === 'pragma')) sendHeaders.push(['Pragma', 'no-cache']);
  sendHeaders.push(['Connection', 'close']);
  const fallbackHead = () => {
    const path = (u.pathname || '/') + u.search;
    ex.requestLine ||= `${method} ${path} HTTP/1.1`;
    if (!ex.requestHeaders.length) ex.requestHeaders = sendHeaders;
  };

  // resolution + SSRF check, before any connection
  let ip: string;
  try {
    if (net.isIP(host)) ip = host;
    else {
      const r = await Promise.race([
        seam.lookup(host),
        new Promise<never>((_, rej) => setTimeout(() => rej(Object.assign(new Error(t('Résolution DNS de {host} trop longue.', { host })), { code: 'TIMEOUT' })), timeout).unref()),
      ]);
      ip = r.ip;
      ex.cnames = r.cnames?.length ? r.cnames : undefined;
    }
    ex.timings.dns = round(performance.now() - t0);
    ex.ip = ip;
    if (!seam.isAllowed(ip)) throw new UnsafeTargetError(t('Adresse non publique refusée : {ip}. Le serveur de TestAndFix ne suit pas une URL qui mène vers un réseau privé ou local.', { ip }));
  } catch (e) {
    fallbackHead();
    ex.timings.total = round(performance.now() - t0);
    ex.error = { code: errCode(e), message: errText(e, host, port) };
    return ex;
  }

  return new Promise<HttpExchange>((resolve) => {
    const tStart = performance.now();
    let tConnect = 0;
    let tSecure = 0;
    let tSent = 0;
    let tFirst = 0;
    let finished = false;
    const kept: Buffer[] = [];
    let keptBytes = 0;
    let size = 0;
    let truncated = false;
    let sizeComplete = true;
    let tlsSocket: tls.TLSSocket | undefined;

    const finish = (err?: unknown) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      o.signal?.removeEventListener('abort', onAbort);
      const end = performance.now();
      fallbackHead();
      if (tlsSocket && !ex.tls && tSecure) ex.tls = tlsInfo(tlsSocket, host);
      ex.timings.connect = round((tConnect || end) - tStart);
      ex.timings.tls = secure && tConnect ? round((tSecure || end) - tConnect) : 0;
      const sent = tSent || tSecure || tConnect;
      ex.timings.wait = tFirst && sent ? round(tFirst - sent) : sent ? round(end - sent) : 0;
      ex.timings.download = tFirst ? round(end - tFirst) : 0;
      ex.timings.total = round(end - t0);
      if (ex.status !== undefined) {
        const ct = getHeader(ex.rawHeaders, 'content-type');
        const ce = getHeader(ex.rawHeaders, 'content-encoding');
        ex.body = analyzeBody(Buffer.concat(kept), { size, sizeComplete, truncated }, ct, method === 'HEAD' ? undefined : ce);
      }
      if (err && (ex.status === undefined || !(err as { benign?: boolean }).benign)) {
        ex.error = { code: errCode(err), message: errText(err, host, port) };
      }
      req.destroy();
      resolve(ex);
    };

    const opts: https.RequestOptions = {
      host: ip,
      port,
      method,
      path: (u.pathname || '/') + u.search,
      agent: false,
      setHost: false,
      // flat [name, value, ...] array (rawHeaders format): names keep their case and order
      headers: sendHeaders.flat() as unknown as http.OutgoingHttpHeaders,
      family: net.isIPv6(ip) ? 6 : 4,
    };
    if (secure) {
      Object.assign(opts, {
        servername: net.isIP(host) ? undefined : host,
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1'],
      });
    }
    const req = (secure ? https : http).request(opts);
    const onAbort = () => finish(Object.assign(new Error(t('Mesure interrompue.')), { code: 'ABORTED' }));
    o.signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => finish(Object.assign(new Error('timeout'), { code: 'TIMEOUT' })), timeout);

    req.on('socket', (s) => {
      s.once('connect', () => (tConnect = performance.now()));
      if (secure) {
        tlsSocket = s as tls.TLSSocket;
        s.once('secureConnect', () => {
          tSecure = performance.now();
          ex.tls = tlsInfo(s as tls.TLSSocket, host);
        });
      }
    });
    req.on('finish', () => {
      tSent = performance.now();
      const head = (req as unknown as { _header?: string })._header;
      if (head) {
        const p = parseHead(head);
        ex.requestLine = p.line;
        ex.requestHeaders = p.headers;
      }
    });
    req.on('response', (res) => {
      tFirst = performance.now();
      ex.httpVersion = res.httpVersion;
      ex.status = res.statusCode;
      ex.statusText = res.statusMessage;
      ex.rawHeaders = pairs(res.rawHeaders);
      const max = o.maxBody ?? BODY_LIMIT;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (keptBytes < max) {
          const room = max - keptBytes;
          kept.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
          keptBytes += Math.min(room, chunk.length);
          if (chunk.length > room) truncated = true;
        } else truncated = true;
        if (size >= COUNT_LIMIT) {
          sizeComplete = false;
          finish();
        }
      });
      res.on('end', () => finish());
      res.on('aborted', () => finish(Object.assign(new Error(t('Réponse interrompue par le serveur.')), { code: 'ECONNRESET', benign: true })));
      res.on('error', (e) => finish(Object.assign(e, { benign: true })));
    });
    req.on('error', (e) => finish(e));
    req.end();
  });
}

/** Does the server offer HTTP/2 (ALPN h2)? One extra TLS handshake, no request sent. */
export async function probeH2(url: string, o: Pick<TraceRequestOptions, 'dns' | 'network'> & { ip?: string } = {}): Promise<boolean | undefined> {
  const u = new URL(url);
  if (u.protocol !== 'https:') return undefined;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const seam = seamOrDefault(o);
  let ip = o.ip;
  try {
    if (!ip) ip = net.isIP(host) ? host : (await seam.lookup(host)).ip;
  } catch {
    return undefined;
  }
  if (!seam.isAllowed(ip)) return undefined;
  return new Promise((resolve) => {
    const s = tls.connect({ host: ip, port: u.port ? Number(u.port) : 443, servername: net.isIP(host) ? undefined : host, ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: false, timeout: 5000 });
    const done = (v: boolean | undefined) => {
      s.destroy();
      resolve(v);
    };
    s.once('secureConnect', () => done(s.alpnProtocol === 'h2'));
    s.once('error', () => done(undefined));
    s.once('timeout', () => done(undefined));
  });
}
