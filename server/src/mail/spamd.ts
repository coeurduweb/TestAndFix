// Minimal spamc client: SPAMC/1.5 over TCP to spamd, REPORT command.
// Protocol: request line, headers, blank line, message; spamd answers with a status line,
// headers (Spam: True ; 7.2 / 5.0) and the textual report, then closes the connection.
import net from 'node:net';
import { t } from '../i18n.js';

export interface SpamdRule {
  name: string;
  score: number;
  description: string;
}

export interface SpamdResult {
  isSpam: boolean;
  score: number;
  threshold: number;
  rules: SpamdRule[];
  /** Raw report text as spamd returned it. */
  report: string;
  ms: number;
}

export class SpamdError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

export interface SpamdOptions {
  host: string;
  port: number;
  timeoutMs?: number;
  /** spamd user (only meaningful with per-user configs, which our image disables). */
  user?: string;
}

/** Send a command to spamd and return the raw response (headers + body). */
export function spamdRequest(
  command: 'REPORT' | 'SYMBOLS' | 'CHECK' | 'PING',
  message: Buffer | undefined,
  opts: SpamdOptions,
): Promise<{ status: number; statusText: string; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host: opts.host, port: opts.port });
    const chunks: Buffer[] = [];
    let done = false;
    const finish = (err: Error | null, out?: Buffer) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) return reject(err);
      try {
        resolve(parseResponse(out!));
      } catch (e) {
        reject(e);
      }
    };
    const timer = setTimeout(
      () => finish(new SpamdError('ETIMEOUT', t("spamd n'a pas répondu en {n} s", { n: Math.round((opts.timeoutMs ?? 30000) / 1000) }))),
      opts.timeoutMs ?? 30000,
    );
    sock.on('error', (e) => finish(new SpamdError((e as NodeJS.ErrnoException).code ?? 'ECONN', e.message)));
    sock.on('data', (d: Buffer) => chunks.push(d));
    sock.on('end', () => finish(null, Buffer.concat(chunks)));
    sock.on('connect', () => {
      const lines = [`${command} SPAMC/1.5`];
      if (message) lines.push(`Content-length: ${message.length}`);
      if (opts.user) lines.push(`User: ${opts.user}`);
      sock.write(lines.join('\r\n') + '\r\n\r\n');
      if (message) sock.write(message);
      sock.end();
    });
  });
}

function parseResponse(buf: Buffer) {
  const text = buf.toString('utf8');
  const sep = text.search(/\r?\n\r?\n/);
  const head = sep === -1 ? text : text.slice(0, sep);
  const body = sep === -1 ? '' : text.slice(sep).replace(/^\r?\n\r?\n/, '');
  const [statusLine, ...headerLines] = head.split(/\r?\n/);
  const m = /^SPAMD\/[\d.]+\s+(\d+)\s*(.*)$/.exec(statusLine ?? '');
  if (!m) throw new SpamdError('EPROTO', t('Réponse inattendue de spamd : {line}', { line: (statusLine ?? '').slice(0, 80) }));
  const headers: Record<string, string> = {};
  for (const l of headerLines) {
    const i = l.indexOf(':');
    if (i > 0) headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  return { status: Number(m[1]), statusText: m[2].trim(), headers, body };
}

/** "True ; 7.2 / 5.0" */
export function parseSpamHeader(v: string | undefined): { isSpam: boolean; score: number; threshold: number } {
  const m = /^\s*(true|false|yes|no)\s*;\s*(-?[\d.]+)\s*\/\s*(-?[\d.]+)/i.exec(v ?? '');
  if (!m) return { isSpam: false, score: NaN, threshold: NaN };
  return { isSpam: /^(true|yes)$/i.test(m[1]), score: Number(m[2]), threshold: Number(m[3]) };
}

/**
 * Parse the rule table of a SpamAssassin report:
 *
 *  pts rule name              description
 * ---- ---------------------- --------------------------------------------------
 *  0.1 MISSING_MID            Missing Message-Id: header
 * -0.0 NO_RELAYS              Informational: message was not relayed via SMTP
 *                             continuation of the description
 */
export function parseReportRules(report: string): SpamdRule[] {
  const rules: SpamdRule[] = [];
  const lines = report.split(/\r?\n/);
  // our image's template prints only _SUMMARY_ (no table header); the stock one has a header
  let inTable = !lines.some((l) => /^\s*-{3,}\s+-{3,}/.test(l));
  for (const line of lines) {
    if (/^\s*-{3,}\s+-{3,}/.test(line)) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    const m = /^\s*(-?\d+(?:\.\d+)?)\s+([A-Z0-9_]+)\s+(.*)$/.exec(line);
    if (m) {
      rules.push({ score: Number(m[1]), name: m[2], description: m[3].trim() });
      continue;
    }
    const cont = /^\s{10,}(\S.*)$/.exec(line);
    if (cont && rules.length) {
      const last = rules[rules.length - 1];
      last.description = `${last.description} ${cont[1].trim()}`.trim();
      continue;
    }
    if (line.trim() === '') continue;
    // anything else ends the table (template text after the summary)
    if (rules.length) inTable = false;
  }
  return rules;
}

/** Run REPORT on a message. Throws SpamdError when spamd cannot be reached or misbehaves. */
export async function spamdReport(message: Buffer, opts: SpamdOptions): Promise<SpamdResult> {
  const started = performance.now();
  const res = await spamdRequest('REPORT', message, opts);
  if (res.status !== 0) throw new SpamdError(`EX_${res.status}`, t('spamd a répondu {status} {text}', { status: res.status, text: res.statusText }));
  const spam = parseSpamHeader(res.headers.spam);
  return {
    ...spam,
    rules: parseReportRules(res.body),
    report: res.body,
    ms: Math.round(performance.now() - started),
  };
}

export async function spamdPing(opts: SpamdOptions): Promise<boolean> {
  try {
    const res = await spamdRequest('PING', undefined, { ...opts, timeoutMs: opts.timeoutMs ?? 3000 });
    return res.statusText.includes('PONG');
  } catch {
    return false;
  }
}
