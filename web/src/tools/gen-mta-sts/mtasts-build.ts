// MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) generator model: policy file, _mta-sts and
// _smtp._tls records, MX list parsing and coverage. Pure, unit tested.
import { msg } from '../../lib/i18n';
import { parseMailto, stampId } from '../gen-spf/txt';

export type StsMode = 'testing' | 'enforce';
export const MAX_AGE_MAX = 31557600; // RFC 8461 §3.2

export interface StsModel {
  mode: StsMode;
  mx: string[];
  maxAge: number;
  id: string;
  tlsRua: string[];
}

const HOST = /^(\*\.)?((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$/;

/** Tolerant MX list: "10 mx1.exemple.fr.", commas, new lines, capitals; wildcards "*.x.y" kept. */
export function parseMxList(raw: string): { mx: string[]; errors: string[] } {
  const mx: string[] = [];
  const errors: string[] = [];
  for (let line of raw.split(/[\n,;]+/)) {
    line = line.trim().replace(/^mx:\s*/i, '');
    if (!line) continue;
    const host = line.split(/\s+/).pop()!.toLowerCase().replace(/\.$/, '');
    if (HOST.test(host)) {
      if (!mx.includes(host)) mx.push(host);
    } else errors.push(line);
  }
  return { mx, errors };
}

/** RFC 8461 §4.1: "*." matches exactly one left-most label. */
export function mxMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const rest = p.slice(2);
    const i = h.indexOf('.');
    return i > 0 && h.slice(i + 1) === rest;
  }
  return h === p;
}

export const covered = (host: string, patterns: string[]) => patterns.some((p) => mxMatches(host, p));

/** The policy file, LF line ends (RFC 8461 §3.2 accepts CRLF or LF). */
export function policyFile(m: StsModel): string {
  return ['version: STSv1', `mode: ${m.mode}`, ...m.mx.map((h) => `mx: ${h}`), `max_age: ${Math.min(MAX_AGE_MAX, Math.max(0, Math.round(m.maxAge)))}`, ''].join('\n');
}

export const stsRecord = (id: string) => `v=STSv1; id=${id}`;

/** RFC 8461 §3.1: id is 1 to 32 letters or digits. */
export const validId = (id: string) => /^[A-Za-z0-9]{1,32}$/.test(id);

export function tlsRptRecord(rua: string[]): string {
  const uris = rua.map(parseMailto).flatMap((r) => ('uri' in r ? [r.uri] : []));
  return `v=TLSRPTv1; rua=${uris.join(',')}`;
}

export function defaultSts(domain?: string, now = new Date()): StsModel {
  return { mode: 'testing', mx: [], maxAge: 604800, id: stampId(now), tlsRua: domain ? [`tlsrpt@${domain}`] : [] };
}

export const MAX_AGES: { value: number; label: string }[] = [
  { value: 86400, label: msg('1 jour') },
  { value: 604800, label: msg('1 semaine') },
  { value: 1209600, label: msg('2 semaines') },
  { value: MAX_AGE_MAX, label: msg('1 an (maximum)') },
];
