// Path of a message (US-033): Received fields parsed into hops, oldest first, with the delay
// between hops, and the origin hop (the first external relay before the receiving host).
import net from 'node:net';
import psl from 'psl';
import { parseReceived, getClientAddress, getClientHelo } from 'mailauth/lib/parse-received.js';
import { isPublicIp } from '../lib/net.js';
import { t } from '../i18n.js';

export interface Hop {
  /** 1 = oldest hop */
  index: number;
  from?: string;
  /** reverse DNS name the receiving server wrote in the TCP-info comment */
  fromPtr?: string;
  ip?: string;
  helo?: string;
  by?: string;
  with?: string;
  /** true: TLS used, false: plain text, null: not stated */
  tls: boolean | null;
  tlsDetail?: string;
  for?: string;
  at?: string;
  /** seconds since the previous (older) hop, when both have a timestamp */
  delaySec?: number | null;
  raw: string;
}

export function orgDomain(host: string | undefined): string | undefined {
  if (!host) return undefined;
  const h = host.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (net.isIP(h)) return undefined;
  try {
    return psl.get(h) ?? undefined;
  } catch {
    return undefined;
  }
}

function cleanIp(ip: string | false | undefined): string | undefined {
  if (!ip) return undefined;
  const v = ip.replace(/^ipv6:/i, '').replace(/^\[|\]$/g, '');
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(v);
  const out = m ? m[1] : v;
  return net.isIP(out) ? out : undefined;
}

function tlsOf(entry: Record<string, { value?: string; comment?: string } | undefined>): { tls: boolean | null; detail?: string } {
  const withV = entry.with?.value ?? '';
  const t = entry.tls;
  const proto = /\b(TLSv?1(?:\.[0-3])?|SSLv3)\b/i.exec(`${t?.comment ?? ''} ${withV} ${entry.from?.comment ?? ''} ${entry.by?.comment ?? ''}`)?.[1];
  const cipher = /cipher\s+([A-Z0-9_-]+)|\b(TLS_[A-Z0-9_]+|ECDHE-[A-Z0-9-]+)/i.exec(`${t?.comment ?? ''} ${withV}`);
  const detail = [proto, cipher?.[1] ?? cipher?.[2]].filter(Boolean).join(' ') || t?.comment || undefined;
  if (t || /^(e?smtps|esmtpsa|utf8smtps|utf8smtpsa|lmtps)\b/i.test(withV)) return { tls: true, detail };
  if (/^(e?smtp|esmtpa|utf8smtp|utf8smtpa|lmtp)\b/i.test(withV)) return { tls: false };
  return { tls: null };
}

function toIso(ts: string | undefined): string | undefined {
  if (!ts) return undefined;
  const t = Date.parse(ts.replace(/\([^)]*\)/g, '').trim());
  return Number.isFinite(t) ? new Date(t).toISOString() : undefined;
}

/** Received header values, top (newest) first as they appear in the message. Returns hops oldest first. */
export function parseHops(receivedTopFirst: string[]): Hop[] {
  const hops: Hop[] = [];
  const n = receivedTopFirst.length;
  receivedTopFirst.forEach((value, i) => {
    const entry = parseReceived(`Received: ${value}`);
    const e = (entry || {}) as Record<string, { value?: string; comment?: string } | undefined> & { timestamp?: string };
    const ip = cleanIp(entry ? getClientAddress(entry) : false);
    const ptrMatch = /^([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s*\[/i.exec(e.from?.comment ?? '');
    const tls = tlsOf(e);
    hops.push({
      index: n - i,
      from: e.from?.value,
      fromPtr: ptrMatch?.[1]?.toLowerCase(),
      ip,
      helo: (entry ? getClientHelo(entry) : false) || undefined,
      by: e.by?.value,
      with: e.with?.value?.split(/\s+/)[0],
      // "Received: by host with SMTP id" without a from clause is the stamp of the origin, not a network
      // transfer: no TLS verdict (user, 2026-11-12: Gmail's own stamp showed as a plaintext hop)
      tls: !e.from?.value && !ip ? null : tls.tls,
      tlsDetail: tls.detail,
      for: e.for?.value?.replace(/^<|>$/g, ''),
      at: toIso(e.timestamp),
      raw: value,
    });
  });
  hops.reverse();
  for (let i = 0; i < hops.length; i++) {
    const prev = hops[i - 1];
    const cur = hops[i];
    cur.delaySec = prev?.at && cur.at ? Math.round((Date.parse(cur.at) - Date.parse(prev.at)) / 1000) : i === 0 ? undefined : null;
  }
  return hops;
}

export interface Origin {
  ip: string;
  helo?: string;
  ptr?: string;
  hop: Hop;
  reason: string;
}

/**
 * The sending server as seen by the first receiving host that is not the sender's own
 * infrastructure. Walks from the newest hop down: hops from private addresses and hops between
 * hosts of the receiver's own organisation are internal; the first other hop is the origin.
 * `receiverDomains` are organisational domains known to belong to the receiving side
 * (the mailbox host for IMAP).
 */
export function findOrigin(hops: Hop[], receiverDomains: string[] = []): Origin | undefined {
  const newestFirst = [...hops].reverse();
  const receiverOrgs = new Set(receiverDomains.map((d) => orgDomain(d) ?? d.toLowerCase()));
  const topBy = orgDomain(newestFirst.find((h) => h.by && !net.isIP(h.by.replace(/^\[|\]$/g, '')))?.by);
  if (topBy) receiverOrgs.add(topBy);
  for (const h of newestFirst) {
    if (!h.ip) continue;
    if (!isPublicIp(h.ip)) continue;
    const fromOrg = orgDomain(h.fromPtr) ?? orgDomain(h.from);
    if (fromOrg && receiverOrgs.has(fromOrg)) continue;
    return { ip: h.ip, helo: h.helo, ptr: h.fromPtr, hop: h, reason: t('premier relais externe : {from} vers {by}', { from: h.from ?? h.ip, by: h.by ?? '?' }) };
  }
  const anyPublic = newestFirst.find((h) => h.ip && isPublicIp(h.ip));
  if (anyPublic)
    return { ip: anyPublic.ip!, helo: anyPublic.helo, ptr: anyPublic.fromPtr, hop: anyPublic, reason: t('seule adresse publique des Received') };
  return undefined;
}
