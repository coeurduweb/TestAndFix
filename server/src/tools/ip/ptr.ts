// Reverse DNS of an IP and its forward confirmation (FCrDNS): the PTR name must resolve back to
// the same address.
import ipaddr from 'ipaddr.js';
import { lookupAddresses, lookupType, norm, type Resolver } from '../../lib/email-auth/common.js';
import { reverseName } from '../../lib/net.js';

export interface PtrData {
  ip: string;
  query: string;
  rcode: string;
  names: string[];
  fcrdns: { name: string; ips: string[]; matches: boolean }[];
  confirmed?: string;
  error?: string;
  /** Kind of name, from its look: grand public, default hosting name, or neither. */
  generic?: 'dynamic' | 'hosting';
}

const same = (a: string, b: string) => {
  try {
    return ipaddr.parse(a).toNormalizedString() === ipaddr.parse(b).toNormalizedString();
  } catch {
    return a === b;
  }
};

// Words of the knowledge base (rdns.generic_dynamic, detect.signal)
const DYNAMIC = /dyn|dhcp|dsl|pool|cable|ppp|dial|client|customer|residential|broadband|fibre|fiber|ftth/i;
const MAIL_NAME = /^(mail|smtp|mx|out)[0-9]*[.]/i;
const HOSTING = /amazonaws|compute|googleusercontent|cloudapp|azure|ovh|kimsufi|hetzner|your-server|linode|vultr|digitalocean|scaleway|contabo|ionos|static|server|vps|host|cloud|dedi/i;

export function genericKind(ip: string, name: string): PtrData['generic'] {
  if (MAIL_NAME.test(name)) return undefined;
  if (DYNAMIC.test(name)) return 'dynamic';
  const parts = ip.includes(':') ? [] : ip.split('.');
  const hasIp = parts.length === 4 && (name.includes(parts.join('-')) || name.includes([...parts].reverse().join('-')) || name.includes([...parts].reverse().join('.')) || name.includes(parts.join('.')));
  return hasIp || HOSTING.test(name) ? 'hosting' : undefined;
}

export async function lookupPtr(dns: Resolver, ip: string): Promise<PtrData> {
  const query = reverseName(ip);
  const r = await lookupType(dns, query, 'PTR');
  const names = [...new Set(r.data.map((d) => norm(String(d))))];
  const out: PtrData = { ip, query, rcode: r.rcode, names, fcrdns: [], error: r.error };
  out.fcrdns = await Promise.all(
    names.slice(0, 4).map(async (name) => {
      const a = await lookupAddresses(dns, name, ip.includes(':') ? ['AAAA'] : ['A']);
      return { name, ips: a.ips, matches: a.ips.some((x) => same(x, ip)) };
    }),
  );
  out.confirmed = out.fcrdns.find((f) => f.matches)?.name;
  if (names[0]) out.generic = genericKind(ip, names[0]);
  return out;
}
