// Public or not: an A/AAAA answer in a non-public range (127/8, 0/8, RFC 1918, link-local, CGNAT,
// documentation, ::1, ::, fc00::/7, fe80::/10…) for a name whose real answer is public is a
// rewrite by the resolver (block page, captive portal, filter), never a propagation state.
import ipaddr from 'ipaddr.js';

/** Ranges of ipaddr.js that are reachable on the Internet. Everything else counts as non-public. */
const PUBLIC_V4 = new Set(['unicast']);
const PUBLIC_V6 = new Set(['unicast', '6to4', 'teredo', 'rfc6052', 'rfc6145']);

export function isPublicAddress(ip: string): boolean {
  let a: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    a = ipaddr.parse(ip.trim());
  } catch {
    return true; // not an address: nothing to say
  }
  if (a.kind() === 'ipv6') {
    const v6 = a as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) return PUBLIC_V4.has(v6.toIPv4Address().range());
    return PUBLIC_V6.has(v6.range());
  }
  return PUBLIC_V4.has((a as ipaddr.IPv4).range());
}

/** True when one of the canonical A/AAAA values is non-public. */
export const hasNonPublic = (values: string[]) => values.some((v) => !isPublicAddress(v));
