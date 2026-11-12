// Geolocation of resolvers and of our own server (RIPEstat, no key).
// Only used to place unicast resolvers on the map and to reject impossible locations
// (an RTT shorter than light allows for the distance). Never used for any DNS answer.
import type { ResolveSession } from '../../dns/iterative.js';
import type { ServerLocation } from './store.js';

const RIPESTAT = 'https://stat.ripe.net/data';

export interface GeoPoint {
  country_code: string;
  city: string | null;
  lat: number;
  lon: number;
  geo_precision: 'city' | 'country';
}

interface GeoLite {
  located_resources?: { locations?: { country: string; city: string; latitude: number; longitude: number; covered_percentage: number }[] }[];
}

export async function geolocateIp(ip: string, timeoutMs = 8000): Promise<GeoPoint | null> {
  try {
    const r = await fetch(`${RIPESTAT}/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}&sourceapp=check-propagation`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!r.ok) return null;
    const d = ((await r.json()) as { data?: GeoLite }).data;
    const loc = d?.located_resources?.[0]?.locations?.sort((a, b) => b.covered_percentage - a.covered_percentage)[0];
    // '?' and 0,0 are MaxMind's "unknown" (anycast space, typically)
    if (!loc?.country || loc.country === '?' || typeof loc.latitude !== 'number' || (loc.latitude === 0 && loc.longitude === 0)) return null;
    return {
      country_code: loc.country.toUpperCase(),
      city: loc.city || null,
      lat: loc.latitude,
      lon: loc.longitude,
      geo_precision: loc.city ? 'city' : 'country',
    };
  } catch {
    return null;
  }
}

/**
 * Our public IPv4 as seen by Google's authoritative servers (o-o.myaddr.l.google.com TXT
 * returns the address of whoever asks; the session asks the authoritative servers itself).
 */
export async function ownPublicIp(session: ResolveSession): Promise<string | null> {
  try {
    const r = await session.resolve('o-o.myaddr.l.google.com', 'TXT');
    for (const a of r.answers) {
      const v = (a.data as Buffer[]).map((b) => b.toString()).join('');
      if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) return v;
    }
  } catch {
    /* unknown */
  }
  return null;
}

/** CHECK_PROPAGATION_SERVER_LOCATION="lat,lon" overrides the lookup (behind NAT, VPN…). */
export async function serverLocation(session: ResolveSession): Promise<ServerLocation | null> {
  const env = process.env.CHECK_PROPAGATION_SERVER_LOCATION;
  if (env && /^-?\d+(\.\d+)?,\s*-?\d+(\.\d+)?$/.test(env)) {
    const [lat, lon] = env.split(',').map(Number);
    return { ip: null, country_code: null, city: null, lat, lon, source: 'CHECK_PROPAGATION_SERVER_LOCATION' };
  }
  const ip = await ownPublicIp(session);
  if (!ip) return null;
  const g = await geolocateIp(ip);
  if (!g) return null;
  return { ip, country_code: g.country_code, city: g.city, lat: g.lat, lon: g.lon, source: 'RIPEstat maxmind-geo-lite' };
}
