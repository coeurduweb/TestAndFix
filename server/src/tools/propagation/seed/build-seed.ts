// Builds server/data-seed/resolvers.json, the versioned pool of CANDIDATE resolvers.
// Nothing in this file is trusted at runtime: every candidate is re-qualified daily by
// qualify.ts before it can be shown. The seed only says "worth testing" and gives metadata.
//
// Run from server/:  npx tsx src/tools/propagation/seed/build-seed.ts
//
// Inputs (research done on 2026-11-10, see research/resolveurs.md):
//   research/resolveurs-candidats.json   291 documented or sampled resolvers
//   research/raw/nameservers.json        public-dns.info dump (metadata only: frozen since 2023-08)
//   research/work/deep.res               3 468 IPv4 that gave the consensus answer, with NXDOMAIN test
//   research/work/div_ips.txt            549 IPv4 that answered with another view of example.com
//   trickest/resolvers + massdns lists   downloaded now, probed once (a.root-servers.net A)
// Enrichment: RIPEstat (no key) maxmind-geo-lite for country/city/lat/lon, network-info and
// as-overview for the ASN and its holder when public-dns.info does not know the IP.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { query } from '../../../dns/client.js';
import { mapLimit } from '../util.js';
import type { SeedResolver } from '../types.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..', '..', '..', '..');
const research = path.join(repo, 'research');
const out = path.join(repo, 'server', 'data-seed', 'resolvers.json');

const TRICKEST = 'https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt';
const MASSDNS = 'https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt';
const RIPESTAT = 'https://stat.ripe.net/data';

interface Candidate {
  ip: string;
  name: string;
  provider: string;
  country_code: string;
  city?: string;
  anycast: boolean;
  filtering: string;
  source: string;
  group: string;
  test?: { status: string };
}
interface PdEntry {
  ip: string;
  name: string;
  as_number: number | null;
  as_org: string;
  country_id: string;
  city: string;
}

async function ripe<T>(call: string, resource: string): Promise<T | null> {
  const url = `${RIPESTAT}/${call}/data.json?resource=${encodeURIComponent(resource)}&sourceapp=check-propagation`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (r.ok) return ((await r.json()) as { data: T }).data;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
  }
  return null;
}

interface GeoLite {
  located_resources: { locations: { country: string; city: string; latitude: number; longitude: number; covered_percentage: number }[] }[];
}

async function geolocate(ip: string) {
  const d = await ripe<GeoLite>('maxmind-geo-lite', ip);
  const loc = d?.located_resources?.[0]?.locations?.sort((a, b) => b.covered_percentage - a.covered_percentage)[0];
  // '?' and 0,0 are MaxMind's "unknown" (typically anycast space)
  if (!loc || !loc.country || loc.country === '?' || (loc.latitude === 0 && loc.longitude === 0)) return null;
  return {
    country_code: loc.country.toUpperCase(),
    city: loc.city || null,
    lat: loc.latitude,
    lon: loc.longitude,
    geo_precision: (loc.city ? 'city' : 'country') as 'city' | 'country',
  };
}

/**
 * ASNs that only run anycast public DNS services or CDNs. An open resolver found in these ASNs by
 * public-dns.info or trickest is one more address of an anycast service, not a local resolver:
 * it is dropped (the documented addresses of these services are kept in the 'global' group).
 * Hosting and transit ASNs (Lumen 3356, Cogent 174, HE 6939, Alibaba, Tencent, Yandex, xTom)
 * are NOT listed: they also host real unicast resolvers, the RTT check sorts them out.
 */
export const ANYCAST_DNS_ASNS = new Set([
  13335, // Cloudflare
  15169, // Google
  19281, // Quad9
  36692, // Cisco OpenDNS
  212772, // AdGuard
  398962, // Control D
  34939, // NextDNS
  205157, // CleanBrowsing
  57926, // SafeDNS
  33517, // Oracle Dyn
  23393, // NuCDN (Comodo Secure DNS)
  12008, 19905, 397213, 397215, // Vercara / UltraDNS / Neustar / Verisign public DNS
  198121, // DNS4EU
  50902, // dns0.eu
  57138, // Mullvad
  131621, // TWNIC (Quad101)
]);

/** Last pass, also runnable alone on an existing seed: `build-seed.ts --refinalize`. */
function finalize(list: SeedResolver[]): { list: SeedResolver[]; dropped: number } {
  const kept: SeedResolver[] = [];
  let dropped = 0;
  for (const r of list) {
    if (r.group === 'local' && r.asn != null && ANYCAST_DNS_ASNS.has(r.asn)) {
      dropped++;
      continue;
    }
    if (r.country_code === '?' || (r.lat === 0 && r.lon === 0)) {
      const before = r.geo_note?.match(/public-dns\.info: ([A-Z]{2})/)?.[1];
      r.country_code = before ?? '';
      r.city = null;
      r.lat = null;
      r.lon = null;
      r.geo_precision = null;
      delete r.geo_note;
    }
    kept.push(r);
  }
  kept.sort((a, b) => (a.group === b.group ? a.country_code.localeCompare(b.country_code) || a.ip.localeCompare(b.ip) : a.group === 'global' ? -1 : 1));
  return { list: kept, dropped };
}

function write(list: SeedResolver[], dropped: number) {
  const doc = {
    _about:
      'Candidate resolvers for the propagation tool. NOT a list of good resolvers: each one is re-qualified daily before being shown. Built by server/src/tools/propagation/seed/build-seed.ts.',
    built_at: new Date().toISOString(),
    counts: {
      total: list.length,
      global: list.filter((r) => r.group === 'global').length,
      local: list.filter((r) => r.group === 'local').length,
      with_coordinates: list.filter((r) => r.lat != null).length,
      countries: new Set(list.map((r) => r.country_code).filter(Boolean)).size,
      dropped_anycast_asn: dropped,
    },
    resolvers: list,
  };
  fs.writeFileSync(out, JSON.stringify(doc, null, 0).replace(/\},\{/g, '},\n{') + '\n');
  console.log(doc.counts);
}

/**
 * `build-seed.ts --add-ipv6`: add IPv6 candidates to the existing seed (US-062).
 * Documented resolvers: their published IPv6 address (research kept it only when it answered);
 * public-dns.info: IPv6 entries with reliability >= 0.99 and no error (frozen 2023 data, so
 * candidates only: the daily qualification decides, when the server has IPv6).
 */
async function addIpv6() {
  const doc = JSON.parse(fs.readFileSync(out, 'utf8')) as { resolvers: SeedResolver[]; counts: { dropped_anycast_asn?: number } };
  const list = doc.resolvers;
  const have = new Set(list.map((r) => r.ip));
  const byV4 = new Map(list.map((r) => [r.ip, r]));
  const candidates = JSON.parse(fs.readFileSync(path.join(research, 'resolveurs-candidats.json'), 'utf8')) as (Candidate & { ipv6?: string })[];
  const added: SeedResolver[] = [];
  for (const c of candidates) {
    if (!c.ipv6 || have.has(c.ipv6) || !net.isIPv6(c.ipv6)) continue;
    const base = byV4.get(c.ip);
    if (!base) continue;
    added.push({ ...base, ip: c.ipv6, name: `${base.name} (IPv6)`, lat: base.anycast ? null : base.lat, lon: base.anycast ? null : base.lon });
    have.add(c.ipv6);
  }
  const pd = JSON.parse(fs.readFileSync(path.join(research, 'raw', 'nameservers.json'), 'utf8')) as (PdEntry & { reliability: number; error: string })[];
  for (const p of pd) {
    if (!net.isIPv6(p.ip) || have.has(p.ip) || p.reliability < 0.99 || p.error) continue;
    added.push({
      ip: p.ip,
      name: p.name ? p.name.replace(/\.$/, '') : p.ip,
      provider: p.as_org || 'inconnu',
      asn: p.as_number ?? null,
      country_code: (p.country_id || '').toUpperCase(),
      city: p.city || null,
      lat: null,
      lon: null,
      geo_precision: null,
      anycast: false,
      filtering: 'none',
      source: `https://public-dns.info/nameserver/${(p.country_id || '').toLowerCase()}.html`,
      group: 'local',
    });
    have.add(p.ip);
  }
  await mapLimit(added.filter((r) => !r.anycast && r.lat == null), 6, async (r) => {
    const g = await geolocate(r.ip);
    if (g) {
      if (r.country_code && r.country_code !== g.country_code) r.geo_note = `public-dns.info: ${r.country_code}`;
      Object.assign(r, g);
    }
  });
  console.log(`IPv6 added: ${added.length} (${added.filter((r) => r.anycast).length} anycast)`);
  const f = finalize([...list, ...added]);
  write(f.list, f.dropped + (doc.counts.dropped_anycast_asn ?? 0));
}

async function main() {
  if (process.argv.includes('--add-ipv6')) return addIpv6();
  if (process.argv.includes('--refinalize')) {
    const doc = JSON.parse(fs.readFileSync(out, 'utf8')) as { resolvers: SeedResolver[]; counts: { dropped_anycast_asn?: number } };
    const f = finalize(doc.resolvers);
    write(f.list, f.dropped + (doc.counts.dropped_anycast_asn ?? 0));
    return;
  }
  const candidates = JSON.parse(fs.readFileSync(path.join(research, 'resolveurs-candidats.json'), 'utf8')) as Candidate[];
  const pd = new Map<string, PdEntry>();
  for (const e of JSON.parse(fs.readFileSync(path.join(research, 'raw', 'nameservers.json'), 'utf8')) as PdEntry[]) pd.set(e.ip, e);

  const pool = new Map<string, SeedResolver>();
  const add = (r: SeedResolver) => {
    if (!net.isIPv4(r.ip) || pool.has(r.ip)) return;
    pool.set(r.ip, r);
  };

  // 1. Documented resolvers and the research sample (all statuses: the daily job decides).
  for (const c of candidates) {
    const p = pd.get(c.ip);
    add({
      ip: c.ip,
      name: c.name,
      provider: c.provider,
      asn: p?.as_number ?? null,
      country_code: c.country_code,
      city: c.city ?? null,
      lat: null,
      lon: null,
      geo_precision: null,
      anycast: c.anycast,
      filtering: c.filtering,
      source: c.source,
      group: c.anycast ? 'global' : 'local',
    });
  }
  const fromPd = (ip: string) => {
    const p = pd.get(ip);
    if (!p) return;
    add({
      ip,
      name: p.name ? p.name.replace(/\.$/, '') : ip,
      provider: p.as_org || 'inconnu',
      asn: p.as_number ?? null,
      country_code: (p.country_id || '').toUpperCase(),
      city: p.city || null,
      lat: null,
      lon: null,
      geo_precision: null,
      anycast: false,
      filtering: 'none',
      source: `https://public-dns.info/nameserver/${(p.country_id || '').toLowerCase()}.html`,
      group: 'local',
    });
  };
  // 2. public-dns.info resolvers that answered correctly and honestly on 2026-11-10.
  let honest = 0;
  for (const line of fs.readFileSync(path.join(research, 'work', 'deep.res'), 'utf8').split('\n')) {
    const [ip, status, , nx] = line.split('\t');
    if (status === 'NOERROR' && nx === 'NXDOMAIN') {
      honest++;
      fromPd(ip);
    }
  }
  // 3. Resolvers that answered with another view of example.com (cause unknown): retest them.
  const div = fs.readFileSync(path.join(research, 'work', 'div_ips.txt'), 'utf8').split('\n').filter(Boolean);
  for (const ip of div) fromPd(ip);
  console.log(`candidates ${candidates.length}, honest deep.res ${honest}, div ${div.length}, pool ${pool.size}`);

  // 4. trickest + massdns: IPs unknown so far, kept only if they answer a.root-servers.net A now.
  const lists: [string, string][] = [];
  for (const [url, label] of [[TRICKEST, 'https://github.com/trickest/resolvers'], [MASSDNS, 'https://github.com/blechschmidt/massdns']]) {
    const txt = await (await fetch(url)).text();
    for (const l of txt.split('\n')) {
      const ip = l.trim();
      if (net.isIPv4(ip) && !pool.has(ip)) lists.push([ip, label]);
    }
  }
  const uniq = new Map(lists);
  console.log(`trickest+massdns new IPv4: ${uniq.size}, probing…`);
  const alive: [string, string][] = [];
  await mapLimit([...uniq], 100, async ([ip, label]) => {
    try {
      const r = await query(ip, 'a.root-servers.net', 'A', { timeoutMs: 2000 });
      if (r.rcode === 'NOERROR' && r.flags.ra && r.answers.some((a) => a.type === 'A' && a.data === '198.41.0.4')) alive.push([ip, label]);
    } catch {
      /* dead */
    }
  });
  console.log(`alive: ${alive.length}`);
  for (const [ip, label] of alive) {
    const p = pd.get(ip);
    add({
      ip,
      name: p?.name ? p.name.replace(/\.$/, '') : ip,
      provider: p?.as_org || 'inconnu',
      asn: p?.as_number ?? null,
      country_code: (p?.country_id || '').toUpperCase(),
      city: p?.city || null,
      lat: null,
      lon: null,
      geo_precision: null,
      anycast: false,
      filtering: 'none',
      source: label,
      group: 'local',
    });
  }

  // 5. Enrichment (unicast only: an anycast address has no single location).
  const list = [...pool.values()];
  const asnHolder = new Map<number, string>();
  let done = 0;
  await mapLimit(list, 8, async (r) => {
    if (!r.anycast) {
      const g = await geolocate(r.ip);
      if (g) {
        if (r.country_code && r.country_code !== g.country_code) r.geo_note = `public-dns.info: ${r.country_code}`;
        Object.assign(r, g);
      }
    }
    if (r.asn == null) {
      const ni = await ripe<{ asns: string[] }>('network-info', r.ip);
      if (ni?.asns?.[0]) r.asn = Number(ni.asns[0]);
    }
    if (++done % 500 === 0) console.log(`enriched ${done}/${list.length}`);
  });
  const missingHolders = [...new Set(list.filter((r) => r.provider === 'inconnu' && r.asn != null).map((r) => r.asn!))];
  await mapLimit(missingHolders, 8, async (asn) => {
    const d = await ripe<{ holder: string }>('as-overview', `AS${asn}`);
    if (d?.holder) asnHolder.set(asn, d.holder);
  });
  for (const r of list) if (r.provider === 'inconnu' && r.asn != null && asnHolder.has(r.asn)) r.provider = asnHolder.get(r.asn)!;

  const f = finalize(list);
  write(f.list, f.dropped);
}

await main();
