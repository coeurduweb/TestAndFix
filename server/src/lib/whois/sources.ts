// Where to ask: the lists published by IANA, kept in memory with their own expiry. These are lists
// of servers, not measures (same reasoning as the OpenPhish feed in CONVENTIONS.md):
//   - RDAP bootstrap for DNS, https://data.iana.org/rdap/dns.json (RFC 9224). RFC 9224 §8: "Clients
//     SHOULD NOT fetch the registry on every RDAP request" and should refresh it from the HTTP
//     Expires header. We follow Expires (then Cache-Control max-age), never less than 5 min, 24 h
//     when the server gives neither, and keep the old copy when a refresh fails.
//   - the WHOIS server of a TLD, from whois.iana.org (the "whois:" line of the TLD record, the same
//     data as the IANA Root Zone Database). No expiry is published for it: kept 24 h, a
//     conservative choice; the root zone changes servers rarely.
//   - the RDAP base URL of an ICANN-accredited registrar from its IANA id, in the IANA "Registrar
//     IDs" registry (https://www.iana.org/assignments/registrar-ids/registrar-ids.xml, element
//     <rdapurl><server>). Used only when the registry answered by WHOIS (an RDAP registry answer
//     already gives that URL, RDAP Response Profile 2.2 §2.4.6). About 1 MB: kept per its
//     Cache-Control max-age (1 h when read on 2026-11-12), at least 1 h.
import type { SafeFetchResult } from '../net.js';
import { t } from '../../i18n.js';

export const IANA_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
export const IANA_WHOIS = 'whois.iana.org';
export const IANA_REGISTRAR_IDS = 'https://www.iana.org/assignments/registrar-ids/registrar-ids.xml';

export type Http = (url: string, headers?: Record<string, string>) => Promise<SafeFetchResult>;

const MIN_BOOT_MS = 5 * 60_000;
const DEFAULT_BOOT_MS = 24 * 3600_000;
const TLD_WHOIS_MS = 24 * 3600_000;
const MIN_RIDS_MS = 3600_000;

/** Lifetime of a downloaded file from its Expires or Cache-Control header. */
export function lifetime(headers: Record<string, string>, now: number, fallback: number, min: number): number {
  const exp = headers.expires ? Date.parse(headers.expires) : NaN;
  if (!Number.isNaN(exp)) return Math.max(exp - now, min);
  const maxAge = /max-age=(\d+)/i.exec(headers['cache-control'] ?? '')?.[1];
  if (maxAge) return Math.max(Number(maxAge) * 1000, min);
  return fallback;
}

interface Cached<T> {
  value: T;
  until: number;
}

export class WhoisDirectory {
  private boot?: Cached<[string[], string[]][]>;
  private bootLoading?: Promise<[string[], string[]][]>;
  private tldWhois = new Map<string, Cached<string | null>>();
  private rids?: Cached<Map<string, string>>;

  constructor(private readonly now: () => number = Date.now) {}

  /** RDAP base URL of the registry of this name (longest matching suffix), or null without RDAP. */
  async rdapBase(http: Http, name: string): Promise<string | null> {
    const services = await this.bootstrap(http);
    const labels = name.split('.');
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.');
      const svc = services.find(([tlds]) => tlds.includes(suffix));
      if (svc) {
        const url = svc[1].find((u) => u.startsWith('https://')) ?? svc[1][0];
        return url ? (url.endsWith('/') ? url : url + '/') : null;
      }
    }
    return null;
  }

  private async bootstrap(http: Http): Promise<[string[], string[]][]> {
    const now = this.now();
    if (this.boot && this.boot.until > now) return this.boot.value;
    this.bootLoading ??= (async () => {
      try {
        const r = await http(IANA_BOOTSTRAP, { accept: 'application/json' });
        if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
        const json = JSON.parse(r.body.toString('utf8')) as { services?: [string[], string[]][] };
        if (!Array.isArray(json.services)) throw new Error(t('fichier sans liste de services'));
        this.boot = { value: json.services, until: this.now() + lifetime(r.headers, this.now(), DEFAULT_BOOT_MS, MIN_BOOT_MS) };
        return json.services;
      } catch (e) {
        // a stale copy is better than no RDAP at all: retry the download in 5 min
        if (this.boot) {
          this.boot.until = this.now() + MIN_BOOT_MS;
          return this.boot.value;
        }
        throw new Error(t('liste RDAP de l’IANA indisponible ({error})', { error: (e as Error).message }));
      } finally {
        this.bootLoading = undefined;
      }
    })();
    return this.bootLoading;
  }

  /** The WHOIS server of a TLD, as whois.iana.org gives it ("whois:" line), or null when it has none. */
  async tldWhoisServer(tld: string, ask: (host: string, query: string) => Promise<string>): Promise<string | null> {
    const now = this.now();
    const c = this.tldWhois.get(tld);
    if (c && c.until > now) return c.value;
    const text = await ask(IANA_WHOIS, tld);
    const server = /^\s*whois:\s*(\S+)/im.exec(text)?.[1]?.toLowerCase() ?? /^\s*refer:\s*(\S+)/im.exec(text)?.[1]?.toLowerCase() ?? null;
    this.tldWhois.set(tld, { value: server, until: now + TLD_WHOIS_MS });
    return server;
  }

  /** RDAP base URL of a registrar from the IANA Registrar IDs registry. */
  async registrarRdapBase(http: Http, ianaId: string): Promise<string | undefined> {
    const now = this.now();
    if (!this.rids || this.rids.until <= now) {
      const r = await http(IANA_REGISTRAR_IDS, { accept: 'application/xml' });
      if (r.status !== 200) throw new Error(t('registre des bureaux d’enregistrement de l’IANA : HTTP {status}', { status: r.status }));
      this.rids = { value: parseRegistrarIds(r.body.toString('utf8')), until: now + lifetime(r.headers, now, MIN_RIDS_MS, MIN_RIDS_MS) };
    }
    return this.rids.value.get(ianaId);
  }
}

/** IANA id to RDAP base URL, from registrar-ids.xml (records with an <rdapurl><server>). */
export function parseRegistrarIds(xml: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of xml.matchAll(/<record\b[^>]*>([\s\S]*?)<\/record>/g)) {
    const id = /<value>\s*(\d+)\s*<\/value>/.exec(m[1])?.[1];
    const server = /<rdapurl>\s*<server>\s*(https:\/\/[^<\s]+)\s*<\/server>/.exec(m[1])?.[1];
    if (id && server) out.set(id, server.endsWith('/') ? server : server + '/');
  }
  return out;
}

/** The directory of the process. */
export const sharedDirectory = new WhoisDirectory();
