// Minimal cookie jar for one trace: what a browser would send back from hop to hop
// (RFC 6265 domain, path, secure and expiry rules, simplified). Lives for one trace only.

interface Cookie {
  name: string;
  value: string;
  domain: string;
  hostOnly: boolean;
  path: string;
  secure: boolean;
  expires?: number;
}

function defaultPath(u: URL): string {
  const p = u.pathname;
  if (!p.startsWith('/') || p.lastIndexOf('/') === 0) return '/';
  return p.slice(0, p.lastIndexOf('/'));
}

function domainMatch(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

function pathMatch(reqPath: string, cookiePath: string): boolean {
  if (reqPath === cookiePath) return true;
  if (!reqPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || reqPath[cookiePath.length] === '/';
}

export class CookieJar {
  private list: Cookie[] = [];

  /** Store the Set-Cookie values of a response to `url`. */
  store(url: string, setCookies: string[], now = Date.now()) {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    for (const line of setCookies) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const c: Cookie = { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim(), domain: host, hostOnly: true, path: defaultPath(u), secure: false };
      let maxAge: number | undefined;
      for (const a of attrs) {
        const i = a.indexOf('=');
        const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
        const v = i < 0 ? '' : a.slice(i + 1).trim();
        if (k === 'domain' && v) {
          const d = v.replace(/^\./, '').toLowerCase();
          if (!domainMatch(host, d)) {
            c.domain = '';
            break;
          }
          c.domain = d;
          c.hostOnly = false;
        } else if (k === 'path' && v.startsWith('/')) c.path = v;
        else if (k === 'secure') c.secure = true;
        else if (k === 'max-age' && /^-?\d+$/.test(v)) maxAge = Number(v);
        else if (k === 'expires') {
          const t = Date.parse(v);
          if (!Number.isNaN(t)) c.expires = t;
        }
      }
      if (!c.domain) continue;
      if (maxAge !== undefined) c.expires = now + maxAge * 1000;
      this.list = this.list.filter((x) => !(x.name === c.name && x.domain === c.domain && x.path === c.path));
      if (c.expires === undefined || c.expires > now) this.list.push(c);
    }
  }

  /** Cookie header for a request to `url`, or undefined. */
  header(url: string, now = Date.now()): { value?: string; count: number } {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const send = this.list
      .filter((c) => (c.expires === undefined || c.expires > now) && (c.hostOnly ? host === c.domain : domainMatch(host, c.domain)) && pathMatch(u.pathname || '/', c.path) && (!c.secure || u.protocol === 'https:'))
      .sort((a, b) => b.path.length - a.path.length);
    return { value: send.length ? send.map((c) => `${c.name}=${c.value}`).join('; ') : undefined, count: send.length };
  }
}
