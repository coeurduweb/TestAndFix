// MX records of a domain (RFC 5321 §5.1, RFC 7505 Null MX, RFC 2181 §10.3 no CNAME target).
import net from 'node:net';
import { isPublicIp } from '../net.js';
import type { PassedCheck } from '../../tools/types.js';
import { issue, lookupAddresses, lookupType, norm, pass, type Analysis, type Issue, type Resolver } from './common.js';
import { t, tPlural } from '../../i18n.js';

export interface MxHost {
  host: string;
  preference: number;
  ipv4: string[];
  ipv6: string[];
  /** The MX name is an alias (CNAME), forbidden by RFC 2181 §10.3. */
  cname?: string[];
  ipLiteral: boolean;
  privateIps: string[];
  error?: string;
}

export interface MxData {
  domain: string;
  rcode: string;
  hosts: MxHost[];
  nullMx: boolean;
  /** Addresses of the domain itself, used as implicit MX when no MX exists (RFC 5321 §5.1). */
  implicit?: string[];
}

export interface MxAnalysis extends Analysis {
  data: MxData;
}

export async function analyzeMx(dns: Resolver, domain: string): Promise<MxAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const r = await lookupType(dns, domain, 'MX');
  const data: MxData = { domain, rcode: r.rcode, hosts: [], nullMx: false };
  if (r.error) return { issues, passed, unavailable: [{ source: 'dns', reason: t('MX {domain} : {error}', { domain, error: r.error }) }], data };
  if (r.rcode === 'NXDOMAIN') {
    issues.push(issue('mx.domain_nxdomain', { domain }));
    return { issues, passed, data };
  }
  const recs = r.data
    .map((d) => d as { preference: number; exchange: string })
    .map((d) => ({ preference: Number(d.preference), host: norm(d.exchange) }))
    .sort((a, b) => a.preference - b.preference || a.host.localeCompare(b.host));
  if (r.cnames.length) issues.push(issue('infrastructure.cname_at_apex', { domain, value: r.cnames.join(' → ') }, { evidence: `${domain} CNAME ${r.cnames.join(' → ')}` }));
  data.nullMx = recs.some((m) => m.host === '' || m.host === '.');
  if (!recs.length) {
    const a = await lookupAddresses(dns, domain);
    data.implicit = a.ips;
    issues.push(issue('mx.missing', { domain, value: a.ips.join(', ') || undefined }, { evidence: a.ips.length ? t('adresses de {domain} (MX implicite) : {ips}', { domain, ips: a.ips.join(', ') }) : undefined }));
    return { issues, passed, data };
  }
  if (data.nullMx) {
    if (recs.length > 1) issues.push(issue('mx.null_mx_mixed', { domain }, { evidence: recs.map((m) => `${m.preference} ${m.host || '.'}`).join('\n') }));
    else issues.push(issue('mx.null_mx_on_sending_domain', { domain }, { evidence: `0 .`, severity: 'info', penalty: 0 }));
  }
  data.hosts = await Promise.all(
    recs
      .filter((m) => m.host && m.host !== '.')
      .map(async (m): Promise<MxHost> => {
        const ipLiteral = /^[0-9.]+$/.test(m.host) || m.host.includes(':');
        const a = ipLiteral ? { ips: [], cnames: [], rcode: 'NOERROR', error: undefined } : await lookupAddresses(dns, m.host);
        const ips = a.ips;
        return {
          host: m.host,
          preference: m.preference,
          ipv4: ips.filter((x) => net.isIPv4(x)),
          ipv6: ips.filter((x) => net.isIPv6(x)),
          cname: a.cnames.length ? [...new Set(a.cnames)] : undefined,
          ipLiteral,
          privateIps: ips.filter((x) => !isPublicIp(x)),
          error: a.error,
        };
      }),
  );
  const list = data.hosts.map((h) => `${h.preference} ${h.host} → ${[...h.ipv4, ...h.ipv6].join(', ') || t('aucune adresse')}`).join('\n');
  const lit = data.hosts.filter((h) => h.ipLiteral);
  if (lit.length) issues.push(issue('mx.ip_literal', { domain, value: lit.map((h) => h.host).join(', ') }, { evidence: list }));
  const cn = data.hosts.filter((h) => h.cname);
  if (cn.length) issues.push(issue('mx.cname_target', { domain, value: cn.map((h) => `${h.host} → ${h.cname!.join(' → ')}`).join(', ') }, { evidence: list }));
  const priv = data.hosts.filter((h) => h.privateIps.length);
  if (priv.length) issues.push(issue('mx.private_address', { domain, value: priv.map((h) => `${h.host} (${h.privateIps.join(', ')})`).join(', ') }, { evidence: list }));
  const real = data.hosts.filter((h) => !h.ipLiteral);
  if (real.length && real.every((h) => !h.ipv4.length && !h.ipv6.length && !h.error)) issues.push(issue('mx.target_nxdomain', { domain }, { evidence: list }));
  else {
    const dead = real.filter((h) => !h.ipv4.length && !h.ipv6.length && !h.error);
    if (dead.length) issues.push(issue('mx.some_target_without_address', { domain, value: dead.map((h) => h.host).join(', ') }, { evidence: list }));
  }
  if (!issues.length) passed.push(pass('mx.valid', 'mx', tPlural(data.hosts.length, '{n} serveur MX valide', '{n} serveurs MX valides'), data.hosts.map((h) => h.host).join(', ')));
  return { issues, passed, data };
}
