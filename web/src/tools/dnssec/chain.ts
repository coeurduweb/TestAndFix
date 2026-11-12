// DNSSEC chain of trust as lab rows, from the root down to the zone. Pure, unit tested.
import { t } from '../../lib/i18n';
import type { DnssecData, ZoneChain } from '../domain/model';
import { dnssecDev, type Metric } from '../domain/rows';

const ZONE_IDS = [
  'dnssec.bogus', 'dnssec.ds_mismatch', 'dnssec.ds_missing', 'dnssec.dnskey_missing', 'dnssec.rrsig_expired', 'dnssec.rrsig_expiring',
  'dnssec.unsigned', 'dnssec.algorithm_not_recommended', 'dnssec.ds_sha1',
];

export function zoneSummary(z: ZoneChain): string {
  if (!z.ds.length && !z.dnskey.length) return t('ni DS au parent, ni clé dans la zone');
  const valid = z.rrsig.filter((s) => s.current && s.verified !== false).length;
  const matched = z.ds.filter((d) => d.matches !== null).length;
  return t('{matched}/{ds} DS reliés · {keys} DNSKEY · {valid}/{sigs} signatures valides', { matched, ds: z.ds.length, keys: z.dnskey.length, valid, sigs: z.rrsig.length });
}

export function chainMetrics(d: DnssecData, domain: string): Metric[] {
  const rows: Metric[] = [
    { key: 'root', label: '.', mono: true, sub: t('racine : ancre de confiance des résolveurs'), measured: t('clé de la racine'), reference: t('connue des résolveurs'), dev: { kind: 'ok', text: t('ancre') } },
  ];
  const target = d.chain.some((z) => z.zone === d.zone) ? d.zone : d.chain[d.chain.length - 1]?.zone;
  d.chain.forEach((z, i) => {
    const soon = z.rrsig.filter((s) => s.current).reduce((m, s) => Math.min(m, s.expiresInHours), Infinity);
    let dev = dnssecDev(z.status);
    if (z.status === 'secure' && soon < 72) dev = { kind: 'warn', text: t('expire {n} h', { n: Math.max(0, Math.round(soon)) }), direction: 'down' };
    rows.push({
      key: `z-${z.zone}`,
      label: z.zone,
      mono: true,
      depth: i + 1,
      sub: t('{kind}, déléguée par {parent}', {
        kind: z.zone === domain ? t('le domaine') : z.zone === target && z.zone.includes('.') ? t('zone de {domain}', { domain }) : t('zone parente'),
        parent: z.parent === '.' ? t('la racine') : z.parent,
      }),
      measured: zoneSummary(z),
      reference: t('DS relié à une KSK, signatures valides'),
      dev,
      ids: z.zone === target ? ZONE_IDS : undefined,
    });
  });
  if (d.nsec3)
    rows.push({
      key: 'nsec3', label: t('NSEC3 : itérations'), measured: t('{iterations}, sel de {bytes} octets', { iterations: d.nsec3.iterations, bytes: d.nsec3.saltLength }), reference: t('0, sans sel (RFC 9276)'),
      dev: d.nsec3.iterations > 0 ? { kind: 'warn', text: String(d.nsec3.iterations), direction: 'up' } : { kind: 'ok' }, ids: ['dnssec.nsec3_iterations'],
    });
  return rows;
}

/** Signature lifetime: hours up to 48 h, days beyond. */
export function fmtHours(h: number): string {
  const abs = Math.abs(h);
  const v = abs > 48 ? t('{n} j', { n: Math.round(abs / 24) }) : t('{n} h', { n: abs });
  return h >= 0 ? t('dans {v}', { v }) : t('il y a {v}', { v });
}
