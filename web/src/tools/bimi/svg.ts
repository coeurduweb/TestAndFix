// BIMI logo and certificate as lab rows. Pure, unit tested.
import type { Deviation } from '../../components/Report';
import { t } from '../../lib/i18n';
import type { SvgCheck } from '../domain/model';
import type { Metric } from '../domain/rows';

// tokens kept as such in every language; the size and format advice comes flagged in sizeWarnings
const COVERED = [/baseProfile/i, /version=/i, /<title>/i];
const KB = 1024;

export function svgMetrics(s: SvgCheck): Metric[] {
  const ok: Deviation = { kind: 'ok' };
  const rows: Metric[] = [];
  const typeOk = !s.contentType || /image\/svg\+xml/i.test(s.contentType);
  rows.push({
    key: 'http', label: t('Réponse HTTPS'), measured: s.error ?? `${s.status ?? '?'}${s.contentType ? `, ${s.contentType}` : ''}`, reference: '200, image/svg+xml',
    dev: s.error || (s.status !== undefined && s.status !== 200) ? { kind: 'out', text: t('illisible'), direction: 'down' } : typeOk ? ok : { kind: 'warn', text: t('type'), direction: 'down' },
    ids: ['bimi.logo_unreachable', 'bimi.logo_not_https'],
  });
  if (s.error) return rows;
  rows.push({
    key: 'profile', label: t('Profil (baseProfile)'), measured: s.baseProfile ?? t('absent'), reference: 'tiny-ps',
    dev: s.baseProfile === 'tiny-ps' ? ok : { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['bimi.svg_not_tiny_ps'],
  });
  rows.push({ key: 'version', label: t('Version SVG'), measured: s.version ?? t('absente'), reference: '1.2', dev: s.version === '1.2' ? ok : { kind: 'out', text: s.version ?? t('absente'), direction: 'down' } });
  rows.push({ key: 'title', label: t('Élément <title>'), measured: s.title ? `« ${s.title} »` : t('absent'), reference: t('présent, nom de la marque'), dev: s.title ? ok : { kind: 'out', text: t('absent'), direction: 'down' } });
  rows.push({
    key: 'square', label: t('Format'), measured: s.viewBox ? `viewBox ${s.viewBox}` : t('viewBox absent'), reference: t('carré'),
    dev: s.square ? ok : { kind: 'warn', text: t('non carré'), direction: 'down' }, ids: ['bimi.logo_size'],
  });
  if (s.bytes !== undefined) {
    const kb = Math.round((s.bytes / KB) * 10) / 10;
    rows.push({
      key: 'size', label: t('Poids du fichier'), measured: t('{n} Ko', { n: String(kb).replace('.', ',') }), reference: t('≤ 32 Ko'),
      dev: s.bytes > 32 * KB ? { kind: 'warn', text: t('{n} Ko', { n: Math.round(s.bytes / KB - 32) }), direction: 'up' } : ok, ids: ['bimi.logo_size'],
    });
  }
  return rows;
}

/** Problems and advice of the server not already shown by a measured row. */
export function otherSvgIssues(s: SvgCheck): { text: string; must: boolean }[] {
  const left = (list: string[], must: boolean) => list.filter((x) => !COVERED.some((re) => re.test(x)) && !s.sizeWarnings?.includes(x)).map((text) => ({ text, must }));
  return [...left(s.problems, true), ...left(s.warnings, false)];
}

/** Attach ids to the leftover rows so that their finding folds under them. */
export function leftoverMetrics(s: SvgCheck): Metric[] {
  return otherSvgIssues(s).map((x, i) => ({
    key: `left-${i}`,
    label: x.text,
    dev: x.must ? { kind: 'out', text: t('écart'), direction: 'down' } : { kind: 'info', text: t('conseil') },
    ids: x.must ? ['bimi.svg_forbidden_content'] : ['bimi.svg_recommendation'],
  }));
}

/** Readable name of a certificate subject or issuer: its CN, else its O. */
export function certName(dn: string): string {
  const parts = dn.split(/(?<!\\),\s*/).map((p) => p.replace(/\\,/g, ','));
  const get = (k: string) => parts.find((p) => p.startsWith(`${k}=`))?.slice(k.length + 1);
  return get('CN') ?? get('O') ?? dn;
}
