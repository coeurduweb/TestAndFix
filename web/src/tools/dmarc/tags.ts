// DMARC tags as lab rows: what is measured, what is recommended, which findings they carry.
import type { Deviation } from '../../components/Report';
import { msg, t } from '../../lib/i18n';
import type { DmarcData, DmarcReportUri, DmarcTag } from '../domain/model';
import { policyDev, type Metric } from '../domain/rows';

const RANK: Record<string, number> = { none: 0, quarantine: 1, reject: 2 };

/** Recommended value and findings of each tag (RFC 9989 wording for np=, t=, psd=). */
const TAGS: Record<string, { ref: string; ids?: string[] }> = {
  v: { ref: 'DMARC1' },
  p: { ref: msg('quarantine ou reject'), ids: ['dmarc.policy_none', 'dmarc.policy_invalid'] },
  sp: { ref: msg('au moins p='), ids: ['dmarc.sp_weaker'] },
  np: { ref: 'reject', ids: ['dmarc.np_absent'] },
  pct: { ref: '100', ids: ['dmarc.pct_partial', 'dmarc.pct_zero'] },
  t: { ref: 'n', ids: ['dmarc.testing_flag'] },
  adkim: { ref: 'r ou s', ids: ['dmarc.strict_alignment'] },
  aspf: { ref: 'r ou s', ids: ['dmarc.strict_alignment'] },
  rua: { ref: msg('mailto: d’une boîte lue'), ids: ['dmarc.rua_missing', 'dmarc.rua_invalid_uri', 'dmarc.rua_external_unauthorized'] },
  ruf: { ref: msg('facultatif'), ids: ['dmarc.ruf_present'] },
  fo: { ref: msg('0, ou 1 avec ruf='), ids: ['dmarc.fo_without_ruf'] },
  ri: { ref: '86400' },
  rf: { ref: 'afrf', ids: ['dmarc.obsolete_tags'] },
  psd: { ref: msg('n (sauf suffixe public)') },
};

export function dmarcTagMetric(tag: DmarcTag, d: DmarcData): Metric {
  const spec = TAGS[tag.name];
  let dev: Deviation = { kind: 'ok' };
  if (!tag.valid) dev = { kind: 'out', text: t('invalide'), direction: 'down' };
  else if (tag.name === 'p') dev = policyDev(tag.value);
  else if (tag.name === 'sp' && (RANK[tag.value] ?? 0) < (RANK[d.policy ?? ''] ?? 0)) dev = { kind: 'warn', text: t('plus faible'), direction: 'down' };
  else if (tag.name === 'pct' && Number(tag.value) < 100) dev = { kind: 'warn', text: `${100 - Number(tag.value)} %`, direction: 'down' };
  else if (tag.name === 'rua' && !tag.value) dev = { kind: 'warn', text: t('absent'), direction: 'down' };
  else if (!spec) dev = { kind: 'info', text: t('inconnue') };
  else if (tag.implicit) dev = { kind: 'info', text: t('défaut') };
  const measured = tag.name === 'rua' && !tag.value ? t('absent') : `${tag.value}${tag.implicit ? ' ' + t('(par défaut)') : ''}`;
  return {
    key: `tag-${tag.name}`,
    label: `${tag.name}=`,
    mono: true,
    sub: tag.error ?? tag.meaning,
    measured,
    reference: spec ? t(spec.ref) : '',
    dev,
    ids: [...(spec?.ids ?? []), ...(tag.name === 'v' ? ['dmarc.syntax_invalid', 'dmarc.multiple_records', 'dmarc.duplicate_tag', 'dmarc.unknown_tags'] : [])],
  };
}

/** Name that the destination publishes to accept reports for `sender` (RFC 9990 §3). */
export const authorizationName = (sender: string, dest: string) => `${sender}._report._dmarc.${dest}`;

export function reportMetric(x: DmarcReportUri, i: number, sender: string): Metric {
  let dev: Deviation = { kind: 'ok' };
  let measured = t('même domaine, rien à autoriser');
  if (x.error) {
    dev = { kind: 'out', text: t('invalide'), direction: 'down' };
    measured = x.error;
  } else if (x.external) {
    measured = x.authorized ? t('autorisation publiée') : t('autorisation absente');
    dev = x.authorized ? { kind: 'ok' } : { kind: 'out', text: t('refusés'), direction: 'down' };
  }
  return {
    key: `rep-${i}`,
    label: x.address ?? x.uri,
    mono: true,
    sub: `${x.tag === 'rua' ? t('rapports agrégés') : t('rapports d’échec')}${x.external ? ', ' + t('domaine externe {domain}', { domain: x.domain }) : ''}${x.maxSize ? ', ' + t('taille max {size}', { size: x.maxSize }) : ''}`,
    measured,
    reference: x.external ? t('TXT sur {name}', { name: authorizationName(sender, x.domain ?? '…') }) : '',
    dev,
    ids: ['dmarc.rua_external_unauthorized', 'dmarc.rua_invalid_uri'],
    evidence: x.domain,
  };
}
