// MTA-STS and TLS-RPT: TXT record, policy file served over HTTPS, mode and max_age, MX covered
// by the policy, TLS report addresses.
import { useParams } from 'react-router';
import { Details } from '../../components/Verdict';
import { CodeBlock, Notice } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtInt, fmtMs, plural } from '../../lib/format';
import { t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { MtaStsData } from '../domain/model';
import { fmtDuration, type Metric } from '../domain/rows';

const POLICY_IDS = ['mta-sts.policy_unreachable', 'mta-sts.policy_cert_invalid', 'mta-sts.policy_redirect', 'mta-sts.wrong_content_type'];

function policyRows(d: MtaStsData): Metric[] {
  const rows: Metric[] = [
    {
      key: 'txt', label: t('Enregistrement _mta-sts.{domain}', { domain: d.domain }), measured: d.record ? `id=${d.id ?? t('absent')}` : d.records.length > 1 ? t('{n} enregistrements', { n: d.records.length }) : t('absent'), reference: 'v=STSv1; id=…',
      dev: d.record ? { kind: 'ok' } : { kind: 'info', text: t('absent') }, ids: ['mta-sts.missing', 'mta-sts.txt_malformed'],
    },
  ];
  if (!d.record) return rows;
  const f = d.fetch;
  rows.push({
    key: 'fetch', label: t('Fichier servi en HTTPS'), sub: d.policyUrl,
    measured: f?.error ? f.error : f?.certError ? t('certificat : {error}', { error: f.certError }) : `HTTP ${f?.status ?? '?'}${f?.contentType ? `, ${f.contentType}` : ''}${f?.ms !== undefined ? `, ${fmtMs(f.ms)}` : ''}`,
    reference: t('200, text/plain, certificat valide'),
    dev: !f || f.error || f.certError || (f.status !== undefined && f.status !== 200) ? { kind: 'out', text: f?.status ? `HTTP ${f.status}` : t('introuvable'), direction: 'down' } : f.contentType && !/text\/plain/i.test(f.contentType) ? { kind: 'warn', text: t('type'), direction: 'down' } : { kind: 'ok' },
    ids: POLICY_IDS,
  });
  const p = d.policy;
  if (p) {
    rows.push({
      key: 'mode', label: t('Mode'), measured: p.mode ?? t('absent'), reference: 'enforce',
      dev: p.mode === 'enforce' ? { kind: 'ok' } : p.mode === 'testing' ? { kind: 'warn', text: 'testing', direction: 'down' } : { kind: 'out', text: p.mode ?? t('absent'), direction: 'down' },
      ids: ['mta-sts.testing_mode', 'mta-sts.mode_none', 'mta-sts.policy_malformed'],
    });
    if (p.maxAge !== undefined)
      rows.push({
        key: 'maxage', label: t('Durée de cache (max_age)'), measured: `${fmtInt(p.maxAge)} s, ${fmtDuration(Math.round(p.maxAge / 86400))}`, reference: t('1 semaine à 1 an'),
        dev: p.maxAge > 31557600 ? { kind: 'out', text: t('trop long'), direction: 'up' } : p.maxAge < 604800 ? { kind: 'warn', text: t('court'), direction: 'down' } : { kind: 'ok' },
        ids: ['mta-sts.max_age_short', 'mta-sts.max_age_too_long'],
      });
    for (const m of [...d.mx].sort((a, b) => a.preference - b.preference))
      rows.push({
        key: `mx-${m.host}`, label: m.host, mono: true, sub: t('MX priorité {n}', { n: m.preference }), measured: m.covered === true ? t('couvert') : m.covered === false ? t('absent de la politique') : t('non évalué'), reference: t('listé dans mx:'),
        dev: m.covered === true ? { kind: 'ok' } : m.covered === false ? { kind: 'out', text: t('non couvert'), direction: 'down' } : { kind: 'info', text: t('non évalué') },
        ids: ['mta-sts.mx_not_covered'], evidence: m.host,
      });
  }
  return rows;
}

function tlsRptRows(d: MtaStsData): Metric[] {
  const tr = d.tlsrpt;
  const rows: Metric[] = [
    {
      key: 'tlsrpt', label: t('Enregistrement _smtp._tls.{domain}', { domain: d.domain }), measured: tr.record ? t('publié') : tr.records.length > 1 ? t('{n} enregistrements', { n: tr.records.length }) : t('absent'), reference: 'v=TLSRPTv1; rua=…',
      dev: tr.record && !tr.errors.length ? { kind: 'ok' } : tr.errors.length ? { kind: 'out', text: t('invalide'), direction: 'down' } : { kind: 'info', text: t('absent') }, ids: ['mta-sts.tlsrpt_missing', 'mta-sts.tlsrpt_malformed'],
    },
  ];
  for (const [i, u] of tr.rua.entries()) rows.push({ key: `rua-${i}`, label: u.replace(/^mailto:/, ''), mono: true, sub: u.startsWith('mailto:') ? t('par e-mail') : t('par HTTPS'), measured: t('destination des rapports'), dev: { kind: 'ok' } });
  for (const [i, e] of tr.errors.entries()) rows.push({ key: `err-${i}`, label: e, dev: { kind: 'out', text: t('écart'), direction: 'down' } });
  return rows;
}

export default function MtaStsPage() {
  const { domain: raw } = useParams();
  const domain = raw ? toDomain(raw) : undefined;
  const url = domain ? `/api/mta-sts/${encodeURIComponent(domain)}` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<MtaStsData>>(url);
  useRecent(domain, `/mta-sts/${domain}`, 'MTA-STS');

  if (!domain) {
    return (
      <ToolEmpty
        title={t('MTA-STS et TLS-RPT')}
        desc={t('Enregistrement, fichier de politique servi en HTTPS, mode, durée de cache, MX couverts, adresses des rapports TLS.')}
        basePath="/mta-sts"
        examples={[
          { domain: 'gmail.com', why: t('politique enforce, tous les MX couverts') },
          { domain: 'cloudflare.com', why: t('enregistrement publié, fichier de politique introuvable') },
        ]}
      >
        {raw && <Notice tone="error" title={t('« {raw} » n’est pas un nom de domaine', { raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
      </ToolEmpty>
    );
  }

  return (
    <ReportFrame
      domain={domain}
      r={r}
      loading={loading}
      error={error}
      rerun={rerun}
      facts={(r) => {
        const d = r.data;
        const covered = d.mx.filter((m) => m.covered === true).length;
        return [
          { label: 'MTA-STS', value: !d.record ? t('absent') : d.policy?.mode ? t('mode {mode}', { mode: d.policy.mode }) : t('fichier introuvable') },
          ...(d.policy ? [{ label: t('MX couverts'), value: t('{n} sur {total}', { n: covered, total: d.mx.length }) }] : []),
          { label: 'TLS-RPT', value: d.tlsrpt.rua.length ? t('demandé') : t('absent') },
        ];
      }}
    >
      {(r) => {
        const d = r.data;
        return (
          <>
            <Details title="MTA-STS" count={!d.record ? t('absent') : d.policy?.mode ?? t('fichier introuvable')}>
              {d.record && <CodeBlock code={d.record} label={t('TXT de _mta-sts.{domain}', { domain })} />}
              <MetricTable rows={policyRows(d)} />
            </Details>
            {d.policy?.raw && (
              <Details title={t('Fichier de politique')} count={d.policyUrl}>
                <CodeBlock code={d.policy.raw.replace(/\r\n/g, '\n').trim()} label={d.policyUrl} />
                {d.policy.errors.length > 0 && (
                  <Notice tone="warn" title={t('Lignes invalides')}>
                    <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
                      {d.policy.errors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  </Notice>
                )}
              </Details>
            )}
            <Details title="TLS-RPT" count={d.tlsrpt.rua.length ? plural(d.tlsrpt.rua.length, 'adresse', 'adresses') : t('absent')}>
              {d.tlsrpt.record && <CodeBlock code={d.tlsrpt.record} label={t('TXT de _smtp._tls.{domain}', { domain })} />}
              <MetricTable rows={tlsRptRows(d)} />
            </Details>
            <SeeAlso
              links={[
                { to: `/generateurs/mta-sts?domaine=${encodeURIComponent(domain)}`, label: t('Générateur MTA-STS') },
                { to: `/smtp/${domain}`, label: t('Serveurs SMTP') },
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
