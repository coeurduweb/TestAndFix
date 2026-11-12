// DMARC: each tag as a lab row (measured, recommended, meaning), effective policy of the
// subdomains, report addresses and their authorization, progressive plan none → quarantine → reject.
import { useParams, useSearchParams } from 'react-router';
import { Details } from '../../components/Verdict';
import { CodeBlock, Notice } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { FixBlock, PastedRecord, ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { DmarcData, DmarcReportUri, DmarcTag } from '../domain/model';
import { policyDev, type Metric } from '../domain/rows';
import { authorizationName, dmarcTagMetric, reportMetric } from './tags';

export default function DmarcPage() {
  const { domain: raw } = useParams();
  const [params] = useSearchParams();
  const domain = raw ? toDomain(raw) : undefined;
  const url = domain ? `/api/dmarc/${encodeURIComponent(domain)}` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<DmarcData>>(url);
  useRecent(domain, `/dmarc/${domain}`, 'DMARC');

  if (!domain) {
    const record = params.get('enregistrement');
    return (
      <ToolEmpty
        title="DMARC"
        desc={t('Chaque balise lue et expliquée, politique réelle des sous-domaines, adresses de rapports et leur autorisation, plan de montée en charge prêt à copier.')}
        basePath="/dmarc"
        examples={[
          { domain: 'cnn.com', why: t('p=reject avec rapports externes autorisés') },
          { domain: 'doctissimo.fr', why: t('aucun DMARC publié') },
        ]}
      >
        {raw && <Notice tone="error" title={t('« {raw} » n’est pas un nom de domaine', { raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
        {record && <PastedRecord record={record} kind="DMARC" basePath="/dmarc" />}
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
      facts={(r) =>
        r.data.record
          ? [
              { label: t('Politique'), value: `p=${r.data.effectivePolicy ?? '?'}` },
              { label: t('Sous-domaines'), value: `sp=${r.data.subdomainPolicy ?? '?'}` },
              { label: t('Rapports'), value: r.data.reports.filter((x) => x.tag === 'rua').length ? t('{n} adresse(s)', { n: r.data.reports.filter((x) => x.tag === 'rua').length }) : t('aucun') },
            ]
          : [{ label: t('Enregistrement'), value: t('absent') }]
      }
      fix={(r) => {
        const d = r.data;
        const base = d.foundAt?.replace(/^_dmarc\./, '') ?? domain;
        const plan = d.plan;
        if (!(d.suggested && d.suggested !== d.record) && !plan.length) return null;
        return (
          <FixBlock title={d.record ? t('L’enregistrement corrigé à publier') : t('L’enregistrement à publier')}>
            {d.suggested && d.suggested !== d.record && (
              <>
                <CodeBlock code={d.suggested} label={t('TXT de _dmarc.{base}', { base })} tone="suggested" copyLabel={t('Copier l’enregistrement')} />
                <p className="field__hint">{d.record ? t('Remplace l’enregistrement actuel : un seul TXT v=DMARC1 doit exister sur ce nom.') : t('À publier en TXT sur _dmarc.{base}.', { base })}</p>
              </>
            )}
            {plan.length > 1 && (
              <ol className="dm-plan">
                {plan.map((p, i) => {
                  const [head, ...tail] = p.when.split(' : ');
                  return (
                    <li key={i}>
                      <div className="dm-plan__when">
                        <strong>{t('Étape {n}, {head}', { n: i + 1, head })}</strong>
                        {tail.length ? ` : ${tail.join(' : ')}` : ''}
                      </div>
                      {p.record !== d.suggested ? (
                        <CodeBlock code={p.record} label={t('TXT de _dmarc.{base}', { base })} copyLabel={t('Copier')} />
                      ) : (
                        <p className="field__hint">{t('C’est l’enregistrement ci-dessus.')}</p>
                      )}
                    </li>
                  );
                })}
              </ol>
            )}
          </FixBlock>
        );
      }}
      issueExtra={(f, r) => {
        if (f.id !== 'dmarc.rua_external_unauthorized') return null;
        const base = r.data.foundAt?.replace(/^_dmarc\./, '') ?? domain;
        return r.data.reports
          .filter((x) => x.external && x.authorized === false && x.domain)
          .map((x, i) => <CodeBlock key={i} code={`${authorizationName(base, x.domain!)}  TXT  "v=DMARC1;"`} label={t('À publier par {domain}', { domain: x.domain })} tone="suggested" />);
      }}
    >
      {(r) => {
        const d = r.data;
        const tags: DmarcTag[] = [...d.tags];
        if (d.record && !tags.some((x) => x.name === 'rua')) tags.push({ name: 'rua', value: '', meaning: t('Adresses des rapports agrégés quotidiens'), valid: true, implicit: true });
        const tagRows = tags.map((x) => dmarcTagMetric(x, d));
        const base = d.foundAt?.replace(/^_dmarc\./, '') ?? domain;
        const effective: Metric[] = [
          { key: 'eff', label: t('Courrier de {domain}', { domain }), measured: d.effectivePolicy, reference: t('quarantine ou reject'), dev: policyDev(d.effectivePolicy) },
          { key: 'sub', label: t('Sous-domaines de {base}', { base }), measured: d.subdomainPolicy, sub: d.tags.find((x) => x.name === 'sp' && !x.implicit) ? t('fixé par sp=') : t('pas de sp= : même politique que p='), reference: t('au moins p='), dev: policyDev(d.subdomainPolicy) },
          {
            key: 'np', label: t('Sous-domaines inexistants'), measured: d.nonExistentPolicy ?? d.subdomainPolicy, sub: d.nonExistentPolicy ? t('fixé par np=') : t('pas de np= : politique des sous-domaines'), reference: 'reject',
            dev: (d.nonExistentPolicy ?? d.subdomainPolicy) === 'reject' ? { kind: 'ok' } : { kind: 'info', text: t('à durcir') },
          },
          { key: 'align', label: t('Alignement'), measured: t('DKIM {dkim}, SPF {spf}', { dkim: d.alignment.dkim === 's' ? t('strict') : t('souple'), spf: d.alignment.spf === 's' ? t('strict') : t('souple') }), reference: t('souple suffit'), dev: { kind: 'info', text: t('noté') } },
        ];
        const reports = d.reports.map((x: DmarcReportUri, i) => reportMetric(x, i, base));
        const reportExtra = Object.fromEntries(
          d.reports.map((x, i) => [`rep-${i}`, x.authorizationRecord ? <CodeBlock key={i} code={x.authorizationRecord} label={t('Autorisation lue sur {name}', { name: authorizationName(base, x.domain ?? '') })} /> : null]).filter(([, v]) => v),
        );
        return (
          <>
            {d.inherited && (
              <Notice title={t('{domain} n’a pas d’enregistrement propre', { domain })}>
                {t('La politique appliquée est celle de {foundAt}, héritée du domaine organisationnel {orgDomain}.', { foundAt: d.foundAt, orgDomain: d.orgDomain })}
              </Notice>
            )}
            {d.record ? (
              <>
                <Details title={t('Enregistrement et balises')} count={t('{n} balises écrites', { n: d.tags.filter((x) => !x.implicit).length })}>
                  <CodeBlock code={d.record} label={t('TXT de {name}', { name: d.foundAt ?? `_dmarc.${domain}` })} />
                  <MetricTable rows={tagRows} />
                </Details>
                <Details title={t('Politique effective')} count={`p=${d.effectivePolicy}, sp=${d.subdomainPolicy}`}>
                  <MetricTable rows={effective} />
                </Details>
                <Details title={t('Adresses de rapport')} count={`${d.reports.length}`}>
                  {reports.length ? (
                    <MetricTable rows={reports} extra={reportExtra} />
                  ) : (
                    <p className="dm-note">{t('Aucune adresse : personne ne reçoit les rapports qui montrent qui envoie au nom de {base}.', { base })}</p>
                  )}
                </Details>
              </>
            ) : (
              <p className="dm-note">{t('Aucun enregistrement sur _dmarc.{domain} ni sur le domaine organisationnel {orgDomain}.', { domain, orgDomain: d.orgDomain })}</p>
            )}
            <SeeAlso
              links={[
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
                { to: '/rapports-dmarc', label: t('Lire les rapports reçus') },
                { to: `/generateurs/dmarc?domaine=${encodeURIComponent(domain)}`, label: t('Générateur DMARC') },
                { to: `/spf/${domain}`, label: 'SPF' },
                { to: `/dkim/${domain}`, label: 'DKIM' },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
