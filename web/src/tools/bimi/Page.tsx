// BIMI: record, logo as an inbox shows it (square and round), SVG Tiny PS conformity, mark
// certificate (VMC or CMC: issuer, dates, days left), DMARC prerequisite.
import { useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router';
import { BadgeCheck } from 'lucide-react';
import { Details } from '../../components/Verdict';
import { CodeBlock, Field, Notice, SubmitButton } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtBytes, fmtInt } from '../../lib/format';
import { rich, t, tn } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { PastedRecord, ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { BimiData, VmcCheck } from '../domain/model';
import { isoDay, type Metric } from '../domain/rows';
import { certName, leftoverMetrics, svgMetrics } from './svg';

function Preview({ d }: { d: BimiData }) {
  const [failed, setFailed] = useState(false);
  const url = d.logoUrl;
  const https = !!url && /^https:\/\//i.test(url);
  const sender = d.domain.split('.')[0];
  const name = d.svg?.title?.trim() || sender.charAt(0).toUpperCase() + sender.slice(1);
  if (!https || failed) {
    return (
      <p className="dm-note">
        {!url ? t('Aucun logo déclaré (balise l= vide ou absente).') : !https ? t('Logo non affiché : son adresse n’est pas en HTTPS, aucune messagerie ne le chargera.') : t('Le navigateur n’a pas pu charger ce logo.')}
      </p>
    );
  }
  const blockers = [
    !d.dmarcEligible && t('DMARC insuffisant'),
    (d.svg?.problems.length ?? 0) > 0 && t('SVG hors profil Tiny PS'),
    !d.vmc && t('pas de certificat (Gmail, Apple Mail)'),
    d.vmc && (d.vmc.error || d.vmc.expired) && t('certificat illisible ou expiré'),
    d.vmc?.logotype?.found && d.vmc.logotype.matchesSvg === false && t('logo différent de celui du certificat'),
  ].filter(Boolean) as string[];
  const verified = d.vmc?.kind === 'VMC' && !blockers.length;
  return (
    <>
    <div className="dm-bimi">
      <div className="dm-bimi__frames">
        <figure className="dm-bimi__frame" style={{ margin: 0 }}>
          <img className="dm-bimi__square" src={url} alt={t('Logo BIMI de {domain}, cadre carré', { domain: d.domain })} onError={() => setFailed(true)} referrerPolicy="no-referrer" />
          <figcaption>{t('carré')}</figcaption>
        </figure>
        <figure className="dm-bimi__frame" style={{ margin: 0 }}>
          <img className="dm-bimi__round" src={url} alt={t('Logo BIMI de {domain}, cadre rond', { domain: d.domain })} referrerPolicy="no-referrer" />
          <figcaption>{t('rond')}</figcaption>
        </figure>
      </div>
      <div className="dm-inbox" aria-label={t('Aperçu dans une boîte de réception')}>
        <div className="dm-inbox__row">
          <img className="dm-inbox__avatar" src={url} alt="" referrerPolicy="no-referrer" />
          <div style={{ minWidth: 0 }}>
            <div className="dm-inbox__from">
              {name}
              {verified && <BadgeCheck aria-label={t('expéditeur vérifié (VMC)')} />}
            </div>
            <div className="dm-inbox__subject">{t('Votre commande est confirmée')}</div>
          </div>
          <span className="dm-inbox__time">09:41</span>
        </div>
        <div className="dm-inbox__row">
          <span className="dm-inbox__initial" aria-hidden>
            A
          </span>
          <div style={{ minWidth: 0 }}>
            <div className="dm-inbox__from">{t('Autre expéditeur')}</div>
            <div className="dm-inbox__subject">{t('Sans BIMI : une initiale à la place du logo')}</div>
          </div>
          <span className="dm-inbox__time">09:12</span>
        </div>
      </div>
    </div>
    <p className="field__hint" style={{ marginTop: 'var(--s2)' }}>
      {blockers.length
        ? t('Aperçu du fichier publié. Les messageries exigeantes ne l’afficheront pas encore : {list}.', { list: blockers.join(', ') })
        : t('Aperçu du fichier publié, tel qu’une messagerie compatible BIMI l’affiche.')}
    </p>
    </>
  );
}

function certRows(v: VmcCheck, domain: string): Metric[] {
  const leaf = v.certificates.find((c) => !c.ca) ?? v.certificates[0];
  const rows: Metric[] = [
    {
      key: 'kind', label: t('Type de certificat'), measured: v.kind ?? t('inconnu'), sub: v.markType ? t('marque : {type}', { type: v.markType }) : undefined, reference: t('VMC ou CMC'),
      dev: v.kind === 'VMC' || v.kind === 'CMC' ? { kind: 'ok' } : { kind: 'out', text: t('inconnu'), direction: 'down' }, ids: ['bimi.certificate_invalid', 'bimi.cmc_no_checkmark'],
    },
  ];
  if (leaf) {
    rows.push({ key: 'issuer', label: t('Émetteur'), measured: certName(leaf.issuer), dev: { kind: 'info', text: t('noté') } });
    rows.push({
      key: 'dates', label: t('Validité'), measured: t('du {from} au {to}', { from: isoDay(leaf.validFrom), to: isoDay(leaf.validTo) }), reference: t('≥ 30 jours restants'),
      dev: v.expired ? { kind: 'out', text: t('expiré'), direction: 'down' } : v.daysLeft !== undefined && v.daysLeft < 30 ? { kind: 'warn', text: t('{n} j', { n: v.daysLeft }), direction: 'down' } : { kind: 'ok', text: v.daysLeft !== undefined ? t('{n} j', { n: v.daysLeft }) : t('conforme') },
    });
  }
  rows.push({ key: 'covers', label: t('Couvre {domain}', { domain }), measured: leaf?.san.join(', ') || t('aucun nom'), reference: domain, dev: v.coversDomain ? { kind: 'ok' } : { kind: 'out', text: t('non'), direction: 'down' } });
  rows.push({ key: 'chain', label: t('Chaîne de certificats'), measured: v.chainLinked ? tn(v.certificates.length, '{n} certificat, liés', '{n} certificats, liés') : tn(v.certificates.length, '{n} certificat', '{n} certificats'), reference: t('liés jusqu’à la racine'), dev: v.chainLinked ? { kind: 'ok' } : { kind: 'warn', text: t('rompue'), direction: 'down' } });
  if (v.logotype)
    rows.push({
      key: 'logo', label: t('Logo du certificat = fichier l='), measured: !v.logotype.found ? t('aucun logo dans le certificat') : v.logotype.matchesSvg ? t('identiques (SHA-256)') : t('différents'), reference: t('identiques'),
      dev: v.logotype.matchesSvg ? { kind: 'ok' } : { kind: 'warn', text: t('différent'), direction: 'down' }, ids: ['bimi.certificate_logo_mismatch'],
    });
  for (const [i, p] of v.problems.entries()) rows.push({ key: `p-${i}`, label: p, dev: { kind: 'out', text: t('écart'), direction: 'down' } });
  return rows;
}

function SelectorForm({ domain, selector }: { domain: string; selector: string }) {
  const [value, setValue] = useState(selector === 'default' ? '' : selector);
  const navigate = useNavigate();
  return (
    <form
      className="page-form"
      style={{ marginBottom: 0 }}
      onSubmit={(e) => {
        e.preventDefault();
        const s = value.trim().toLowerCase().replace(/\._bimi\..*$/, '');
        navigate(`/bimi/${domain}${s && s !== 'default' ? `?selecteur=${encodeURIComponent(s)}` : ''}`);
      }}
    >
      <div style={{ flex: '0 1 18rem' }}>
        <Field label={t('Autre sélecteur BIMI')} hint={t('Rare : seulement si vos messages portent un en-tête BIMI-Selector.')}>
          {(id, dsc) => <input id={id} aria-describedby={dsc} className="input input--mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder="default" spellCheck={false} autoCapitalize="off" />}
        </Field>
      </div>
      <SubmitButton>{t('Mesurer')}</SubmitButton>
    </form>
  );
}

export default function BimiPage() {
  const { domain: raw } = useParams();
  const [params] = useSearchParams();
  const domain = raw ? toDomain(raw) : undefined;
  const selector = params.get('selecteur')?.trim() || 'default';
  const url = domain ? `/api/bimi/${encodeURIComponent(domain)}${selector !== 'default' ? `?selector=${encodeURIComponent(selector)}` : ''}` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<BimiData>>(url);
  useRecent(domain, `/bimi/${domain}`, 'BIMI');

  if (!domain) {
    const record = params.get('enregistrement');
    return (
      <ToolEmpty
        title="BIMI"
        desc={t('Le logo tel qu’une boîte de réception l’affiche, sa conformité SVG Tiny PS, le certificat de marque et le DMARC qu’il exige.')}
        basePath="/bimi"
        examples={[
          { domain: 'cnn.com', why: t('logo conforme, certificat VMC DigiCert') },
          { domain: 'cloudflare.com', why: t('SVG non conforme au profil Tiny PS') },
        ]}
      >
        {raw && <Notice tone="error" title={t('« {raw} » n’est pas un nom de domaine', { raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
        {record && <PastedRecord record={record} kind="BIMI" basePath="/bimi" />}
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
        if (!d.record) return [{ label: 'BIMI', value: d.declined ? t('refus déclaré') : t('absent') }, { label: 'DMARC', value: d.dmarc?.effectivePolicy ? `p=${d.dmarc.effectivePolicy}` : t('absent') }];
        return [
          { label: t('Logo'), value: !d.svg ? t('non lu') : d.svg.error ? t('illisible') : d.svg.problems.length ? t('hors profil Tiny PS') : t('conforme') },
          { label: t('Certificat'), value: !d.vmc ? t('aucun') : d.vmc.error ? t('illisible') : `${d.vmc.kind ?? '?'}${d.vmc.daysLeft !== undefined ? ', ' + t('{n} j', { n: d.vmc.daysLeft }) : ''}` },
          { label: 'DMARC', value: d.dmarc?.effectivePolicy ? `p=${d.dmarc.effectivePolicy}` : t('absent') },
        ];
      }}
      fix={(r) =>
        r.data.record && r.data.logoUrl ? (
          <section className="block" aria-labelledby="logo-t">
            <h2 className="block__title" id="logo-t">
              {t('Votre logo dans une boîte de réception')}
            </h2>
            <div className="issue">
              <Preview d={r.data} />
            </div>
          </section>
        ) : null
      }
    >
      {(r) => {
        const d = r.data;
        const recordRows: Metric[] = [
          {
            key: 'record', label: t('Enregistrement {name}', { name: d.name }), measured: d.record ? (d.inherited ? t('hérité de {foundAt}', { foundAt: d.foundAt }) : t('publié')) : d.declined ? t('refus déclaré (l= vide)') : t('absent'), reference: 'v=BIMI1; l=…; a=…',
            dev: d.record && !d.declined ? { kind: 'ok' } : { kind: 'info', text: d.declined ? t('refusé') : t('absent') },
          },
          {
            key: 'dmarc', label: t('Prérequis DMARC'), measured: d.dmarc?.effectivePolicy ? `p=${d.dmarc.effectivePolicy}, pct=${d.dmarc.pct}${d.dmarc.subdomainPolicy ? `, sp=${d.dmarc.subdomainPolicy}` : ''}` : t('aucun DMARC'),
            sub: d.dmarc?.foundAt, reference: t('quarantine ou reject, pct=100'),
            dev: d.dmarcEligible ? { kind: 'ok' } : { kind: 'out', text: t('insuffisant'), direction: 'down' },
          },
        ];
        const svgRows = d.svg ? [...svgMetrics(d.svg), ...leftoverMetrics(d.svg)] : [];
        return (
          <>
            {d.svg && (
              <Details title={t('Fichier du logo (SVG Tiny PS)')} count={d.svg.problems.length ? t('{n} écart(s) au profil', { n: d.svg.problems.length }) : t('conforme')} defaultOpen>
                <MetricTable rows={svgRows} />
                {d.svg.url && (
                  <p className="field__hint" style={{ marginTop: 'var(--s2)' }}>
                    {rich('Fichier lu : <a>{url}</a>', { url: d.svg.url }, { a: (c) => <a href={d.svg!.url} target="_blank" rel="noreferrer noopener" className="mono">{c}</a> })}
                    {d.svg.bytes !== undefined && `, ${fmtBytes(d.svg.bytes)}`}
                  </p>
                )}
              </Details>
            )}
            {d.record && (
              <Details title={t('Certificat de marque')} count={!d.vmc ? t('aucun') : d.vmc.error ? t('illisible') : d.vmc.kind ?? ''}>
                {d.vmc ? (
                  d.vmc.error ? (
                    <MetricTable rows={[{ key: 'err', label: t('Fichier a='), measured: d.vmc.error, reference: t('certificat PEM lisible'), dev: { kind: 'out', text: t('illisible'), direction: 'down' } }]} />
                  ) : (
                    <MetricTable rows={certRows(d.vmc, domain)} />
                  )
                ) : (
                  <MetricTable rows={[{ key: 'none', label: t('Certificat (balise a=)'), measured: t('aucun'), reference: t('VMC ou CMC'), dev: { kind: 'warn', text: t('absent'), direction: 'down' }, sub: t('Gmail et Apple Mail exigent un VMC ou un CMC ; Yahoo affiche le logo sans.') }]} />
                )}
              </Details>
            )}
            <Details title={t('Enregistrement et prérequis DMARC')} defaultOpen={!d.record}>
              {d.record && <CodeBlock code={d.record} label={t('TXT de {name}', { name: d.foundAt ?? d.name })} />}
              <MetricTable rows={recordRows} />
            </Details>
            <Details title={t('Autre sélecteur BIMI')} count={selector}>
              <SelectorForm domain={domain} selector={selector} />
            </Details>
            <SeeAlso
              links={[
                { to: `/dmarc/${domain}`, label: 'DMARC' },
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
