// DNSSEC: chain of trust from the root down to the zone, one row per link with its status, and
// under each link the DS published by the parent, the zone keys and their signatures.
import type { ReactNode } from 'react';
import { useParams } from 'react-router';
import { Details } from '../../components/Verdict';
import { Notice } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { msg, rich, t } from '../../lib/i18n';
import { fmtInt, plural } from '../../lib/format';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { DnssecData, ZoneChain } from '../domain/model';
import { isoDay, type Metric } from '../domain/rows';
import { chainMetrics, fmtHours } from './chain';

const DIGEST: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

const MONO = { m: (c: ReactNode) => <span className="mono">{c}</span> };
const STATUS: Record<string, string> = { secure: msg('signée et validée'), insecure: msg('non signée'), bogus: msg('chaîne cassée'), indeterminate: msg('indéterminé') };

function ZoneDetail({ z, hideProblems }: { z: ZoneChain; hideProblems?: boolean }) {
  return (
    <div className="stack-sm">
      {z.problems.length > 0 && !hideProblems && (
        <Notice tone="error" title={t('Ce qui casse ce maillon')}>
          <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
            {z.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </Notice>
      )}
      <div className="lab-detail__label">{t('DS publiés par {parent}', { parent: z.parent === '.' ? t('la racine') : z.parent })}</div>
      {z.ds.length ? (
        <div className="dm-sub-table">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('Keytag')}</th>
                <th scope="col">{t('Algorithme')}</th>
                <th scope="col">{t('Condensé')}</th>
                <th scope="col">{t('Clé correspondante')}</th>
              </tr>
            </thead>
            <tbody>
              {z.ds.map((d, i) => (
                <tr key={i}>
                  <td>{d.keyTag}</td>
                  <td>{d.algorithm}</td>
                  <td className="dm-digest">
                    {DIGEST[d.digestType] ?? d.digestType} {d.digest.slice(0, 16)}…
                  </td>
                  <td className={d.matches === null ? 'out-text' : 'ok-text'}>{d.matches === null ? t('aucune') : t('DNSKEY {n}', { n: d.matches })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">{t('Aucun DS : la zone n’est pas raccrochée à la chaîne.')}</p>
      )}
      {z.dnskey.length > 0 && (
        <>
          <div className="lab-detail__label">{t('Clés de la zone (DNSKEY)')}</div>
          <div className="dm-sub-table">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">{t('Keytag')}</th>
                  <th scope="col">{t('Rôle')}</th>
                  <th scope="col">{t('Algorithme')}</th>
                  <th scope="col">{t('Taille')}</th>
                </tr>
              </thead>
              <tbody>
                {z.dnskey.map((k) => (
                  <tr key={k.keyTag}>
                    <td>{k.keyTag}</td>
                    <td>{k.revoked ? t('révoquée') : k.ksk ? t('KSK (signe les clés)') : t('ZSK (signe la zone)')}</td>
                    <td>{k.algorithmName}</td>
                    <td>{k.bits ? t('{n} bits', { n: k.bits }) : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {z.rrsig.length > 0 && (
        <>
          <div className="lab-detail__label">{t('Signatures lues (RRSIG)')}</div>
          <div className="dm-sub-table">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">{t('Couvre')}</th>
                  <th scope="col">{t('Par la clé')}</th>
                  <th scope="col">{t('Expire')}</th>
                  <th scope="col">{t('État')}</th>
                </tr>
              </thead>
              <tbody>
                {z.rrsig.map((s, i) => (
                  <tr key={i}>
                    <td>{s.typeCovered}</td>
                    <td>{s.keyTag}</td>
                    <td>
                      {isoDay(s.expiration)} ({fmtHours(s.expiresInHours)})
                    </td>
                    <td className={!s.current || s.verified === false ? 'out-text' : undefined}>
                      {!s.current ? t('hors validité') : s.verified === true ? t('vérifiée') : s.verified === false ? (s.verifyError ? t('invalide : {error}', { error: s.verifyError }) : t('invalide')) : t('en cours de validité')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {(z.servers.parent || z.servers.zone) && (
        <p className="field__hint">
          {z.servers.parent && z.servers.zone
            ? rich('Interrogés : parent <m>{parent}</m>, zone <m>{zone}</m>', { parent: z.servers.parent, zone: z.servers.zone }, MONO)
            : z.servers.parent
              ? rich('Interrogés : parent <m>{parent}</m>', { parent: z.servers.parent }, MONO)
              : rich('Interrogés : zone <m>{zone}</m>', { zone: z.servers.zone }, MONO)}
        </p>
      )}
    </div>
  );
}

export default function DnssecPage() {
  const { domain: raw } = useParams();
  const domain = raw ? toDomain(raw) : undefined;
  const url = domain ? `/api/dns/${encodeURIComponent(domain)}/dnssec` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<DnssecData>>(url);
  useRecent(domain, `/dnssec/${domain}`, 'DNSSEC');

  if (!domain) {
    return (
      <ToolEmpty
        title="DNSSEC"
        desc={t("Chaîne de confiance de la racine jusqu’à la zone : DS du parent, clés de la zone, signatures et leur échéance, maillon par maillon.")}
        basePath="/dnssec"
        examples={[
          { domain: 'cloudflare.com', why: t('zone signée, chaîne valide') },
          { domain: 'dnssec-failed.org', why: t('DS qui ne correspond à aucune clé') },
          { domain: 'gmail.com', why: t('zone non signée') },
        ]}
      >
        {raw && <Notice tone="error" title={t('« {name} » n’est pas un nom de domaine', { name: raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
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
      facts={(r) => [
        { label: t('Zone'), value: r.data.zone || t('aucune') },
        { label: t('État'), value: STATUS[r.data.status] ? t(STATUS[r.data.status]) : r.data.status },
        ...(r.data.chain.length ? [{ label: t('Maillons'), value: String(r.data.chain.length + 1) }] : []),
      ]}
      noScore={(x) => !x.data.zone.includes('.') && domain.includes('.')}
      sentence={(x) => (!x.data.zone.includes('.') && domain.includes('.') ? (x.data.zone ? t('Aucune zone déléguée pour {domain} : la chaîne s’arrête à .{zone}, le domaine n’existe pas ou n’a pas de serveurs de noms.', { domain, zone: x.data.zone }) : t('Aucune zone déléguée pour {domain} : le domaine n’existe pas ou n’a pas de serveurs de noms.', { domain })) : undefined)}
      skeleton={[{ title: t('Chaîne de confiance'), rows: [t('Racine'), t('Domaine de premier niveau'), t('Zone du domaine')] }]}
    >
      {(r) => {
        const d = r.data;
        const rows: Metric[] = chainMetrics(d, domain);
        const explained = r.findings.some((f) => f.penalty > 0); // the cards above already say what breaks
        const extra = Object.fromEntries(d.chain.map((z) => [`z-${z.zone}`, <ZoneDetail key={z.zone} z={z} hideProblems={explained && z.zone === d.zone} />]));
        const broken = d.chain.find((z) => z.status === 'bogus');
        return (
          <>
            {d.chain.length ? (
              <Details title={t('Chaîne de confiance, de la racine à la zone')} count={plural(d.chain.length + 1, 'maillon', 'maillons')} defaultOpen>
                <MetricTable rows={rows} extra={extra} openKey={broken ? `z-${broken.zone}` : undefined} />
              </Details>
            ) : (
              <p className="dm-note">{t('Aucune zone n’a pu être suivie depuis la racine pour {domain}.', { domain })}</p>
            )}
            <SeeAlso
              links={[
                { to: `/dns/${domain}?type=DNSKEY`, label: t('Recherche DNSKEY') },
                { to: `/dns/${domain}?type=DS`, label: t('Recherche DS') },
                { to: `/whois/${domain}`, label: 'Whois' },
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
