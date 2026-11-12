// SMTP connection test of each MX: banner, EHLO, STARTTLS, TLS version, certificate. When
// outbound port 25 is blocked on the machine running check, says so and gives the command to
// run from elsewhere instead of a false verdict.
import { useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router';
import { Details } from '../../components/Verdict';
import { CodeBlock, Field, Notice, SubmitButton } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtMs } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { MetricTable } from '../domain/MetricTable';
import { ReportFrame, SeeAlso, ToolEmpty, useRecent } from '../domain/common';
import type { SmtpData, SmtpProbe } from '../domain/model';
import { isoDay, type Metric } from '../domain/rows';
import { certName } from '../bimi/svg';

function probeRows(p: SmtpProbe): Metric[] {
  const ev = p.host;
  const rows: Metric[] = [
    {
      key: 'connect', label: t('Connexion TCP'), measured: p.status === 'ok' ? `${fmtMs(p.connectMs)}` : p.error ?? p.status, reference: t('< 5 s'),
      dev: p.status === 'ok' ? { kind: 'ok' } : { kind: 'out', text: p.status === 'timeout' ? t('muet') : p.status === 'refused' ? t('refusée') : t('échec'), direction: 'down' },
      ids: ['mx.host_unreachable'], evidence: ev,
    },
  ];
  if (p.status !== 'ok') return rows;
  rows.push({ key: 'banner', label: t('Bannière 220'), measured: p.banner ?? t('aucune'), sub: p.bannerMs !== undefined ? t('en {time}', { time: fmtMs(p.bannerMs) }) : undefined, reference: t('nom du serveur'), dev: p.banner ? { kind: 'ok' } : { kind: 'out', text: t('absente'), direction: 'down' }, ids: ['infrastructure.smtp_banner_mismatch'], evidence: ev });
  rows.push({ key: 'starttls', label: t('STARTTLS annoncé'), measured: p.starttls ? t('oui') : t('non'), sub: p.extensions.length ? p.extensions.join(' · ') : undefined, reference: t('oui'), dev: p.starttls ? { kind: 'ok' } : { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['tls.mx_no_starttls'], evidence: ev });
  if (p.tls) {
    rows.push({
      key: 'tls', label: t('Négociation TLS'), measured: p.tls.ok ? `${p.tls.protocol ?? '?'}${p.tls.cipher ? `, ${p.tls.cipher}` : ''}` : p.tls.error ?? t('échec'), reference: t('TLS 1.2 ou 1.3'),
      dev: !p.tls.ok ? { kind: 'out', text: t('échec'), direction: 'down' } : /TLSv1(\.[01])?$/.test(p.tls.protocol ?? '') ? { kind: 'out', text: t('ancienne'), direction: 'down' } : { kind: 'ok' },
      ids: ['tls.mx_starttls_broken', 'tls.mx_old_version_only'], evidence: ev,
    });
    const c = p.tls.cert;
    if (c) {
      rows.push({
        key: 'cert', label: t('Certificat'), measured: c.issuer ? certName(c.issuer) : t('émetteur inconnu'), sub: c.validTo ? (c.daysLeft !== undefined ? t('jusqu’au {date}, {n} j', { date: isoDay(c.validTo), n: c.daysLeft }) : t('jusqu’au {date}', { date: isoDay(c.validTo) })) : undefined,
        reference: t('reconnu, ≥ 14 j'),
        dev: c.daysLeft !== undefined && c.daysLeft < 0 ? { kind: 'out', text: t('expiré'), direction: 'down' } : c.selfSigned ? { kind: 'warn', text: t('auto-signé'), direction: 'down' } : !c.trusted ? { kind: 'warn', text: t('non reconnu'), direction: 'down' } : c.daysLeft !== undefined && c.daysLeft < 14 ? { kind: 'warn', text: t('{n} j', { n: c.daysLeft }), direction: 'down' } : { kind: 'ok' },
        ids: ['tls.mx_cert_expired', 'tls.mx_cert_expiring', 'tls.mx_cert_self_signed', 'tls.mx_cert_chain_incomplete'], evidence: ev,
      });
      rows.push({ key: 'name', label: t('Nom couvert par le certificat'), measured: c.nameMatches ? p.host : c.nameError ?? (c.altNames.slice(0, 3).join(', ') || c.subject), reference: p.host, dev: c.nameMatches ? { kind: 'ok' } : { kind: 'warn', text: t('autre nom'), direction: 'down' }, ids: ['tls.mx_cert_name_mismatch'], evidence: ev });
    }
  }
  return rows;
}

function HostForm({ domain, hosts, current }: { domain: string; hosts: string[]; current?: string }) {
  const [value, setValue] = useState(current ?? '');
  const [err, setErr] = useState<string | null>(null);
  const navigate = useNavigate();
  const go = (h: string) => {
    const d = toDomain(h);
    if (!d) return setErr(t('Saisissez un nom de serveur, par exemple mx1.exemple.fr.'));
    setErr(null);
    navigate(`/smtp/${domain}?hote=${encodeURIComponent(d)}`);
  };
  return (
    <div className="stack-sm">
      <form
        className="page-form"
        style={{ marginBottom: 0 }}
        onSubmit={(e) => {
          e.preventDefault();
          go(value);
        }}
      >
        <div style={{ flex: '0 1 24rem' }}>
          <Field label={t('Tester un seul serveur')} hint={t('Un MX de secours, un relais sortant, un serveur pas encore publié.')} error={err}>
            {(id, dsc) => <input id={id} aria-describedby={dsc} className="input input--mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder="mx1.exemple.fr" spellCheck={false} autoCapitalize="off" />}
          </Field>
        </div>
        <SubmitButton>{t('Tester')}</SubmitButton>
      </form>
      {(hosts.length > 0 || current) && (
        <div className="chips" aria-label={t('Serveurs MX du domaine')}>
          {current && (
            <button type="button" className="chip" onClick={() => navigate(`/smtp/${domain}`)}>
              {t('Tous les MX')}
            </button>
          )}
          {hosts.map((h) => (
            <button key={h} type="button" className="chip mono" aria-pressed={h === current} onClick={() => go(h)}>
              {h}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SmtpPage() {
  const { domain: raw } = useParams();
  const [params] = useSearchParams();
  const domain = raw ? toDomain(raw) : undefined;
  const host = params.get('hote') ? toDomain(params.get('hote')!) : undefined;
  const url = domain ? `/api/smtp/${encodeURIComponent(domain)}${host ? `?host=${encodeURIComponent(host)}` : ''}` : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<SmtpData>>(url);
  useRecent(domain, `/smtp/${domain}`, 'SMTP');

  if (!domain) {
    return (
      <ToolEmpty
        title={t('Serveurs SMTP')}
        desc={t('Connexion au port 25 de chaque MX : bannière, STARTTLS, version de TLS et certificat.')}
        basePath="/smtp"
        examples={[{ domain: 'gmail.com', why: t('cinq MX Google') }]}
      >
        {raw && <Notice tone="error" title={t('«\u00a0{name}\u00a0» n’est pas un nom de domaine', { name: raw })}>{t('Saisissez un nom comme exemple.fr.')}</Notice>}
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
        ...(host ? [{ label: t('Serveur'), value: host }] : [{ label: 'MX', value: String(r.data.mx.length) }]),
        { label: t('Port 25 depuis TestAndFix'), value: r.data.port25.reachable ? t('ouvert') : t('bloqué') },
      ]}
      noScore={(x) => !x.data.port25.reachable && !x.data.probes.length}
      sentence={(r) =>
        !r.data.port25.reachable && !r.data.probes.length
          ? t('Non vérifiable depuis cette machine : son port 25 sortant est bloqué, ce n’est pas un défaut de {domain}.', { domain })
          : undefined
      }
      fix={(r) => {
        const d = r.data;
        const blocked = !d.port25.reachable && !d.probes.length;
        const first = host ?? [...d.mx].sort((a, b) => a.preference - b.preference)[0]?.host;
        if (!blocked) return null;
        return (
          <section className="block" aria-labelledby="why-t">
            <h2 className="block__title" id="why-t">
              {t('Mesurer depuis un serveur')}
            </h2>
            <div className="issue">
              <p>
                {rich('Pour savoir si le port 25 sort de cette machine, TestAndFix tente les serveurs de référence de Gmail (<m>gmail-smtp-in.l.google.com</m>) et d’iCloud (<m>mx1.mail.icloud.com</m>), toujours joignables : ils ne répondent pas non plus, c’est donc la sortie d’ici qui est fermée.', undefined, { m: (c) => <span className="mono">{c}</span> })}
              </p>
              <p className="field__hint">{t('Constaté : {detail}', { detail: d.port25.detail })}</p>
              {first && (
                <>
                  <p>{t('Depuis une machine qui a le port 25 ouvert (un VPS, le serveur d’envoi), la même mesure en une ligne :')}</p>
                  <CodeBlock code={`openssl s_client -starttls smtp -connect ${first}:25 -servername ${first} -crlf </dev/null`} label={t('Bannière, STARTTLS, version TLS et certificat')} />
                  <CodeBlock code={`swaks --to postmaster@${domain} --server ${first} --tls --quit-after RCPT`} label={t('Dialogue SMTP complet, sans envoyer de message (swaks)')} />
                </>
              )}
            </div>
          </section>
        );
      }}
    >
      {(r) => {
        const d = r.data;
        const blocked = !d.port25.reachable && !d.probes.length;
        const mxRows: Metric[] = [...d.mx]
          .sort((a, b) => a.preference - b.preference)
          .map((m) => ({ key: m.host, label: m.host, mono: true, sub: t('priorité {n}', { n: m.preference }), measured: m.ips.join(', ') || t('aucune adresse'), reference: t('connexion sur le port 25'), dev: { kind: 'info', text: t('non mesuré') } }));
        return (
          <>
            {blocked ? (
              <Details title={t('Serveurs MX')} count={String(d.mx.length)} defaultOpen>
                <MetricTable rows={mxRows} />
              </Details>
            ) : (
              d.probes.map((p, i) => (
                <Details key={`${p.host}-${p.ip}`} title={`${p.host} (${p.ip})`} count={p.status === 'ok' ? (p.starttls ? `STARTTLS${p.tls?.protocol ? `, ${p.tls.protocol}` : ''}` : t('sans STARTTLS')) : p.status} defaultOpen={i === 0}>
                  <MetricTable rows={probeRows(p)} />
                  {p.transcript.length > 0 && (
                    <div className="dm-transcript" style={{ marginTop: 'var(--s3)' }}>
                      <CodeBlock code={p.transcript.join('\n')} label={p.totalMs !== undefined ? t('Dialogue SMTP, {time}', { time: fmtMs(p.totalMs) }) : t('Dialogue SMTP')} />
                    </div>
                  )}
                </Details>
              ))
            )}
            <Details title={t('Tester un autre serveur')} count={host ?? t('tous les MX')}>
              <HostForm domain={domain} hosts={d.mx.map((m) => m.host)} current={host} />
            </Details>
            <SeeAlso
              links={[
                { to: `/mta-sts/${domain}`, label: 'MTA-STS' },
                { to: `/dns/${domain}?type=MX`, label: t('Recherche MX') },
                { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
              ]}
            />
          </>
        );
      }}
    </ReportFrame>
  );
}
