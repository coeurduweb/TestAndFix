// One domain: the answer first (registrar, expiry, age, statuses), then what the registry and the
// registrar each say with the differences marked, the statuses explained, the contacts, and the
// technical part folded (name servers, sources tried, raw answers).
import { useState } from 'react';
import { Link } from 'react-router';
import { Details } from '../../components/Verdict';
import { CodeBlock, Notice } from '../../components/ui';
import { fmtDateTime, fmtMs, fmtRelative, plural } from '../../lib/format';
import { msg, rich, t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { useCheck } from '../../lib/useCheck';
import { ReportFrame, SeeAlso, useRecent } from '../domain/common';
import { compareRows, contactField, fmtDays, frDay, PROTOCOL_LABEL, ROLE_LABEL, type PartyRecord, type WhoisReport } from './model';

function sourceLabel(p: PartyRecord | undefined, fallback: string) {
  return p ? (
    <>
      {PROTOCOL_LABEL[p.protocol]} <span className="mono">{p.server}</span>
    </>
  ) : (
    <span className="muted">{fallback}</span>
  );
}

function registrarFallback(d: WhoisReport): string {
  if (d.registrarNotAnnounced) return t('aucun serveur annoncé par le registre');
  if (d.registrarUnknown) return t('ne publie pas ce nom');
  if (!d.registry) return t('non interrogé');
  return t('injoignable');
}

function registrarNote(d: WhoisReport) {
  const tried = d.attempts.filter((a) => a.party === 'registrar');
  const where = tried.map((a) => `${PROTOCOL_LABEL[a.protocol]} ${a.server}`).join(', ');
  const name = d.merged.registrar?.name;
  // the optional parts are data in parentheses, no words
  const vars = { name: name ? ` (${name})` : '', where: where ? ` (${where})` : '', tld: d.tld };
  if (d.registrarUnknown)
    return t('Le bureau d’enregistrement{name} ne publie pas ce nom{where}. Les obligations RDAP de l’ICANN ne couvrent que les domaines génériques (gTLD) : pour .{tld}, les données ci-dessus sont celles du registre.', vars);
  if (d.registrarNotAnnounced) return t('Le registre de .{tld} n’indique aucun serveur de bureau d’enregistrement à interroger : les données ci-dessus sont les siennes.', vars);
  return t('Le bureau d’enregistrement{name} n’a pas répondu{where} : seules les données du registre sont affichées. Réessayez dans quelques minutes.', vars);
}

function Compare({ d }: { d: WhoisReport }) {
  const rows = compareRows(d);
  const real = d.divergences.filter((x) => !x.expected).length;
  if (!d.registrar)
    return (
      <section className="block" aria-labelledby="wh-cmp-t">
        <h2 className="block__title" id="wh-cmp-t">
          {t('Registre')}
          <span className="block__count block__count--neutral">{d.registry ? `${PROTOCOL_LABEL[d.registry.protocol]} ${d.registry.server}` : ''}</span>
        </h2>
        <div className="wh-cmp surface">
          <table className="wh-cmp__table wh-cmp__table--one">
            <tbody>
              {rows.map((r) => (
                <tr key={r.key}>
                  <th scope="row">{r.label}</th>
                  <td className={r.key === 'nameservers' || r.key === 'status' ? 'mono wh-wrap' : 'mono'}>{r.registry || <span className="muted">{t('non indiqué')}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="field__hint">{registrarNote(d)}</p>
      </section>
    );
  return (
    <section className="block" aria-labelledby="wh-cmp-t">
      <h2 className="block__title" id="wh-cmp-t">
        {t('Registre et bureau d’enregistrement')}
        {real > 0 ? <span className="block__count block__count--warn">{plural(real, 'écart', 'écarts')}</span> : d.registry && d.registrar ? <span className="block__count block__count--ok">{t('concordent')}</span> : null}
      </h2>
      <div className="wh-cmp surface">
        <table className="wh-cmp__table">
          <thead>
            <tr>
              <th scope="col">
                <span className="visually-hidden">{t('Donnée')}</span>
              </th>
              <th scope="col">
                {t('Registre')}
                <span className="wh-src">{sourceLabel(d.registry, t('injoignable'))}</span>
              </th>
              <th scope="col">
                {t('Bureau d’enregistrement')}
                <span className="wh-src">{sourceLabel(d.registrar, registrarFallback(d))}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className={r.diverges ? (r.expected ? 'wh-row--soft' : 'wh-row--diff') : undefined}>
                <th scope="row">
                  {r.label}
                  {r.diverges && (
                    <span className={`tag ${r.expected ? '' : 'tag--warn'}`} title={r.expected ? t('Les deux bases changent à des moments différents : écart courant') : undefined}>
                      {r.expected ? t('écart habituel') : t('diffère')}
                    </span>
                  )}
                </th>
                <td data-label={t('Registre')} className={r.key === 'nameservers' || r.key === 'status' ? 'mono wh-wrap' : 'mono'}>
                  {r.registry || <span className="muted">{t('non indiqué')}</span>}
                </td>
                <td data-label={t('Bureau')} className={r.key === 'nameservers' || r.key === 'status' ? 'mono wh-wrap' : 'mono'}>
                  {d.registrar ? r.registrar || <span className="muted">{t('non indiqué')}</span> : <span className="muted">{t('sans réponse')}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {real > 0 && (
        <p className="field__hint">
          {t('Le registre fait foi pour les dates, les statuts et la délégation ; le bureau d’enregistrement garde sa propre date d’échéance (celle de votre contrat avec lui) et les contacts.')}
        </p>
      )}
    </section>
  );
}

function Statuses({ d }: { d: WhoisReport }) {
  const list = d.merged.statusDetails ?? [];
  if (!list.length && !d.merged.registryStatus.length) return null;
  return (
    <section className="block" aria-labelledby="wh-st-t">
      <h2 className="block__title" id="wh-st-t">
        {t('Statuts')}
      </h2>
      <ul className="wh-status surface">
        {list.map((s) => (
          <li key={s.code}>
            <span className={`dot ${s.kind === 'bad' ? 'dot--out' : s.kind === 'lock' ? 'dot--ok' : ''}`} aria-hidden />
            <span className="mono wh-status__code">{s.code}</span>
            <span className="wh-status__meaning">
              {s.meaning}
              {s.setBy && <span className="muted"> · {s.setBy === 'registre' ? t('posé par le registre') : t('posé par le bureau d’enregistrement')}</span>}
              {!s.epp && <span className="muted"> · {t('hors EPP')}</span>}
            </span>
          </li>
        ))}
        {d.merged.registryStatus.map((s) => (
          <li key={`r-${s}`}>
            <span className="dot" aria-hidden />
            <span className="mono wh-status__code">{s}</span>
            <span className="wh-status__meaning">{t('statut du registre, hors EPP')}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Contacts({ d }: { d: WhoisReport }) {
  const list = d.merged.contacts;
  return (
    <section className="block" aria-labelledby="wh-ct-t">
      <h2 className="block__title" id="wh-ct-t">
        {t('Contacts')}
      </h2>
      {!list.length ? (
        <p className="block__empty">{t('Aucun contact publié par les serveurs interrogés.')}</p>
      ) : (
        <div className="wh-contacts">
          {list.map((c) => (
            <div key={c.role} className="wh-contact surface">
              <h3 className="wh-contact__role">{t(ROLE_LABEL[c.role])}</h3>
              {!c.name && !c.org && !c.email ? (
                <p className="muted wh-contact__none">{c.redacted.length ? t('Nom, organisation et e-mail masqués.') : t('Rien de publié.')}</p>
              ) : (
              <dl>
                {(['name', 'org', 'email'] as const).map((f) => {
                  const v = contactField(c, f);
                  return (
                    <div key={f}>
                      <dt>{f === 'name' ? t('Nom') : f === 'org' ? t('Organisation') : t('E-mail')}</dt>
                      <dd className={v && !v.hidden ? (f === 'email' ? 'mono' : undefined) : 'muted'}>{v ? (v.hidden && f === 'org' ? t('masquée') : v.text) : f === 'org' ? t('non publiée') : t('non publié')}</dd>
                    </div>
                  );
                })}
              </dl>
              )}
              {c.privacyService && <p className="wh-contact__note">{t('Service d’anonymat : le vrai titulaire n’est pas publié.')}</p>}
              {c.contactUrl && (
                <p className="wh-contact__note">
                  <a href={c.contactUrl} target="_blank" rel="noreferrer noopener">
                    {t('Formulaire de contact')}
                  </a>
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

const ATTEMPT_TEXT = { ok: msg('a répondu'), not_found: msg('ne connaît pas ce nom'), error: msg('échec'), rate_limited: msg('limite de requêtes'), unsupported: msg('non proposé') } as const;

function Technical({ d, domain }: { d: WhoisReport; domain: string }) {
  return (
    <>
      {d.merged.nameservers.length > 0 && (
        <Details title={t('Serveurs de noms')} count={plural(d.merged.nameservers.length, 'serveur', 'serveurs')} defaultOpen>
          <ul className="wh-ns">
            {d.merged.nameservers.map((n) => (
              <li key={n} className="mono">
                {n}
              </li>
            ))}
          </ul>
          {d.merged.dnssec !== undefined && <p className="field__hint">{d.merged.dnssec ? t('DNSSEC déclaré au registre : oui (délégation signée).') : t('DNSSEC déclaré au registre : non.')}</p>}
        </Details>
      )}
      {d.a !== undefined && (
        <Details title={t('Adresse IPv4 (A)')} count={d.a.length ? plural(d.a.length, 'adresse', 'adresses') : t('aucune')} defaultOpen>
          {d.a.length ? (
            <ul className="wh-ns">
              {d.a.map((ip) => (
                <li key={ip} className="mono">
                  <Link to={`/ip/${ip}`}>{ip}</Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="field__hint">{t('{domain} n’a pas d’enregistrement A.', { domain: d.queried })}</p>
          )}
          <p className="field__hint">{t('Lu dans le DNS au moment de la recherche, pas dans le Whois.')}</p>
        </Details>
      )}
      <Details title={t('Sources interrogées')} count={plural(d.attempts.length, 'requête', 'requêtes')}>
        <ol className="wh-attempts">
          {d.attempts.map((a, i) => (
            <li key={i}>
              <span className={`dot ${a.status === 'ok' ? 'dot--ok' : a.status === 'not_found' || a.status === 'unsupported' ? '' : 'dot--warn'}`} aria-hidden />
              <span>
                {rich('{party} · {proto} <m>{server}</m> : {status}', { party: a.party === 'registry' ? t('Registre') : t('Bureau'), proto: PROTOCOL_LABEL[a.protocol], server: a.server, status: t(ATTEMPT_TEXT[a.status]) }, { m: (c) => <span className="mono">{c}</span> })}
                {a.reason && a.status !== 'ok' ? ` (${a.reason})` : ''}
                {a.ms !== undefined && <span className="muted"> · {fmtMs(a.ms)}</span>}
              </span>
            </li>
          ))}
        </ol>
        <p className="field__hint">
          {t('RDAP d’abord, WHOIS (port 43) en repli. Chaque serveur reçoit au plus une requête à la fois, espacées d’une seconde en RDAP et de trois en WHOIS ; un serveur qui demande d’attendre (HTTP 429) est laissé tranquille le temps indiqué.')}
        </p>
      </Details>
      {[d.registry, d.registrar].filter((p): p is PartyRecord => !!p).map((p) => (
        <Details key={p.party} title={p.party === 'registry' ? t('Réponse brute du registre') : t('Réponse brute du bureau d’enregistrement')} count={`${PROTOCOL_LABEL[p.protocol]} ${p.server}`}>
          <div className="wh-raw">
            <CodeBlock code={p.raw} label={p.url ?? t('{server}, port 43', { server: p.server })} />
          </div>
          {p.rawTruncated && <p className="field__hint">{t('Réponse tronquée à 200 Ko.')}</p>}
        </Details>
      ))}
      <SeeAlso
        links={[
          { to: `/dnssec/${domain}`, label: t('DNSSEC') },
          { to: `/dns/${domain}?type=NS`, label: t('Recherche NS') },
          { to: `/domaine/${domain}`, label: t('Scanner {domain}', { domain }) },
        ]}
      />
    </>
  );
}

export function WhoisSingle({ domain }: { domain: string }) {
  const [fresh, setFresh] = useState(0);
  const url = `/api/whois/${encodeURIComponent(domain)}${fresh ? `?frais=${fresh}` : ''}`;
  const { data: r, error, loading } = useCheck<CheckResult<WhoisReport>>(url);
  useRecent(domain, `/whois/${domain}`, msg('Whois'));
  const rerun = () => setFresh((n) => n + 1);

  return (
    <div className="wh-page">
      <ReportFrame
        domain={r?.data.unicode && r.data.unicode !== domain ? `${r.data.unicode} (${domain})` : domain}
        r={r}
        loading={loading}
        error={error}
        rerun={rerun}
        facts={(x) => {
          const m = x.data.merged;
          const out: { label: string; value: string }[] = [];
          if (m.registrar?.name) out.push({ label: t('Bureau d’enregistrement'), value: m.registrar.name });
          if (m.expires && m.expiresInDays !== undefined)
            out.push({ label: t('Expire le'), value: m.expiresInDays < 0 ? t('{date}, dépassé de {duration}', { date: frDay(m.expires), duration: fmtDays(m.expiresInDays) }) : t('{date}, dans {duration}', { date: frDay(m.expires), duration: fmtDays(m.expiresInDays) }) });
          if (m.created && m.ageDays !== undefined) out.push({ label: t('Créé le'), value: t('{date}, il y a {duration}', { date: frDay(m.created), duration: fmtDays(m.ageDays) }) });
          if (m.status.length) out.push({ label: t('Statuts'), value: m.status.join(', ') });
          if (x.data.queried !== x.data.domain) out.push({ label: t('Domaine interrogé'), value: x.data.queried });
          return out;
        }}
        noScore={(x) => !x.data.notFound && (!x.data.registry || (!x.data.merged.expires && !x.data.merged.created))}
        sentence={(x) => {
          const d = x.data;
          if (d.notFound) return t('{domain} n’est pas enregistré : le registre de .{tld} ne le connaît pas.', { domain: d.unicode, tld: d.tld });
          if (!d.registry) return t('Le registre de .{tld} n’a pas répondu : résultat provisoire, réessayez dans un instant.', { tld: d.tld });
          if (!d.merged.expires && !d.merged.created) return t('Le registre de .{tld} ne publie ni date de création ni date d’expiration pour ce nom.', { tld: d.tld });
          return undefined;
        }}
        afterIssues={(x) => {
          const d = x.data;
          if (d.notFound) return null;
          return (
            <>
              {d.cachedAt && (
                <Notice title={t('Réponse lue {when}', { when: fmtRelative(d.cachedAt) })}>
                  {t('Pour ne pas solliciter deux fois de suite les serveurs du registre et du bureau d’enregistrement, une réponse est gardée 10 minutes (lue le {date}). « Mesurer à nouveau » les interroge tout de suite.', { date: fmtDateTime(d.cachedAt) })}
                </Notice>
              )}
              {d.registry && <Compare d={d} />}
              <Statuses d={d} />
              {d.registry && <Contacts d={d} />}
            </>
          );
        }}
      >
        {(x) => <Technical d={x.data} domain={domain} />}
      </ReportFrame>
    </div>
  );
}
