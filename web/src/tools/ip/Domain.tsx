// Domain reputation (/ip/<domaine>, US-069), same screen as the IP reputation. Band with the
// verdict, the cards to fix (domain listings with their delisting page), then the addresses of the
// domain (site and mail servers) each with its listing state and a link to its own report, what
// is fine, and the domain lists and threat sources in collapsed details.
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { LabRow, LabTable, RerunButton, ReportHeader, ShareButton, Unavailable } from '../../components/Report';
import { CopyButton, Notice, Skel } from '../../components/ui';
import { Details, IssueList } from '../../components/Verdict';
import { ApiError } from '../../lib/api';
import { fmtDateTime, plural } from '../../lib/format';
import { t, tn, msg } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { Finding } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { InvalidInput, IpHero } from './Form';
import { addressGroups, domainAddresses, domainReducer, domainSummary, initialDomain, type AddressGroup, type DomainAddress, type DomainState } from './domain-model';
import { uniqueIds, type DnsblHit } from './model';
import { ListingExtra, ListRows } from './Single';
import { useSse } from './sse';

const fmtAgeShort = (days: number) => (days < 60 ? plural(days, 'jour', 'jours') : days < 730 ? t('{n} mois', { n: Math.floor(days / 30.44) }) : t('{n} ans', { n: Math.floor(days / 365.25) }));

function AddressLine({ a }: { a: DomainAddress }) {
  const r = a.row;
  const listed = r?.status === 'listed';
  return (
    <li className={`ipd-line${listed ? ' ipd-line--listed' : ''}`}>
      <Link className="ipd-line__ip mono" to={`/ip/${encodeURIComponent(a.ip)}`} aria-label={t('Compte rendu complet de {ip}', { ip: a.ip })}>
        {a.ip}
      </Link>
      <span className="ipd-line__state">
        {!r ? (
          <Skel w="12ch" />
        ) : r.status === 'private' ? (
          <span className="muted">{t('non publique')}</span>
        ) : listed ? (
          <span className="ipd-bad">
            <span className="dot dot--out" aria-hidden /> {t('inscrite sur {names}', { names: [...new Set(r.listed.map((l) => l.name))].join(', ') })}
          </span>
        ) : (
          <span>
            <span className="dot dot--ok" aria-hidden /> {t('absente')}
          </span>
        )}
      </span>
      <span className="ipd-line__ptr mono">{r ? r.ptr ?? t('pas de reverse DNS') : ''}</span>
    </li>
  );
}

function GroupCard({ g }: { g: AddressGroup }) {
  const clean = !g.listed && !g.pending;
  // follows the measure (open while pending or listed, folded once clean) until the user toggles it
  const [userOpen, setUserOpen] = useState<boolean | null>(null);
  const open = userOpen ?? !clean;
  const n = g.addresses.length;
  const summary = g.pending
    ? tn(n, '{n} adresse, {pending} en cours', '{n} adresses, {pending} en cours', { pending: g.pending })
    : g.listed
      ? tn(g.listed, '{n} adresse inscrite sur {total}', '{n} adresses inscrites sur {total}', { total: n })
      : tn(n, '{n} adresse, aucune inscription', '{n} adresses, aucune inscription');
  const bodyId = `ipd-${g.role}-${g.host}`.replace(/[^a-z0-9-]/gi, '-');
  return (
    <li className="nl__item">
      <button type="button" className="nl__row" aria-expanded={open} aria-controls={bodyId} onClick={() => setUserOpen(!open)}>
        <span className={`dot ${g.listed ? 'dot--out' : clean ? 'dot--ok' : 'dot--pending'}`} aria-hidden />
        <span className="nl__name">
          {g.role === 'web' ? t('Site web') : <span className="mono">{g.host}</span>}
          <small className={g.role === 'web' ? 'mono' : undefined}>{g.role === 'web' ? g.host : g.preference !== undefined ? t('serveur de mail, priorité {n}', { n: g.preference }) : t('serveur de mail')}</small>
        </span>
        <span className={`nl__val${g.listed ? ' nl__val--out' : ''}`}>{summary}</span>
        <span className="nl__chev" aria-hidden />
      </button>
      {open && (
        <ul className="ipd-lines nl__open" id={bodyId}>
          {g.addresses.map((a) => (
            <AddressLine key={a.ip} a={a} />
          ))}
        </ul>
      )}
    </li>
  );
}

function Addresses({ state, running }: { state: DomainState; running: boolean }) {
  const groups = addressGroups(state);
  const aDone = !!state.events.a || !!state.result;
  const mxDone = !!state.events.mx || !!state.result;
  const web = groups.filter((g) => g.role === 'web').reduce((n, g) => n + g.addresses.length, 0);
  const mx = groups.filter((g) => g.role === 'mail').length;
  return (
    <section className="surface nl" aria-labelledby="addr-t">
      <h2 className="nl__head" id="addr-t">
        {t('Les adresses du domaine')}
        {groups.length > 0 && (
          <small>
            {plural(web, 'IP du site', 'IP du site')}, {plural(mx, 'serveur de mail', 'serveurs de mail')}
          </small>
        )}
      </h2>
      <ul className="nl__list">
        {groups.map((g) => (
          <GroupCard key={g.role + g.host} g={g} />
        ))}
        {running && (!aDone || !mxDone) && (
          <li className="nl__item">
            <div className="nl__row">
              <span className="dot dot--pending" aria-hidden />
              <Skel w="40%" />
            </div>
          </li>
        )}
      </ul>
      {!running && !groups.length && <p className="nl__empty">{t('Ce domaine ne publie aucune adresse de site ni aucun serveur de mail.')}</p>}
    </section>
  );
}

function intelMeasure(data: unknown): string {
  const d = data as Record<string, unknown> | undefined;
  if (!d) return t('consultée');
  if (Array.isArray(d.matches)) return d.matches.length ? t('{n} menace(s) : {types}', { n: d.matches.length, types: (d.matches as { threatType?: string }[]).map((m) => m.threatType).join(', ') }) : t('aucune menace connue');
  const stats = d.stats as { malicious?: number; suspicious?: number } | undefined;
  if (stats) return t('{malicious} malveillant, {suspicious} suspect', { malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0 });
  if (typeof d.listed === 'boolean') return d.listed ? (typeof d.onlineCount === 'number' ? t('recensé, {n} adresse(s) active(s)', { n: d.onlineCount }) : t('recensé')) : t('absent de la base');
  if (typeof d.found === 'boolean') return d.found ? t('connu') : t('jamais analysé');
  return t('consultée, aucune alerte');
}

const INTEL = [
  { id: 'safebrowsing', label: 'Google Safe Browsing' },
  { id: 'virustotal', label: 'VirusTotal' },
  { id: 'urlhaus', label: 'URLhaus' },
];

export function DomainRep({ domain }: { domain: string }) {
  const req = useMemo(() => ({ url: `/api/ip/domain/${encodeURIComponent(domain)}/stream` }), [domain]);
  const { state, status, error, restart } = useSse(req, domain, domainReducer, initialDomain);
  const r = state.result;
  const d = r?.data;
  const running = status === 'open';

  useEffect(() => {
    pushRecent({ value: domain, path: `/ip/${encodeURIComponent(domain)}`, label: msg('Réputation') });
  }, [domain]);

  if (error && !state.domain && !r) {
    if (error instanceof ApiError && error.status === 400) return <InvalidInput value={domain} reason={errorMessage(error)} />;
    return (
      <div className="ipx-page page-stack">
        <Notice tone="error" title={t('Mesure impossible')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={restart}>
            {t('Relancer')}
          </button>
        </Notice>
        <IpHero below />
      </div>
    );
  }

  const sum = domainSummary(state);
  // the rdap event carries either the facts or the whole RDAP analysis ({ data: {...} })
  type Rd = { ageDays?: number; created?: string; registrar?: string | { name?: string } };
  const rdRaw = state.events.rdap?.ok ? (state.events.rdap.data as Rd & { data?: Rd }) : undefined;
  const rdFacts = rdRaw?.data ?? rdRaw;
  const rdap = rdFacts ? { ageDays: rdFacts.ageDays, created: rdFacts.created, registrar: typeof rdFacts.registrar === 'object' ? rdFacts.registrar?.name : rdFacts.registrar } : undefined;
  const ageDays = d?.ageDays ?? rdap?.ageDays;
  const addrs = domainAddresses(state);
  const facts = [
    { label: t('Âge'), value: ageDays !== undefined ? fmtAgeShort(ageDays) : state.events.rdap || r ? t('inconnu') : '…' },
    { label: t('Listes de domaines'), value: state.lists.length ? tn(sum.listed.length, '{n} inscription sur {total}', '{n} inscriptions sur {total}', { total: sum.total }) : '…' },
    { label: t('IP du site'), value: state.events.a || r ? String(addrs.filter((a) => a.role === 'web').length) : '…' },
    { label: 'MX', value: state.events.mx || r ? String(new Set(addrs.filter((a) => a.role === 'mail').map((a) => a.host)).size) : '…' },
  ];
  const findings = r?.findings ?? [];
  const hitOf = (f: Finding): DnsblHit | undefined => (d?.lists.listed ?? sum.listed).find((h) => h.query && f.evidence?.startsWith(h.query + ' '));
  const unavailable = (r?.unavailable ?? []).filter((u) => u.reason);
  const sentence = r
    ? d && !d.exists
      ? d.nxdomain
        ? t('Le domaine {domain} n’existe pas (NXDOMAIN) : aucun site ni serveur de mail ne répond sous ce nom.', { domain })
        : t('Le domaine {domain} n’existe pas : aucun site ni serveur de mail ne répond sous ce nom.', { domain })
      : sum.listed.length
        ? tn(sum.listed.length, 'Inscrit sur {n} liste de domaines ({names}) : les liens vers ce domaine font classer les mails en indésirables.', 'Inscrit sur {n} listes de domaines ({names}) : les liens vers ce domaine font classer les mails en indésirables.', { names: sum.listed.map((h) => h.name).join(', ') }) +
          (sum.listedAddresses ? ' ' + tn(sum.listedAddresses, 'Et {n} adresse du domaine est listée.', 'Et {n} adresses du domaine sont listées.') : '')
        : sum.listedAddresses
          ? tn(sum.listedAddresses, 'Le domaine est absent des listes, mais {n} de ses adresses est listée : voyez ci-dessous laquelle et comment la faire retirer.', 'Le domaine est absent des listes, mais {n} de ses adresses sont listées : voyez ci-dessous laquelle et comment la faire retirer.')
          : undefined
    : undefined;

  return (
    <div className="ipx-page page-stack">
      <ReportHeader
        subject={<span className="mono">{state.domain ?? domain}</span>}
        meta={facts}
        score={r?.score}
        findings={uniqueIds(r?.findings)}
        passed={r?.passed}
        pending={running && !r}
        sentence={sentence}
        actions={
          <>
            <RerunButton onClick={restart} busy={running} />
            <CopyButton text={domain} label={t('Copier le domaine')} what={t('Domaine copié')} />
            <ShareButton />
            <Link className="btn btn--sm" to={`/domaine/${encodeURIComponent(domain)}`}>
              {t('Scanner le domaine')}
            </Link>
          </>
        }
      />
      {error && (
        <Notice tone="error" title={r ? t('Mesure incomplète') : t('Mesure impossible')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={restart}>
            {t('Relancer')}
          </button>
        </Notice>
      )}

      <div className="page-stack">
        {r ? (
          <>
            <IssueList
              findings={findings}
              passed={r.passed}
              extra={(f) => {
                const h = hitOf(f);
                return h ? <ListingExtra hit={h} withTxt={false} /> : undefined;
              }}
            />
          </>
        ) : (
          <section className="block" aria-labelledby="live-t" aria-busy={running}>
            <h2 className="block__title" id="live-t">
              {sum.listed.length ? t('À corriger') : t('Mesure en cours')}
              {sum.listed.length > 0 && <span className="block__count">{sum.listed.length}</span>}
            </h2>
            <div className="issues">
              {sum.listed.map((h) => (
                <article key={h.zone} className="issue issue--out">
                  <h3 className="issue__title">{t('Inscrit sur {name}', { name: h.name })}</h3>
                  <p className="issue__why">
                    {h.meaning
                      ? t('Code {codes} ({meaning}). La correction s’affiche à la fin de la mesure.', { codes: h.codes.join(', '), meaning: h.meaning })
                      : t('Code {codes}. La correction s’affiche à la fin de la mesure.', { codes: h.codes.join(', ') })}
                  </p>
                  <ListingExtra hit={h} />
                </article>
              ))}
              {running && (
                <div className="issue ipx-progress">
                  <p className="ipx-progress__text">
                    {(() => {
                      const head = state.lists.length ? t('{answered} listes de domaines sur {total} ont répondu', { answered: sum.answered, total: sum.total }) : t('Interrogation des listes de domaines');
                      return sum.addresses ? t('{head}, {done} adresses sur {total} vérifiées', { head, done: sum.addresses - sum.pendingAddresses, total: sum.addresses }) : head;
                    })()}
                  </p>
                  <div className="ipx-progress__bar" aria-hidden>
                    <span style={{ width: `${state.lists.length ? (sum.answered / sum.total) * 100 : 4}%` }} />
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        <Addresses state={state} running={running} />

        {(state.lists.length > 0 || r) && (
          <section className="page-stack" aria-label={t('Détails techniques')}>
            <Details title={t('Listes de domaines, une par une')} count={tn(sum.listed.length, '{n} inscription sur {total}', '{n} inscriptions sur {total}', { total: sum.total })} defaultOpen={!r}>
              <div className="ipx-bl">
                <ListRows lists={state.lists} hits={state.hits} />
              </div>
            </Details>
            <Details title={t('Sources de sécurité')} count="Safe Browsing, VirusTotal, URLhaus">
              <LabTable columns={[t('Source'), t('Résultat'), t('Détail'), t('État')]}>
                {INTEL.map(({ id, label }) => {
                  const ev = state.events[id];
                  if (!ev && !r) return <LabRow key={id} label={label} measured={<Skel w="16ch" />} deviation={{ kind: 'pending' }} />;
                  if (!ev || !ev.ok)
                    return (
                      <LabRow key={id} label={label} measured={<span className="muted">{t('non consultée')}</span>} reference={<span className="ipx-reason">{(ev?.reason ?? t('pas de réponse')).split(' : ')[0]}</span>} deviation={{ kind: 'info', text: /clé|key/i.test(ev?.reason ?? '') ? t('sans clé') : t('non consultée') }} />
                    );
                  return <LabRow key={id} label={label} measured={intelMeasure(ev.data)} deviation={{ kind: 'info', text: t('consultée') }} />;
                })}
              </LabTable>
            </Details>
            {(d?.created || rdap?.created) && (
              <Details title={t('Enregistrement du domaine (RDAP)')} count={d?.registrar ?? rdap?.registrar}>
                <LabTable>
                  <LabRow label={t('Créé le')} measured={fmtDateTime(d?.created ?? rdap?.created)} deviation={{ kind: 'info', text: t('noté') }} />
                  {(d?.registrar ?? rdap?.registrar) && <LabRow label={t('Bureau d’enregistrement')} measured={d?.registrar ?? rdap?.registrar} deviation={{ kind: 'info', text: t('noté') }} />}
                </LabTable>
              </Details>
            )}
          </section>
        )}
        <Unavailable items={unavailable} />
      </div>
    </div>
  );
}
