// Subdomains revealed by Certificate Transparency (US-051), "Clair et direct": verdict band, what to
// fix, then the list of every name read at a glance (state with a large icon, what it resolves to,
// the certificate it serves), filled live as the names resolve. Technical tables last, folded.
import { memo, useDeferredValue, useEffect, useMemo, useState } from 'react';
import { Navigate, useParams } from 'react-router';
import { CircleAlert, CircleCheck, Download, ListTree, Loader2, Search } from 'lucide-react';
import { ToolHero } from '../../components/ToolHero';
import { Details, IssueList } from '../../components/Verdict';
import { ReportHeader, RerunButton, ShareButton, Unavailable } from '../../components/Report';
import { Notice, Skel } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtDateTime, fmtInt, fmtMs, plural } from '../../lib/format';
import { locale, msg, rich, t } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import {
  countFilters, filterRows, noCertNote, resolvesTo, rowStatus, shownCert, STATUS_LABEL, toCsv,
  type CertBrief, type Filter, type RowStatus, type SortKey, type SourceSummary, type SubRow, type WildcardRow,
} from './model';
import { useSubdomainStream } from './useStream';
import './subdomains.css';

const PAGE = 150;
const fmtDay = (iso?: string) => (iso ? new Date(iso).toLocaleDateString(locale(), { timeZone: 'UTC' }) : '');
const yearOf = (iso?: string) => (iso ? iso.slice(0, 4) : '');

const hero = () => ({
  icon: ListTree,
  title: t('Sous-domaines'),
  desc: t('Chaque certificat publié laisse une trace publique. Retrouvez tous les sous-domaines d’un domaine, ce qu’ils résolvent maintenant, et ceux qu’un inconnu pourrait reprendre.'),
  basePath: '/sous-domaines',
  examples: ['gitlab.com', 'github.com', 'gouv.fr'],
});

/* ---------- one row: a lit dot, the name, the state; opens on the certificate ---------- */
const DOT: Record<RowStatus, string> = {
  risk: 'dot--out',
  dangling: 'dot--out',
  active: 'dot--ok',
  error: 'dot--warn',
  pending: 'dot--pending',
  dead: '',
  skipped: '',
};

const Row = memo(function Row({ r }: { r: SubRow }) {
  const st = rowStatus(r);
  const [open, setOpen] = useState(false);
  const cert = shownCert(r);
  const soon = cert && !cert.expired && cert.kind === 'served' && (cert.daysLeft ?? 99) < 14;
  const id = `sd-${r.name.replace(/[^a-z0-9]/gi, '-')}`;
  const flag = r.takeover ? t('reprise possible chez {service}', { service: r.takeover.service }) : r.internal ? t('nom interne : {name}', { name: r.internal }) : r.dns?.viaWildcardDns ? t('via le joker DNS') : '';
  return (
    <li className={`nl__item sd-row sd-row--${st}`}>
      <button type="button" className="nl__row" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen((o) => !o)}>
        <span className={`dot ${DOT[st]}`} aria-hidden />
        <span className="nl__name">
          <span className="mono sd-name">{r.name}</span>
          <small className="mono">
            {r.dns ? resolvesTo(r) || ' ' : <Skel w="18ch" />}
            {flag && <span className={r.takeover ? 'sd-flag sd-flag--out' : 'sd-flag'}> · {flag}</span>}
          </small>
        </span>
        <span className={`nl__val sd-status sd-status--${st}`}>{t(STATUS_LABEL[st])}</span>
        <span className="nl__chev" aria-hidden />
      </button>
      {open && (
        <dl className="nl__open sd-open" id={id}>
          <div>
            <dt>{t('Certificat')}</dt>
            <dd>
              {cert ? (
                <>
                  {cert.issuer || t('Émetteur inconnu')}
                  {/* an old certificate of a name that no longer resolves is history, not a problem: red only for live names */}
                  <span className={`sd-exp ${cert.expired && st === 'active' ? 'sd-exp--out' : soon ? 'sd-exp--warn' : ''}`}>
                    {cert.kind === 'served'
                      ? cert.expired
                        ? t('servi, expiré le {date}', { date: fmtDay(cert.to) })
                        : t('servi, expire le {date}', { date: fmtDay(cert.to) })
                      : cert.expired
                        ? t('publié, expiré le {date}', { date: fmtDay(cert.to) })
                        : t('publié, valable jusqu’au {date}', { date: fmtDay(cert.to) })}
                  </span>
                </>
              ) : (
                <span className={`sd-exp ${noCertNote(r).warn ? 'sd-exp--warn' : ''}`}>{r.dns?.status === 'active' || !r.dns ? noCertNote(r).text : r.certCount ? '' : t('aucun certificat retrouvé par les sources')}</span>
              )}
            </dd>
          </div>
          {(r.firstSeen || r.certCount > 0) && (
            <div>
              <dt>{t('Historique')}</dt>
              <dd>
                {r.firstSeen ? t('vu depuis {year}', { year: yearOf(r.firstSeen) }) : ''}
                {r.firstSeen && r.certCount > 0 ? ', ' : ''}
                {r.certCount > 0 ? plural(r.certCount, 'certificat publié', 'certificats publiés') : ''}
              </dd>
            </div>
          )}
          {r.takeover && (
            <div>
              <dt>{t('Risque')}</dt>
              <dd>
                <a href={`#issue-subdomains.${r.takeover.level === 'vulnerable' ? 'takeover_risk' : 'takeover_possible'}`}>{t('Reprise possible chez {service} : voir la correction', { service: r.takeover.service })}</a>
              </dd>
            </div>
          )}
        </dl>
      )}
    </li>
  );
});

function WildRow({ w }: { w: WildcardRow }) {
  const expired = w.validUntil ? Date.parse(w.validUntil) < Date.now() : false;
  return (
    <li className="nl__item sd-row sd-row--wild">
      <div className="nl__row">
        <span className="dot" aria-hidden />
        <span className="nl__name">
          <span className="mono sd-name">{w.name}</span>
          <small>
            {t('couvre tout nom d’un niveau sous {name}', { name: w.name.slice(2) })}
            {w.lastCert ? `, ${w.lastCert.issuerShort}` : ''}
            {w.certCount > 0 ? `, ${plural(w.certCount, 'certificat', 'certificats')}` : ''}
          </small>
        </span>
        <span className={`nl__val ${expired ? 'nl__val--out' : ''}`}>{w.validUntil ? (expired ? t('expiré le {date}', { date: fmtDay(w.validUntil) }) : t('jusqu’au {date}', { date: fmtDay(w.validUntil) })) : t('joker')}</span>
        <span aria-hidden />
      </div>
    </li>
  );
}

/* ---------- the list, with its filters ---------- */
const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: msg('Tous') },
  { id: 'active', label: msg('Actifs') },
  { id: 'dead', label: msg('Morts') },
  { id: 'risk', label: msg('À risque') },
  { id: 'wildcards', label: msg('Jokers') },
];
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'name', label: msg('Nom') },
  { id: 'recent', label: msg('Récents') },
  { id: 'first', label: msg('Anciens') },
];

function SubList({ domain, rows, wildcards, live, newerThanCt, certSource }: { domain: string; rows: SubRow[]; wildcards: WildcardRow[]; live: boolean; newerThanCt: number; certSource?: string }) {
  const [filter, setFilter] = useState<Filter>('all');
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<SortKey>('name');
  const [shown, setShown] = useState(PAGE);
  const query = useDeferredValue(q);
  const counts = useMemo(() => countFilters(rows, wildcards.length), [rows, wildcards.length]);
  const list = useMemo(() => (filter === 'wildcards' ? [] : filterRows(rows, filter, query, sort)), [rows, filter, query, sort]);
  const wild = useMemo(() => wildcards.filter((w) => !query.trim() || w.name.includes(query.trim().toLowerCase())), [wildcards, query]);
  useEffect(() => setShown(PAGE), [filter, query, sort]);

  const exportCsv = () => {
    const blob = new Blob([toCsv(filter === 'wildcards' ? rows : list)], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sous-domaines-${domain}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  const total = filter === 'wildcards' ? wild.length : list.length;
  return (
    <section className="surface nl" aria-labelledby="subs-t">
      <h2 className="nl__head" id="subs-t">
        {t('Les sous-domaines')}
        <small>{fmtInt(rows.length)}</small>
      </h2>
      <div className="sd-panel">
        <div className="sd-tools">
          <div className="chips" role="group" aria-label={t('Filtrer')}>
            {FILTERS.map((f) => (
              <button key={f.id} type="button" className="chip" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {t(f.label)}
                <span className="sd-chipcount">{fmtInt(counts[f.id])}</span>
              </button>
            ))}
          </div>
          <div className="sd-tools__row">
            <label className="sd-search">
              <Search aria-hidden />
              <input className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('Chercher un nom ou une cible')} aria-label={t('Chercher un sous-domaine')} spellCheck={false} autoCapitalize="off" />
            </label>
            <div className="segmented" role="group" aria-label={t('Trier')}>
              {SORTS.map((s) => (
                <button key={s.id} type="button" aria-pressed={sort === s.id} onClick={() => setSort(s.id)}>
                  {t(s.label)}
                </button>
              ))}
            </div>
            <button type="button" className="btn btn--sm" onClick={exportCsv} disabled={!rows.length}>
              <Download aria-hidden />
              {t('Exporter en CSV')}
            </button>
          </div>
        </div>
        {newerThanCt > 0 && !live && (
          <p className="sd-note">
            {t('Pour {names}, le certificat servi est plus récent que ceux renvoyés par {source} : les journaux publics prennent du retard. L’état et l’expiration affichés viennent du serveur lui-même.', {
              names: plural(newerThanCt, 'nom', 'noms'),
              source: certSource === 'certspotter' ? 'Cert Spotter' : 'crt.sh',
            })}
          </p>
        )}
        {total === 0 ? (
          <p className="sd-empty">{rows.length ? t('Aucun nom ne correspond à ce filtre.') : t('Aucun sous-domaine dans les journaux publics.')}</p>
        ) : (
          <ul className="nl__list sd-list" aria-busy={live || undefined}>
            {filter === 'wildcards' ? wild.slice(0, shown).map((w) => <WildRow key={w.name} w={w} />) : list.slice(0, shown).map((r) => <Row key={r.name} r={r} />)}
          </ul>
        )}
        {total > shown && (
          <button type="button" className="btn btn--sm sd-more" onClick={() => setShown((n) => n + PAGE * 2)}>
            {total - shown <= PAGE * 2 ? t('Afficher les {n} restants', { n: total - shown }) : t('Afficher les {n} suivants sur {total}', { n: PAGE * 2, total: total - shown })}
          </button>
        )}
      </div>
    </section>
  );
}

/* ---------- sources while measuring ---------- */
function SourcesLine({ sources, inventory, toResolve, resolved }: { sources: SourceSummary[]; inventory: boolean; toResolve: number; resolved: number }) {
  const names: SourceSummary['source'][] = ['crt.name', 'crt.sh', 'certspotter'];
  const label = { 'crt.name': 'crt.name', 'crt.sh': 'crt.sh', certspotter: 'Cert Spotter' } as const;
  return (
    <div className="sd-progress" role="status" aria-live="polite">
      <ul className="sd-sources">
        {names.map((n) => {
          const s = sources.find((x) => x.source === n);
          const crtsh = sources.find((x) => x.source === 'crt.sh');
          if (n === 'certspotter' && !s && (!crtsh || crtsh.status === 'ok')) return null;
          return (
            <li key={n} className={`sd-src sd-src--${s?.status ?? 'pending'}`}>
              {!s ? <Loader2 aria-hidden className="spin" /> : s.status === 'ok' ? <CircleCheck aria-hidden /> : <CircleAlert aria-hidden />}
              <strong>{label[n]}</strong>
              <span>
                {!s ? (n === 'crt.sh' ? t('en cours, souvent lent') : t('en cours')) : s.status === 'ok' ? (s.certs ? plural(s.certs, 'certificat', 'certificats') : plural(s.names, 'nom', 'noms')) : s.error}
              </span>
            </li>
          );
        })}
      </ul>
      {inventory && (
        <p className="sd-resolving">
          {t('Résolution DNS depuis la racine : {resolved} sur {total}', { resolved, total: toResolve })}
          <span className="sd-bar" aria-hidden>
            <span style={{ width: `${toResolve ? (resolved / toResolve) * 100 : 0}%` }} />
          </span>
        </p>
      )}
    </div>
  );
}

/* ---------- technical details ---------- */
function SourcesTable({ sources }: { sources: SourceSummary[] }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">{t('Source')}</th>
            <th scope="col">{t('État')}</th>
            <th scope="col">{t('Noms')}</th>
            <th scope="col">{t('Certificats')}</th>
            <th scope="col">{t('Durée')}</th>
            <th scope="col">{t('Remarque')}</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((s) => (
            <tr key={s.source}>
              <td>{s.label}</td>
              <td>{s.status === 'ok' ? t('a répondu') : s.status === 'skipped' ? t('non interrogée') : t('indisponible')}</td>
              <td className="mono">{s.status === 'ok' ? fmtInt(s.names) : ''}</td>
              <td className="mono">{s.status === 'ok' ? (s.certs ? fmtInt(s.certs) : t('aucun détail')) : ''}</td>
              <td className="mono">{s.status === 'skipped' ? '' : fmtMs(s.ms)}</td>
              <td>{s.error ?? (s.truncated ? t('réponse coupée à la taille limite') : '')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CertsTable({ rows }: { rows: SubRow[] }) {
  const [shown, setShown] = useState(60);
  const withCerts = rows.filter((r) => r.certs?.length);
  if (!withCerts.length) return <p className="muted">{t('Aucune source n’a donné le détail des certificats (crt.name ne garde que les noms).')}</p>;
  return (
    <>
      <div className="table-wrap">
        <table className="data-table sd-certs">
          <thead>
            <tr>
              <th scope="col">{t('Nom')}</th>
              <th scope="col">{t('Émetteur')}</th>
              <th scope="col">{t('Numéro de série')}</th>
              <th scope="col">{t('Valable du')}</th>
              <th scope="col">{t('au')}</th>
              <th scope="col">{t('Joker')}</th>
            </tr>
          </thead>
          {withCerts.slice(0, shown).map((r) => (
            <tbody key={r.name}>
              {r.certs!.map((c: CertBrief, i) => (
                <tr key={c.source + c.id}>
                  {i === 0 && (
                    <th scope="rowgroup" rowSpan={r.certs!.length} className="mono">
                      {r.name}
                      {r.certCount > r.certs!.length && <span className="sd-more-certs">{t('{n} au total, 10 derniers', { n: r.certCount })}</span>}
                    </th>
                  )}
                  <td title={c.issuer}>{c.issuerShort}</td>
                  <td className="mono sd-serial">{c.serial ?? (c.sha256 ? `SHA-256 ${c.sha256.slice(0, 16)}…` : '')}</td>
                  <td className="mono">{fmtDay(c.notBefore)}</td>
                  <td className="mono">{fmtDay(c.notAfter)}</td>
                  <td className="mono">{c.viaWildcard ?? ''}</td>
                </tr>
              ))}
            </tbody>
          ))}
        </table>
      </div>
      {withCerts.length > shown && (
        <button type="button" className="btn btn--sm" onClick={() => setShown((n) => n + 120)}>
          {t('Afficher d’autres noms ({n} restants)', { n: withCerts.length - shown })}
        </button>
      )}
    </>
  );
}

/* ---------- page ---------- */
export default function SubdomainsPage() {
  const { domain } = useParams();
  const valid = domain ? toDomain(domain) : undefined;
  const ready = domain && valid === domain ? domain : null;
  const { state, status, restart } = useSubdomainStream(ready);

  useEffect(() => {
    if (ready) pushRecent({ value: ready, path: `/sous-domaines/${ready}`, label: msg('Sous-domaines') });
  }, [ready]);

  if (domain && valid && valid !== domain) return <Navigate to={`/sous-domaines/${encodeURIComponent(valid)}`} replace />;
  if (domain && !valid)
    return (
      <>
        <Notice tone="warn" title={t('« {name} » n\'est pas un nom de domaine', { name: domain })}>{t('Corrigez-le ci-dessous : une URL ou une adresse e-mail marchent aussi.')}</Notice>
        <ToolHero {...hero()} />
      </>
    );
  if (!ready) return <ToolHero {...hero()} />;

  const r = state.result;
  const d = r?.data;
  const live = status === 'open';
  const failed = status === 'error' && !r;
  const rows = state.rows;
  const active = rows.filter((x) => x.dns?.status === 'active').length;
  const dead = rows.filter((x) => x.dns?.status === 'dead' || x.dns?.status === 'dangling').length;
  const okSources = (d?.sources ?? state.sources).filter((s) => s.status === 'ok');
  const facts = state.inventory
    ? [
        { label: t('Sous-domaines'), value: fmtInt(rows.length) },
        { label: t('Actifs'), value: fmtInt(active) },
        { label: t('Ne résolvent plus'), value: fmtInt(dead) },
        { label: t('Sources'), value: okSources.map((s) => s.label).join(', ') || t('aucune') },
        ...(r ? [{ label: t('Mesuré le'), value: fmtDateTime(r.measuredAt) }] : []),
      ]
    : [];
  const noSource = !!d && !okSources.length;

  return (
    <div className="page-stack">
      <ReportHeader
        subject={<span className="mono">{ready}</span>}
        meta={facts}
        score={r && !noSource ? r.score : undefined}
        findings={r?.findings}
        passed={r?.passed}
        pending={live || (!r && !failed)}
        sentence={noSource ? t('Aucune source Certificate Transparency n’a répondu : relancez la mesure dans quelques minutes.') : undefined}
        actions={
          <>
            <RerunButton onClick={restart} busy={live} />
            <ShareButton />
          </>
        }
      />
      {(state.error || failed) && (
        <Notice tone="error" title={t('Mesure interrompue')}>
          {state.error ?? t('La connexion au serveur de TestAndFix s’est coupée. Relancez la mesure.')}
        </Notice>
      )}
      {live && <SourcesLine sources={state.sources} inventory={state.inventory} toResolve={state.toResolve} resolved={state.resolvedSoFar} />}
      {live && !state.inventory && (
        <div className="issues" aria-busy="true">
          {[0, 1].map((i) => (
            <div key={i} className="issue">
              <Skel w="30%" />
              <Skel w="70%" />
              <Skel w="55%" />
            </div>
          ))}
        </div>
      )}
      <div className="page-stack">
        {r && <IssueList findings={r.findings} passed={r.passed} />}
        {(state.inventory || d) && !noSource && (
          <SubList domain={ready} rows={rows} wildcards={state.wildcards} live={live} newerThanCt={d?.servedNewerThanCt ?? 0} certSource={d?.certSource} />
        )}
        {d && (
          <section className="page-stack" aria-label={t('Détails techniques')}>
            <Details title={t('Sources interrogées')} count={t('{ok} sur {total} ont répondu', { ok: okSources.length, total: d.sources.filter((s) => s.status !== 'skipped').length })} defaultOpen={okSources.length < d.sources.filter((s) => s.status !== 'skipped').length}>
              <SourcesTable sources={d.sources} />
              <p className="field__hint">
                {t('crt.name et crt.sh sont interrogés ensemble ; Cert Spotter seulement si crt.sh ne répond pas (quota sans clé faible, certificats non expirés uniquement). Aucune réponse n’est gardée en cache.')}
                {d.notResolved > 0 && ` ${t('{n} noms au-delà des {limit} plus récents ne sont pas résolus.', { n: d.notResolved, limit: d.limit })}`}
              </p>
            </Details>
            <Details title={t('Certificats publiés, par sous-domaine')} count={plural(rows.reduce((n, x) => n + x.certCount, 0), 'certificat', 'certificats')}>
              <CertsTable rows={rows} />
            </Details>
            {d.wildcardDns && (
              <Details title={t('Joker DNS')} count={d.wildcardDns.ips.join(', ')}>
                <p>
                  {rich('Un nom tiré au hasard, <m>{name}</m>, reçoit <m>{ips}</m>.', { name: d.wildcardDns.name, ips: d.wildcardDns.ips.join(', ') }, { m: (c) => <span className="mono">{c}</span> })}
                </p>
              </Details>
            )}
          </section>
        )}
        {r && <Unavailable items={r.unavailable} />}
      </div>
    </div>
  );
}
