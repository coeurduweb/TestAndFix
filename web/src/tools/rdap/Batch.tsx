// A list of domains (/whois?liste=a,b,c): one row per domain, skeleton first, filled as the server
// answers (each registry and registrar server is asked at its own pace, see the note under the
// table), sortable, exportable in CSV for Excel (semicolon, BOM), plain CSV (comma) or JSON.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { ArrowDown, ArrowUp, ChevronsUpDown, Download, RotateCw, ScrollText } from 'lucide-react';
import { ShareButton } from '../../components/Report';
import { Notice, Skel, useToast } from '../../components/ui';
import { plural } from '../../lib/format';
import { msg, rich, t, tn } from '../../lib/i18n';
import { errorMessage } from '../../lib/useCheck';
import { useSse } from '../ip/sse';
import { BATCH_MAX, batchReducer, contactLine, frDay, initialBatch, toCsv, toJson, type WhoisRow } from './model';

type SortKey = 'domain' | 'registrar' | 'created' | 'expires';
interface Sort {
  key: SortKey;
  dir: 'asc' | 'desc';
}

const COLS: { key?: SortKey; label: string; cls: string }[] = [
  { key: 'domain', label: msg('Domaine'), cls: 'wh-c-dom' },
  { key: 'registrar', label: msg('Bureau d’enregistrement'), cls: 'wh-c-rar' },
  { key: 'created', label: msg('Création'), cls: 'wh-c-date' },
  { key: 'expires', label: msg('Expiration'), cls: 'wh-c-date' },
  { label: msg('Statuts'), cls: 'wh-c-st' },
  { label: msg('Serveurs de noms'), cls: 'wh-c-ns' },
  { label: msg('IPv4 (A)'), cls: 'wh-c-a' },
  { label: msg('Titulaire'), cls: 'wh-c-ct' },
  { label: msg('Sources'), cls: 'wh-c-src' },
];

function sortValue(r: WhoisRow | undefined, k: SortKey, d: string): string {
  if (!r) return '￿';
  if (k === 'domain') return r.unicode || d;
  if (k === 'registrar') return (r.registrar ?? '￿').toLowerCase();
  return r[k] ?? '￿';
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Row({ domain, r }: { domain: string; r?: WhoisRow }) {
  if (!r)
    return (
      <tr className="wh-tb-row wh-tb-row--pending">
        <td className="wh-c-dom mono">{domain}</td>
        {COLS.slice(1).map((c, i) => (
          <td key={i} className={c.cls}>
            <Skel w={i === 0 ? '12ch' : '8ch'} />
          </td>
        ))}
      </tr>
    );
  const real = r.divergences.filter((d) => !d.expected);
  const soon = r.expiresInDays !== undefined && r.expiresInDays < 30;
  return (
    <tr className="wh-tb-row">
      <td className="wh-c-dom">
        <Link to={`/whois/${encodeURIComponent(r.domain)}`} className="mono" title={t('Registre et bureau d’enregistrement côte à côte')}>
          {r.unicode || r.domain}
        </Link>
        {r.unicode && r.unicode !== r.domain && <span className="muted mono wh-ace">{r.domain}</span>}
      </td>
      {r.notFound ? (
        <td className="wh-c-rar" colSpan={COLS.length - 1}>
          <span className="tag">{t('non enregistré')}</span>
        </td>
      ) : !r.ok ? (
        <td className="wh-c-rar" colSpan={COLS.length - 1}>
          <span className="tag tag--warn">{t('registre injoignable')}</span> <span className="muted">{r.error}</span>
        </td>
      ) : (
        <>
          <td className="wh-c-rar">
            {r.registrar ?? <span className="muted">{t('non indiqué')}</span>}
            {r.reseller && <span className="muted wh-sub">{t('revendeur : {name}', { name: r.reseller })}</span>}
          </td>
          <td className="wh-c-date mono">
            {frDay(r.created)}
            {r.ageDays !== undefined && <span className="muted wh-sub">{plural(r.ageDays, 'jour', 'jours')}</span>}
          </td>
          <td className="wh-c-date mono">
            {frDay(r.expires)}
            {r.expiresInDays !== undefined && (
              <span className={`wh-sub ${soon ? 'out-text' : 'muted'}`}>{r.expiresInDays < 0 ? t('expiré') : t('dans {duration}', { duration: plural(r.expiresInDays, 'jour', 'jours') })}</span>
            )}
          </td>
          <td className="wh-c-st mono">
            {[...r.status, ...r.registryStatus].map((s) => (
              <span key={s}>{s}</span>
            ))}
          </td>
          <td className="wh-c-ns mono">
            {r.nameservers.map((n) => (
              <span key={n}>{n}</span>
            ))}
          </td>
          <td className="wh-c-a mono">{r.a === undefined ? <span className="muted">{t('non mesuré')}</span> : r.a.length ? r.a.map((ip) => <span key={ip}>{ip}</span>) : <span className="muted">{t('aucune')}</span>}</td>
          <td className="wh-c-ct">{contactLine(r.contacts.find((c) => c.role === 'registrant')) || <span className="muted">{t('non publié')}</span>}</td>
          <td className="wh-c-src">
            <span className="wh-sub">{r.registrySource}</span>
            <span className="wh-sub muted">{r.registrarSource}</span>
            {real.length > 0 && (
              <span className="tag tag--warn" title={real.map((d) => t('{label} : registre {registry}, bureau {registrar}', { label: d.label, registry: d.registry, registrar: d.registrar })).join(' ; ')}>
                {plural(real.length, 'écart', 'écarts')}
              </span>
            )}
          </td>
        </>
      )}
    </tr>
  );
}

export function WhoisBatch({ domains, dropped = [], invalid = [] }: { domains: string[]; dropped?: string[]; invalid?: string[] }) {
  const key = domains.join(',');
  const req = useMemo(() => ({ url: '/api/whois/batch/stream', method: 'POST' as const, json: { domains } }), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  const { state, status, error, restart } = useSse(req, key, batchReducer, initialBatch(domains));
  const [sort, setSort] = useState<Sort | null>(null);
  const toast = useToast();

  const all = state.expected;
  const rows = state.rows;
  const done = Object.keys(rows).length;
  const total = state.count ?? all.length;
  const running = status === 'open';
  const found = Object.values(rows).filter((r) => r.ok).length;
  const soon = Object.values(rows).filter((r) => r.expiresInDays !== undefined && r.expiresInDays < 30).length;
  const failed = Object.values(rows).filter((r) => !r.ok && !r.notFound).length;
  const ordered = sort
    ? [...all].sort((a, b) => {
        const x = sortValue(rows[a], sort.key, a);
        const y = sortValue(rows[b], sort.key, b);
        return (x < y ? -1 : x > y ? 1 : 0) * (sort.dir === 'asc' ? 1 : -1);
      })
    : all;
  const shownRows = ordered.map((d) => rows[d]).filter((r): r is WhoisRow => !!r);
  const toggleSort = (k: SortKey) => setSort((s) => (s?.key === k ? (s.dir === 'asc' ? { key: k, dir: 'desc' } : null) : { key: k, dir: 'asc' }));
  const base = `check-whois-${new Date().toISOString().slice(0, 10)}`;
  const save = (kind: 'excel' | 'standard' | 'json') => {
    if (kind === 'json') download(`${base}.json`, toJson(shownRows), 'application/json');
    else download(`${base}${kind === 'standard' ? '-virgules' : ''}.csv`, toCsv(shownRows, kind), 'text/csv;charset=utf-8');
    toast(kind === 'json' ? t('Fichier JSON enregistré') : t('Fichier CSV enregistré'));
  };
  const ignored = [...invalid.map((v) => ({ value: v, reason: t('ce n’est pas un nom de domaine') })), ...state.invalid];

  return (
    <div className="wh-page page-stack">
      <header className={`verdict verdict--${running ? 'pending' : soon ? 'bad' : failed ? 'watch' : 'good'}`}>
        <div className="verdict__main">
          <div className="verdict__mood">
            {running ? <RotateCw aria-hidden className="spin" /> : <ScrollText aria-hidden />}
            {running ? t('Mesure en cours') : t('Whois de la liste')}
          </div>
          <h1 className="verdict__subject">{plural(total, 'domaine', 'domaines')}</h1>
          <p className="verdict__sentence">
            {running
              ? t('Registre puis bureau d’enregistrement de chaque domaine, au rythme que chaque serveur supporte : {done} sur {total}.', { done, total })
              : soon
                ? tn(soon, '{n} domaine expire dans moins de 30 jours ou est déjà expiré.', '{n} domaines expirent dans moins de 30 jours ou sont déjà expirés.')
                : failed
                  ? tn(failed, '{n} registre n’a pas répondu : relancez la mesure dans quelques minutes pour ce domaine.', '{n} registres n’ont pas répondu : relancez la mesure dans quelques minutes pour ces domaines.')
                  : t('Les {total} domaines sont mesurés.', { total })}
          </p>
          <dl className="verdict__facts">
            <div>
              <dt>{t('Mesurés')}</dt>
              <dd>{t('{done} sur {total}', { done, total })}</dd>
            </div>
            <div>
              <dt>{t('Enregistrés')}</dt>
              <dd>{done ? found : '…'}</dd>
            </div>
            {soon > 0 && (
              <div>
                <dt>{t('Expirent sous 30 jours')}</dt>
                <dd>{soon}</dd>
              </div>
            )}
          </dl>
          <div className="verdict__actions">
            <button type="button" className="btn btn--sm" onClick={restart} disabled={running}>
              <RotateCw aria-hidden />
              {t('Mesurer à nouveau')}
            </button>
            <button type="button" className="btn btn--sm btn--primary" disabled={!done} onClick={() => save('excel')}>
              <Download aria-hidden />
              {t('Exporter pour Excel')}
            </button>
            <button type="button" className="btn btn--sm" disabled={!done} onClick={() => save('standard')}>
              {t('CSV virgules')}
            </button>
            <button type="button" className="btn btn--sm" disabled={!done} onClick={() => save('json')}>
              JSON
            </button>
            <ShareButton />
          </div>
        </div>
      </header>

      {error && (
        <Notice tone="error" title={done ? t('Mesure incomplète') : t('Mesure impossible')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={restart}>
            {t('Relancer')}
          </button>
        </Notice>
      )}
      {dropped.length > 0 && (
        <Notice tone="warn" title={t('{n} domaines au-delà de {max} non mesurés', { n: dropped.length, max: BATCH_MAX })}>
          {rich('Une liste compte {max} domaines au plus, pour ne pas surcharger les serveurs des registres. Mesurez les suivants dans une seconde liste, à partir de <m>{first}</m>.', { max: BATCH_MAX, first: dropped[0] }, { m: (c) => <span className="mono">{c}</span> })}
        </Notice>
      )}
      {(ignored.length > 0 || state.duplicates > 0) && (
        <Notice tone="info" title={t('Saisies écartées')}>
          {state.duplicates > 0 && <p>{tn(state.duplicates, '{n} doublon retiré (même domaine enregistré).', '{n} doublons retirés (même domaine enregistré).')}</p>}
          {ignored.length > 0 && (
            <ul className="wh-ignored">
              {ignored.map((v, i) => (
                <li key={v.value + i}>
                  <span className="mono">{v.value}</span> : {v.reason}
                </li>
              ))}
            </ul>
          )}
        </Notice>
      )}

      <section className="block" aria-labelledby="wh-tb-t">
        <h2 className="block__title" id="wh-tb-t">
          {t('Domaines')}
        </h2>
        <div className="wh-tb-wrap surface" tabIndex={0} role="region" aria-labelledby="wh-tb-t">
          <table className="wh-tb">
            <thead>
              <tr>
                {COLS.map((c) => {
                  const active = !!c.key && sort?.key === c.key;
                  const Icon = !active ? ChevronsUpDown : sort!.dir === 'asc' ? ArrowUp : ArrowDown;
                  return (
                    <th key={c.label} className={c.cls} scope="col" aria-sort={c.key ? (active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}>
                      {c.key ? (
                        <button type="button" onClick={() => toggleSort(c.key!)}>
                          {t(c.label)}
                          <Icon aria-hidden className={active ? undefined : 'wh-sort-idle'} />
                        </button>
                      ) : (
                        t(c.label)
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {ordered.map((d) => (
                <Row key={d} domain={d} r={rows[d]} />
              ))}
            </tbody>
          </table>
        </div>
        <p className="field__hint">
          {t('Chaque serveur reçoit une requête à la fois, une par seconde en RDAP, une toutes les trois secondes en WHOIS : une longue liste chez un même registre prend donc quelques minutes. Une réponse reste gardée 10 minutes. La date d’expiration est celle du registre ; les écarts avec le bureau d’enregistrement sont détaillés sur la page de chaque domaine.')}
        </p>
      </section>
    </div>
  );
}
