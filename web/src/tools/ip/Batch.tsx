// A range (/ip/203.0.113.0%2F24) or a list (/ip?liste=a,b,c): one row per address, skeleton
// first, filled as the server answers. Major lists only (server rule). Sortable, "listées
// seulement" filter, CSV export of the rows in the order shown.
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { ArrowDown, ArrowUp, CheckCircle2, ChevronsUpDown, Download, ExternalLink, OctagonAlert, RotateCw } from 'lucide-react';
import { RerunButton, ShareButton, Unavailable } from '../../components/Report';
import { Notice, Skel, useToast } from '../../components/ui';
import { fmtScore, plural, scoreBand } from '../../lib/format';
import { msg, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import { errorMessage } from '../../lib/useCheck';
import { countryName } from '../dns/fmt';
import { batchReducer, byZone, expectedIps, initialBatch, isRange, sortRows, statusText, toCsv, type BatchRow, type Sort, type SortKey } from './model';
import { StartFailed } from './Single';
import { useSse } from './sse';

const COLS: { key: SortKey; label: string; cls: string }[] = [
  { key: 'ip', label: msg('Adresse'), cls: 'ipb-c-ip' },
  { key: 'status', label: msg('Résultat'), cls: 'ipb-c-status' },
  { key: 'major', label: msg('Listes'), cls: 'ipb-c-lists' },
  { key: 'ptr', label: msg('Reverse DNS'), cls: 'ipb-c-ptr' },
  { key: 'asn', label: msg('Réseau'), cls: 'ipb-c-asn' },
  { key: 'country', label: msg('Pays'), cls: 'ipb-c-cc' },
  { key: 'score', label: msg('Note'), cls: 'ipb-c-score' },
];

function StatusTag({ r }: { r: BatchRow }) {
  // only a listing carries colour; a clean or private row stays in light ink
  if (r.status === 'listed') return <span className="tag tag--out">{statusText(r)}</span>;
  return <span className="ipb-status-plain">{statusText(r)}</span>;
}

function Row({ ip, r }: { ip: string; r?: BatchRow }) {
  if (!r)
    return (
      <tr className="ipb-row ipb-row--pending">
        <td className="ipb-c-ip mono">{ip}</td>
        <td className="ipb-c-status"><Skel w="7ch" /></td>
        <td className="ipb-c-lists"><Skel w="12ch" /></td>
        <td className="ipb-c-ptr"><Skel w="16ch" /></td>
        <td className="ipb-c-asn"><Skel w="10ch" /></td>
        <td className="ipb-c-cc"><Skel w="4ch" /></td>
        <td className="ipb-c-score"><Skel w="3ch" /></td>
      </tr>
    );
  return (
    <tr className={`ipb-row ipb-row--${r.status}`}>
      <td className="ipb-c-ip mono">
        <Link to={`/ip/${encodeURIComponent(r.ip)}`} title={t('Compte rendu complet de cette adresse')}>
          {r.ip}
        </Link>
      </td>
      <td className="ipb-c-status">
        <StatusTag r={r} />
      </td>
      <td className="ipb-c-lists">
        {r.status === 'private' ? (
          <span className="muted">{r.range}</span>
        ) : r.listed.length ? (
          <span className="ipb-lists">
            {byZone(r.listed).map((l, i) => (
              <span key={l.zone + i} className="ipb-listing">
                <strong>{l.name}</strong>
                <span className="mono ipb-code">
                  {l.codes.join(', ')}
                  {l.meaning ? ` ${l.meaning}` : ''}
                </span>
                {l.delistUrl && (
                  <a className="ipx-ext" href={l.delistUrl} target="_blank" rel="noreferrer noopener" aria-label={t('Page de retrait de {name}', { name: l.name })}>
                    {t('retrait')}
                    <ExternalLink aria-hidden />
                  </a>
                )}
              </span>
            ))}
          </span>
        ) : (
          <span className="muted">
            {t('aucune')}
            {r.refused.length > 0 && <> · {t('requête refusée par {names}', { names: r.refused.join(', ') })}</>}
            {r.errors.length > 0 && <> · {t('sans réponse de {names}', { names: r.errors.join(', ') })}</>}
          </span>
        )}
      </td>
      <td className="ipb-c-ptr mono">
        {r.ptr ? (
          <>
            {r.ptr}
            {r.fcrdns === false && <span className="tag tag--warn ipb-fcr">{t('non confirmé')}</span>}
          </>
        ) : r.status === 'private' ? null : (
          <span className="ipb-noptr" title={t('Aucun reverse DNS : voir le compte rendu de l’adresse')}>{t('aucun')}</span>
        )}
      </td>
      <td className="ipb-c-asn">
        {r.asn ? (
          <>
            <span className="mono">AS{r.asn}</span> <span className="muted">{r.asName}</span>
          </>
        ) : null}
      </td>
      <td className="ipb-c-cc" title={r.country ? countryName(r.country) : undefined}>
        {r.country}
      </td>
      <td className="ipb-c-score mono" data-band={r.score !== undefined ? scoreBand(r.score) : undefined}>
        {r.score !== undefined ? fmtScore(r.score) : ''}
      </td>
    </tr>
  );
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function BatchIp({ items, invalidInput = [] }: { items: string[]; invalidInput?: string[] }) {
  const key = items.join(',');
  const single = items.length === 1 && isRange(items[0]) ? items[0] : null;
  const req = useMemo(
    () => (single ? { url: `/api/ip/${single.split('/').map(encodeURIComponent).join('/')}/stream` } : { url: '/api/ip/batch/stream', method: 'POST' as const, json: { ips: items } }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key],
  );
  const expected = useMemo(() => expectedIps(items), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  const { state, status, error, restart } = useSse(req, key, batchReducer, initialBatch(expected));
  const [sort, setSort] = useState<Sort | null>(null);
  const [onlyListed, setOnlyListed] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (single) pushRecent({ value: single, path: `/ip/${encodeURIComponent(single)}`, label: msg('Plage IP') });
  }, [single]);

  const all = [...state.expected, ...state.extra];
  const rows = state.rows;
  const done = Object.keys(rows).length;
  const total = state.count ?? all.length;
  const listed = Object.values(rows).filter((r) => r.status === 'listed').length;
  const priv = Object.values(rows).filter((r) => r.status === 'private').length;
  const running = status === 'open';
  const r = state.result;
  const ordered = sort ? sortRows(all, rows, sort) : all;
  const shown = onlyListed ? ordered.filter((ip) => rows[ip]?.status === 'listed') : ordered;
  const subject = single ?? (items.length <= 3 ? items.join(', ') : `${plural(total, 'adresse', 'adresses')}`);
  const invalid = [...invalidInput.map((v) => ({ value: v, reason: t('ce n’est ni une adresse IP ni une plage de /24 à /32') })), ...state.invalid];

  const toggleSort = (k: SortKey) =>
    setSort((s) => (s?.key === k ? (s.dir === 'asc' ? { key: k, dir: 'desc' } : null) : { key: k, dir: k === 'major' || k === 'status' ? 'desc' : 'asc' }));

  if (error && state.count === undefined && !r) return <StartFailed value={items.join('\n')} error={error} onRetry={restart} />;

  return (
    <div className="ipx-page page-stack">
      <header className={`verdict verdict--${!done || running && !r ? (listed ? 'bad' : 'pending') : listed ? 'bad' : 'good'}`}>
        <div className="verdict__main">
          <div className="verdict__mood">
            {running && !r ? <RotateCw aria-hidden className="spin" /> : listed ? <OctagonAlert aria-hidden /> : <CheckCircle2 aria-hidden />}
            {running && !r ? t('Mesure en cours') : listed ? t('À corriger') : t('Excellent')}
          </div>
          <h1 className="verdict__subject mono">{subject}</h1>
          <p className="verdict__sentence">
            {!done
              ? tn(total, '{n} adresse interrogée sur les listes noires majeures, les lignes arrivent au fur et à mesure.', '{n} adresses interrogées sur les listes noires majeures, les lignes arrivent au fur et à mesure.')
              : listed
                ? tn(listed, '{n} adresse est inscrite sur une liste noire majeure. Ouvrez chacune pour la procédure de retrait.', '{n} adresses sont inscrites sur une liste noire majeure. Ouvrez chacune pour la procédure de retrait.')
                : running
                  ? t('Aucune adresse listée pour l’instant ({done} sur {total}).', { done, total })
                  : t('Aucune des {n} adresses publiques n’est sur les listes majeures.', { n: total - priv })}
          </p>
          <dl className="verdict__facts">
            <div>
              <dt>{t('Listées')}</dt>
              <dd>{done ? listed : '…'}</dd>
            </div>
            <div>
              <dt>{t('Mesurées')}</dt>
              <dd>{t('{done} sur {total}', { done, total })}</dd>
            </div>
            {priv > 0 && (
              <div>
                <dt>{t('Non publiques')}</dt>
                <dd>{priv}</dd>
              </div>
            )}
            {state.lists.length > 0 && (
              <div>
                <dt>{t('Listes')}</dt>
                <dd>{state.lists.map((l) => l.name).join(', ')}</dd>
              </div>
            )}
          </dl>
          <div className="verdict__actions">
            <RerunButton onClick={restart} busy={running} />
            <button
              type="button"
              className="btn btn--sm"
              disabled={!done}
              onClick={() => {
                download(`check-ip-${(single ?? 'liste').replace(/[^0-9a-z.]+/gi, '_')}.csv`, toCsv(shown, rows));
                toast(t('Fichier CSV enregistré'));
              }}
            >
              <Download aria-hidden />
              {t('Exporter en CSV')}
            </button>
            <ShareButton />
          </div>
        </div>
        <div className="verdict__score">
          <div className="verdict__number" aria-label={t('{listed} adresses listées sur {total}', { listed, total })}>
            {done ? listed : '…'}
            <small>/{total}</small>
          </div>
          <p className="ipb-score-label">{listed > 1 ? t('adresses listées') : t('adresse listée')}</p>
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
      {invalid.length > 0 && (
        <Notice tone="warn" title={invalid.length > 1 ? t('{n} saisies ignorées', { n: invalid.length }) : t('Une saisie ignorée')}>
          <ul className="ipb-invalid">
            {invalid.map((v, i) => (
              <li key={v.value + i}>
                <span className="mono">{v.value}</span> : {v.reason}
              </li>
            ))}
          </ul>
        </Notice>
      )}

      <section className="block" aria-labelledby="ipb-t">
        <div className="ipb-head">
          <h2 className="block__title" id="ipb-t">
            {t('Adresses')}
            {listed > 0 && <span className="block__count">{listed}</span>}
          </h2>
          <div className="ipb-tools">
            <button type="button" className="chip" aria-pressed={onlyListed} onClick={() => setOnlyListed((v) => !v)} disabled={!listed && !onlyListed}>
              {t('Listées seulement')}{listed ? ` (${listed})` : ''}
            </button>
          </div>
        </div>
        <div className="ipb-wrap">
          <table className="ipb-table">
            <thead>
              <tr>
                {COLS.map((c) => {
                  const active = sort?.key === c.key;
                  const Icon = !active ? ChevronsUpDown : sort!.dir === 'asc' ? ArrowUp : ArrowDown;
                  return (
                    <th key={c.key} className={c.cls} scope="col" aria-sort={active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                      <button type="button" onClick={() => toggleSort(c.key)}>
                        {t(c.label)}
                        <Icon aria-hidden className={active ? undefined : 'ipb-sort-idle'} />
                      </button>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {shown.map((ip) => (
                <Row key={ip} ip={ip} r={rows[ip]} />
              ))}
            </tbody>
          </table>
          {onlyListed && !shown.length && <p className="muted ipb-none">{t('Aucune adresse listée.')}</p>}
        </div>
      </section>
      <Unavailable items={(r?.unavailable ?? []).filter((u) => u.reason)} />
    </div>
  );
}
