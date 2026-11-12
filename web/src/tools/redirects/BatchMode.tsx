// List mode (US-072): one URL per line, up to 100, traced 6 at a time; sortable table,
// filter by final status, CSV export. Rows fill in as each batch of 6 returns.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { AlertTriangle, ArrowDown, ArrowUp, CheckCircle2, CircleX, Download } from 'lucide-react';
import { ReportHeader, RerunButton, ShareButton } from '../../components/Report';
import { Notice, Skel } from '../../components/ui';
import { post } from '../../lib/api';
import { fmtDateTime, fmtMs, fmtScore, plural } from '../../lib/format';
import { msg, t, tn } from '../../lib/i18n';
import { errorMessage } from '../../lib/useCheck';
import { OptionsLine } from './OptionsBar';
import { Sep } from './Sep';
import { Url } from './Url';
import { csvCell, shortUrl, toneOf, uaLabel, type BatchRow, type TraceOptions } from './model';

const CHUNK = 6;
type SortKey = 'input' | 'redirects' | 'finalStatus' | 'final' | 'ms' | 'score';
type Filter = 'all' | '2' | '3' | '4' | '5' | 'err' | 'alert';
const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: msg('Toutes') },
  { id: '2', label: '2xx' },
  { id: '3', label: '3xx' },
  { id: '4', label: '4xx' },
  { id: '5', label: '5xx' },
  { id: 'err', label: msg('Erreurs') },
  { id: 'alert', label: msg('Avec alerte') },
];

const match = (r: BatchRow, f: Filter) =>
  f === 'all' ? true : f === 'err' ? !!r.error || r.finalStatus === undefined : f === 'alert' ? r.alerts > 0 : String(r.finalStatus ?? '').startsWith(f);

export function BatchMode({ urls, options, onOptions }: { urls: string[]; options: TraceOptions; onOptions: (o: TraceOptions) => void }) {
  const [rows, setRows] = useState<(BatchRow | null)[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [nonce, setNonce] = useState(0);
  const [measuredAt, setMeasuredAt] = useState<string>('');
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 } | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const alive = useRef(0);
  const list = useMemo(() => urls.slice(0, 100), [urls]);

  useEffect(() => {
    const run = ++alive.current;
    setRows(list.map(() => null));
    setError(null);
    (async () => {
      for (let i = 0; i < list.length; i += CHUNK) {
        if (alive.current !== run) return;
        try {
          const r = await post<{ rows: BatchRow[]; measuredAt: string }>('/api/redirects/batch', {
            urls: list.slice(i, i + CHUNK),
            ua: options.ua === 'custom' ? options.uaText : options.ua,
            method: options.method,
          });
          if (alive.current !== run) return;
          setMeasuredAt(r.measuredAt);
          setRows((prev) => prev.map((x, j) => (j >= i && j < i + CHUNK ? r.rows[j - i] : x)));
        } catch (e) {
          if (alive.current === run) setError(e);
          return;
        }
      }
    })();
    return () => {
      alive.current++;
    };
  }, [list, options.ua, options.uaText, options.method, nonce]);

  const done = rows.filter(Boolean) as BatchRow[];
  const running = done.length < list.length && !error;
  const shown = useMemo(() => {
    const idx = rows.map((r, i) => ({ r, i })).filter(({ r }) => (r ? match(r, filter) : filter === 'all'));
    if (!sort) return idx;
    return [...idx].sort((a, b) => {
      if (!a.r || !b.r) return a.r ? -1 : 1;
      const x = a.r[sort.key] ?? '';
      const y = b.r[sort.key] ?? '';
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * sort.dir;
    });
  }, [rows, sort, filter]);
  const counts = useMemo(() => Object.fromEntries(FILTERS.map((f) => [f.id, done.filter((r) => match(r, f.id)).length])), [done]);

  const exportCsv = () => {
    const head = [t('URL de départ'), t('Sauts'), t('Statuts'), t('Statut final'), t('URL finale'), t('Temps (ms)'), t('Note'), t('Alerte'), t('Erreur')];
    const lines = done.map((r) => [r.input, r.redirects, r.statuses.join(' > '), r.finalStatus, r.final, r.ms, r.score, r.alert, r.error].map(csvCell).join(';'));
    const blob = new Blob(['﻿' + [head.join(';'), ...lines].join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `redirections-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  const SORTS: { key: SortKey | null; label: string }[] = [
    { key: null, label: t('Ordre saisi') },
    { key: 'score', label: t('Note') },
    { key: 'redirects', label: t('Sauts') },
    { key: 'ms', label: t('Temps') },
    { key: 'finalStatus', label: t('Statut final') },
  ];
  const pickSort = (key: SortKey | null) => setSort((s) => (key === null ? null : s?.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === 'score' ? 1 : -1 }));

  const withAlert = done.filter((r) => r.alerts > 0 || r.error).length;
  // the band needs a score to take its colour: the mean of the URLs that could be scored
  const scored = done.filter((r) => r.score !== undefined);
  const mean = scored.length ? Math.round((scored.reduce((n, r) => n + r.score!, 0) / scored.length) * 10) / 10 : undefined;
  return (
    <div className="rd-result">
      <ReportHeader
        subject={plural(list.length, 'URL suivie', 'URL suivies')}
        score={running ? null : mean}
        pending={running}
        findings={[]}
        passed={[]}
        sentence={
          running
            ? t('Mesure en cours : {done} sur {total}, six à la fois.', { done: done.length, total: list.length })
            : withAlert
              ? t('{n} URL à revoir sur {total}. Cliquez une ligne pour voir sa chaîne et ses corrections.', { n: withAlert, total: list.length })
              : t('Les {n} URL aboutissent sans anomalie.', { n: list.length })
        }
        meta={[
          { label: t('Avancement'), value: `${done.length}/${list.length}` },
          { label: t('Sans alerte'), value: done.length - withAlert },
          { label: t('À revoir'), value: withAlert },
          ...(mean !== undefined && !running ? [{ label: t('Note moyenne'), value: `${fmtScore(mean)}/10` }] : []),
          ...(measuredAt ? [{ label: t('Mesuré le'), value: fmtDateTime(measuredAt) }] : []),
        ]}
        actions={
          <>
            <RerunButton onClick={() => setNonce((n) => n + 1)} busy={running} />
            <button type="button" className="btn btn--sm" onClick={exportCsv} disabled={!done.length}>
              <Download aria-hidden />
              {t('Exporter en CSV')}
            </button>
            <ShareButton />
          </>
        }
      />
      <OptionsLine options={options} onChange={onOptions} withMethod={false} />
      {urls.length > 100 && <Notice tone="warn" title={t('Liste coupée')}>{t('Seules les 100 premières URL sont suivies ({n} collées).', { n: urls.length })}</Notice>}
      {error ? <Notice tone="error" title={t('Le lot s’est arrêté')}>{errorMessage(error)}</Notice> : null}

      <section className="block" aria-labelledby="list-t">
        <h2 className="block__title" id="list-t">
          {t('Résultats')}
          <span className="block__count block__count--neutral">{list.length}</span>
        </h2>
        <div className="rd-listbar">
          <div className="chips" role="group" aria-label={t('Filtrer par statut final')}>
            {FILTERS.map((f) => (
              <button key={f.id} type="button" className="chip" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {t(f.label)} <span className="mono rd-chipn">{f.id === 'all' ? list.length : counts[f.id]}</span>
              </button>
            ))}
          </div>
          <div className="chips" role="group" aria-label={t('Trier')}>
            {SORTS.map((o) => (
              <button key={o.label} type="button" className="chip" aria-pressed={(sort?.key ?? null) === o.key} onClick={() => pickSort(o.key)}>
                {o.label}
                {sort?.key === o.key && o.key !== null && (sort.dir === 1 ? <ArrowUp aria-label={t('croissant')} /> : <ArrowDown aria-label={t('décroissant')} />)}
              </button>
            ))}
          </div>
        </div>
        <ul className="rd-blist">
          {shown.map(({ r, i }) => {
            if (!r)
              return (
                <li key={i} className="rd-brow rd-brow--pending">
                  <span className="rd-brow__icon"><Skel w="1.5rem" /></span>
                  <span className="rd-brow__main">
                    <span className="mono rd-brow__url">{shortUrl(list[i])}</span>
                    <Skel w="40%" />
                  </span>
                  <Skel w="4ch" />
                </li>
              );
            const bad = !!r.error || r.finalStatus === undefined || r.finalStatus >= 400;
            const warn = !bad && r.alerts > 0;
            const Icon = bad ? CircleX : warn ? AlertTriangle : CheckCircle2;
            return (
              <li key={i} className={`rd-brow ${bad ? 'rd-brow--bad' : warn ? 'rd-brow--warn' : 'rd-brow--ok'}`}>
                <Link className="rd-brow__link" to={`/redirections?url=${encodeURIComponent(r.start ?? r.input)}`}>
                  <Icon aria-label={bad ? t('Erreur') : warn ? t('À revoir') : t('Sans alerte')} className="rd-brow__icon" />
                  <span className="rd-brow__main">
                    <span className="mono rd-brow__url"><Url href={shortUrl(r.input)} /></span>
                    <span className="rd-brow__chain mono">
                      {r.statuses.map((st, j) => (
                        <span key={j} className={`rd-c--${toneOf(st)}`}>
                          {j > 0 && <Sep />}
                          {st}
                        </span>
                      ))}
                      {r.final && r.finalStatus !== undefined && r.redirects > 0 && (
                        <span className="rd-brow__final"><Sep /><Url href={shortUrl(r.final)} /></span>
                      )}
                    </span>
                    <span className={`rd-brow__alert ${bad ? 'out-text' : ''}`}>
                      {r.error ?? r.alert ?? t('Aucune alerte')}
                      {r.alerts > 1 && !r.error ? tn(r.alerts - 1, ', et {n} autre alerte', ', et {n} autres alertes') : ''}
                    </span>
                  </span>
                  <span className="rd-brow__side">
                    {r.score !== undefined && <span className="rd-brow__score mono">{fmtScore(r.score)}</span>}
                    <span className="mono rd-brow__ms">{fmtMs(r.ms)}</span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}
