// Comparison of the current message with another one: the score before and now, then what was
// fixed, what appeared and what changed, as short lists read at a glance (Signal: one surface, a
// lit dot per line, the delta in mono).
import { Link } from 'react-router';
import { ArrowRight, X } from 'lucide-react';
import { Notice, Skel } from '../../components/ui';
import { fmtDateTime, fmtPenalty, fmtScore, plural } from '../../lib/format';
import { t } from '../../lib/i18n';
import { errorMessage, useCheck } from '../../lib/useCheck';
import type { CompareResult } from './types';

const byCost = <T extends { penalty: number }>(l: T[]) => [...l].sort((a, b) => b.penalty - a.penalty);

export function CompareSection({ currentId, otherId, closeTo }: { currentId: string; otherId: string; closeTo: string }) {
  const { data: c, error, loading } = useCheck<CompareResult>(`/api/mail/compare?a=${encodeURIComponent(otherId)}&b=${encodeURIComponent(currentId)}`);
  const close = (
    <Link to={closeTo} replace className="btn btn--sm">
      <X aria-hidden />
      {t('Fermer la comparaison')}
    </Link>
  );
  if (error)
    return (
      <div className="stack-sm mr-compare-err">
        <Notice tone="error" title={t('Comparaison impossible')}>
          {(error as { code?: string }).code === 'report_not_ready' ? t('Un des deux messages n’a pas encore de compte rendu : attendez la fin de son analyse.') : errorMessage(error)}
        </Notice>
        <div>{close}</div>
      </div>
    );
  if (loading || !c)
    return (
      <section className="surface mr-compare" aria-busy="true">
        <Skel w="30%" />
        <Skel w="60%" />
      </section>
    );
  const d = c.scoreDelta;
  const fixed = byCost(c.removed.filter((f) => f.penalty > 0));
  const added = byCost(c.added.filter((f) => f.penalty > 0));
  const free = [...c.added, ...c.removed].filter((f) => f.penalty <= 0);
  return (
    <section className="surface mr-compare" id="s-compare" aria-labelledby="compare-t">
      <div className="mr-compare__head">
        <h2 id="compare-t">{t('Par rapport au message du {date}', { date: fmtDateTime(c.a.receivedAt) })}</h2>
        {close}
      </div>
      <div className="mr-compare__scores">
        <span className="mr-compare__score">{fmtScore(c.a.score)}</span>
        <ArrowRight aria-hidden />
        <span className="mr-compare__score mr-compare__score--now">{fmtScore(c.b.score)}</span>
        <span className={`mr-compare__delta ${d > 0 ? 'is-up' : d < 0 ? 'is-down' : ''}`}>
          {d > 0 ? t(d >= 2 ? '+{d} points' : '+{d} point', { d: fmtScore(d) }) : d < 0 ? t(d <= -2 ? '{d} points' : '{d} point', { d: fmtScore(d) }) : t('note inchangée')}
        </span>
      </div>
      <p className="mr-compare__ref">
        {t('Avant :')} <Link to={`/mail/message/${c.a.id}`}>{c.a.subject ?? c.a.from ?? c.a.id}</Link>
        {c.unchanged.length > 0 && ` · ${plural(c.unchanged.length, 'anomalie inchangée', 'anomalies inchangées')}`}
      </p>
      {!c.sameSender && <Notice tone="warn">{t('Les deux messages ne viennent pas du même domaine : les écarts mêlent deux configurations.')}</Notice>}
      <div className="mr-compare__lists">
        {fixed.length > 0 && (
          <div>
            <h3>{t('Corrigé depuis')}</h3>
            <ul className="mr-delta">
              {fixed.map((f) => (
                <li key={f.id}>
                  <span className="dot dot--ok" aria-hidden />
                  <span>{f.title}</span>
                  <b className="is-up">+{fmtPenalty(f.penalty)}</b>
                </li>
              ))}
            </ul>
          </div>
        )}
        {(added.length > 0 || c.changed.length > 0) && (
          <div>
            <h3>{t('Nouveau ou changé')}</h3>
            <ul className="mr-delta">
              {added.map((f) => (
                <li key={f.id}>
                  <span className="dot dot--out" aria-hidden />
                  <span>{f.title}</span>
                  <b className="is-down">−{fmtPenalty(f.penalty)}</b>
                </li>
              ))}
              {c.changed.map((f) => {
                const worse = f.after.penalty > f.before.penalty;
                return (
                  <li key={f.id}>
                    <span className={`dot ${worse ? 'dot--out' : 'dot--ok'}`} aria-hidden />
                    <span>
                      {f.title} <span className="muted">({t('{before} pt, maintenant {after} pt', { before: fmtPenalty(f.before.penalty), after: fmtPenalty(f.after.penalty) })})</span>
                    </span>
                    <b className={worse ? 'is-down' : 'is-up'}>{worse ? `−${fmtPenalty(f.after.penalty - f.before.penalty)}` : `+${fmtPenalty(f.before.penalty - f.after.penalty)}`}</b>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
      {!fixed.length && !added.length && !c.changed.length && <p className="mr-compare__same">{t('Les mêmes anomalies que dans le message précédent.')}</p>}
      {free.length > 0 && <p className="mr-compare__free">{plural(free.length, 'remarque sans effet sur la note a changé', 'remarques sans effet sur la note ont changé')}.</p>}
    </section>
  );
}
