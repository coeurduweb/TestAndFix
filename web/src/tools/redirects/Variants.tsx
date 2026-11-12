// "Comparer les variantes": http/https × www/sans www, one line each read at a glance (tick or
// cross, statuses, final URL, time), then the fixes as cards with the Apache and nginx rule in view.
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { AlertTriangle, CheckCircle2, CircleX } from 'lucide-react';
import { IssueCard } from '../../components/Verdict';
import { Notice, Skel } from '../../components/ui';
import { fmtMs, fmtScore } from '../../lib/format';
import { rich, t, tn } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { shortUrl, toneOf, type VariantsData } from './model';
import { Sep } from './Sep';
import { Url } from './Url';
import { variantValues } from './values';

const mono = { m: (c: ReactNode) => <span className="mono">{c}</span> };

function conformText(n: number, language: boolean): string {
  const count = tn(n, '{n} redirection', '{n} redirections');
  return language ? t('Conforme : {count}, plus la langue', { count }) : t('Conforme : {count}', { count });
}

export function VariantsSection({ result, loading, error, expected }: { result: CheckResult<VariantsData> | null; loading: boolean; error: unknown; expected: string[] }) {
  const d = result?.data;
  // red only when the variants end on different pages; extra hops are a warning
  const severe = !!result?.findings.some((f) => f.penalty > 0 && (f.severity === 'critical' || f.severity === 'high'));
  const issues = (result?.findings ?? []).filter((f) => f.penalty > 0).sort((a, b) => b.penalty - a.penalty);
  const notes = (result?.findings ?? []).filter((f) => f.penalty <= 0);
  if (error) return <Notice tone="error" title={t('Comparaison impossible')}>{errorMessage(error)}</Notice>;
  return (
    <div className="stack" style={{ gap: 'var(--s5)' }}>
      <ul className="rd-blist">
        {loading && !d &&
          expected.map((l) => (
            <li key={l} className="rd-brow rd-brow--pending">
              <span className="rd-brow__icon"><Skel w="1.5rem" /></span>
              <span className="rd-brow__main">
                <span className="mono rd-brow__url">{l}</span>
                <Skel w="45%" />
              </span>
              <Skel w="5ch" />
            </li>
          ))}
        {d?.variants.map((v) => {
          const Icon = v.conform ? CheckCircle2 : severe || v.error ? CircleX : AlertTriangle;
          const cls = v.conform ? 'rd-brow--ok' : severe || v.error ? 'rd-brow--bad' : 'rd-brow--warn';
          return (
            <li key={v.url} className={`rd-brow ${cls}`}>
              <Link className="rd-brow__link" to={`/redirections?url=${encodeURIComponent(v.url)}`}>
                <Icon aria-label={v.conform ? t('Conforme') : t('Non conforme')} className="rd-brow__icon" />
                <span className="rd-brow__main">
                  <span className="mono rd-brow__url">{v.label}</span>
                  <span className="rd-brow__chain mono">
                    {v.hops.length
                      ? v.hops.map((h, i) => (
                          <span key={i} className={`rd-c--${toneOf(h.status)}`}>
                            {i > 0 && <Sep />}
                            {h.status ?? t('erreur')}
                          </span>
                        ))
                      : <span className="rd-c--out">{t('erreur')}</span>}
                    {!v.error && v.redirects > 0 && (
                      <span className="rd-brow__final"><Sep /><Url href={shortUrl(v.final)} /></span>
                    )}
                  </span>
                  <span className={`rd-brow__alert ${v.conform ? '' : 'rd-strong'}`}>
                    {v.error ?? (v.conform ? conformText(v.effective ?? v.redirects, v.language > 0) : v.reasons.join(', '))}
                  </span>
                </span>
                <span className="rd-brow__side">
                  <span className="mono rd-brow__ms">{fmtMs(v.ms)}</span>
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
      {d && (
        <p className="rd-varsum">
          <span>
          {d.allSame && d.conform
            ? rich('Les {n} variantes aboutissent à <m>{url}</m>, chacune en une redirection permanente au plus.', { n: d.variants.length, url: shortUrl(d.canonical ?? '') }, mono)
            : d.canonical
              ? rich('Adresse de référence : <m>{url}</m>. {count}.', { url: shortUrl(d.canonical), count: tn(d.variants.filter((v) => !v.conform).length, '{n} variante à corriger', '{n} variantes à corriger') }, mono)
              : t('Aucune variante n’aboutit à une page qui répond.')}
          </span>
          <span className="rd-varsum__note">{t('Cette comparaison a sa propre note ({score}) : elle ne change pas celle de l’URL suivie.', { score: result?.score !== undefined ? `${fmtScore(result.score)}/10` : t('non calculée') })}</span>
        </p>
      )}
      {d && issues.length > 0 && (
        <div className="issues">
          {issues.map((f, i) => (
            <IssueCard key={f.id + i} f={f} index={i} extra={<VMeasured f={f} d={d} />} />
          ))}
        </div>
      )}
      {d && notes.length > 0 && (
        <div className="issues issues--info">
          {notes.map((f, i) => (
            <IssueCard key={f.id + i} f={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function VMeasured({ f, d }: { f: Parameters<typeof variantValues>[0]; d: VariantsData }) {
  const v = variantValues(f, d);
  if (!v.measured && !v.reference) return null;
  return (
    <p className="rd-measured">
      {v.measured && <span>{rich('Mesuré <b>{value}</b>', { value: v.measured }, { b: (c) => <strong className="mono">{c}</strong> })}</span>}
      {v.reference && <span>{rich('attendu <b>{value}</b>', { value: v.reference }, { b: (c) => <strong className="mono">{c}</strong> })}</span>}
    </p>
  );
}
