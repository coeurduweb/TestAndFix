// Fix loop (2026-11-12): test, fix, then see the fix land. While the page stays open, the records that
// decide the domain's email are read from the authoritative servers every 15 s (a light fingerprint);
// the full scan runs again only when they change, then the page shows what is fixed, what is new, the
// score before and after, and until when resolvers may keep the previous value (its TTL).
import { ArrowRight, CircleCheck, CircleX, Eye, RefreshCw, Square } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { get } from '../../lib/api';
import { fmtScore } from '../../lib/format';
import { locale, t, tn } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';

export interface WatchedRecord {
  name: string;
  type: string;
  rcode: string;
  values: string[];
  ttl: number | null;
}
export interface Fingerprint {
  domain: string;
  at: string;
  hash: string;
  serial: number | null;
  complete: boolean;
  records: WatchedRecord[];
}

const POLL_MS = 15_000;

/** A TTL in words: 45 s, 5 min, 1 h 30 min, 2 d. */
export function fmtTtl(s: number): string {
  if (s < 120) return tn(s, '{n} seconde', '{n} secondes');
  if (s < 3600) return tn(Math.round(s / 60), '{n} minute', '{n} minutes');
  if (s < 2 * 86400) return tn(Math.round(s / 3600), '{n} heure', '{n} heures');
  return tn(Math.round(s / 86400), '{n} jour', '{n} jours');
}
const MAX_WATCH_MS = 30 * 60_000;

type Phase = 'idle' | 'starting' | 'watching' | 'rescanning' | 'changed' | 'timeout' | 'error';
interface Lost {
  title: string;
  penalty: number;
}
interface Baseline {
  result: CheckResult;
  lost: Map<string, Lost>;
  fp?: Fingerprint;
  startedAt: number;
}

// keyed by id and title: one situation can apply several times (five DKIM keys of 1024 bits)
const lostOf = (r: CheckResult) => new Map(r.findings.filter((f) => f.penalty > 0).map((f) => [`${f.id}|${f.title}`, { title: f.title, penalty: f.penalty }]));

/** Records whose values or status differ, with the TTL a resolver may still hold the previous answer for. */
export function changedRecords(before: Fingerprint, after: Fingerprint): { name: string; type: string; heldFor: number | null }[] {
  const soaMin = (() => {
    try {
      return Number((JSON.parse(before.records.find((r) => r.type === 'SOA')?.values[0] ?? '{}') as { minttl?: number }).minttl ?? NaN);
    } catch {
      return NaN;
    }
  })();
  return after.records
    .filter((r) => r.type !== 'SOA')
    .flatMap((r) => {
      const old = before.records.find((o) => o.name === r.name && o.type === r.type);
      if (!old || (old.rcode === r.rcode && old.values.join('\n') === r.values.join('\n'))) return [];
      // a value that did not exist was cached as an absence, for the zone's negative TTL (RFC 2308)
      const heldFor = old.values.length ? old.ttl : Number.isFinite(soaMin) ? soaMin : null;
      return [{ name: r.name, type: r.type, heldFor }];
    });
}

export function FixLoop({ domain, result, selectors, done, restart }: { domain: string; result?: CheckResult; selectors: string[]; done: boolean; restart: () => void }) {
  const [phase, setPhase] = useState<Phase>('idle');
  const [lastRead, setLastRead] = useState<number>();
  const [polls, setPolls] = useState(0);
  const [now, setNow] = useState(Date.now());
  const [changes, setChanges] = useState<{ name: string; type: string; heldFor: number | null }[]>([]);
  const [detectedAt, setDetectedAt] = useState<number>();
  const base = useRef<Baseline | undefined>(undefined);
  const url = `/api/domain/${encodeURIComponent(domain)}/fingerprint${selectors.length ? `?selectors=${encodeURIComponent(selectors.join(','))}` : ''}`;

  const start = () => {
    if (!result) return;
    base.current = { result, lost: lostOf(result), startedAt: Date.now() };
    setChanges([]);
    setPhase('starting');
    get<Fingerprint>(url)
      .then((fp) => {
        if (base.current) base.current.fp = fp;
        setLastRead(Date.now());
        setPhase('watching');
      })
      .catch(() => setPhase('error'));
  };

  // one read of the authoritative servers every 15 s while watching
  useEffect(() => {
    if (phase !== 'watching') return;
    const id = setTimeout(async () => {
      const b = base.current;
      if (!b) return;
      if (Date.now() - b.startedAt > MAX_WATCH_MS) return setPhase('timeout');
      try {
        const fp = await get<Fingerprint>(url);
        setLastRead(Date.now());
        if (fp.complete && b.fp?.complete && fp.hash !== b.fp.hash) {
          setChanges(changedRecords(b.fp, fp));
          setDetectedAt(Date.now());
          b.fp = fp;
          setPhase('rescanning');
          restart();
          return;
        }
        if (fp.complete && !b.fp?.complete) b.fp = fp;
      } catch {
        /* a missed read: the next one decides */
      }
      setPolls((n) => n + 1);
    }, POLL_MS);
    return () => clearTimeout(id);
  }, [phase, polls, url, restart]);

  useEffect(() => {
    if (phase !== 'watching') return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [phase]);

  // the new measurement has arrived
  useEffect(() => {
    if (phase === 'rescanning' && done && result && result !== base.current?.result) setPhase('changed');
  }, [phase, done, result]);

  if (!result && phase === 'idle') return null;

  if (phase === 'idle') {
    return (
      <section className="surface fix-loop fix-loop--idle" aria-labelledby="fix-loop-t">
        <div className="fix-loop__lead">
          <h2 id="fix-loop-t" className="fix-loop__title">
            {t('Vous publiez une correction ?')}
          </h2>
          <p className="fix-loop__text">{t('TestAndFix relit les serveurs qui font autorité toutes les 15 secondes et refait la mesure dès que la zone change : vous voyez ce qui est corrigé, et quand le monde entier le verra.')}</p>
        </div>
        <button type="button" className="btn btn--primary" onClick={start}>
          <Eye aria-hidden /> {t('Surveiller ma correction')}
        </button>
      </section>
    );
  }

  if (phase === 'starting' || phase === 'watching') {
    const ago = lastRead ? Math.max(0, Math.round((now - lastRead) / 1000)) : undefined;
    return (
      <section className="surface fix-loop fix-loop--live" aria-live="polite" aria-labelledby="fix-loop-t">
        <span className="fix-loop__pulse" aria-hidden />
        <div className="fix-loop__lead">
          <h2 id="fix-loop-t" className="fix-loop__title">
            {t('Surveillance de {domain}', { domain })}
          </h2>
          <p className="fix-loop__text">
            {ago === undefined ? t('Première lecture des serveurs qui font autorité…') : t('Serveurs qui font autorité relus il y a {s} s : aucun changement pour l’instant.', { s: ago })}{' '}
            <span className="muted">{t('Une lecture toutes les 15 secondes, pendant 30 minutes au plus.')}</span>
          </p>
        </div>
        <button type="button" className="btn" onClick={() => setPhase('idle')}>
          <Square aria-hidden /> {t('Arrêter')}
        </button>
      </section>
    );
  }

  if (phase === 'rescanning') {
    return (
      <section className="surface fix-loop fix-loop--live" aria-live="polite">
        <span className="fix-loop__pulse" aria-hidden />
        <div className="fix-loop__lead">
          <h2 className="fix-loop__title">{t('La zone a changé : nouvelle mesure en cours')}</h2>
          <p className="fix-loop__text mono">{changes.map((c) => `${c.type} ${c.name}`).join(' · ')}</p>
        </div>
      </section>
    );
  }

  if (phase === 'timeout' || phase === 'error') {
    return (
      <section className="surface fix-loop" aria-live="polite">
        <div className="fix-loop__lead">
          <h2 className="fix-loop__title">{phase === 'timeout' ? t('Aucun changement en 30 minutes') : t('Surveillance impossible')}</h2>
          <p className="fix-loop__text">
            {phase === 'timeout'
              ? t('Les serveurs qui font autorité servent toujours les mêmes enregistrements. Vérifiez que la correction est publiée chez l’hébergeur DNS du domaine (celui de ses serveurs NS).')
              : t('Les serveurs qui font autorité n’ont pas pu être lus. Réessayez dans un instant.')}
          </p>
        </div>
        <button type="button" className="btn" onClick={start}>
          <RefreshCw aria-hidden /> {t('Surveiller à nouveau')}
        </button>
      </section>
    );
  }

  // changed: what the fix did
  const b = base.current!;
  const after = lostOf(result!);
  const fixed = [...b.lost].filter(([id]) => !after.has(id)).map(([, l]) => l);
  const added = [...after].filter(([id]) => !b.lost.has(id)).map(([, l]) => l);
  const still = [...after.keys()].filter((id) => b.lost.has(id)).length;
  const fmtTime = (ms: number) => new Date(ms).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' });
  return (
    <section className="surface fix-loop fix-loop--done" aria-live="polite" aria-labelledby="fix-loop-t">
      <div className="fix-loop__lead">
        <h2 id="fix-loop-t" className="fix-loop__title">
          {fixed.length ? tn(fixed.length, '{n} point corrigé', '{n} points corrigés') : t('La zone a changé, sans point corrigé')}
          {b.result.score !== undefined && result?.score !== undefined && (
            <span className="fix-loop__score mono">
              {' '}
              {fmtScore(b.result.score)} <ArrowRight aria-label={t('puis')} /> {fmtScore(result.score)}
            </span>
          )}
        </h2>
        <ul className="fix-loop__list">
          {fixed.map((f) => (
            <li key={f.title} className="fix-loop__item fix-loop__item--ok">
              <CircleCheck aria-hidden /> {f.title}
            </li>
          ))}
          {added.map((f) => (
            <li key={f.title} className="fix-loop__item fix-loop__item--new">
              <CircleX aria-hidden /> {t('Nouveau : {title}', { title: f.title })}
            </li>
          ))}
        </ul>
        {still > 0 && <p className="fix-loop__text">{tn(still, 'Encore {n} point à corriger, plus bas.', 'Encore {n} points à corriger, plus bas.')}</p>}
        {changes.map((c) => (
          <p key={`${c.type} ${c.name}`} className="fix-loop__text">
            <span className="mono">
              {c.type} {c.name}
            </span>{' '}
            :{' '}
            {c.heldFor !== null && detectedAt
              ? t('les résolveurs qui avaient l’ancienne réponse en mémoire la gardent {held} au plus, jusque vers {time}.', { held: fmtTtl(c.heldFor), time: fmtTime(detectedAt + c.heldFor * 1000) })
              : t('la durée pendant laquelle les résolveurs gardent l’ancienne réponse est inconnue.')}{' '}
            <Link to={`/propagation/${encodeURIComponent(c.name)}?type=${encodeURIComponent(c.type)}`}>{t('Suivre la propagation')}</Link>
          </p>
        ))}
      </div>
      <button type="button" className="btn" onClick={start}>
        <Eye aria-hidden /> {t('Continuer à surveiller')}
      </button>
    </section>
  );
}
