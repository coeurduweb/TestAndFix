// The chain, large (v2 « Clair et direct »): one card per hop, the status very big in its colour
// with a plain label (« 301, définitive »), an arrow between the steps saying how the next one is
// reached, the time on the right. Clicking a step opens it in place with its tabs.
import { useEffect, useState } from 'react';
import { ArrowDown, ChevronDown, CircleX } from 'lucide-react';
import { Skel } from '../../components/ui';
import { fmtMs } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import { HopDetail } from './HopDetail';
import { IconCopy } from './IconCopy';
import { KIND_LABEL, meaningOf, reasonOf, toneOf, type Hop } from './model';
import { Url } from './Url';

/** « 301, définitive », « 200, la page répond », « Erreur réseau ». */
export function plainStatus(hop: Hop): { code: string; label: string; detail?: string } {
  const ex = hop.exchange;
  if (ex.status === undefined) return ex.error?.code === 'UNSAFE_TARGET' ? { code: t('Refus'), label: t('adresse privée refusée') } : { code: t('Erreur'), label: t('pas de réponse') };
  const s = ex.status;
  const meaning = meaningOf(s);
  let label = meaning || (s >= 200 && s < 300 ? t('la page répond') : '');
  if (hop.redirect && hop.redirect.kind !== 'http') label = hop.redirect.delay !== undefined ? t('puis {kind} après {delay} s', { kind: t(KIND_LABEL[hop.redirect.kind]), delay: hop.redirect.delay }) : t('puis {kind}', { kind: t(KIND_LABEL[hop.redirect.kind]) });
  return { code: String(s), label, detail: reasonOf(s, ex.statusText) };
}

function Step({ hop, open, onToggle, last }: { hop: Hop; open: boolean; onToggle: () => void; last: boolean }) {
  const ex = hop.exchange;
  const st = plainStatus(hop);
  const tone = ex.status === undefined ? 'out' : toneOf(ex.status);
  const id = `rd-step-${hop.index}`;
  return (
    <li className={`rd-step rd-step--${tone} ${open ? 'rd-step--open' : ''} ${last ? 'rd-step--last' : ''}`}>
      <div className="rd-step__card">
        <div className="rd-step__row">
          <button type="button" className="rd-step__toggle" aria-expanded={open} aria-controls={open ? id : undefined} onClick={onToggle}>
            <span className={`dot rd-step__dot ${tone === 'ok' ? 'dot--ok' : tone === 'out' ? 'dot--out' : ''}`} aria-hidden />
            <span className="rd-step__status">
              <span className="rd-step__code">{st.code}</span>
              <span className="rd-step__label">
                {st.label && <strong>{st.label}</strong>}
                {st.detail && <span className="rd-step__reason">{st.detail}</span>}
              </span>
            </span>
            <span className="rd-step__body">
              <span className="rd-step__url">
                <Url href={hop.url} />
              </span>
              <span className="rd-step__meta">
                <span className="visually-hidden">{t('Étape {n}, ', { n: hop.index })}</span>
                {hop.method}
                {ex.ip && <> · {ex.ip}</>}
                {ex.httpVersion && <> · HTTP/{ex.httpVersion}</>}
                {ex.tls?.protocol && <> · {ex.tls.protocol}</>}
              </span>
              {ex.status === undefined && ex.error && (
                <span className="rd-step__error">
                  <CircleX aria-hidden />
                  {ex.error.message}
                </span>
              )}
            </span>
            <span className="rd-step__time">
              {fmtMs(ex.timings.total)}
              <ChevronDown aria-hidden className="rd-step__chev" />
              <span className="visually-hidden">{open ? t('Masquer le détail') : t('Voir en-têtes, corps, temps et certificat')}</span>
            </span>
          </button>
          <IconCopy text={hop.url} label={t('Copier l’URL de l’étape {n}', { n: hop.index })} what={t('URL copiée')} />
        </div>
        {open && (
          <div id={id} className="rd-step__detail">
            <HopDetail hop={hop} />
          </div>
        )}
      </div>
      {hop.redirect && (
        <div className="rd-arrow">
          <ArrowDown aria-hidden className="rd-arrow__icon" />
          <span className="rd-arrow__text">
            <span className="visually-hidden">{t('Redirige, par ')}</span>
            <span className="rd-arrow__how">{hop.redirect.kind === 'http' ? 'Location' : t(KIND_LABEL[hop.redirect.kind])}</span>
            <code>
              <Url href={hop.redirect.kind === 'js' ? hop.redirect.to : hop.redirect.raw} />
            </code>
          </span>
        </div>
      )}
      {hop.jsSeen && !hop.redirect && (
        <p className="rd-arrow rd-arrow--note">
          {rich('Script repéré dans la page, non suivi (la page a son propre contenu) : <c>{url}</c>', { url: hop.jsSeen.url }, { c: (x) => <code>{x}</code> })}
        </p>
      )}
    </li>
  );
}

export function HopList({ hops, running, autoOpen }: { hops: Hop[]; running: boolean; autoOpen?: number }) {
  const [open, setOpen] = useState<Set<number>>(new Set());
  useEffect(() => {
    if (autoOpen !== undefined) setOpen(new Set([autoOpen]));
  }, [autoOpen]);
  const toggle = (i: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });
  return (
    <ol className="rd-steps" aria-label={t('Chaîne de redirections, étape par étape')}>
      {hops.map((h, i) => (
        <Step key={h.index} hop={h} open={open.has(h.index)} onToggle={() => toggle(h.index)} last={!running && i === hops.length - 1} />
      ))}
      {running && (
        <li className="rd-step rd-step--pending" aria-label={t('Étape en cours de mesure')}>
          <div className="rd-step__card">
            <div className="rd-step__row">
              <span className="rd-step__toggle">
                <span className="dot dot--pending rd-step__dot" aria-hidden />
                <span className="rd-step__status">
                  <Skel w="4ch" />
                </span>
                <span className="rd-step__body">
                  <Skel w="60%" />
                  <Skel w="30%" />
                </span>
                <span className="rd-step__time">
                  <Skel w="5ch" />
                </span>
              </span>
            </div>
          </div>
        </li>
      )}
    </ol>
  );
}
