// "Mon carnet": what this browser holds on the server (its notebook, visible only from this browser
// and the devices linked to it), the linked devices, linking a new one by code or QR code, and
// erasing the traces. Asked on 2026-11-11: put forward, reassuring, short. Every destructive action
// asks in place (no browser dialog: forbidden in this project's tooling). A code (typed, or opened
// as /carnet?code=XXXX-XXXX from a link or a QR code) first shows the devices of the notebook it
// joins; linking takes a click, and moving the data held here a second, explicit choice (JoinFlow).
// The head is neutral: green, amber and red are kept for measured results (UI-SIGNAL.md).
import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import QRCode from 'qrcode';
import { BookLock, Eraser, Link2, Monitor, QrCode, ShieldAlert, Smartphone } from 'lucide-react';
import { Verdict } from '../../components/Verdict';
import { CopyButton, Field, Notice, Skel, SubmitButton } from '../../components/ui';
import { ApiError } from '../../lib/api';
import {
  clearLocalTraces, countsText, detachDevice, eraseNotebook, getMe, isCode, linkWithCode, makeLinkCode, normalizeCode, previewLink, total,
  type Counts, type Device, type LinkCode, type LinkPreview, type Me,
} from '../../lib/carnet';
import { fmtInt, fmtRelative, plural } from '../../lib/format';
import { locale, rich, t, tn } from '../../lib/i18n';
import { errorMessage } from '../../lib/useCheck';

import './carnet.css';

const fmtDay = (iso: string) => new Date(iso).toLocaleDateString(locale(), { day: 'numeric', month: 'long', year: 'numeric' });
const MONO = { m: (c: ReactNode) => <span className="mono">{c}</span> };
const B = { b: (c: ReactNode) => <strong>{c}</strong> };
const isPhone = (label: string | null) => !!label && /iphone|ipad|android|mobile|téléphone|tablette/i.test(label);

function useNow(ms = 1000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return now;
}

function linkError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 429) {
      const s = (e.body as { retryAfter?: number } | null)?.retryAfter;
      return t("Trop d'essais. Réessayez dans {wait}.", { wait: s ? plural(s, 'seconde', 'secondes') : t('une minute') });
    }
    if (e.status === 400 || e.code === 'invalid_or_expired_code') return t('Ce code est inconnu ou a expiré. Demandez un nouveau code sur l’autre appareil.');
  }
  return errorMessage(e);
}

/* ---------- head ---------- */

function Head({ me, onLink }: { me: Me; onLink: () => void }) {
  const others = me.devices.filter((d) => !d.current).length;
  const n = total(me.counts);
  return (
    <Verdict
      tone="neutral"
      icon={BookLock}
      mood={t('Privé')}
      subject={others ? t('Seuls ce navigateur et vos appareils reliés voient ce carnet.') : t('Seul ce navigateur voit ce carnet.')}
      sentence={
        n
          ? t('Il garde {counts}. Chaque élément s’efface seul au bout de {days} jours.', { counts: countsText(me.counts), days: me.retentionDays })
          : t('Il est vide pour l’instant. Ce que vous mesurez ici y entre, et s’efface seul au bout de {days} jours.', { days: me.retentionDays })
      }
      facts={[
        ...(me.oldest ? [{ label: t('Plus ancienne donnée'), value: fmtDay(me.oldest) }] : []),
        { label: t('Appareils'), value: fmtInt(me.devices.length) },
      ]}
      actions={
        <>
          <button type="button" className="btn btn--primary" onClick={onLink}>
            <QrCode aria-hidden />
            {t('Relier un appareil')}
          </button>
          <a className="btn" href="#effacer">
            <Eraser aria-hidden />
            {t('Effacer mes traces')}
          </a>
        </>
      }
    />
  );
}

function HeadSkeleton() {
  return (
    <header className="verdict verdict--pending" aria-busy="true" aria-label={t('Lecture du carnet')}>
      <div className="verdict__main">
        <Skel w="10ch" />
        <h1 className="verdict__subject">
          <Skel w="22ch" />
        </h1>
        <Skel w="44ch" />
      </div>
    </header>
  );
}

/* ---------- devices ---------- */

function Devices({ me, onChanged }: { me: Me; onChanged: (detachedCurrent: boolean) => void }) {
  const [asking, setAsking] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (asking) cancelRef.current?.focus();
  }, [asking]);
  const alone = me.devices.length === 1;
  const detach = async (d: Device) => {
    setBusy(true);
    setErr(null);
    try {
      await detachDevice(d.id);
      setAsking(null);
      onChanged(!!d.current);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const devices = [...me.devices].sort((a, b) => Number(!!b.current) - Number(!!a.current) || Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt));
  return (
    <section className="surface cn-card" aria-labelledby="cn-dev-t">
      <h2 className="block__title" id="cn-dev-t">
        {t('Appareils reliés')} <span className="block__count block__count--neutral">{fmtInt(me.devices.length)}</span>
      </h2>
      <ul className="cn-devices">
        {devices.map((d) => {
          const Icon = isPhone(d.label) ? Smartphone : Monitor;
          const open = asking === d.id;
          return (
            <li key={d.id} className="cn-dev" data-asking={open || undefined}>
              <div className="cn-dev__row">
                <Icon aria-hidden className="cn-dev__icon" />
                <span className="cn-dev__main">
                  <span className="cn-dev__name">
                    {d.label || t('Appareil sans nom')}
                    {d.current && <span className="tag tag--lab">{t('Ce navigateur')}</span>}
                  </span>
                  <span className="cn-dev__sub">
                    {t('{seen} · relié le {date}', { seen: d.current ? t('en ce moment') : t('vu {when}', { when: fmtRelative(d.lastSeenAt) }), date: fmtDay(d.createdAt) })}
                  </span>
                </span>
                {!open && (
                  <button type="button" className="btn btn--sm btn--ghost" onClick={() => (setErr(null), setAsking(d.id))} aria-label={d.label ? t('Détacher {name}', { name: d.label }) : t('Détacher cet appareil')}>
                    {t('Détacher')}
                  </button>
                )}
              </div>
              {open && (
                <div className="cn-ask" role="group" aria-label={t('Confirmer le détachement')}>
                  <p>
                    {d.current && alone ? (
                      total(me.counts)
                        ? rich('<b>C’est le seul appareil de ce carnet.</b> Le détacher efface ses données ({counts}) : ce navigateur repart avec un carnet vide.', { counts: countsText(me.counts) }, B)
                        : rich('<b>C’est le seul appareil de ce carnet.</b> Le détacher efface ses données : ce navigateur repart avec un carnet vide.', undefined, B)
                    ) : d.current ? (
                      t('Ce navigateur quitte le carnet et repart avec un carnet vide. Vos autres appareils le gardent.')
                    ) : (
                      t('Cet appareil ne verra plus ce carnet. Les données restent ici.')
                    )}
                  </p>
                  <div className="cn-ask__btns">
                    <button type="button" className="btn btn--sm btn--danger" disabled={busy} onClick={() => detach(d)}>
                      {d.current && alone ? t('Détacher et effacer') : t('Détacher')}
                    </button>
                    <button type="button" ref={cancelRef} className="btn btn--sm btn--ghost" disabled={busy} onClick={() => setAsking(null)}>
                      {t('Annuler')}
                    </button>
                  </div>
                  {err && <p className="field__error" role="alert">{err}</p>}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/* ---------- linking ---------- */

function QrImage({ url }: { url: string }) {
  const [svg, setSvg] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    QRCode.toString(url, { type: 'svg', margin: 0, errorCorrectionLevel: 'M', color: { dark: '#000000ff', light: '#00000000' } })
      .then((s) => alive && setSvg(s))
      .catch(() => alive && setSvg(null));
    return () => {
      alive = false;
    };
  }, [url]);
  return (
    <div className="cn-qr" role="img" aria-label={t('Code QR qui ouvre la page de liaison sur l’autre appareil')}>
      {svg ? <div className="cn-qr__svg" dangerouslySetInnerHTML={{ __html: svg }} /> : <Skel w="100%" />}
    </div>
  );
}

function CodeShown({ code, onCancel, onRenew }: { code: LinkCode; onCancel: () => void; onRenew: () => void }) {
  const now = useNow(1000);
  const left = Math.max(0, Math.round((Date.parse(code.expiresAt) - now) / 1000));
  const url = `${window.location.origin}/carnet?code=${encodeURIComponent(code.code)}`;
  if (!left)
    return (
      <div className="cn-code cn-code--expired">
        <p>
          {rich('Le code <m>{code}</m> a expiré sans servir.', { code: code.code }, MONO)}
        </p>
        <div className="cn-ask__btns">
          <button type="button" className="btn btn--primary" onClick={onRenew}>
            <QrCode aria-hidden />
            {t('Nouveau code')}
          </button>
          <button type="button" className="btn btn--ghost" onClick={onCancel}>
            {t('Fermer')}
          </button>
        </div>
      </div>
    );
  return (
    <div className="cn-code">
      <QrImage url={url} />
      <div className="cn-code__side">
        <p className="cn-code__label">{t('Sur l’autre appareil, scannez ce code, ou ouvrez Mon carnet et tapez :')}</p>
        <code className="cn-code__value" aria-label={t('Code de liaison : {code}', { code: code.code.split('').join(' ') })}>
          {code.code}
        </code>
        <p className="cn-code__left">
          <span className="visually-hidden">{t('Valable 5 minutes, une seule fois.')}</span>
          <span className="live" aria-hidden>
            {t('expire dans {time}', { time: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` })}
          </span>
          <span className="cn-code__once" aria-hidden> · {t('une seule fois')}</span>
        </p>
        <div className="cn-ask__btns">
          <CopyButton text={url} label={t('Copier le lien')} what={t('Lien de liaison copié')} />
          <button type="button" className="btn btn--sm btn--ghost" onClick={onCancel}>
            Annuler
          </button>
        </div>
      </div>
    </div>
  );
}

type LinkState = { kind: 'idle' } | { kind: 'busy' } | { kind: 'code'; code: LinkCode } | { kind: 'joined'; labels: string[] } | { kind: 'error'; text: string };

function LinkCard({
  me,
  ask,
  onLinked,
  onSeen,
}: {
  me: Me;
  /** bumped by the verdict button: show a code */
  ask: number;
  onLinked: (moved: Counts) => void;
  onSeen: (m: Me) => void;
}) {
  const [st, setSt] = useState<LinkState>({ kind: 'idle' });
  const [typed, setTyped] = useState('');
  const [joinErr, setJoinErr] = useState<string | null>(null);
  /** the typed code, once checked: its preview replaces the field */
  const [checking, setChecking] = useState<string | null>(null);
  const cardRef = useRef<HTMLElement>(null);
  const known = useRef(new Set(me.devices.map((d) => d.id)));

  const show = useCallback(async () => {
    setSt({ kind: 'busy' });
    known.current = new Set(me.devices.map((d) => d.id));
    try {
      setSt({ kind: 'code', code: await makeLinkCode() });
    } catch (e) {
      setSt({ kind: 'error', text: errorMessage(e) });
    }
  }, [me.devices]);

  useEffect(() => {
    if (!ask) return;
    cardRef.current?.scrollIntoView({ behavior: window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    show();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ask]);

  // while a code is shown, watch for the other device: the code card turns into "relié"
  const showing = st.kind === 'code' ? st.code : null;
  useEffect(() => {
    if (!showing) return;
    const timer = setInterval(async () => {
      if (Date.parse(showing.expiresAt) < Date.now()) return;
      try {
        const m = await getMe();
        const fresh = m.devices.filter((d) => !known.current.has(d.id));
        if (fresh.length) {
          setSt({ kind: 'joined', labels: fresh.map((d) => d.label || t('Appareil sans nom')) });
          onSeen(m);
        }
      } catch {
        /* the next tick will tell */
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [showing, onSeen]);

  const join = (e: FormEvent) => {
    e.preventDefault();
    const code = normalizeCode(typed);
    if (!isCode(code)) return setJoinErr(t('Un code a cette forme : ABCD-EFGH (huit lettres ou chiffres).'));
    setJoinErr(null);
    setChecking(code);
  };

  return (
    <section className="surface cn-card" id="relier" aria-labelledby="cn-link-t" ref={cardRef}>
      <h2 className="block__title" id="cn-link-t">
        {t('Relier un appareil')}
      </h2>
      <p className="cn-note">{t('Votre téléphone ou un autre ordinateur verra alors ce carnet, et tout ce que vous y ferez. Il vous montrera d’abord les appareils déjà reliés.')}</p>
      {st.kind === 'code' ? (
        <CodeShown code={st.code} onCancel={() => setSt({ kind: 'idle' })} onRenew={show} />
      ) : st.kind === 'joined' ? (
        <div className="cn-done" role="status">
          <span className="dot dot--ok" aria-hidden />
          <span>
            {st.labels.length > 1 ? rich('<b>{names}</b> sont reliés à ce carnet.', { names: st.labels.join(', ') }, B) : rich('<b>{names}</b> est relié à ce carnet.', { names: st.labels.join(', ') }, B)}
          </span>
        </div>
      ) : (
        <div className="cn-ask__btns">
          <button type="button" className="btn" onClick={show} aria-busy={st.kind === 'busy' || undefined} disabled={st.kind === 'busy'}>
            <QrCode aria-hidden />
            {t('Afficher un code')}
          </button>
          {st.kind === 'error' && <span className="field__error" role="alert">{st.text}</span>}
        </div>
      )}
      {checking ? (
        <div className="cn-join cn-join--flow">
          <JoinFlow
            code={checking}
            level={3}
            onLinked={(moved) => {
              setChecking(null);
              setTyped('');
              onLinked(moved);
            }}
            onCancel={() => setChecking(null)}
          />
        </div>
      ) : (
        <form className="cn-join" onSubmit={join} noValidate>
          <Field label={t('Vous avez reçu un code ?')} hint={t('Vous verrez d’abord à quels appareils il relie ce navigateur.')} error={joinErr}>
            {(id, d) => (
              <input
                id={id}
                aria-describedby={d}
                aria-invalid={joinErr ? true : undefined}
                className="input input--mono cn-join__input"
                value={typed}
                placeholder="ABCD-EFGH"
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                inputMode="text"
                maxLength={12}
                onChange={(e) => setTyped(normalizeCode(e.target.value))}
              />
            )}
          </Field>
          <SubmitButton disabled={!typed}>{t('Continuer')}</SubmitButton>
        </form>
      )}
    </section>
  );
}

/**
 * Joining the notebook of another device, from a typed code or /carnet?code=… (link, QR code).
 * Security review of 2026-11-11: a code sent by someone else would let them read everything this
 * browser does afterwards, and before that review its data moved over in one click. So the preview
 * (POST /api/me/link/preview, which does not use the code) shows the devices of that notebook
 * first, and data held here moves only on a second, explicit choice. Never link on opening a URL.
 */
function JoinFlow({ code, level = 2, onLinked, onCancel }: { code: string; level?: 2 | 3; onLinked: (moved: Counts) => void; onCancel: () => void }) {
  const [p, setP] = useState<LinkPreview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<null | 'link' | 'merge' | 'erase'>(null);
  useEffect(() => {
    let alive = true;
    setP(null);
    setErr(null);
    previewLink(code).then(
      (r) => alive && setP(r),
      (e) => alive && setErr(linkError(e)),
    );
    return () => {
      alive = false;
    };
  }, [code]);

  const go = async (how: 'link' | 'merge' | 'erase') => {
    setBusy(how);
    setErr(null);
    try {
      if (how === 'erase') {
        await eraseNotebook('data');
        clearLocalTraces();
      }
      onLinked((await linkWithCode(code, how === 'merge')).moved);
    } catch (e) {
      // data arrived since the preview: ask again, with what would move now
      if (e instanceof ApiError && e.status === 409 && e.code === 'confirm_merge') {
        const joining = (e.body as { joining?: Counts } | null)?.joining;
        if (joining && p) setP({ ...p, joining });
      } else setErr(linkError(e));
    } finally {
      setBusy(null);
    }
  };

  const H = level === 2 ? 'h2' : 'h3';
  const tid = useId();
  const held = p ? total(p.joining) : 0;
  return (
    <section className={`cn-flow${level === 2 ? ' surface cn-flow--top' : ''}`} aria-labelledby={tid} aria-busy={!p && !err ? true : undefined}>
      <H className="block__title" id={tid}>
        {t('Rejoindre le carnet de ces appareils ?')}
      </H>
      {!p && !err && (
        <div className="stack-sm">
          <Skel w="24ch" />
          <Skel w="40ch" />
        </div>
      )}
      {err && !p && (
        <>
          <p className="field__error" role="alert">{err}</p>
          <div className="cn-ask__btns">
            <button type="button" className="btn btn--ghost" onClick={onCancel}>
              {t('Fermer')}
            </button>
          </div>
        </>
      )}
      {p && (
        <>
          <p className="cn-note">
            {p.devices.length > 1
              ? rich('Le code <m>{code}</m> ouvre un carnet relié à {n} appareils :', { code, n: p.devices.length }, MONO)
              : rich('Le code <m>{code}</m> ouvre un carnet relié à cet appareil :', { code }, MONO)}
          </p>
          <ul className="cn-devices cn-flow__devices">
            {p.devices.map((d, i) => {
              const Icon = isPhone(d.label) ? Smartphone : Monitor;
              return (
                <li key={i} className="cn-dev">
                  <div className="cn-dev__row">
                    <Icon aria-hidden className="cn-dev__icon" />
                    <span className="cn-dev__main">
                      <span className="cn-dev__name">{d.label || 'Appareil sans nom'}</span>
                      <span className="cn-dev__sub">{t('vu {when}', { when: fmtRelative(d.lastSeenAt) })}</span>
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
          <p className="cn-flow__says">
            {p.devices.length > 1
              ? t('Ce navigateur rejoindra ce carnet : ces appareils verront tout ce que vous ferez ici à partir de maintenant.')
              : t('Ce navigateur rejoindra ce carnet : cet appareil verra tout ce que vous ferez ici à partir de maintenant.')}
          </p>
          {held > 0 && (
            <p className="cn-flow__says">
              {p.devices.length > 1
                ? t('Ce navigateur garde déjà {counts}. Si vous les versez dans ce carnet, ces appareils les verront aussi.', { counts: countsText(p.joining) })
                : t('Ce navigateur garde déjà {counts}. Si vous les versez dans ce carnet, cet appareil les verra aussi.', { counts: countsText(p.joining) })}
            </p>
          )}
          <p className="cn-flow__warn">
            <ShieldAlert aria-hidden />
            {t('Ne reliez que vos propres appareils : quelqu’un qui vous envoie un code peut lire tout ce que vous faites ensuite.')}
          </p>
          <div className="cn-ask__btns">
            {held > 0 ? (
              <>
                <button type="button" className="btn" disabled={!!busy} aria-busy={busy === 'merge' || undefined} onClick={() => go('merge')}>
                  {t('Relier et y verser mes données')}
                </button>
                <button type="button" className="btn" disabled={!!busy} aria-busy={busy === 'erase' || undefined} onClick={() => go('erase')}>
                  {t('Effacer mes données puis relier')}
                </button>
              </>
            ) : (
              <button type="button" className="btn btn--primary" disabled={!!busy} aria-busy={busy === 'link' || undefined} onClick={() => go('link')}>
                <Link2 aria-hidden />
                {t('Relier ce navigateur')}
              </button>
            )}
            <button type="button" className="btn btn--ghost" disabled={!!busy} onClick={onCancel}>
              {t('Annuler')}
            </button>
          </div>
          {err && <p className="field__error" role="alert">{err}</p>}
        </>
      )}
    </section>
  );
}

/* ---------- erasing ---------- */

type Scope = 'data' | 'all';
type Erased = { scope: Scope; erased: Counts; local: number };

function EraseCard({ me, onErased }: { me: Me; onErased: (r: Erased) => void }) {
  const [asking, setAsking] = useState<Scope | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (asking) cancelRef.current?.focus();
  }, [asking]);
  const others = me.devices.filter((d) => !d.current).length;
  const what = countsText(me.counts, '');
  const erase = async (scope: Scope) => {
    setBusy(true);
    setErr(null);
    try {
      const r = await eraseNotebook(scope);
      const local = clearLocalTraces();
      setAsking(null);
      onErased({ scope, erased: r.erased, local });
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const confirmText = (scope: Scope) => {
    const gone = what ? tn(total(me.counts), '{what} disparaît', '{what} disparaissent', { what: `${what[0].toUpperCase()}${what.slice(1)}` }) : '';
    if (scope === 'data')
      return gone
        ? others
          ? t('{gone} pour ce navigateur et vos appareils reliés, avec ce que ce navigateur retient.', { gone })
          : t('{gone}, avec ce que ce navigateur retient.', { gone })
        : t('Le carnet est déjà vide : seul ce que ce navigateur retient disparaît.');
    const after = others ? t('tous les appareils sont détachés : chacun repart avec un carnet neuf') : t('ce navigateur repart avec un carnet neuf');
    return gone ? t('{gone}, et {after}.', { gone, after }) : t('Le carnet est déjà vide, et {after}.', { after });
  };
  const OPTIONS: { scope: Scope; title: string; text: string; danger?: boolean }[] = [
    {
      scope: 'data',
      title: t('Effacer mes données'),
      text: `${what ? t('Vide le carnet ({what}) et ce que ce navigateur retient.', { what }) : t('Vide le carnet et ce que ce navigateur retient.')} ${others ? t('Vos appareils restent reliés.') : t('Ce navigateur garde son carnet, vide.')}`,
    },
    {
      scope: 'all',
      title: t('Tout effacer, appareils compris'),
      text: others ? t('Vide le carnet et oublie les {n} appareils : chacun repart avec un carnet neuf.', { n: others + 1 }) : t('Vide le carnet et oublie ce navigateur, qui repart avec un carnet neuf.'),
      danger: true,
    },
  ];
  return (
    <section className="surface cn-card" id="effacer" aria-labelledby="cn-erase-t">
      <h2 className="block__title" id="cn-erase-t">
        {t('Effacer mes traces')}
      </h2>
      <ul className="cn-opts">
        {OPTIONS.map((o) => (
          <li key={o.scope} className="cn-opt" data-asking={asking === o.scope || undefined}>
            <div className="cn-opt__row">
              <span className="cn-opt__main">
                <span className="cn-opt__title">{o.title}</span>
                <span className="cn-opt__text">{o.text}</span>
              </span>
              {asking !== o.scope && (
                <button type="button" className={`btn btn--sm${o.danger ? ' btn--danger' : ''}`} disabled={!!asking && asking !== o.scope} onClick={() => (setErr(null), setAsking(o.scope))}>
                  {o.title}
                </button>
              )}
            </div>
            {asking === o.scope && (
              <div className="cn-ask" role="group" aria-label={t('Confirmer : {title}', { title: o.title })}>
                <p>
                  {rich('<b>C’est définitif.</b>', undefined, B)}{' '}
                  {confirmText(o.scope)}
                </p>
                <div className="cn-ask__btns">
                  <button type="button" className="btn btn--sm btn--danger" disabled={busy} aria-busy={busy || undefined} onClick={() => erase(o.scope)}>
                    {o.scope === 'data' ? t('Effacer') : t('Tout effacer')}
                  </button>
                  <button type="button" ref={cancelRef} className="btn btn--sm btn--ghost" disabled={busy} onClick={() => setAsking(null)}>
                    {t('Annuler')}
                  </button>
                </div>
                {err && <p className="field__error" role="alert">{err}</p>}
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/* ---------- page ---------- */

export default function CarnetPage() {
  const [params, setParams] = useSearchParams();
  const urlCode = normalizeCode(params.get('code') ?? '');
  const [me, setMe] = useState<Me | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [ask, setAsk] = useState(0);
  const [news, setNews] = useState<string | null>(null);

  const reload = useCallback(() => {
    getMe().then(
      (m) => (setMe(m), setErr(null)),
      (e) => setErr(e),
    );
  }, []);
  useEffect(reload, [reload]);

  const dropCode = () =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        n.delete('code');
        return n;
      },
      { replace: true },
    );

  const linked = (moved: Counts) => {
    dropCode();
    setNews(
      total(moved)
        ? tn(total(moved), 'Ce navigateur est relié. {counts} de ce navigateur a rejoint le carnet.', 'Ce navigateur est relié. {counts} de ce navigateur ont rejoint le carnet.', { counts: countsText(moved) })
        : t('Ce navigateur est relié. Il n’avait rien à y apporter.'),
    );
    reload();
  };
  const onSeen = useCallback((m: Me) => setMe(m), []);

  if (err && !me)
    return (
      <div className="cn">
        <header className="page-head">
          <h1 className="page-head__title">{t('Mon carnet')}</h1>
        </header>
        <Notice tone="error" title={t('Carnet illisible')}>
          {errorMessage(err)}{' '}
          <button type="button" className="btn btn--sm" onClick={reload}>
            {t('Réessayer')}
          </button>
        </Notice>
      </div>
    );

  return (
    <div className="cn">
      {urlCode && isCode(urlCode) && <JoinFlow code={urlCode} onLinked={linked} onCancel={dropCode} />}
      {news && (
        <div className="cn-done surface cn-news" role="status">
          <span className="dot dot--ok" aria-hidden />
          <span>{news}</span>
          <button type="button" className="btn btn--sm btn--ghost" onClick={() => setNews(null)}>
            {t('Fermer')}
          </button>
        </div>
      )}
      {me ? <Head me={me} onLink={() => setAsk((n) => n + 1)} /> : <HeadSkeleton />}
      {me && (
        <>
          <div className="cn-grid">
            <Devices
              me={me}
              onChanged={(current) => {
                if (current) {
                  clearLocalTraces();
                  setNews(t('Ce navigateur est détaché : il repart avec un carnet vide.'));
                }
                reload();
              }}
            />
            <LinkCard me={me} ask={ask} onLinked={linked} onSeen={onSeen} />
          </div>
          <EraseCard
            me={me}
            onErased={(r) => {
              const server = countsText(r.erased, '');
              const local = r.local ? plural(r.local, 'élément retenu par ce navigateur', 'éléments retenus par ce navigateur') : '';
              const parts = [server, local].filter(Boolean);
              setNews(
                `${parts.length > 1 ? t('Effacé : {a}, et {b}.', { a: parts[0], b: parts[1] }) : parts.length ? t('Effacé : {a}.', { a: parts[0] }) : t('Il n’y avait rien à effacer.')}${r.scope === 'all' ? ` ${t('Ce navigateur repart avec un carnet neuf, sans appareil relié.')}` : ''}`,
              );
              window.scrollTo({ top: 0 });
              reload();
            }}
          />
          <p className="cn-limits">
            {rich('<b>Ce que le carnet ne couvre pas.</b> Le mot de passe du site est le même pour tout le monde. Effacer vos cookies ou ouvrir une fenêtre privée donne un carnet vide. Un lien de partage s’ouvre par toute personne qui a le mot de passe, jusqu’à ce que vous l’arrêtiez.', undefined, B)}
          </p>
        </>
      )}
    </div>
  );
}
