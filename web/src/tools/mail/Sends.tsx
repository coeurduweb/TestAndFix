// The sends of one test address, numbered like mail-tester's ("Envoi 1 · 6,0", "Envoi 2 · 7,4",
// "+ Nouvel envoi"), the current one marked, and beside them when this one was sent (a live
// counter), how long it took to arrive and when it was written. Asked by the user on 2026-11-11.
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Copy, Plus } from 'lucide-react';
import { copyText, useToast } from '../../components/ui';
import { fmtDateTime, fmtScore, scoreBand } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import { fmtDelay, fmtWhen, numberSends, type Timing } from './logic';
import { Pop } from './Pop';
import type { AddressInfo, MessageSummary } from './types';

/** Current time, every second for a recent send, every 30 s after an hour. */
export function useTicker(since: number | undefined): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (since === undefined) return;
    const fast = Date.now() - since < 3600_000;
    const timer = setTimeout(() => setNow(Date.now()), fast ? 1000 : 30_000);
    return () => clearTimeout(timer);
  }, [since, now]);
  return now;
}

export function expiryText(a: AddressInfo, now = Date.now()): string {
  const left = Date.parse(a.expiresAt) - now;
  if (left <= 0) return t('expirée le {date}', { date: fmtDateTime(a.expiresAt) });
  const days = Math.floor(left / 86400000);
  const hours = Math.round(left / 3600000);
  return t('valable jusqu’au {date} ({left})', { date: fmtDateTime(a.expiresAt), left: days >= 1 ? t('{n} j', { n: days }) : t('{n} h', { n: hours }) });
}

/** What "Renvoyer un test" and "Nouvel envoi" open: the address to copy, and where the next send will show. */
export function ResendPanel({ address, following, close }: { address?: AddressInfo; following: boolean; close: () => void }) {
  const toast = useToast();
  if (!address)
    return (
      <div className="mr-resend">
        <p className="mr-resend__t">{t('Adresse de test introuvable')}</p>
        <p className="mr-resend__note">{t('Créez-en une nouvelle pour envoyer un autre message.')}</p>
        <Link className="btn btn--primary" to="/mail" onClick={close}>
          {t('Nouvelle adresse de test')}
        </Link>
      </div>
    );
  const expired = address.expired || Date.parse(address.expiresAt) <= Date.now();
  return (
    <div className="mr-resend">
      <p className="mr-resend__t">{expired ? t('Cette adresse ne reçoit plus') : t('Envoyez un nouveau message à')}</p>
      <div className="mr-resend__box">
        <code className="mr-resend__addr">{address.address}</code>
        {!expired && (
          <button
            type="button"
            className="btn btn--primary btn--sm"
            aria-keyshortcuts="C"
            onClick={() =>
              copyText(address.address).then((ok) => {
                if (!ok) return;
                toast(t('Adresse copiée'));
                close();
              })
            }
          >
            <Copy aria-hidden />
            {t('Copier')}
          </button>
        )}
      </div>
      {expired ? (
        <Link className="btn btn--primary" to="/mail" onClick={close}>
          {t('Nouvelle adresse de test')}
        </Link>
      ) : following ? (
        <p className="mr-resend__note">
          <span className="live">{t('à l’écoute')}</span> {t('Le nouvel envoi s’affiche ici dès son arrivée.')}
        </p>
      ) : (
        <p className="mr-resend__note">
          <Link to={`/mail/${address.id}`} onClick={close}>
            {t('Suivre l’adresse')}
          </Link>{' '}
          {t(': la page affiche le nouvel envoi dès son arrivée.')}
        </p>
      )}
      <p className="mr-resend__meta">{expiryText(address)}</p>
    </div>
  );
}

export function SendsBar({
  current,
  messages,
  address,
  following,
  timing,
  hrefOf,
}: {
  current: MessageSummary;
  /** every message of the address (newest first or not); empty for an import */
  messages: MessageSummary[];
  address?: AddressInfo;
  /** the page follows the live stream of the address */
  following: boolean;
  timing: Timing;
  hrefOf: (id: string) => string;
}) {
  const sends = current.via === 'upload' ? [] : numberSends(messages.some((m) => m.id === current.id) ? messages : [...messages, current]);
  const mine = sends.find((s) => s.id === current.id);
  const latest = sends.length > 0 && sends[sends.length - 1].id === current.id;
  const now = useTicker(timing.sentAt);
  const where = address?.address ?? current.rcptTo[0];
  return (
    <div className="mr-sends">
      {sends.length > 0 && (
        <nav className="mr-sendtabs" aria-label={t('Envois sur cette adresse')}>
          {sends.map((s) => (
            <Link key={s.id} className="mr-send" to={hrefOf(s.id)} replace={following} aria-current={s.id === current.id ? 'true' : undefined} data-band={s.score === null ? undefined : scoreBand(s.score)}>
              {t('Envoi {n}', { n: s.n })}
              <b>{s.status === 'done' && s.score !== null ? fmtScore(s.score) : s.status === 'error' ? t('échec') : '…'}</b>
              <span className="visually-hidden">{s.score !== null ? t(' sur 10') : ''}</span>
            </Link>
          ))}
          <Pop
            label={t('Nouvel envoi')}
            className="mr-send mr-send--new"
            trigger={
              <>
                <Plus aria-hidden />
                {t('Nouvel envoi')}
              </>
            }
          >
            {(close) => <ResendPanel address={address} following={following} close={close} />}
          </Pop>
        </nav>
      )}
      <p className="mr-sendinfo">
        {current.via === 'upload' ? (
          <span>
            <b>{t('Message importé')}</b>
            {timing.importedAt !== undefined && ` ${t('le {when}', { when: fmtWhen(timing.importedAt) })}`}
          </span>
        ) : (
          <span>
            <b>{latest ? t('Dernier envoi reçu') : mine ? t('Envoi {n}', { n: mine.n }) : t('Message reçu')}</b>
            {where && (
              <>
                {' '}
                {rich('sur <m>{where}</m>', { where }, { m: (c) => <span className="mono">{c}</span> })}
              </>
            )}
          </span>
        )}
        {timing.sentAt !== undefined && (
          <span>
            {t('envoyé')}{' '}
            <time className="live" dateTime={new Date(timing.sentAt).toISOString()} title={fmtWhen(timing.sentAt)}>
              {now - timing.sentAt >= 1000 ? (
                <>
                  {rich('il y a <b>{delay}</b>', { delay: fmtDelay((now - timing.sentAt) / 1000) }, { b: (c) => <b className="mono">{c}</b> })}
                </>
              ) : (
                t('à l’instant')
              )}
            </time>
          </span>
        )}
        {timing.transitSec !== null && (
          <span>
            {rich('acheminé en <b>{delay}</b>', { delay: fmtDelay(timing.transitSec) }, { b: (c) => <b className="mono">{c}</b> })}
          </span>
        )}
        {timing.writtenAt !== undefined && <span>{t('écrit le {when}', { when: fmtWhen(timing.writtenAt) })}</span>}
      </p>
    </div>
  );
}
