// Mail test. /mail creates a test address on arrival (no click) and moves to /mail/<id>; that page
// waits for the message on a live stream and switches by itself to its report. /mail/message/<id>
// is the permalink of one report (?comparer=<id> adds the comparison with another message).
import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router';
import { Copy, MailCheck } from 'lucide-react';
import { Details } from '../../components/Verdict';
import { CodeBlock, copyText, Notice, Skel, useToast } from '../../components/ui';
import { MailPath } from '../../components/MailPath';
import { post } from '../../lib/api';
import { msg, rich, t } from '../../lib/i18n';
import { errorMessage, useCheck } from '../../lib/useCheck';
import { fmtDelay } from './logic';
import { expiryText } from './Sends';
import { MessageReport } from './MessageReport';
import type { AddressInfo, MailStatus, MessageSummary, StepState, StoredReport } from './types';
import { useMailStream, type Conn } from './useMailStream';
import type { Share } from '../../lib/carnet';
import './mail.css';

/* ---------- small hooks ---------- */

function useNow(ms = 1000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return now;
}

/** "C" copies the test address (not while typing, not with a modifier). */
function useCopyKey(text: string | undefined, onCopied: () => void) {
  useEffect(() => {
    if (!text) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'c' && e.key !== 'C') return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if ((e.target as HTMLElement)?.closest('input, textarea, select, [contenteditable="true"]')) return;
      if (window.getSelection()?.toString()) return;
      e.preventDefault();
      copyText(text).then((ok) => ok && onCopied());
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [text, onCopied]);
}

/* ---------- the waiting screen: one address, one gesture ---------- */

function useCopyAddress(a: AddressInfo | undefined) {
  const toast = useToast();
  const copied = useCallback(() => toast(t('Adresse copiée')), [toast]);
  useCopyKey(a?.address, copied);
  return () => a && copyText(a.address).then((ok) => ok && copied());
}

/** Status of reception in one sober line: only what is off is spelled out. */
function ReceptionLine({ status, conn }: { status: MailStatus | null; conn: Conn }) {
  if (!status) return <p className="mail-wait__status"><Skel w="18ch" /></p>;
  const items: { ok: boolean; text: string }[] = [
    { ok: status.smtp.listening, text: status.smtp.listening ? t('Serveur de réception prêt') : t('Serveur SMTP arrêté') },
    { ok: conn === 'open', text: conn === 'open' ? t('Page à l’écoute') : conn === 'closed' ? t('Connexion perdue, rechargez la page') : t('Reconnexion…') },
    { ok: status.spamd.reachable, text: status.spamd.reachable ? t('SpamAssassin prêt') : t('SpamAssassin injoignable : note calculée sans lui') },
    ...(status.imap.enabled ? [{ ok: status.imap.connected, text: status.imap.connected ? t('Boîte IMAP connectée') : t('Boîte IMAP déconnectée') }] : []),
  ];
  return (
    <ul className="mail-wait__status" aria-label={t('État de la réception')}>
      {items.map((it) => (
        <li key={it.text} className={it.ok ? 'is-ok' : 'is-off'}>
          <span className={`dot ${it.ok ? 'dot--ok' : 'dot--warn'}`} aria-hidden />
          {it.text}
        </li>
      ))}
    </ul>
  );
}

function LocalHelp({ address, status }: { address: AddressInfo; status: MailStatus }) {
  const local = /(^|\.)localhost$/i.test(status.domain) || /\.(test|local|invalid)$/i.test(status.domain);
  if (!local) return null;
  const host = !status.smtp.host || status.smtp.host === '0.0.0.0' || status.smtp.host === '::' ? '127.0.0.1' : status.smtp.host;
  const port = status.smtp.port ?? 25;
  return (
    <div className="mail-wait__local">
      <Details title={t('Envoyer depuis ce poste')}>
        <p className="mail-note">
          {rich('Le domaine <m>{domain}</m> n’existe que sur ce poste : un message venu de l’extérieur n’arrivera pas. Envoyez-le directement au serveur de TestAndFix :', { domain: status.domain }, { m: (c) => <span className="mono">{c}</span> })}
        </p>
        <div className="stack-sm mail-local">
          <CodeBlock code={`swaks --server ${host}:${port} --to ${address.address}`} label={t('Avec swaks')} />
          <CodeBlock code={`curl smtp://${host}:${port} --mail-from vous@exemple.fr --mail-rcpt ${address.address} --upload-file message.eml`} label={t('Avec curl et un fichier .eml')} />
        </div>
      </Details>
    </div>
  );
}

/** mail-tester's screen, done better: the address huge in the middle, Copy, and a live wait. */
function WaitScreen({ a, openedAt, status, conn }: { a?: AddressInfo; openedAt: number; status: MailStatus | null; conn: Conn }) {
  const copy = useCopyAddress(a);
  const now = useNow(1000);
  return (
    <section className="hero mail-wait" aria-labelledby="mail-wait-t">
      <span className="hero__icon">
        <MailCheck aria-hidden />
      </span>
      <h1 className="hero__title" id="mail-wait-t">
        {t('Test de mail')}
      </h1>
      <p className="hero__desc">{t(PAGE_DESC)}</p>
      <div className="hero__shell mail-wait__shell">
        <div className="mail-wait__box">
          {a ? (
            <code className="mail-wait__addr" aria-label={t('Adresse de test : {address}', { address: a.address })}>
              {/* a long domain may wrap, only before the @ (2026-11-12: a 31-character address overflowed at 1440 px) */}
              {a.address.split('@')[0]}
              <wbr />@{a.address.split('@').slice(1).join('@')}
            </code>
          ) : (
            <span className="mail-wait__addr" aria-label={t('Création de l’adresse de test')}>
              <Skel w="18ch" />
            </span>
          )}
          <button type="button" className="btn btn--primary mail-wait__copy" onClick={copy} disabled={!a} aria-keyshortcuts="C">
            <Copy aria-hidden />
            {t('Copier')}
            <kbd aria-hidden>C</kbd>
          </button>
        </div>
      </div>
      {a && (
        <>
          <p className="mail-wait__live">
            {/* the counter ticks every second: kept out of the live region, which would read it each time */}
            <span role="status">{t('En attente du message')}</span> <span className="live" aria-hidden>
              {rich('depuis <b>{delay}</b>', { delay: fmtDelay((now - openedAt) / 1000) }, { b: (c) => <b className="mono">{c}</b> })}
            </span>
          </p>
          <ReceptionLine status={status} conn={conn} />
          <p className="mail-wait__meta">
            {a.expired ? <strong className="out-text">{t('Adresse expirée : elle ne reçoit plus.')}</strong> : expiryText(a, now)} ·{' '}
            <Link to="/mail">{t('Nouvelle adresse')}</Link> · <Link to="/mail/analyse">{t('Message déjà reçu ? Analysez son .eml')}</Link>
          </p>
          {!a.expired && <MailPath className="mail-wait__path" label={t('Ce que le compte rendu contrôlera, étape par étape')} />}
          {status && <LocalHelp address={a} status={status} />}
        </>
      )}
    </section>
  );
}

const PAGE_DESC = msg('Envoyez votre message à cette adresse depuis l’outil à tester : le compte rendu s’affiche ici dès réception.');

/* ---------- pages ---------- */

let creating: Promise<AddressInfo> | null = null;

function CreateAddress() {
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let alive = true;
    // one address even when React mounts the effect twice (development)
    creating ??= post<AddressInfo>('/api/mail/addresses', {}).finally(() => setTimeout(() => (creating = null), 1000));
    creating.then(
      (a) => alive && navigate(`/mail/${a.id}`, { replace: true }),
      (e) => alive && setError(e),
    );
    return () => {
      alive = false;
    };
  }, [navigate, attempt]);
  const [openedAt] = useState(() => Date.now());
  return error ? (
    <Notice tone="error" title={t('Impossible de créer l’adresse de test')}>
      {errorMessage(error)}{' '}
      <button type="button" className="btn btn--sm" onClick={() => (setError(null), setAttempt((n) => n + 1))}>
        {t('Réessayer')}
      </button>
    </Notice>
  ) : (
    <WaitScreen openedAt={openedAt} status={null} conn="connecting" />
  );
}

function AddressPage({ id }: { id: string }) {
  const [openedAt] = useState(() => Date.now());
  const [params, setParams] = useSearchParams();
  const { data: initial, error } = useCheck<AddressInfo & { messages: MessageSummary[] }>(`/api/mail/addresses/${encodeURIComponent(id)}`);
  const { data: status } = useCheck<MailStatus>('/api/mail/status');
  const { state, conn } = useMailStream(initial ? id : null);
  const address = state.address ?? (initial ? { ...initial } : undefined);
  const messages = state.ready ? state.messages : (initial?.messages ?? []);
  const wanted = params.get('message');
  const selectedId = messages.some((m) => m.id === wanted) ? wanted! : messages[0]?.id;

  // a new message: show it
  useEffect(() => {
    if (state.arrived && state.arrived !== params.get('message')) setParams({ message: state.arrived }, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.arrived]);

  if (error) {
    const missing = (error as { status?: number }).status === 404;
    return (
      <>
        <header className="page-head">
          <div>
            <h1 className="page-head__title">{missing ? t('Adresse de test introuvable') : t('Adresse de test illisible')}</h1>
          </div>
        </header>
        <Notice tone="error" title={missing ? t('Cette adresse n’est pas dans votre carnet') : t('Lecture impossible')}>
          {missing ? `${t('Elle a été supprimée, ou elle appartient au carnet d’un autre navigateur.')} ` : `${errorMessage(error)} `}
          <Link to="/mail">{t('Créer une nouvelle adresse')}</Link>
        </Notice>
      </>
    );
  }
  if (!address || !messages.length) return <WaitScreen a={address} openedAt={openedAt} status={status} conn={conn} />;

  const sel = messages.find((m) => m.id === selectedId)!;
  return <AddressReport address={address} sel={sel} messages={messages} state={state} />;
}

/** The report of the selected send, with "C" copying the address for the next one. */
function AddressReport({ address, sel, messages, state }: { address: AddressInfo; sel: MessageSummary; messages: MessageSummary[]; state: ReturnType<typeof useMailStream>['state'] }) {
  useCopyAddress(address);
  return (
    <>
      <MessageReportLoader
        key={sel.id}
        message={sel}
        streamReport={state.reports[sel.id]}
        progress={state.progress[sel.id]}
        steps={state.steps}
        streamError={state.errors[sel.id]}
        siblings={messages}
        address={address}
      />
    </>
  );
}

/** Report from the stream when it came by it, otherwise fetched once. */
function MessageReportLoader({
  message,
  streamReport,
  progress,
  steps,
  streamError,
  siblings,
  address,
}: {
  message: MessageSummary;
  streamReport?: StoredReport;
  progress?: Record<string, StepState>;
  steps: Record<string, string>;
  streamError?: string;
  siblings: MessageSummary[];
  address?: AddressInfo;
}) {
  const need = !streamReport && (message.status === 'done' || message.status === 'error');
  const { data } = useCheck<{ report: StoredReport | null; share?: Share | null }>(need ? `/api/mail/messages/${encodeURIComponent(message.id)}` : null);
  return (
    <MessageReport message={message} report={streamReport ?? data?.report} progress={progress} steps={steps} streamError={streamError} siblings={siblings} address={address} share={data ? (data.share ?? null) : undefined} live />
  );
}

function MessagePage({ id }: { id: string }) {
  const location = useLocation();
  const pre = (location.state as { preload?: { message: MessageSummary; report: StoredReport } } | null)?.preload;
  const preloaded = pre && pre.message.id === id ? pre : undefined;
  const { data, error } = useCheck<{ message: MessageSummary; report: StoredReport | null; share?: Share | null }>(preloaded ? null : `/api/mail/messages/${encodeURIComponent(id)}`);
  const m = preloaded ?? data;
  if (error) {
    const missing = (error as { status?: number }).status === 404;
    return (
      <>
        <header className="page-head">
          <div>
            <h1 className="page-head__title">{t('Compte rendu introuvable')}</h1>
          </div>
        </header>
        <Notice tone="error" title={missing ? t('Ce compte rendu n’est pas dans votre carnet') : t('Lecture impossible')}>
          {missing ? `${t('Il a été supprimé, ou il appartient au carnet d’un autre navigateur : demandez à son auteur un lien de partage.')} ` : `${errorMessage(error)} `}
          {rich('<a>Lancer un nouveau test</a> ou <b>analyser un .eml</b>.', undefined, { a: (c) => <Link to="/mail">{c}</Link>, b: (c) => <Link to="/mail/analyse">{c}</Link> })}
        </Notice>
      </>
    );
  }
  if (!m)
    return (
      <div className="mail-report" aria-busy="true" aria-label={t('Chargement du compte rendu')}>
        <header className="verdict verdict--pending mr-verdict">
          <div className="verdict__main">
            <Skel w="12ch" />
            <Skel w="28ch" />
            <Skel w="40ch" />
          </div>
        </header>
        <div className="surface mr-skel">
          {[0, 1, 2].map((i) => (
            <div key={i}>
              <Skel w="40%" />
              <Skel w="10%" />
            </div>
          ))}
        </div>
      </div>
    );
  return <MessageReport key={id} message={m.message} report={m.report} share={data ? (data.share ?? null) : undefined} />;
}

export default function MailPage() {
  const { addressId, messageId } = useParams();
  return <div className="mail-page">{messageId ? <MessagePage id={messageId} /> : addressId ? <AddressPage id={addressId} /> : <CreateAddress />}</div>;
}

