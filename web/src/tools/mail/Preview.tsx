// The message as it arrives, full width (the user found the old preview too narrow, 2026-11-11):
// a desktop frame and a phone frame side by side, stacked on a narrow screen, in three versions
// (HTML, text only, remote images blocked). The HTML runs in a sandboxed frame without script;
// remote images load only on demand (loading them tells the sender the message was opened). Links
// that lead nowhere or that nobody can see are circled. The raw source is in the technical tabs.
import { useEffect, useMemo, useState } from 'react';
import { CopyButton, Notice, Skel } from '../../components/ui';
import { fmtBytes, plural } from '../../lib/format';
import { t, tn } from '../../lib/i18n';
import { countRemoteImages, decodeWords, markEmptyLinks, previewDocument } from './logic';
import type { MailReport } from './types';

type View = 'html' | 'text' | 'blocked';
const MAX_SOURCE = 400_000;

function TextBody({ text }: { text?: string }) {
  return <pre className="mr-mailtext">{text?.trim() ? text : t('(partie texte vide)')}</pre>;
}

export function Preview({ r, messageId }: { r: MailReport; messageId: string }) {
  const pv = r.data.preview;
  const hasHtml = !!pv?.html;
  const hasText = !!pv?.text;
  const remoteCount = useMemo(() => (pv?.html ? countRemoteImages(pv.html) : 0), [pv?.html]);
  // remote images stay blocked until asked: the default view is "Images bloquées" when there are some
  const first: View = hasHtml ? (remoteCount > 0 ? 'blocked' : 'html') : 'text';
  const [view, setView] = useState<View>(first);
  useEffect(() => setView(first), [messageId, first]);

  const marked = useMemo(() => (pv?.html ? markEmptyLinks(pv.html) : { html: '', empty: 0, invisible: 0 }), [pv?.html]);
  const doc = useMemo(() => (pv?.html ? previewDocument(marked.html, { remote: view === 'html', inline: pv.inline }) : ''), [marked.html, pv?.html, pv?.inline, view]);

  // the frame cannot be measured (sandboxed, no script): size it from the content
  const words = r.data.content?.visibleWords ?? 0;
  const imgs = r.data.content?.images ?? 0;
  const deskRem = Math.round(Math.min(44, Math.max(12, 4 + imgs * 5 + words * 0.09)));
  const phoneRem = Math.round(Math.min(40, Math.max(12, 4 + imgs * 4 + words * 0.2)));

  const views: { id: View; label: string }[] = [
    ...(hasHtml ? [{ id: 'html' as const, label: 'HTML' }] : []),
    ...(hasText ? [{ id: 'text' as const, label: t('Texte seul') }] : []),
    ...(hasHtml ? [{ id: 'blocked' as const, label: t('Images bloquées') }] : []),
  ];
  const flagged = marked.empty + marked.invisible > 0 && view !== 'text';
  const flagText = marked.empty
    ? plural(marked.empty, 'lien vide repéré', 'liens vides repérés')
    : plural(marked.invisible, 'lien invisible repéré', 'liens invisibles repérés');
  const fromName = decodeWords(r.data.message.fromName) || r.data.message.from || t('Expéditeur');
  const subject = decodeWords(r.data.message.subject)?.trim() || t('(sans objet)');
  const showText = view === 'text' || !hasHtml;

  if (!hasHtml && !hasText)
    return (
      <section className="surface mr-letter" aria-labelledby="mr-letter-t">
        <div className="mr-letter__bar">
          <h2 id="mr-letter-t">{t('Le message tel qu’il arrive')}</h2>
        </div>
        <p className="mr-letter__none">{t('Ni partie HTML ni partie texte : le message n’a rien à afficher (en-têtes seuls ?). Sa source est dans l’onglet « Source ».')}</p>
      </section>
    );

  return (
    <section className="surface mr-letter" aria-labelledby="mr-letter-t">
      <div className="mr-letter__bar">
        <h2 id="mr-letter-t">{t('Le message tel qu’il arrive')}</h2>
        {views.length > 1 && (
          <div className="segmented" role="group" aria-label={t('Version affichée')}>
            {views.map((v) => (
              <button key={v.id} type="button" aria-pressed={view === v.id} onClick={() => setView(v.id)}>
                {v.label}
              </button>
            ))}
          </div>
        )}
      </div>
      {view === 'blocked' && remoteCount > 0 && (
        <p className="mr-letter__note">
          {tn(remoteCount, '{n} image distante bloquée, comme dans une messagerie qui protège le lecteur. « HTML » la charge : l’expéditeur peut alors voir que le message a été ouvert.', '{n} images distantes bloquées, comme dans une messagerie qui protège le lecteur. « HTML » les charge : l’expéditeur peut alors voir que le message a été ouvert.')}
        </p>
      )}
      {pv?.htmlTruncated && view !== 'text' && (
        <div className="mr-letter__note">
          <Notice tone="warn">{t('HTML de plus de 1 Mo : l’aperçu est tronqué.')}</Notice>
        </div>
      )}
      <div className="mr-desk">
        <figure className="mr-frame">
          <figcaption className="mr-frame__cap">
            <span>{t('Ordinateur')}</span>
            {flagged && <span className="mr-frame__flag">{flagText}</span>}
          </figcaption>
          {showText ? (
            <div className="mr-mailbody" tabIndex={0} aria-label={t('Partie texte du message')}>
              <TextBody text={pv?.text} />
            </div>
          ) : (
            <iframe className="mr-mailframe" style={{ height: `min(75vh, ${deskRem}rem)` }} title={t('Aperçu du message sur ordinateur, sans script')} sandbox="" referrerPolicy="no-referrer" srcDoc={doc} />
          )}
        </figure>
        <figure className="mr-frame mr-frame--phone">
          <figcaption className="mr-frame__cap">
            <span>{t('Téléphone')}</span>
          </figcaption>
          <div className="mr-phone">
            <div className="mr-phone__screen">
              <div className="mr-phone__from">
                <b>{fromName}</b>
                <span>{subject}</span>
              </div>
              {showText ? (
                <div className="mr-phone__text" tabIndex={0} aria-label={t('Partie texte du message, sur téléphone')}>
                  <TextBody text={pv?.text} />
                </div>
              ) : (
                <iframe className="mr-phone__frame" style={{ height: `min(70vh, ${phoneRem}rem)` }} title={t('Aperçu du message sur téléphone, sans script')} sandbox="" referrerPolicy="no-referrer" srcDoc={doc} />
              )}
            </div>
          </div>
        </figure>
      </div>
    </section>
  );
}

/** The raw message, fetched when its tab opens. */
export function SourceView({ messageId, url }: { messageId: string; url?: string }) {
  const [source, setSource] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    setSource(null);
    setErr(null);
    fetch(url ?? `/api/mail/messages/${encodeURIComponent(messageId)}/raw`, { credentials: 'same-origin', cache: 'no-store' })
      .then((res) => (res.ok ? res.text() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then((txt) => alive && setSource(txt))
      .catch((e) => alive && setErr((e as Error).message));
    return () => {
      alive = false;
    };
  }, [messageId, url]);
  if (err)
    return (
      <Notice tone="error" title={t('Source indisponible')}>
        {t('Le serveur n’a pas rendu le message ({err}). Le fichier reste téléchargeable avec le bouton de téléchargement du verdict.', { err })}
      </Notice>
    );
  if (source === null)
    return (
      <div className="mr-source" aria-busy="true">
        <Skel w="60%" /> <Skel w="80%" /> <Skel w="45%" />
      </div>
    );
  return (
    <div className="stack-sm">
      <div className="mr-source__bar">
        <span className="muted">
          {fmtBytes(source.length)}
          {source.length > MAX_SOURCE ? ` ${t(': seuls les {size} premiers sont affichés', { size: fmtBytes(MAX_SOURCE) })}` : ''}
        </span>
        <CopyButton text={source} label={t('Copier la source')} what={t('Source copiée')} />
      </div>
      <div className="mr-source" tabIndex={0} aria-label={t('Source du message')}>
        <pre>{source.slice(0, MAX_SOURCE)}</pre>
      </div>
    </div>
  );
}
