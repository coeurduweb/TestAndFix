// Paste headers or a raw message, or drop a .eml: the analysis starts by itself as soon as the
// content is recognised as a message, follows its steps on the live stream of the import
// address, then opens the report permalink (/mail/message/<id>).
import { useEffect, useRef, useState, type DragEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { FileKey2, FileUp } from 'lucide-react';
import { Notice, SubmitButton } from '../../components/ui';
import { api, ApiError } from '../../lib/api';
import { fmtBytes, fmtScore, scoreBand } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import { takePendingFiles, takePendingText } from '../../lib/pending';
import { useCheck } from '../../lib/useCheck';
import { looksLikeMessage } from '../mail/logic';
import { DEFAULT_STEPS } from '../mail/MessageReport';
import { AnalysisProgress } from '../mail/Panels';
import type { MessageSummary, StoredReport } from '../mail/types';
import { useMailStream } from '../mail/useMailStream';
import '../mail/mail.css';
import './analyze.css';

const UPLOAD = 'upload';
type Input = { kind: 'text'; text: string } | { kind: 'file'; file: File };

function messageOf(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { error?: string; detail?: string } | null;
    if (b?.error === 'not_a_message') return b.detail ?? t('Aucun en-tête reconnu : collez le source complet du message.');
    if (b?.error === 'empty_message') return t('Le message est vide.');
    if (b?.error === 'invalid_upload') return b.detail ? t('Fichier illisible ({detail}).', { detail: b.detail }) : t('Fichier illisible.');
    if (e.status === 413) return t('Fichier trop gros pour être analysé.');
  }
  if (e instanceof TypeError) return t('Le serveur de TestAndFix ne répond pas. Vérifiez qu’il tourne.');
  return (e as Error)?.message ?? t('Erreur inconnue.');
}

const isEml = (f: File) => /\.(eml|msg|txt)$/i.test(f.name) || f.type === 'message/rfc822' || f.type === 'text/plain' || f.type === '';

export default function MailAnalyzePage() {
  const navigate = useNavigate();
  const [text, setText] = useState('');
  const [input, setInput] = useState<Input | null>(null);
  const [phase, setPhase] = useState<'idle' | 'waiting' | 'posting'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const took = useRef(false);
  const { state, conn } = useMailStream(phase === 'idle' ? null : UPLOAD);
  const busy = phase !== 'idle';
  const recent = useCheck<{ messages: MessageSummary[] }>(`/api/mail/addresses/${UPLOAD}`);

  const start = (i: Input) => {
    if (busy) return;
    setError(null);
    setInput(i);
    setPhase('waiting');
  };

  // the stream must be open before the upload, to see the steps of this message
  useEffect(() => {
    if (phase !== 'waiting') return;
    if (conn === 'open') return setPhase('posting');
    const timer = setTimeout(() => setPhase('posting'), 1500);
    return () => clearTimeout(timer);
  }, [phase, conn]);

  useEffect(() => {
    if (phase !== 'posting' || !input) return;
    let alive = true;
    const body = input.kind === 'file' ? (() => {
      const fd = new FormData();
      fd.append('file', input.file, input.file.name);
      return { body: fd };
    })() : { json: { raw: input.text } };
    api<{ messageId: string; message: MessageSummary; report: StoredReport }>('/api/mail/analyze', { method: 'POST', ...body })
      .then((r) => {
        if (!alive) return;
        navigate(`/mail/message/${r.messageId}`, { state: { preload: { message: r.message, report: r.report } } });
      })
      .catch((e) => {
        if (!alive) return;
        setError(messageOf(e));
        setPhase('idle');
      });
    return () => {
      alive = false;
    };
  }, [phase, input, navigate]);

  // what the universal input or the global drop handed over
  useEffect(() => {
    if (took.current) return;
    took.current = true;
    const files = takePendingFiles().filter(isEml);
    const pasted = takePendingText('check:pending-message');
    if (files.length) {
      if (files.length > 1) setNotice(t('{n} fichiers déposés : seul {name} est analysé. Déposez les autres un par un.', { n: files.length, name: files[0].name }));
      start({ kind: 'file', file: files[0] });
    } else if (pasted) {
      setText(pasted);
      start({ kind: 'text', text: pasted });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onFiles = (list: FileList | File[] | null) => {
    const files = Array.from(list ?? []);
    if (!files.length) return;
    const f = files.find(isEml);
    if (!f) return setError(t('{name} n’est pas un message : déposez un fichier .eml (source complète du message).', { name: files[0].name }));
    setNotice(files.length > 1 ? t('{n} fichiers déposés : seul {name} est analysé.', { n: files.length, name: f.name }) : null);
    start({ kind: 'file', file: f });
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    onFiles(e.dataTransfer.files);
  };

  const arrived = state.arrived;
  const progress = arrived ? state.progress[arrived] : undefined;
  const steps = Object.keys(state.steps).length ? state.steps : DEFAULT_STEPS;
  const uploads = (recent.data?.messages ?? []).slice(0, 5);

  return (
    <div className="mail-page">
      <section className="hero ma-hero" aria-labelledby="ma-t">
      <span className="hero__icon">
        <FileKey2 aria-hidden />
      </span>
      <h1 className="hero__title" id="ma-t">
        {t('Analyser un message reçu')}
      </h1>
      <p className="hero__desc">{t('Collez ses en‑têtes ou son source complet, ou ouvrez son fichier .eml : le compte rendu part tout seul.')}</p>

      <form
        className={`ma-drop ${over ? 'ma-drop--over' : ''}`}
        data-own-drop
        onDragEnter={(e) => {
          if (Array.from(e.dataTransfer.types).includes('Files')) setOver(true);
        }}
        onDragOver={(e) => {
          if (Array.from(e.dataTransfer.types).includes('Files')) e.preventDefault();
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setOver(false);
        }}
        onDrop={onDrop}
        onSubmit={(e) => {
          e.preventDefault();
          if (text.trim()) start({ kind: 'text', text });
        }}
        aria-busy={busy || undefined}
      >
        <label className="field__label" htmlFor="ma-source">
          {t('Source du message ou en-têtes')}
        </label>
        <textarea
          id="ma-source"
          className="textarea textarea--mono ma-source"
          value={text}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          aria-describedby="ma-hint"
          aria-invalid={error ? true : undefined}
          placeholder={'Received: from mail.exemple.fr (mail.exemple.fr [203.0.113.7])\n\tby mx.google.com with ESMTPS id …\nFrom: Contact <contact@exemple.fr>\nSubject: …'}
          disabled={busy}
          onChange={(e) => setText(e.target.value)}
          onPaste={(e) => {
            const el = e.currentTarget;
            const pasted = e.clipboardData.getData('text');
            const next = el.value.slice(0, el.selectionStart) + pasted + el.value.slice(el.selectionEnd);
            if (looksLikeMessage(next)) {
              e.preventDefault();
              setText(next);
              start({ kind: 'text', text: next });
            }
          }}
        />
        {error ? (
          <span className="field__error" role="alert" id="ma-hint">
            {error}
          </span>
        ) : (
          <span className="field__hint" id="ma-hint">
            {t('L’analyse part au collage dès que le texte ressemble à un message. Gmail : « Afficher l’original » dans le menu du message. Outlook : « Afficher la source du message ». Apple Mail : Option + Commande + U. Thunderbird : Ctrl + U.')}
          </span>
        )}
        <div className="ma-actions">
          <SubmitButton busy={busy} disabled={!text.trim()}>
            {busy ? t('Analyse en cours') : t('Analyser')}
          </SubmitButton>
          <button type="button" className="btn" onClick={() => fileRef.current?.click()} disabled={busy}>
            <FileUp aria-hidden />
            {t('Choisir un fichier .eml')}
          </button>
          <span className="muted ma-or">{t('ou glissez-le dans ce cadre')}</span>
          <input
            ref={fileRef}
            type="file"
            accept=".eml,.txt,message/rfc822"
            className="visually-hidden"
            tabIndex={-1}
            aria-hidden
            onChange={(e) => {
              onFiles(e.target.files);
              e.target.value = '';
            }}
          />
        </div>
        {over && <div className="ma-drop__hint">{t('Déposez le .eml pour l’analyser')}</div>}
      </form>
      {!busy && uploads.length > 0 && (
        <div className="hero__examples ma-recent" aria-label={t('Analyses récentes')}>
          {uploads.map((m) => (
            <Link key={m.id} className="chip" to={`/mail/message/${m.id}`}>
              <span className="ma-recent__subj">{m.subject?.trim() || m.from || t('sans objet')}</span>
              {m.score !== null && (
                <span className="ma-recent__score" data-band={scoreBand(m.score)}>
                  {fmtScore(m.score)}
                </span>
              )}
            </Link>
          ))}
        </div>
      )}
      {!busy && (
        <p className="hero__hint">
          {rich('Pour tester un envoi de bout en bout (IP, TLS et HELO observés, pas déduits), <a>envoyez plutôt à une adresse de test</a>.', undefined, { a: (c) => <Link to="/mail">{c}</Link> })}
        </p>
      )}
      </section>

      {notice && <Notice tone="info">{notice}</Notice>}
      {busy && (
        <div className="ma-progress">
          <p className="mail-note">
            {input?.kind === 'file'
              ? t('{name} ({size}) : le compte rendu s’ouvre à la fin de l’analyse.', { name: input.file.name, size: fmtBytes(input.file.size) })
              : t('{size} collés : le compte rendu s’ouvre à la fin de l’analyse.', { size: fmtBytes(new Blob([input?.kind === 'text' ? input.text : '']).size) })}
          </p>
          <AnalysisProgress steps={steps} progress={progress} />
        </div>
      )}

    </div>
  );
}
