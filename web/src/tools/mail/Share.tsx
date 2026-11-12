// "Partager" in the actions of a mail report: a read-only link /partage/<token>, opened by anyone who
// has the site password, until it is stopped. Without a share, nothing about sharing shows but the
// button; with one, the button says "Partagé" and its window gives the link and "Arrêter le partage".
import { useEffect, useState } from 'react';
import { Link2, Share2 } from 'lucide-react';
import { CopyButton, copyText, useToast } from '../../components/ui';
import { api, get, post } from '../../lib/api';
import type { Share } from '../../lib/carnet';
import { errorMessage } from '../../lib/useCheck';
import { t } from '../../lib/i18n';
import { Pop } from './Pop';

const urlOf = (s: Share) => `${window.location.origin}${s.path}`;

export function ShareAction({ messageId, initial }: { messageId: string; /** undefined: not known, read once */ initial?: Share | null }) {
  const toast = useToast();
  const [share, setShare] = useState<Share | null | undefined>(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setShare(initial), [initial]);
  useEffect(() => {
    if (initial !== undefined) return;
    let alive = true;
    get<{ share: Share | null }>(`/api/mail/messages/${encodeURIComponent(messageId)}/share`)
      .then((r) => alive && setShare(r.share ?? null))
      .catch(() => alive && setShare(null));
    return () => {
      alive = false;
    };
  }, [messageId, initial]);

  const base = `/api/mail/messages/${encodeURIComponent(messageId)}/share`;
  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      const s = await post<Share>(base);
      setShare(s);
      if (await copyText(urlOf(s))) toast(t('Lien de partage copié'));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const stop = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(base, { method: 'DELETE' });
      setShare(null);
      toast(t('Partage arrêté : le lien ne s’ouvre plus'));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Pop
      label={share ? t('Compte rendu partagé') : t('Partager ce compte rendu')}
      className="btn mr-share"
      trigger={
        share ? (
          <>
            <Link2 aria-hidden className="mr-share__on" />
            {t('Partagé')}
          </>
        ) : (
          <>
            <Share2 aria-hidden />
            {t('Partager')}
          </>
        )
      }
    >
      {() => (
        <div className="mr-sharebox">
          {share ? (
            <>
              <p className="mr-sharebox__title">{t('Partagé par lien')}</p>
              <code className="mr-sharebox__url">{urlOf(share)}</code>
              <p className="mr-sharebox__text">{t('En lecture seule, pour toute personne qui a le mot de passe du site.')}</p>
              <div className="mr-sharebox__btns">
                <CopyButton text={urlOf(share)} label={t('Copier le lien')} what={t('Lien de partage copié')} />
                <button type="button" className="btn btn--sm btn--danger" onClick={stop} disabled={busy} aria-busy={busy || undefined}>
                  {t('Arrêter le partage')}
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="mr-sharebox__title">{t('Partager ce compte rendu')}</p>
              <p className="mr-sharebox__text">
                {t('Un lien en lecture seule. Il s’ouvre pour toute personne qui a le mot de passe du site, jusqu’à ce que vous arrêtiez le partage.')}
              </p>
              <div className="mr-sharebox__btns">
                <button type="button" className="btn btn--primary btn--sm" onClick={create} disabled={busy || share === undefined} aria-busy={busy || undefined}>
                  <Link2 aria-hidden />
                  {t('Créer le lien')}
                </button>
              </div>
            </>
          )}
          {err && (
            <p className="field__error" role="alert">
              {err}
            </p>
          )}
        </div>
      )}
    </Pop>
  );
}
