import { useState } from 'react';
import { Lock, LockKeyhole } from 'lucide-react';
import { ApiError } from '../lib/api';
import { Field, Notice, SubmitButton } from '../components/ui';
import { useAuth } from './auth';
import { t, tn } from '../lib/i18n';

/** Inline login: shown in place of a protected page, the page opens as soon as the password is right. */
export function LoginPanel({ title }: { title?: string }) {
  const { login, configured } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <section className="hero login-panel">
      <span className="hero__icon">
        <Lock aria-hidden />
      </span>
      <h1 className="hero__title">{title ?? t('Mot de passe')}</h1>
      <p className="hero__desc">{t('Les vérifications sont réservées. Les générateurs restent ouverts sans mot de passe.')}</p>
      <p className="login-panel__private">
        <LockKeyhole aria-hidden />
        {t('Vos recherches restent liées à ce navigateur : personne d’autre ne les voit.')}
      </p>
      {!configured && (
        <Notice tone="warn" title={t('Aucun mot de passe configuré')}>
          {t('Renseignez CHECK_PASSWORD_HASH (ou CHECK_PASSWORD en développement) dans le fichier .env du serveur.')}
        </Notice>
      )}
      <form
        className="surface login-panel__form"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await login(password);
          } catch (err) {
            const ae = err as ApiError;
            const body = ae.body as { retryAfter?: number; remaining?: number } | null;
            setError(
              ae.status === 429
                ? t("Trop d'essais. Réessayez dans {n} s.", { n: body?.retryAfter ?? 60 })
                : ae.status === 401
                  ? body?.remaining !== undefined
                    ? tn(body.remaining, 'Mot de passe incorrect (encore {n} essai cette minute).', 'Mot de passe incorrect (encore {n} essais cette minute).')
                    : t('Mot de passe incorrect.')
                  : t('Connexion impossible pour le moment. Vérifiez que le serveur tourne.'),
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <Field label={t('Mot de passe')} error={error}>
          {(id, d) => (
            <input id={id} aria-describedby={d} className="input" type="password" autoComplete="current-password" autoFocus value={password}
              onChange={(e) => setPassword(e.target.value)} required />
          )}
        </Field>
        <div className="login-panel__foot">
          <p className="field__hint">{t('Vous restez connecté 30 jours sur ce navigateur.')}</p>
          <SubmitButton busy={busy}>{t('Ouvrir')}</SubmitButton>
        </div>
      </form>
    </section>
  );
}
