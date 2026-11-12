// The path of a test message and what the report checks at each step (only what it really
// measures: see server/src/mail/analyze). Used on the home card and on the mail wait screen, where
// a signal travels along it (stopped under prefers-reduced-motion).
import { msg, t } from '../lib/i18n';

const MAIL_STEPS = [
  { title: msg('Serveur d’envoi'), checks: msg('IP, PTR, HELO, TLS') },
  { title: msg('Authentification'), checks: msg('SPF, DKIM, DMARC') },
  { title: msg('Réputation'), checks: msg('listes noires') },
  { title: msg('Contenu'), checks: msg('SpamAssassin, liens, désinscription') },
];

export function MailPath({ label = t('Ce que le test contrôle, étape par étape'), className = '' }: { label?: string; className?: string }) {
  return (
    <ol className={`msg-route fam--mail ${className}`} aria-label={label}>
      {MAIL_STEPS.map((s) => (
        <li key={s.title} className="msg-route__step">
          <span className="msg-route__node" aria-hidden />
          <span className="msg-route__title">{t(s.title)}</span>
          <span className="msg-route__checks">{t(s.checks)}</span>
        </li>
      ))}
    </ol>
  );
}
