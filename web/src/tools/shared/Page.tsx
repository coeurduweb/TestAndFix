// /partage/:token: a mail report shared by link, read-only (the same report as /mail/message/:id,
// without sends, comparison, reanalysis or share button). The site password is still required: a
// share link is for people who have it. Stopped or unknown link: a clear empty state.
import { Link, useParams } from 'react-router';
import { Link2 } from 'lucide-react';
import { Empty, Notice, Skel } from '../../components/ui';
import { errorMessage, useCheck } from '../../lib/useCheck';
import { t } from '../../lib/i18n';
import { MessageReport } from '../mail/MessageReport';
import type { MessageSummary, StoredReport } from '../mail/types';
import '../mail/mail.css';

export default function SharedReportPage() {
  const { token = '' } = useParams();
  // the server leaves out the test address of a shared message (addressId, rcptTo, masked elsewhere)
  const { data, error } = useCheck<{ message: Omit<MessageSummary, 'addressId' | 'rcptTo'> & Partial<Pick<MessageSummary, 'addressId' | 'rcptTo'>>; report: StoredReport | null }>(
    `/api/shared/${encodeURIComponent(token)}`,
  );

  if (error) {
    const gone = (error as { status?: number }).status === 404;
    return (
      <div className="mail-page">
        <header className="page-head">
          <h1 className="page-head__title">{gone ? t('Lien expiré ou arrêté') : t('Compte rendu partagé illisible')}</h1>
        </header>
        {gone ? (
          <Empty title={t('Ce lien de partage ne s’ouvre plus')} action={<Link className="btn" to="/mail">{t('Tester un de vos messages')}</Link>}>
            {t('Son auteur a arrêté le partage, ou le compte rendu a été effacé. Demandez-lui un nouveau lien.')}
          </Empty>
        ) : (
          <Notice tone="error" title={t('Lecture impossible')}>
            {errorMessage(error)}
          </Notice>
        )}
      </div>
    );
  }

  if (!data)
    return (
      <div className="mail-page">
        <div className="mail-report" aria-busy="true" aria-label={t('Chargement du compte rendu partagé')}>
          <header className="verdict verdict--pending mr-verdict">
            <div className="verdict__main">
              <Skel w="12ch" />
              <Skel w="28ch" />
              <Skel w="40ch" />
            </div>
          </header>
        </div>
      </div>
    );

  return (
    <div className="mail-page">
      <p className="mr-shared-note">
        <Link2 aria-hidden />
        {t('Compte rendu partagé par lien, en lecture seule. Il ne fait pas partie de votre carnet.')}
      </p>
      <MessageReport key={token} message={{ ...data.message, addressId: data.message.addressId ?? 'shared', rcptTo: data.message.rcptTo ?? [] }} report={data.report} sharedToken={token} />
    </div>
  );
}
