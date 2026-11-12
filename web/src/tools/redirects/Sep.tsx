// Separator between two statuses of a chain ("301, then 200"): an icon, read as "puis".
import { t } from '../../lib/i18n';
import { ArrowRight } from 'lucide-react';

export function Sep() {
  return (
    <span className="rd-sep">
      <ArrowRight aria-hidden />
      <span className="visually-hidden"> {t('puis')} </span>
    </span>
  );
}
