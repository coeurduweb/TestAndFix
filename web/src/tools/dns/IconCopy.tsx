// Icon-only copy button for table rows: the accessible name says what is copied.
import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { t } from '../../lib/i18n';
import { copyText, useToast } from '../../components/ui';

export function IconCopy({ text, label, what }: { text: string; label: string; what?: string }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--ghost btn--icon rr-copy"
      aria-label={label}
      title={label}
      onClick={async (e) => {
        e.stopPropagation();
        if (await copyText(text)) {
          setDone(true);
          toast(what ?? t('Copié'));
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
    </button>
  );
}
