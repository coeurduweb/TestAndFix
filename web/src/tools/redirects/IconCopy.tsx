// Icon-only copy button for a header line: the accessible name says what is copied.
import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { copyText, useToast } from '../../components/ui';
import { t } from '../../lib/i18n';

export function IconCopy({ text, label, what }: { text: string; label: string; what?: string }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--ghost btn--icon rd-icopy"
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
