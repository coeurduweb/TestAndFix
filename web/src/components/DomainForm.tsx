// Single input for domain tools: tolerant (accepts URL, e-mail address), recent values as chips.
import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { toDomain } from '../lib/detect';
import { getRecent } from '../lib/recent';
import { t } from '../lib/i18n';
import { Field, SubmitButton } from './ui';

export function DomainForm({
  basePath,
  initial = '',
  label,
  placeholder = 'example.com',
  busy,
  hint,
  extra,
  buildPath,
  acceptIp,
}: {
  basePath: string;
  initial?: string;
  label?: string;
  placeholder?: string;
  busy?: boolean;
  hint?: ReactNode;
  extra?: ReactNode;
  buildPath?: (domain: string) => string;
  acceptIp?: boolean;
}) {
  const [value, setValue] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  useEffect(() => setValue(initial), [initial]);
  const recent = Array.from(
    new Set(
      getRecent()
        .map((r) => toDomain(r.value))
        .filter((d): d is string => !!d && d !== initial),
    ),
  ).slice(0, 5);

  const go = (raw: string) => {
    const v = raw.trim();
    const d = acceptIp && /^[\d.:a-f]+$/i.test(v) && v.includes('.') ? v : toDomain(v);
    if (!d) {
      setError(t('Saisissez un nom de domaine, par exemple exemple.fr (une URL ou une adresse e-mail marche aussi).'));
      return;
    }
    setError(null);
    navigate(buildPath ? buildPath(d) : `${basePath}/${encodeURIComponent(d)}`);
  };

  return (
    <form
      className="page-form"
      onSubmit={(e) => {
        e.preventDefault();
        go(value);
      }}
    >
      <Field label={label ?? t('Domaine')} hint={hint ?? t('Une URL ou une adresse e-mail marche aussi : le domaine en est extrait.')} error={error}>
        {(id, d) => (
          <input
            id={id}
            aria-describedby={d}
            className="input input--mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            autoFocus={!initial}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            inputMode="url"
          />
        )}
      </Field>
      {extra}
      <SubmitButton busy={busy}>{t('Mesurer')}</SubmitButton>
      {recent.length > 0 && !initial && (
        <div className="chips" style={{ flexBasis: '100%' }} aria-label={t('Domaines récents')}>
          {recent.map((r) => (
            <button key={r} type="button" className="chip mono" onClick={() => go(r)}>
              {r}
            </button>
          ))}
        </div>
      )}
    </form>
  );
}
