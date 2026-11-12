// Landing state of a tool (v2): one task on the screen, like mail-tester: a title, one big input,
// clickable examples and recent values. Enter measures.
import { useState, type ComponentType, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { ArrowRight } from 'lucide-react';
import { isIp, toDomain } from '../lib/detect';
import { getRecent } from '../lib/recent';
import { t } from '../lib/i18n';

export function ToolHero({
  icon: Icon,
  title,
  desc,
  basePath,
  placeholder = 'example.com',
  examples = [],
  buildPath,
  accept = 'domain',
  label,
  children,
}: {
  icon?: ComponentType<{ 'aria-hidden'?: boolean }>;
  title: string;
  desc: ReactNode;
  basePath: string;
  placeholder?: string;
  examples?: string[];
  buildPath?: (value: string) => string;
  /** what the input takes */
  accept?: 'domain' | 'domain-or-ip' | 'ip' | 'any';
  label?: string;
  children?: ReactNode;
}) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const recent = Array.from(
    new Set(
      getRecent()
        .map((r) => (accept === 'ip' ? (isIp(r.value) ? r.value : undefined) : toDomain(r.value)))
        .filter((d): d is string => !!d),
    ),
  ).slice(0, 4);

  const go = (raw: string) => {
    const v = raw.trim();
    let out: string | undefined;
    if (accept === 'any') out = v || undefined;
    else if (accept === 'ip') out = isIp(v) ? v : undefined;
    else if (accept === 'domain-or-ip' && isIp(v)) out = v;
    else out = toDomain(v);
    if (!out) {
      setError(
        accept === 'ip'
          ? t('Saisissez une adresse IP, par exemple 8.8.8.8.')
          : t('Saisissez un nom de domaine, par exemple exemple.fr. Une URL ou une adresse e-mail marchent aussi.'),
      );
      return;
    }
    setError(null);
    navigate(buildPath ? buildPath(out) : `${basePath}/${encodeURIComponent(out)}`);
  };

  return (
    <section className="hero">
      {Icon && (
        <span className="hero__icon">
          <Icon aria-hidden />
        </span>
      )}
      <h1 className="hero__title">{title}</h1>
      <p className="hero__desc">{desc}</p>
      <form
        className="hero__form"
        onSubmit={(e) => {
          e.preventDefault();
          go(value);
        }}
      >
        <div className="hero__shell">
          <div className="hero__box">
            <input
              aria-label={label ?? t('Domaine à mesurer')}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? 'hero-err' : undefined}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              autoFocus
              spellCheck={false}
              autoCapitalize="off"
              autoComplete="off"
              inputMode="url"
            />
            <button type="submit" className="btn btn--primary">
              {t('Mesurer')}
              <ArrowRight aria-hidden />
            </button>
          </div>
        </div>
        {error && (
          <p className="hero__error" id="hero-err" role="alert">
            {error}
          </p>
        )}
      </form>
      {(recent.length > 0 || examples.length > 0) && (
        <div className="hero__examples" aria-label={recent.length ? t('Récents et exemples') : t('Exemples')}>
          {[...recent, ...examples.filter((e) => !recent.includes(e))].slice(0, 6).map((x) => (
            <button key={x} type="button" className="chip" onClick={() => go(x)}>
              {x}
            </button>
          ))}
        </div>
      )}
      {children}
    </section>
  );
}
