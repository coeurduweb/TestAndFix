// Search box with suggestions: a known sending service, or any include typed by hand.
import { useId, useMemo, useState } from 'react';
import { rich, t } from '../../lib/i18n';
import { searchProviders, type SpfProvider } from './providers';
import { cleanIncludeTarget } from './spf-build';

type Opt = { kind: 'provider'; p: SpfProvider } | { kind: 'include'; domain: string };

export function ProviderSearch({
  selected,
  onProvider,
  onInclude,
}: {
  selected: Set<string>;
  onProvider: (key: string) => void;
  onInclude: (domain: string) => void;
}) {
  const id = useId();
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const options = useMemo<Opt[]>(() => {
    const out: Opt[] = searchProviders(q, selected).slice(0, 7).map((p) => ({ kind: 'provider', p }));
    const inc = cleanIncludeTarget(q);
    if (inc && !out.some((o) => o.kind === 'provider' && o.p.include === inc)) out.push({ kind: 'include', domain: inc });
    return out;
  }, [q, selected]);
  const show = open && q.trim().length > 0;
  const pick = (o: Opt | undefined) => {
    if (!o) return;
    if (o.kind === 'provider') onProvider(o.p.key);
    else onInclude(o.domain);
    setQ('');
    setActive(0);
  };
  return (
    <div className="field gen-combo">
      <label className="field__label" htmlFor={id}>
        {t('Ajouter un service ou un include')}
      </label>
      <input
        id={id}
        className="input"
        role="combobox"
        aria-expanded={show}
        aria-controls={`${id}-list`}
        aria-autocomplete="list"
        aria-activedescendant={show && options[active] ? `${id}-o${active}` : undefined}
        aria-describedby={`${id}-h`}
        value={q}
        placeholder="Brevo, Zoho, sendgrid.net…"
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 120)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActive((a) => Math.min(options.length - 1, a + 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === 'Enter') {
            e.preventDefault();
            pick(options[active]);
          } else if (e.key === 'Escape') {
            setOpen(false);
          }
        }}
      />
      <span className="field__hint" id={`${id}-h`}>
        {t("Nom du service, ou domaine d'un include (spf.exemple.net) donné par votre prestataire.")}
      </span>
      {show && (
        <ul className="gen-combo__pop" id={`${id}-list`} role="listbox" aria-label={t('Suggestions')}>
          {options.length === 0 && <li className="gen-combo__opt muted">{t("Aucun service connu. Tapez le domaine de l'include fourni par le service.")}</li>}
          {options.map((o, i) => (
            <li
              key={o.kind === 'provider' ? o.p.key : o.domain}
              id={`${id}-o${i}`}
              role="option"
              aria-selected={i === active}
              className="gen-combo__opt"
              onMouseDown={(e) => {
                e.preventDefault();
                pick(o);
              }}
              onMouseEnter={() => setActive(i)}
            >
              {o.kind === 'provider' ? (
                <>
                  <span>
                    {o.p.name}
                    <small className="mono">{o.p.include ? `include:${o.p.include}` : o.p.accountInclude ? t('include propre au compte') : t('rien à ajouter au SPF racine')}</small>
                  </span>
                  <span className="gen-chip-cost">{o.p.cost !== undefined ? t('{n} req.', { n: o.p.cost }) : ''}</span>
                </>
              ) : (
                <>
                  <span>
                    {rich('Ajouter <m>include:{domain}</m>', { domain: o.domain }, { m: (c) => <span className="mono">{c}</span> })}
                    <small>{t('Coût inconnu : estimé à 1 requête au moins')}</small>
                  </span>
                  <span className="gen-chip-cost">{t('≥ 1 req.')}</span>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
