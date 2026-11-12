// "Pays…": a popover that opens under its chip. Search with suggestions as you type (accents
// ignored; name, ISO code or continent), continent quick chips, the list with flag, name, number
// of resolvers and a checkbox, keyboard (arrows, Enter, Space after an arrow, Escape), and the
// countries picked in the footer. The picks are applied when it closes, whichever way (decision
// 2026-11-11: a pick is never lost by clicking outside), so the measure starts once, not on every
// tick of a box.
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Flag as FlagIcon, Globe2, Search } from 'lucide-react';
import { fmtCount } from '../dns/fmt';
import { t } from '../../lib/i18n';
import { Popover } from './Popover';
import { Flag } from './ResolverList';
import { fold, optionKey, searchPlaces, type ContinentChip, type PlaceOption } from './places';

function Highlight({ text, q }: { text: string; q: string }) {
  const f = fold(q.trim());
  if (!f) return <>{text}</>;
  // folding keeps one character per character for Latin names, so the indexes match
  const i = fold(text).indexOf(f);
  if (i < 0 || fold(text).length !== text.length) return <>{text}</>;
  return (
    <>
      {text.slice(0, i)}
      <mark>{text.slice(i, i + f.length)}</mark>
      {text.slice(i + f.length)}
    </>
  );
}

export function CountryPicker({
  countries,
  regions,
  chips,
  picked,
  onApply,
}: {
  countries: PlaceOption[];
  regions: PlaceOption[];
  chips: ContinentChip[];
  /** keys "country:FR", "region:155" of the current selection */
  picked: string[];
  onApply: (keys: string[]) => void;
}) {
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [cont, setCont] = useState('');
  const [staged, setStaged] = useState<Set<string>>(new Set(picked));
  const [active, setActive] = useState(0);
  // Space toggles only once the arrows moved in the list; before, it types (Côte d'Ivoire)
  const [nav, setNav] = useState(false);

  const shown = useMemo(() => searchPlaces(countries, regions, q, cont, staged), [countries, regions, q, cont, staged]);
  const byKey = useMemo(() => new Map([...countries, ...regions].map((o) => [optionKey(o), o])), [countries, regions]);

  const openIt = () => {
    setStaged(new Set(picked));
    setQ('');
    setCont('');
    setActive(0);
    setNav(false);
    setOpen(true);
    requestAnimationFrame(() => input.current?.focus());
  };
  const close = () => {
    setOpen(false);
    const next = [...staged].sort();
    if (next.join() !== [...picked].sort().join()) onApply(next);
  };
  const toggle = (k: string) =>
    setStaged((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });

  useEffect(() => {
    if (!open) return;
    listRef.current?.querySelector('[data-active]')?.scrollIntoView({ block: 'nearest' });
  }, [active, open]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setNav(true);
      setActive((a) => Math.min(shown.length - 1, a + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setNav(true);
      setActive((a) => Math.max(0, a - 1));
    } else if ((e.key === 'Home' || e.key === 'End') && nav) {
      e.preventDefault();
      setActive(e.key === 'Home' ? 0 : shown.length - 1);
    } else if ((e.key === 'Enter' || (e.key === ' ' && nav)) && shown[active]) {
      e.preventDefault();
      toggle(optionKey(shown[active]));
    }
  };

  const one = picked.length === 1 ? byKey.get(picked[0]) : null;
  const label = !picked.length ? t('Pays…') : one ? one.name : picked.every((k) => k.startsWith('country:')) ? t('{n} pays', { n: picked.length }) : t('{n} lieux', { n: picked.length });
  const stagedList = [...staged].map((k) => byKey.get(k)).filter((o): o is PlaceOption => !!o);
  const activeId = shown[active] ? `${id}-${optionKey(shown[active]).replace(':', '-')}` : undefined;

  return (
    <>
      <button
        ref={btn}
        type="button"
        className="chip"
        aria-haspopup="dialog"
        aria-expanded={open}
        data-on={picked.length > 0 || undefined}
        aria-controls={open ? `${id}-pop` : undefined}
        onClick={() => (open ? close() : openIt())}
        title={t('Choisir des pays')}
      >
        {one?.kind === 'country' ? <Flag cc={one.code} /> : <FlagIcon aria-hidden />}
        <span>{label}</span>
        {!picked.length && <small>{fmtCount(countries.length)}</small>}
      </button>
      <Popover anchor={btn} open={open} onClose={close} label={t('Choisir des pays')} className="cp">
        <div className="cp__search" id={`${id}-pop`}>
          <Search aria-hidden />
          <input
            ref={input}
            type="text"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
              setNav(false);
            }}
            onKeyDown={onKey}
            placeholder={t('Pays, code ou continent')}
            aria-label={t('Chercher un pays')}
            autoComplete="off"
            spellCheck={false}
            role="combobox"
            aria-expanded="true"
            aria-controls={`${id}-list`}
            aria-activedescendant={activeId}
            aria-autocomplete="list"
          />
          <kbd>{t('Échap')}</kbd>
        </div>
        <div className="cp__conts" role="group" aria-label={t('Continent')}>
          {[{ id: '', name: t('Tous') }, ...chips].map((c) => (
            <button
              key={c.id}
              type="button"
              className="chip"
              aria-pressed={cont === c.id}
              onClick={() => {
                setCont(c.id);
                setActive(0);
                input.current?.focus();
              }}
            >
              {c.name}
            </button>
          ))}
        </div>
        <div className="cp__list" id={`${id}-list`} ref={listRef} role="listbox" aria-multiselectable="true" aria-label={t('Pays')}>
          {shown.map((o, i) => {
            const k = optionKey(o);
            const on = staged.has(k);
            return (
              <div
                key={k}
                id={`${id}-${k.replace(':', '-')}`}
                role="option"
                aria-selected={on}
                data-active={i === active || undefined}
                className="cp__opt"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  toggle(k);
                  setActive(i);
                }}
              >
                {o.kind === 'country' ? <Flag cc={o.code} /> : <Globe2 aria-hidden className="cp__reg" />}
                <span className="cp__name">
                  <Highlight text={o.name} q={q} />
                  {o.kind === 'region' && <span className="cp__kind"> {t('région')}</span>}
                </span>
                <small>{fmtCount(o.count)}</small>
                <span className="cp__cb" aria-hidden />
              </div>
            );
          })}
          {!shown.length && <p className="cp__empty">{t('Aucun pays ne correspond à « {q} ».', { q: q.trim() })}</p>}
        </div>
        <div className="cp__foot">
          <div className="cp__picked" aria-live="polite">
            {stagedList.length ? (
              stagedList.map((o) => (
                <button key={optionKey(o)} type="button" className="cp__tag" onClick={() => toggle(optionKey(o))} aria-label={t('Retirer {name}', { name: o.name })} title={t('Retirer')}>
                  {o.kind === 'country' ? <Flag cc={o.code} /> : <Globe2 aria-hidden />}
                  {o.name}
                </button>
              ))
            ) : (
              <span>{t('Aucun pays coché : le monde entier.')}</span>
            )}
          </div>
          {stagedList.length > 0 && (
            <button type="button" className="btn btn--sm btn--ghost" onClick={() => setStaged(new Set())}>
              {t('Effacer')}
            </button>
          )}
          <button type="button" className="btn btn--sm btn--primary" onClick={close}>
            {t('Mesurer')}
          </button>
        </div>
      </Popover>
    </>
  );
}
