// The universal input: paste anything, check guesses the tool. Enter runs the first suggestion.
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { ArrowRight, Clock, CornerDownLeft, Search } from 'lucide-react';
import { detect, type Action } from '../lib/detect';
import { getRecent, pushRecent } from '../lib/recent';
import { TOOLS, toolById } from './tools';
import { t } from '../lib/i18n';

interface Option {
  key: string;
  section: string;
  label: string;
  hint?: string;
  path: string;
  icon: React.ComponentType<{ 'aria-hidden'?: boolean }>;
  /** tool family, for the hue of the icon tile */
  fam?: string;
  value?: string;
  /** a detected action (not a tool or a recent value) */
  action?: boolean;
}

const norm = (s: string) => s.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

export function Omnibox({ autoFocus, size = 'md' }: { autoFocus?: boolean; size?: 'md' | 'lg' }) {
  const [value, setValue] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLTextAreaElement>(null);
  const listId = useId();
  const navigate = useNavigate();

  // ⌘K / Ctrl+K / "/" focus the box from anywhere
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.closest('input, textarea, select, [contenteditable="true"]');
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
        e.preventDefault();
        ref.current?.focus();
        ref.current?.select();
        setOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // auto-grow
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 192)}px`;
  }, [value]);

  const detection = useMemo(() => detect(value), [value]);

  const options = useMemo<Option[]>(() => {
    const out: Option[] = [];
    const actionToOption = (a: Action): Option => ({
      key: a.path,
      section: t('Lancer'),
      label: a.label,
      hint: a.hint,
      path: a.path,
      icon: toolById(a.tool === 'link' ? 'link' : a.tool)?.icon ?? ArrowRight,
      fam: toolById(a.tool)?.group,
      value: detection.value,
      action: true,
    });
    out.push(...detection.actions.map(actionToOption));
    const q = norm(value.trim());
    if (q && !value.includes('\n')) {
      const tools = TOOLS.filter((m) => norm(`${t(m.title)} ${m.title} ${t(m.nav)} ${m.nav} ${t(m.description)} ${m.keywords ?? ''}`).includes(q)).slice(0, 6);
      out.push(...tools.map((m) => ({ key: `tool:${m.id}`, section: t('Outils'), label: t(m.title), hint: t(m.description), path: m.path, icon: m.icon, fam: m.group })));
    }
    if (!q) {
      out.push(
        ...getRecent()
          .slice(0, 6)
          .map((r) => ({ key: `recent:${r.path}`, section: t('Récents'), label: r.value, hint: t(r.label), path: r.path, icon: Clock })),
      );
      out.push(
        ...['mail', 'domain', 'propagation', 'ip'].map((id) => {
          const m = toolById(id)!;
          return { key: `tool:${m.id}`, section: t('Outils'), label: t(m.title), hint: t(m.description), path: m.path, icon: m.icon, fam: m.group };
        }),
      );
    }
    return out;
  }, [detection, value]);

  useEffect(() => setActive(0), [value]);

  const run = (o: Option | undefined) => {
    if (!o) return;
    if (o.value && o.action) {
      const v = o.value.length > 120 ? `${o.value.slice(0, 117)}…` : o.value;
      if (!o.value.includes('\n')) pushRecent({ value: v, path: o.path, label: o.label });
    }
    if (o.path === '/mail/analyse' && detection.value.includes('\n')) {
      sessionStorage.setItem('check:pending-message', detection.value);
    }
    if (o.path === '/rapports-dmarc' && detection.kind === 'dmarc-xml') {
      sessionStorage.setItem('check:pending-dmarc', detection.value);
    }
    setOpen(false);
    setValue('');
    ref.current?.blur();
    navigate(o.path);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setOpen(true);
      setActive((a) => Math.min(a + 1, options.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      run(options[active]);
    } else if (e.key === 'Escape') {
      if (value) setValue('');
      else {
        setOpen(false);
        ref.current?.blur();
      }
    }
  };

  let lastSection = '';
  const activeId = options[active] ? `${listId}-${active}` : undefined;
  const showPop = open && (options.length > 0 || value.trim().length > 0);

  return (
    <div className={`omni omni--${size}`}>
      <div className="omni__box">
        <Search className="omni__icon" aria-hidden />
        <textarea
          ref={ref}
          className="omni__input"
          rows={1}
          value={value}
          autoFocus={autoFocus}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          aria-label={t('Saisie universelle : domaine, IP, URL, adresse, en-têtes ou enregistrement DNS')}
          aria-expanded={showPop}
          aria-controls={listId}
          aria-activedescendant={showPop ? activeId : undefined}
          aria-autocomplete="list"
          role="combobox"
          placeholder={typeof window !== 'undefined' && window.innerWidth < 640 ? t('Domaine, IP, URL…') : t('Domaine, IP, URL, en-têtes…')}
          onChange={(e) => {
            setValue(e.target.value);
            setOpen(true);
          }}
          // clicking into an empty box opens nothing: the list comes with typing, ↓, ⌘K or /
          onFocus={() => value.trim() && setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKeyDown}
        />
        <span className="omni__kbd" aria-hidden>
          <kbd>{navigator.platform.includes('Mac') ? '⌘' : 'Ctrl'}</kbd>
          <kbd>K</kbd>
        </span>
      </div>
      {showPop && (
        <div className="omni__pop" id={listId} role="listbox" aria-label={t('Suggestions')} tabIndex={-1}>
          {options.length === 0 && (
            <div className="omni__empty">
              {t('Rien de reconnu. Essayez un domaine (exemple.fr), une IP, une URL complète, ou collez des en-têtes de message.')}
            </div>
          )}
          {options.map((o, i) => {
            const head = o.section !== lastSection ? o.section : null;
            lastSection = o.section;
            const Icon = o.icon;
            return (
              <div key={o.key + i}>
                {head && <div className="omni__section">{head}</div>}
                <div
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={i === active}
                  className="omni__option"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    run(o);
                  }}
                  onMouseEnter={() => setActive(i)}
                >
                  <span className={`ftile ftile--sm ${o.fam ? `fam--${o.fam}` : 'fam--outils'}`} aria-hidden>
                    <Icon aria-hidden />
                  </span>
                  <span>
                    <span className="omni__label">{o.label}</span>
                    {o.hint && <span className="omni__hint">{o.hint}</span>}
                  </span>
                  {i === active && (
                    <span className="omni__enter" aria-hidden>
                      <CornerDownLeft size={14} />
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
