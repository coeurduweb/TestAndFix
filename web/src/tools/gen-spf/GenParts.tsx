// Building blocks shared by the four record generators: domain carried by the URL, tolerant
// domain field with recent domains, segmented choice, record output, copy shortcut, prefill note.
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { AlertTriangle, Check, ChevronRight, CircleAlert, CircleCheck, Copy, DatabaseZap, Lock } from 'lucide-react';
import { useAuth } from '../../app/auth';
import { CodeBlock, CopyButton, copyText, useToast } from '../../components/ui';
import { getRecent } from '../../lib/recent';
import { fmtDateTime } from '../../lib/format';
import { rich, t } from '../../lib/i18n';
import { cleanDomain, splitTxt, zoneLine } from './txt';
import './gen.css';

/** Read and write one search parameter, history replaced (no back-button noise). */
export function useParam(name: string): [string, (v: string | null) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(name) ?? '';
  const set = (v: string | null) => {
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        if (v === null || v === '') n.delete(name);
        else n.set(name, v);
        return n;
      },
      { replace: true },
    );
  };
  return [value, set];
}

/** Recent domains from the other tools, newest first. */
export function recentDomains(exclude?: string): string[] {
  return Array.from(new Set(getRecent().map((r) => cleanDomain(r.value)).filter((d): d is string => !!d && d !== exclude))).slice(0, 5);
}

/**
 * Domain field without a submit button: a valid domain is committed when typing pauses,
 * on Enter or on blur. URL, e-mail address, capitals and trailing dot are accepted.
 */
export function DomainField({
  value,
  onCommit,
  label = t('Domaine'),
  hint,
}: {
  value: string;
  onCommit: (domain: string) => void;
  label?: string;
  hint?: ReactNode;
}) {
  const id = useId();
  const [text, setText] = useState(value);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => setText(value), [value]);
  const commit = (raw: string, strict: boolean) => {
    window.clearTimeout(timer.current);
    if (!raw.trim()) {
      setError(null);
      if (value) onCommit('');
      return;
    }
    const d = cleanDomain(raw);
    if (!d) {
      if (strict) setError(t('Saisissez un nom de domaine, par exemple exemple.fr (une URL ou une adresse e-mail marche aussi).'));
      return;
    }
    setError(null);
    if (d !== value) onCommit(d);
  };
  const recent = value ? [] : recentDomains();
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        className="input input--mono"
        value={text}
        placeholder="example.com"
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        inputMode="url"
        autoFocus={!value}
        aria-describedby={`${id}-h`}
        aria-invalid={error ? true : undefined}
        onChange={(e) => {
          const v = e.target.value;
          setText(v);
          window.clearTimeout(timer.current);
          timer.current = window.setTimeout(() => commit(v, false), 650);
        }}
        onBlur={(e) => commit(e.target.value, true)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            commit((e.target as HTMLInputElement).value, true);
          }
        }}
      />
      {error ? (
        <span className="field__error" id={`${id}-h`} role="alert">
          {error}
        </span>
      ) : (
        <span className="field__hint" id={`${id}-h`}>
          {hint ?? t('Une URL ou une adresse e-mail marche aussi : le domaine en est extrait.')}
        </span>
      )}
      {recent.length > 0 && (
        <div className="chips" aria-label={t('Domaines récents')} style={{ marginTop: 'var(--s1)' }}>
          {recent.map((r) => (
            <button key={r} type="button" className="chip mono" onClick={() => onCommit(r)}>
              {r}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export interface SegOption<T extends string> {
  value: T;
  label: ReactNode;
  recommended?: boolean;
  title?: string;
}

/** One choice among a few, as segments. The recommended option says so. */
export function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
  hint,
}: {
  label: string;
  options: SegOption<T>[];
  value: T;
  onChange: (v: T) => void;
  hint?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="gen-seg">
      <span className="gen-label" id={id}>
        {label}
      </span>
      <div className="segmented" role="group" aria-labelledby={id}>
        {options.map((o) => (
          <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)} title={o.title}>
            {o.label}
            {o.recommended && <span className="gen-seg__rec">{t('recommandé')}</span>}
          </button>
        ))}
      </div>
      {hint && <span className="field__hint">{hint}</span>}
    </div>
  );
}

/** Record to publish: name, value, and the 255-character version for zone files when needed. */
export function RecordOut({ name, value, type = 'TXT', nameHint }: { name: string; value: string; type?: string; nameHint?: ReactNode }) {
  const parts = splitTxt(value);
  return (
    <div className="stack-sm">
      <div className="gen-name">
        <span className="muted">{t('Nom')}</span>
        <code>{name}</code>
        <span className="muted">{t('· type {type}', { type })}</span>
        {nameHint && <span className="field__hint">{nameHint}</span>}
      </div>
      <div style={{ paddingTop: 'var(--s2)' }}>
        <CodeBlock code={value} label={t('Valeur à coller')} tone="suggested" />
      </div>
      <p className="field__hint">
        {parts.length > 1
          ? t("{n} caractères, plus de 255 : la plupart des interfaces DNS découpent d'elles-mêmes ; sinon, ou dans un fichier de zone, prenez la version en {parts} chaînes.", { n: value.length, parts: parts.length })
          : t('{n} caractères, une seule chaîne TXT.', { n: value.length })}
      </p>
      {parts.length > 1 && (
        <More summary={t('Version en {n} chaînes, pour un fichier de zone', { n: parts.length })}>
          <CodeBlock code={zoneLine(name, value)} label={t('{n} chaînes de 255 caractères au plus', { n: parts.length })} />
        </More>
      )}
    </div>
  );
}

/** `C` copies the main record when the focus is not in a field. */
export function useCopyShortcut(text: string, what = t('Enregistrement copié')) {
  const toast = useToast();
  const ref = useRef(text);
  ref.current = text;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'c' && e.key !== 'C') return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if ((e.target as HTMLElement)?.closest('input, textarea, select, [contenteditable="true"]')) return;
      if (window.getSelection()?.toString()) return;
      e.preventDefault();
      copyText(ref.current).then((ok) => ok && toast(what));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [toast, what]);
}

export type PrefillState =
  | { kind: 'off' }
  | { kind: 'anonymous' }
  | { kind: 'loading' }
  | { kind: 'done'; at: string; what: string }
  | { kind: 'error'; message: string };

/**
 * Where the defaults come from. Signed out, a small password field turns the DNS reading on
 * without leaving the page (the generator itself never needs it).
 */
export function PrefillNote({ state, domain }: { state: PrefillState; domain: string }) {
  const { login } = useAuth();
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<string | null>(null);
  if (state.kind === 'off') return null;
  if (state.kind === 'anonymous') {
    return (
      <div className="gen-prefill">
        <Lock size={14} aria-hidden />
        <span>{t("Session non connectée : rien n'est lu dans le DNS de {domain}, tout se règle à la main.", { domain })}</span>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setErr(null);
            try {
              await login(pw);
            } catch {
              setErr(t('Mot de passe refusé.'));
            }
          }}
        >
          <label className="visually-hidden" htmlFor="gen-prefill-pw">
            {t('Mot de passe de TestAndFix')}
          </label>
          <input id="gen-prefill-pw" className="input" type="password" autoComplete="current-password" placeholder={t('Mot de passe')} value={pw} onChange={(e) => setPw(e.target.value)} />
          <button type="submit" className="btn btn--sm">
            {t('Lire le DNS')}
          </button>
          {err && <span className="field__error" role="alert">{err}</span>}
        </form>
      </div>
    );
  }
  return (
    <div className="gen-prefill" aria-live="polite">
      <DatabaseZap size={14} aria-hidden />
      {state.kind === 'loading' && <span>{t('Lecture du DNS de {domain}…', { domain })}</span>}
      {state.kind === 'done' && (
        <span>
          {rich('Prérempli depuis le DNS de {domain} ({what}), lu le <m>{date}</m>.', { domain, what: state.what, date: fmtDateTime(state.at) }, { m: (c) => <span className="mono">{c}</span> })}
        </span>
      )}
      {state.kind === 'error' && <span className="out-text">{t("DNS illisible pour l'instant ({message}) : réglez à la main.", { message: state.message })}</span>}
    </div>
  );
}

/** Disclosure with a visible chevron, for advanced settings. */
export function More({ summary, children, defaultOpen }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <details className="gen-more" open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary aria-expanded={open}>
        <ChevronRight aria-hidden />
        {summary}
      </summary>
      <div className="gen-block">{children}</div>
    </details>
  );
}

/** LabTable for the narrow record column (see .gen-table in gen.css). */
export function CompactTable({ children, columns = [t('Contrôle'), t('Mesuré'), t('Référence'), t('Écart')] }: { children: ReactNode; columns?: string[] }) {
  return (
    <table className="lab-table gen-table">
      <thead>
        <tr>
          <th scope="col" className="c-check">{columns[0]}</th>
          <th scope="col">{columns[1]}</th>
          <th scope="col">{columns[2]}</th>
          <th scope="col" className="c-dev">{columns[3]}</th>
        </tr>
      </thead>
      {children}
    </table>
  );
}

/** Bottom bar on narrow screens: the record and its copy button, always in reach. */
export function MobileDock({ value, copy, status, what = t('Enregistrement copié') }: { value: string; copy?: string; status?: ReactNode; what?: string }) {
  return (
    <div className="gen-dock" aria-label={t('Enregistrement, accès rapide')}>
      <span className="gen-dock__value">{value}</span>
      {status}
      <CopyButton text={copy ?? value} label={t('Copier')} what={what} size="md" />
    </div>
  );
}

/* ---------- v2 « Clair et direct » ---------- */
export type PillTone = 'good' | 'watch' | 'bad' | undefined;
export interface Pill {
  label: ReactNode;
  tone?: PillTone;
}

/** Big copy button, primary. */
export function BigCopy({ text, label = t("Copier l'enregistrement"), what = t('Enregistrement copié') }: { text: string; label?: string; what?: string }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--primary"
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true);
          toast(what);
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
      {done ? t('Copié') : label}
    </button>
  );
}

export function Pills({ items }: { items: Pill[] }) {
  if (!items.length) return null;
  return (
    <div className="gen-tags">
      {items.map((p, i) => (
        <span key={i} className={`tag ${p.tone ? `tag--${p.tone === 'good' ? 'ok' : p.tone === 'watch' ? 'warn' : 'out'}` : ''}`}>
          {p.tone === 'good' && <CircleCheck aria-hidden />}
          {p.tone === 'bad' && <CircleAlert aria-hidden />}
          {p.tone === 'watch' && <AlertTriangle aria-hidden />}
          {p.label}
        </span>
      ))}
    </div>
  );
}

/**
 * The produced record, in very large type, stuck at the top on large screens, Copy in evidence.
 * Facts in pills; warnings as children; the 255-character zone version one click away.
 */
export function RecordPanel({
  name,
  type = 'TXT',
  value,
  copy,
  copyLabel,
  copyWhat,
  nameHint,
  pills = [],
  tone,
  actions,
  children,
  zone = true,
  label = t('Enregistrement produit'),
}: {
  name: ReactNode;
  type?: string;
  value: string;
  copy?: string;
  copyLabel?: string;
  copyWhat?: string;
  nameHint?: ReactNode;
  pills?: Pill[];
  tone?: PillTone;
  actions?: ReactNode;
  children?: ReactNode;
  zone?: boolean;
  label?: string;
}) {
  const parts = splitTxt(value);
  const [showZone, setShowZone] = useState(false);
  const nameText = typeof name === 'string' ? name : '';
  const dot = tone === 'bad' ? 'out' : tone === 'watch' ? 'warn' : 'ok';
  return (
    <section className="gen-hero surface" aria-label={label}>
      <header className="gen-hero__head">
        <span className={`dot dot--${dot}`} aria-hidden />
        <span className="gen-hero__label">{label}</span>
      </header>
      <div className="gen-hero__name">
        <span>{t('Nom')}</span>
        <code>{name}</code>
        <span>{type}</span>
      </div>
      {nameHint && <p className="field__hint">{nameHint}</p>}
      <pre className={`gen-hero__value ${value.length > 300 || value.split('\n').length > 5 ? 'gen-hero__value--long' : ''}`} tabIndex={0} aria-label={t('Valeur à coller')}>
        {value}
      </pre>
      <Pills items={pills} />
      <div className="gen-hero__bottom">
        <BigCopy text={copy ?? value} label={copyLabel} what={copyWhat} />
        {actions}
        {zone && parts.length > 1 && nameText && (
          <button type="button" className="btn btn--ghost" aria-expanded={showZone} onClick={() => setShowZone((s) => !s)}>
            {showZone ? t('Masquer la version en {n} chaînes', { n: parts.length }) : t('Voir la version en {n} chaînes', { n: parts.length })}
          </button>
        )}
      </div>
      {showZone && nameText && <CodeBlock code={zoneLine(nameText, value)} label={t('Fichier de zone, {n} chaînes de 255 au plus', { n: parts.length })} />}
      {children}
    </section>
  );
}

/** Page frame of a generator: title, the choices on the left, the produced record stuck on the right. */
export function GenLayout({ title, desc, aside, children, dock }: { title: string; desc: ReactNode; aside: ReactNode; children: ReactNode; dock?: ReactNode }) {
  return (
    <div className="gen">
      <header className="page-head">
        <h1 className="page-head__title">{title}</h1>
        <p className="page-head__desc">{desc}</p>
      </header>
      <div className="gen-layout">
        <div className="gen-in">{children}</div>
        <aside className="gen-out" aria-label={t('Enregistrement produit')}>
          {aside}
        </aside>
      </div>
      {dock}
    </div>
  );
}

/** A plain block of choices. */
export function Block({ title, children, aside, wide, id }: { title: ReactNode; children: ReactNode; aside?: ReactNode; wide?: boolean; id?: string }) {
  const tid = useId();
  return (
    <section className={`gen-card surface ${wide ? 'gen-card--wide' : ''}`} aria-labelledby={tid} id={id}>
      <h2 className="gen-card__title" id={tid}>
        {title}
        {aside}
      </h2>
      <div className="gen-card__body">{children}</div>
    </section>
  );
}

/** Lines read at a glance: icon, value, short note. */
export function Checks({ items }: { items: { key: string; tone: 'ok' | 'bad' | 'watch'; main: ReactNode; note?: ReactNode }[] }) {
  return (
    <ul className="gen-checks">
      {items.map((x) => (
        <li key={x.key} className={`is-${x.tone}`}>
          {x.tone === 'ok' ? <CircleCheck aria-label={t('conforme')} /> : x.tone === 'bad' ? <CircleAlert aria-label={t('à corriger')} /> : <AlertTriangle aria-label={t('à surveiller')} />}
          <span className="gen-checks__main">{x.main}</span>
          {x.note && <span className="gen-checks__note">{x.note}</span>}
        </li>
      ))}
    </ul>
  );
}
