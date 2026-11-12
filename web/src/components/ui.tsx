import { createContext, useCallback, useContext, useId, useRef, useState, type ReactNode } from 'react';
import { AlertTriangle, Check, Copy, Info, Loader2, XCircle } from 'lucide-react';
import { t } from '../lib/i18n';

/* ---------- toast ---------- */
interface Toast {
  id: number;
  text: string;
}
const ToastCtx = createContext<(text: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(0);
  const push = useCallback((text: string) => {
    const id = ++next.current;
    setToasts((list) => [...list.slice(-2), { id, text }]);
    setTimeout(() => setToasts((list) => list.filter((x) => x.id !== id)), 2600);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-region" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div className="toast" key={toast.id}>
            <Check aria-hidden />
            {toast.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* ---------- copy ---------- */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label, what, size = 'sm' }: { text: string; label?: string; what?: string; size?: 'sm' | 'md' }) {
  const toast = useToast();
  const [done, setDone] = useState(false);
  const shown = label ?? t('Copier');
  return (
    <button
      type="button"
      className={`btn ${size === 'sm' ? 'btn--sm' : ''} btn--ghost`}
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true);
          toast(what ?? t('Copié'));
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
      {shown}
    </button>
  );
}

/* ---------- code block ---------- */
export function CodeBlock({
  code,
  label,
  tone,
  copyLabel,
}: {
  code: string;
  label?: string;
  tone?: 'suggested' | 'bad';
  copyLabel?: string;
}) {
  return (
    <div className={`code ${tone ? `code--${tone}` : ''}`}>
      {label && <span className="code__label">{label}</span>}
      <pre>
        <code>{code}</code>
      </pre>
      <CopyButton text={code} label={copyLabel} what={t('Copié dans le presse-papiers')} />
    </div>
  );
}

/* ---------- notices ---------- */
export function Notice({ tone = 'info', title, children }: { tone?: 'info' | 'warn' | 'error'; title?: string; children?: ReactNode }) {
  const Icon = tone === 'error' ? XCircle : tone === 'warn' ? AlertTriangle : Info;
  return (
    <div className={`notice notice--${tone}`} role={tone === 'error' ? 'alert' : undefined}>
      <Icon aria-hidden />
      <div className="stack-sm">
        {title && <div className="notice__title">{title}</div>}
        {children && <div>{children}</div>}
      </div>
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty__title">{title}</div>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Skel({ w = '8ch' }: { w?: string }) {
  return <span className="skel" style={{ ['--w' as string]: w }} aria-hidden />;
}

/* ---------- form controls ---------- */
export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: (id: string, describedBy?: string) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-err` : undefined;
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      {children(id, [hintId, errId].filter(Boolean).join(' ') || undefined)}
      {error ? (
        <span className="field__error" id={errId} role="alert">
          {error}
        </span>
      ) : (
        hint && (
          <span className="field__hint" id={hintId}>
            {hint}
          </span>
        )
      )}
    </div>
  );
}

export function SubmitButton({ busy, children, disabled }: { busy?: boolean; children: ReactNode; disabled?: boolean }) {
  return (
    <button type="submit" className="btn btn--primary" aria-busy={busy || undefined} disabled={disabled || busy}>
      {busy && <Loader2 className="spin" aria-hidden />}
      {children}
    </button>
  );
}
