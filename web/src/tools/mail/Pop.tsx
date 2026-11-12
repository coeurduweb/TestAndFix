// A popover opened on the spot, under the button that asked for it (UI-SIGNAL.md: « une fenêtre qui
// s'ouvre sur place, à l'endroit du clic »). Escape or a click outside closes it and gives the focus
// back to its button. Placed fixed under its button, so no ancestor that clips (the verdict strip) cuts it.
import { useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

export function Pop({
  label,
  trigger,
  className = 'btn',
  align = 'start',
  title,
  children,
}: {
  /** accessible name of the window */
  label: string;
  trigger: ReactNode;
  className?: string;
  align?: 'start' | 'end';
  /** tooltip of an icon-only trigger */
  title?: string;
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const id = useId();
  const [place, setPlace] = useState<CSSProperties>({ visibility: 'hidden' });
  // fixed to the viewport, under its button: the verdict strip clips what overflows it
  useLayoutEffect(() => {
    if (!open) return;
    const put = () => {
      const r = btn.current?.getBoundingClientRect();
      const w = panel.current?.offsetWidth ?? 0;
      const h = panel.current?.offsetHeight ?? 0;
      if (!r) return;
      const vw = document.documentElement.clientWidth;
      const left = align === 'end' ? r.right - w : r.left;
      // above the button when it does not fit below
      const below = r.bottom + 8 + h <= window.innerHeight || r.top - 8 - h < 0;
      setPlace({ position: 'fixed', top: below ? r.bottom + 8 : r.top - 8 - h, left: Math.max(16, Math.min(left, vw - w - 16)), right: 'auto' });
    };
    put();
    window.addEventListener('resize', put);
    window.addEventListener('scroll', put, true);
    return () => {
      window.removeEventListener('resize', put);
      window.removeEventListener('scroll', put, true);
    };
  }, [open, align]);
  const close = () => {
    setOpen(false);
    btn.current?.focus();
  };
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      setOpen(false);
      btn.current?.focus();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    // the first control of the window takes the focus
    panel.current?.querySelector<HTMLElement>('button, a[href], input')?.focus({ preventScroll: true });
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);
  return (
    <div className="mr-popwrap" ref={wrap}>
      <button
        ref={btn}
        type="button"
        className={className}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        aria-haspopup="dialog"
        title={title}
        aria-label={title}
        onClick={() => {
          setPlace({ visibility: 'hidden' });
          setOpen((o) => !o);
        }}
      >
        {trigger}
      </button>
      {open && (
        <div ref={panel} id={id} className={`popover mr-pop mr-pop--${align}`} style={place} role="dialog" aria-label={label}>
          {children(close)}
        </div>
      )}
    </div>
  );
}
