// A window that opens on the spot, under the control that asked for it, over the page (Signal rule:
// never a panel inserted in the page). Scrim behind, Escape or a click outside closes it and gives
// the focus back to the control, Tab stays inside. Placed in fixed coordinates from the control's
// box and kept inside the viewport (16 px gutter), so it never widens the page.
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';

export function Popover({
  anchor,
  open,
  onClose,
  label,
  width = 440,
  className = '',
  children,
}: {
  anchor: RefObject<HTMLElement | null>;
  open: boolean;
  /** how it closed: Escape and the scrim say "dismiss", the caller decides what to keep */
  onClose: (how: 'dismiss' | 'done') => void;
  label: string;
  width?: number;
  className?: string;
  children: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const [pos, setPos] = useState<{ left: number; top: number; w: number; maxH: number } | null>(null);

  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    const place = () => {
      const a = anchor.current?.getBoundingClientRect();
      if (!a) return;
      const vw = document.documentElement.clientWidth;
      const w = Math.min(width, vw - 32);
      const left = Math.max(16, Math.min(a.left, vw - 16 - w));
      const top = a.bottom + 8;
      setPos({ left, top, w, maxH: Math.max(240, window.innerHeight - top - 16) });
    };
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
  }, [open, anchor, width]);

  useEffect(() => {
    if (!open) return;
    const back = anchor.current;
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeRef.current('dismiss');
      } else if (e.key === 'Tab' && box.current) {
        const f = [...box.current.querySelectorAll<HTMLElement>('button:not(:disabled), input, textarea, select, [tabindex="0"]')];
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', key, true);
    return () => {
      document.removeEventListener('keydown', key, true);
      // the focus goes back to the control that opened it
      requestAnimationFrame(() => back?.focus());
    };
  }, [open, anchor]);

  // once placed (it is hidden until then, and a hidden field cannot take the focus), the focus
  // goes to its first field unless the caller already put it inside
  const placed = pos !== null;
  useEffect(() => {
    if (!open || !placed || !box.current || box.current.contains(document.activeElement)) return;
    box.current.querySelector<HTMLElement>('textarea, input, button')?.focus();
  }, [open, placed]);

  if (!open) return null;
  return createPortal(
    <>
      <div className="scrim pp-scrim" onClick={() => onClose('dismiss')} aria-hidden />
      <div
        ref={box}
        className={`popover pp-pop ${className}`}
        role="dialog"
        aria-label={label}
        style={pos ? { left: pos.left, top: pos.top, width: pos.w, maxHeight: Math.min(520, pos.maxH) } : { visibility: 'hidden' }}
      >
        {children}
      </div>
    </>,
    document.body,
  );
}
