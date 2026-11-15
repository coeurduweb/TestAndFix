// The full records of an answer, in a card that opens beside what was pointed at (user, 2026-11-15:
// « plusieurs lignes d'un même type comme le TXT […] on voit +1, +2, +3 mais sans les valeurs », and a
// DKIM key is cut after a few characters). Decision of the same day, with carte blanche given:
//   - the list panel is wider (the map gives the room), so short answers (A, AAAA, MX) read in the row;
//   - a long or multiple answer opens this card on hover of a resolver, on focus of its value and on
//     click (a click pins it: touch screens and keyboards have no hover), every record in full, wrapped,
//     each one marked against the expected value (in plus, missing) and copyable;
//   - the headline opens the same card for the expected value.
// Not a modal: no scrim, the page stays usable, Escape or a click elsewhere closes it. Do not go back to
// a tooltip (`title`) for the values: invisible on touch, cut by the browser, not copyable.
import { Check, Copy } from 'lucide-react';
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { copyText, useToast } from '../../components/ui';
import { t, tn } from '../../lib/i18n';
import { sortValues } from './model';

/** An answer is worth a card when the row cannot show it whole: several records, an alias, or a long value. */
export const LONG_VALUE = 30;
export const needsPeek = (text: string) => text.includes('\n') || text.length > LONG_VALUE;

/** Open on hover after a short delay (no flicker while the pointer crosses the list), pinned by a click. */
export function usePeek() {
  const [open, setOpen] = useState(false);
  const [pinned, setPinned] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  const clear = () => window.clearTimeout(timer.current);
  useEffect(() => clear, []);
  return {
    open,
    pinned,
    show: useCallback((delay = 140) => {
      clear();
      timer.current = window.setTimeout(() => setOpen(true), delay);
    }, []),
    hide: useCallback(() => {
      clear();
      if (!pinned) timer.current = window.setTimeout(() => setOpen(false), 160);
    }, [pinned]),
    keep: useCallback(() => clear(), []),
    toggle: useCallback(() => {
      clear();
      setPinned((p) => !p);
      setOpen((o) => !(o && pinned));
    }, [pinned]),
    close: useCallback(() => {
      clear();
      setPinned(false);
      setOpen(false);
    }, []),
  };
}
export type PeekState = ReturnType<typeof usePeek>;

export function Peek({
  id,
  anchor,
  state,
  beside = false,
  label,
  head,
  children,
  width = 460,
}: {
  id: string;
  anchor: RefObject<HTMLElement | null>;
  state: PeekState;
  /** beside the list panel, over the map, when there is room; else under the anchor */
  beside?: boolean;
  label: string;
  head: ReactNode;
  children: ReactNode;
  width?: number;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; w: number; maxH: number } | null>(null);
  const { open, pinned, close, keep, hide } = state;

  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    const place = () => {
      const el = anchor.current;
      if (!el) return;
      const a = el.getBoundingClientRect();
      const vw = document.documentElement.clientWidth;
      const vh = window.innerHeight;
      const w = Math.min(width, vw - 32);
      // natural height, not the one already capped by a previous pass
      const h = box.current?.scrollHeight ?? 0;
      const panel = beside ? el.closest('.pp-list')?.getBoundingClientRect() : undefined;
      if (panel && panel.left - 12 - w >= 16) {
        const top = Math.max(16, Math.min(a.top - 8, vh - 16 - h));
        setPos({ left: panel.left - 12 - w, top, w, maxH: vh - 16 - top });
        return;
      }
      // under the anchor, else above, else on the side with more room, scrolling inside
      const below = vh - 16 - (a.bottom + 6);
      const above = a.top - 6 - 16;
      const left = Math.max(16, Math.min(a.left, vw - 16 - w));
      if (h <= below || below >= above) setPos({ left, top: a.bottom + 6, w, maxH: below });
      else setPos({ left, top: Math.max(16, a.top - 6 - h), w, maxH: above });
    };
    place();
    // a second pass once the height is known
    const raf = requestAnimationFrame(place);
    const onScroll = (e: Event) => {
      if (box.current?.contains(e.target as Node)) return;
      if (pinned) place();
      else close();
    };
    window.addEventListener('resize', place);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [open, pinned, anchor, beside, width, close]);

  useEffect(() => {
    if (!open) return;
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      close();
    };
    const down = (e: PointerEvent) => {
      const n = e.target as Node;
      if (box.current?.contains(n) || anchor.current?.contains(n)) return;
      close();
    };
    document.addEventListener('keydown', key, true);
    document.addEventListener('pointerdown', down, true);
    return () => {
      document.removeEventListener('keydown', key, true);
      document.removeEventListener('pointerdown', down, true);
    };
  }, [open, anchor, close]);

  if (!open) return null;
  return createPortal(
    <div
      ref={box}
      id={id}
      className="popover pk"
      role="dialog"
      aria-label={label}
      onMouseEnter={keep}
      onMouseLeave={hide}
      onFocus={keep}
      onBlur={(e) => !e.currentTarget.contains(e.relatedTarget as Node) && hide()}
      style={pos ? { position: 'fixed', left: pos.left, top: pos.top, width: pos.w, maxHeight: pos.maxH } : { position: 'fixed', left: 0, top: 0, visibility: 'hidden' }}
    >
      <div className="pk__head">{head}</div>
      {children}
    </div>,
    document.body,
  );
}

/**
 * The records of an answer, each in full, compared with the expected ones when given: the same, in
 * plus (served here, not expected), missing (expected, not served here).
 */
export function Records({ values, cname, reference, subset = false }: { values: string[]; cname?: string | null; reference?: string[] | null; subset?: boolean }) {
  const toast = useToast();
  const ref = reference ? new Set(reference) : null;
  const served = new Set(values);
  const missing = reference ? sortValues(reference.filter((v) => !served.has(v))) : [];
  const extra = ref ? values.filter((v) => !ref.has(v)).length : 0;
  // « contains » mode: what is served in plus is allowed
  const same = !!ref && (subset || extra === 0) && missing.length === 0;
  const copy = async (v: string) => {
    if (await copyText(v)) toast(t('Copié'));
  };
  const line = (v: string, kind: 'same' | 'extra' | 'missing' | 'plain') => (
    <li key={kind + v} className={`pk-rec pk-rec--${kind}`}>
      <code className="mono">{v}</code>
      <span className="pk-rec__side">
        {kind === 'extra' && <span className="pk-tag pk-tag--warn">{t('en plus')}</span>}
        {kind === 'missing' && <span className="pk-tag pk-tag--out">{t('manque')}</span>}
        {kind !== 'missing' && (
          <button type="button" className="btn btn--icon btn--ghost pk-copy" onClick={() => copy(v)} aria-label={t('Copier cette valeur')} title={t('Copier')}>
            <Copy aria-hidden />
          </button>
        )}
      </span>
    </li>
  );
  return (
    <>
      {ref && (
        <p className={`pk-sum ${same ? 'pk-sum--ok' : 'pk-sum--warn'}`}>
          {same ? (
            <>
              <Check aria-hidden /> {subset ? t('Contient la valeur attendue') : t('Identique à la valeur attendue')}
            </>
          ) : (
            [extra ? tn(extra, '{n} valeur en plus', '{n} valeurs en plus') : '', missing.length ? tn(missing.length, '{n} valeur attendue manque', '{n} valeurs attendues manquent') : '']
              .filter(Boolean)
              .join(', ')
          )}
        </p>
      )}
      <ul className="pk-recs">
        {cname && line(`→ ${cname}`, 'plain')}
        {sortValues(values).map((v) => line(v, !ref ? 'plain' : ref.has(v) ? 'same' : subset ? 'plain' : 'extra'))}
        {missing.map((v) => line(v, 'missing'))}
      </ul>
    </>
  );
}
