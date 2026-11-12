// One shape per status, so the map, the filters and the table never depend on colour alone:
// disc up to date, dotted ring regional answer, triangle late, diamond absent, barred ring rewritten, cross failed, ring waiting.
import { msg } from '../../lib/i18n';
import type { RowStatus } from './model';

export const STATUS_LABEL: Record<RowStatus, string> = {
  fresh: msg('à jour'),
  regional: msg('réponse régionale'),
  stale: msg('en retard'),
  missing: msg('absent'),
  rewritten: msg('réécrit'),
  error: msg('erreur'),
  timeout: msg('sans réponse'),
  pending: msg('en attente'),
};

/** The shape centred on (x, y), sized by r. */
export function Shape({ status, r, x = 0, y = 0 }: { status: RowStatus; r: number; x?: number; y?: number }) {
  const cls = `pm-shape pm-shape--${status === 'timeout' ? 'error' : status}`;
  switch (status) {
    case 'fresh':
      return <circle className={cls} cx={x} cy={y} r={r} />;
    case 'regional':
      // a ring with its centre: up to date, but a value of its own
      return (
        <g className={cls}>
          <circle cx={x} cy={y} r={r * 0.92} strokeWidth={r * 0.4} />
          <circle cx={x} cy={y} r={r * 0.36} />
        </g>
      );
    case 'stale':
      return <path className={cls} d={`M${x} ${y - r * 1.2}L${x + r * 1.1} ${y + r * 0.8}L${x - r * 1.1} ${y + r * 0.8}Z`} />;
    case 'missing':
      return <path className={cls} d={`M${x} ${y - r * 1.15}L${x + r * 1.15} ${y}L${x} ${y + r * 1.15}L${x - r * 1.15} ${y}Z`} />;
    case 'rewritten':
      // a "no entry" sign: barred ring
      return (
        <g className={cls}>
          <circle cx={x} cy={y} r={r * 0.95} fill="none" strokeWidth={r * 0.42} />
          <path d={`M${x - r * 0.68} ${y + r * 0.68}L${x + r * 0.68} ${y - r * 0.68}`} strokeWidth={r * 0.42} />
        </g>
      );
    case 'error':
    case 'timeout':
      return (
        <path
          className={cls}
          d={`M${x - r * 0.8} ${y - r * 0.8}L${x + r * 0.8} ${y + r * 0.8}M${x + r * 0.8} ${y - r * 0.8}L${x - r * 0.8} ${y + r * 0.8}`}
          strokeWidth={r * 0.55}
        />
      );
    case 'pending':
      return <circle className={cls} cx={x} cy={y} r={r * 0.75} strokeWidth={r * 0.35} />;
  }
}

/** Inline mark for chips and table cells (decorative: the text next to it carries the status). */
export function StatusMark({ status, size = 12 }: { status: RowStatus; size?: number }) {
  return (
    <svg className="pm-mark" viewBox="-6 -6 12 12" width={size} height={size} aria-hidden focusable="false">
      <Shape status={status} r={4.2} />
    </svg>
  );
}
