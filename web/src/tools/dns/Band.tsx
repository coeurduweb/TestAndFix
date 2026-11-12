// The v2 verdict band for results that are not a score out of 10: a count of records (DNS lookup)
// or a percentage up to date (propagation). Same classes as components/Verdict.tsx, so the look is
// shared; only the big number and its unit change.
import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, OctagonAlert, RotateCw } from 'lucide-react';

export type BandTone = 'good' | 'watch' | 'bad' | 'pending';

const ICON = { good: CheckCircle2, watch: AlertTriangle, bad: OctagonAlert, pending: RotateCw } as const;

export function Band({
  tone,
  mood,
  subject,
  sentence,
  facts = [],
  actions,
  big,
  unit,
  bigLabel,
  under,
}: {
  tone: BandTone;
  mood: string;
  subject: ReactNode;
  sentence: ReactNode;
  facts?: { label: string; value: ReactNode }[];
  actions?: ReactNode;
  big?: ReactNode;
  unit?: string;
  /** Accessible reading of the big number. */
  bigLabel?: string;
  /** Under the big number (a short line). */
  under?: ReactNode;
}) {
  const Icon = ICON[tone];
  return (
    <header className={`verdict verdict--${tone}`}>
      <div className="verdict__main">
        <div className="verdict__mood">
          <Icon aria-hidden className={tone === 'pending' ? 'spin' : undefined} />
          {mood}
        </div>
        <h1 className="verdict__subject">{subject}</h1>
        <p className="verdict__sentence" aria-live="polite">
          {sentence}
        </p>
        {facts.length > 0 && (
          <dl className="verdict__facts">
            {facts.map((f) => (
              <div key={f.label}>
                <dt>{f.label}</dt>
                <dd>{f.value}</dd>
              </div>
            ))}
          </dl>
        )}
        {actions && <div className="verdict__actions">{actions}</div>}
      </div>
      {big !== undefined && (
        <div className="verdict__score">
          <div className="verdict__number" aria-label={bigLabel}>
            {big}
            {unit && <small>{unit}</small>}
          </div>
          {under && <div className="band__under">{under}</div>}
        </div>
      )}
    </header>
  );
}
