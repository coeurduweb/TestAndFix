// Measured rows with the findings they stand for folded under them; the findings that stand for
// no row follow in the same table. Shared by the scanner and the detailed domain pages.
import type { ReactNode } from 'react';
import { FindingDetail, FindingRow, LabRow, LabTable } from '../../components/Report';
import type { Finding } from '../../lib/types';
import { attach, evidenceSubject, rowDeviation, rowPenalty, type AttachedMetric, type Metric } from './rows';

export function MetricLabel({ label, mono, sub, depth = 0 }: { label: ReactNode; mono?: boolean; sub?: ReactNode; depth?: number }) {
  return (
    <span className={`dm-label${depth ? ' dm-label--child' : ''}`} style={depth ? { marginLeft: `calc(${depth - 1} * var(--s4))` } : undefined}>
      <span className={mono ? 'mono dm-label__mono' : undefined}>{label}</span>
      {sub && <span className="dm-label__sub">{sub}</span>}
    </span>
  );
}

export function MetricTable({
  rows,
  findings = [],
  autoOpen,
  extra,
  showRest = true,
  openKey,
  sort,
}: {
  rows: Metric[];
  findings?: Finding[];
  /** Open the heaviest penalized row of this table. */
  autoOpen?: boolean;
  /** Extra content under a row, by row key (records, chains). */
  extra?: Record<string, ReactNode>;
  showRest?: boolean;
  /** Row to open, instead of the heaviest one. */
  openKey?: string;
  /** Heaviest rows first (the order of the measure otherwise). */
  sort?: boolean;
}) {
  const { rows: attached, rest } = attach(rows, findings);
  const restShown = showRest ? rest : [];
  let open: string | undefined = openKey;
  if (autoOpen && !open) {
    let best = 0;
    for (const r of attached) if (rowPenalty(r) > best) (best = rowPenalty(r)), (open = r.key);
    restShown.forEach((f, i) => {
      if (f.penalty > best) (best = f.penalty), (open = `rest-${i}`);
    });
  }
  const items = [
    ...attached.map((r, i) => ({ key: r.key, pen: rowPenalty(r), i, node: <MetricRow key={r.key} r={r} extra={extra?.[r.key]} defaultOpen={open === r.key} /> })),
    ...restShown.map((f, i) => ({
      key: `rest-${i}`,
      pen: Math.max(0, f.penalty),
      i: attached.length + i,
      node: <FindingRow key={`${f.id}-${i}`} f={f} measured={evidenceSubject(f.evidence)} defaultOpen={open === `rest-${i}`} />,
    })),
  ];
  if (sort) items.sort((a, b) => b.pen - a.pen || a.i - b.i);
  return <LabTable>{items.map((x) => x.node)}</LabTable>;
}

function MetricRow({ r, extra, defaultOpen }: { r: AttachedMetric; extra?: ReactNode; defaultOpen?: boolean }) {
  const hasDetail = r.findings.length > 0 || !!extra;
  return (
    <LabRow
      label={<MetricLabel label={r.label} mono={r.mono} sub={r.sub} depth={r.depth} />}
      measured={r.measured}
      reference={r.reference}
      deviation={rowDeviation(r)}
      defaultOpen={defaultOpen}
      detail={
        hasDetail ? (
          <>
            {r.findings.map((f, i) => (
              <div key={i} className="dm-finding">
                <div className="dm-finding__title">{f.title}</div>
                <FindingDetail f={f} />
              </div>
            ))}
            {extra}
          </>
        ) : undefined
      }
    />
  );
}
