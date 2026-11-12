// "Signal" (2026-11-11): the verdict strip (state, subject, number, 20-cell meter), the work list
// (one row per finding, opened in place, grouped by what it does to delivery) and what is fine,
// folded. Every result page opens with these. Mockup: claude.ai/artifact/N8k9en4MPiLdUeQwT2MRDW.
import { useState, type ComponentType, type ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, CircleSlash, OctagonAlert, RotateCw } from 'lucide-react';
import type { Finding, PassedCheck } from '../lib/types';
import { fmtPenalty, fmtScore, plural } from '../lib/format';
import { CodeBlock } from './ui';
import { providerName } from './Report';
import { msg, rich, t } from '../lib/i18n';

export type Tone = 'good' | 'watch' | 'bad' | 'pending' | 'neutral';

export function toneOf(score: number | null | undefined, findings?: Finding[]): Tone {
  if (score === null || score === undefined) return 'pending';
  // without the findings we cannot tell what is behind the score: only a perfect 10 reads as good
  if (!findings) return score >= 10 ? 'good' : score >= 6 ? 'watch' : 'bad';
  const critical = findings.some((f) => f.penalty > 0 && (f.severity === 'critical' || f.severity === 'high'));
  if (score >= 9 && !critical) return 'good';
  if (score >= 6) return 'watch';
  return 'bad';
}

const MOOD: Record<Tone, string> = {
  good: msg('Excellent'),
  watch: msg('À améliorer'),
  bad: msg('À corriger'),
  pending: msg('Mesure en cours'),
  neutral: msg('Non mesuré'),
};

const sev = (f: Finding): 'out' | 'warn' | 'info' =>
  f.penalty <= 0 ? 'info' : f.severity === 'critical' || f.severity === 'high' ? 'out' : 'warn';

/** One sentence in plain French: what is going on, and the first thing to do. */
export function verdictSentence(findings: Finding[], passed: PassedCheck[]): string {
  const out = findings.filter((f) => sev(f) === 'out');
  const warn = findings.filter((f) => sev(f) === 'warn');
  const top = [...out, ...warn].sort((a, b) => b.penalty - a.penalty)[0];
  if (!top) return passed.length ? t('Tout est en ordre : {checks}.', { checks: plural(passed.length, 'contrôle réussi', 'contrôles réussis') }) : t('Rien à signaler.');
  const parts: string[] = [];
  if (out.length) parts.push(plural(out.length, 'problème à corriger', 'problèmes à corriger'));
  if (warn.length) parts.push(plural(warn.length, 'point à surveiller', 'points à surveiller'));
  const list = parts.length > 1 ? t('{a} et {b}', { a: parts[0], b: parts[1] }) : parts[0];
  return t('{list}. Le plus important : {top}.', { list, top: lowerFirst(top.title) });
}
const lowerFirst = (s: string) => (s.length > 1 && s[1] === s[1].toLowerCase() ? s[0].toLowerCase() + s.slice(1) : s);

/* ---------- meter: 20 cells of half a point ---------- */
type Kind = 'out' | 'warn' | 'lost';
const usesImpact = (findings: Finding[]) => findings.some((f) => f.impact);
const kindOf = (f: Finding, impact: boolean): Kind =>
  impact ? (f.impact === 'blocking' ? 'out' : f.impact === 'spam' ? 'warn' : 'lost') : sev(f) === 'out' ? 'out' : sev(f) === 'warn' ? 'warn' : 'lost';
const KIND_LABEL = {
  impact: { out: msg('bloquant'), warn: msg('risque'), lost: msg('améliorations') },
  plain: { out: msg('à corriger'), warn: msg('à surveiller'), lost: msg('autres') },
} as const;
const KIND_COLOR: Record<Kind, string> = { out: 'var(--out)', warn: 'var(--warn)', lost: 'var(--surface-press)' };

export function ScoreBar({ score, findings }: { score: number | null; findings: Finding[]; onPick?: (id: string) => void }) {
  const impact = usesImpact(findings);
  const lostBy: Record<Kind, number> = { out: 0, warn: 0, lost: 0 };
  for (const f of findings) if (f.penalty > 0) lostBy[kindOf(f, impact)] += f.penalty;
  const total = lostBy.out + lostBy.warn + lostBy.lost;
  const kept = score === null ? 0 : Math.max(0, Math.min(20, Math.round(score * 2)));
  const free = 20 - kept;
  // lost cells shared by kind, in proportion to the points each kind cost
  const share: Record<Kind, number> = { out: 0, warn: 0, lost: 0 };
  if (score !== null && free > 0) {
    let left = free;
    for (const k of ['out', 'warn'] as const) {
      share[k] = total ? Math.min(left, Math.round((lostBy[k] / total) * free)) : 0;
      left -= share[k];
    }
    share.lost = left;
  }
  const cells: string[] = [];
  for (let i = 0; i < kept; i++) cells.push('');
  for (const k of ['out', 'warn', 'lost'] as const) for (let i = 0; i < share[k]; i++) cells.push(`is-${k}`);
  while (cells.length < 20) cells.push('is-lost');
  const labels = KIND_LABEL[impact ? 'impact' : 'plain'];
  const summary =
    score === null
      ? t('Note en cours de calcul')
      : total
        ? t('{score} sur 10. Points perdus : {lost}', {
            score: fmtScore(score),
            lost: (['out', 'warn', 'lost'] as const).filter((k) => lostBy[k] > 0).map((k) => `${t(labels[k])} ${fmtPenalty(lostBy[k])}`).join(', '),
          })
        : t('{score} sur 10', { score: fmtScore(score) });
  return (
    <>
      <div className={`meter${score === null ? ' meter--pending' : ''}`} role="img" aria-label={summary}>
        {cells.map((c, i) => (
          <i key={i} className={c || undefined} style={{ ['--i' as string]: i }} />
        ))}
      </div>
      {score !== null && total > 0 && (
        <div className="meter-cap" aria-hidden>
          {(['out', 'warn', 'lost'] as const)
            .filter((k) => lostBy[k] > 0)
            .map((k) => (
              <span key={k}>
                <i style={{ background: KIND_COLOR[k] }} />
                {t(labels[k])} −{fmtPenalty(lostBy[k])}
              </span>
            ))}
        </div>
      )}
    </>
  );
}

/* ---------- verdict strip ---------- */
export function Verdict({
  subject,
  facts = [],
  score,
  findings,
  passed = [],
  pending,
  actions,
  sentence,
  unmeasured,
  mood,
  tone: forced,
  icon,
}: {
  /** No score can be given (port blocked, nothing to measure): neutral strip, never "in progress". */
  unmeasured?: boolean;
  subject: ReactNode;
  facts?: { label: string; value: ReactNode }[];
  score?: number | null;
  findings?: Finding[];
  passed?: PassedCheck[];
  pending?: boolean;
  actions?: ReactNode;
  sentence?: ReactNode;
  /** replaces the state label ("Excellent", "À corriger"...) */
  mood?: ReactNode;
  /** forces the state colour (a mail that cannot be delivered is red whatever its score) */
  tone?: Tone;
  /** replaces the state icon (the notebook shows a lock) */
  icon?: ComponentType<{ 'aria-hidden'?: boolean; className?: string }>;
}) {
  const tone: Tone = forced ?? (unmeasured ? 'neutral' : pending ? 'pending' : toneOf(score, findings));
  const Icon = icon ?? (tone === 'good' ? CheckCircle2 : tone === 'watch' ? AlertTriangle : tone === 'bad' ? OctagonAlert : tone === 'neutral' ? CircleSlash : RotateCw);
  return (
    <header className={`verdict verdict--${tone}`}>
      <div className="verdict__main">
        <div className="verdict__mood">
          <Icon aria-hidden className={tone === 'pending' ? 'spin' : undefined} />
          {mood ?? t(MOOD[tone])}
        </div>
        <h1 className="verdict__subject">{subject}</h1>
        {(pending || sentence || findings) && (
          <p className="verdict__sentence">{pending ? t('Les résultats arrivent au fur et à mesure.') : sentence ?? verdictSentence(findings ?? [], passed)}</p>
        )}
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
      </div>
      {!unmeasured && (score !== undefined || pending) && (
        <div className="verdict__score">
          <div className="verdict__number" aria-hidden>
            {score === null || score === undefined ? <span className="skel verdict__wait" /> : fmtScore(score)}
            <small>/10</small>
          </div>
          <ScoreBar score={score ?? null} findings={findings ?? []} />
        </div>
      )}
      {actions && <div className="verdict__actions">{actions}</div>}
    </header>
  );
}

/* ---------- the work list ---------- */
const AXIS_LABEL = { sender: msg('Expéditeur'), message: msg('Message') } as const;

/** One finding as a row; opens in place on the cause, the fix, what was measured and the sources. */
export function IssueCard({ f, extra, defaultOpen = false }: { f: Finding; extra?: ReactNode; index?: number; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const k = kindOf(f, Boolean(f.impact));
  const bodyId = `issue-${f.id}-body`;
  return (
    <li className="todo__item" id={`issue-${f.id}`}>
      <button type="button" className="todo__row" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen((o) => !o)}>
        {k === 'lost' ? <span aria-hidden /> : <span className={`dot dot--${k}`} aria-hidden />}
        <span className="todo__t">{f.title}</span>
        {f.axis ? <span className={`axis-tag axis-tag--${f.axis}`}>{t(AXIS_LABEL[f.axis])}</span> : <span aria-hidden />}
        <span className={`todo__pts${f.penalty > 0 && k !== 'lost' ? ` todo__pts--${k}` : ''}`}>
          {f.penalty > 0 ? `−${fmtPenalty(f.penalty)}` : '0'}
          <span className="visually-hidden"> {t('point')}</span>
        </span>
        <span className="todo__chev" aria-hidden />
      </button>
      {open && (
        <div className="todo__open" id={bodyId}>
          {f.why && <p>{f.why}</p>}
          {f.suggested && <CodeBlock code={f.suggested} label={t('Correction à appliquer')} tone="suggested" copyLabel={t('Copier la correction')} />}
          {f.fix.length > 0 && (
            <ol className="steps">
              {f.fix.map((x, i) => (
                <li key={i}>{x}</li>
              ))}
            </ol>
          )}
          {f.providerFix && (
            <p>
              {rich('<b>Chez {provider} :</b>', { provider: providerName(f.providerFix.provider) }, { b: (c) => <strong>{c}</strong> })} {f.providerFix.text}
            </p>
          )}
          {extra}
          {f.evidence && <CodeBlock code={f.evidence} label={t('Mesuré')} />}
          {f.exampleBad && <CodeBlock code={f.exampleBad} label={t('À éviter')} tone="bad" />}
          {f.exampleGood && !f.suggested && <CodeBlock code={f.exampleGood} label={t('Exemple correct')} />}
          {f.references.length > 0 && (
            <div className="seen">
              <span>
                {t('Sources')}{' '}
                {f.references.map((r, i) => (
                  <a key={r} href={r} target="_blank" rel="noreferrer noopener">
                    {shortRef(r)}
                    {i < f.references.length - 1 ? ', ' : ''}
                  </a>
                ))}
              </span>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

type Group = { key: string; label: string; tone: 'out' | 'warn' | 'n'; note?: string; items: Finding[] };

function groupsOf(findings: Finding[], title: string): { groups: Group[]; remarks: Finding[] } {
  const byPoints = (a: Finding, b: Finding) => b.penalty - a.penalty;
  if (usesImpact(findings)) {
    // mail reports: what blocks delivery, what risks the spam folder, what only improves
    const of = (i: Finding['impact']) => findings.filter((f) => f.impact === i).sort(byPoints);
    return {
      groups: [
        { key: 'blocking', label: t('Bloque la livraison'), tone: 'out' as const, items: of('blocking') },
        { key: 'spam', label: t("Risque d'indésirables"), tone: 'warn' as const, items: of('spam') },
        { key: 'advice', label: t('Améliorations'), tone: 'n' as const, note: t('sans effet notable sur la livraison'), items: of('advice') },
      ].filter((g) => g.items.length),
      remarks: findings.filter((f) => !f.impact),
    };
  }
  return {
    groups: [
      { key: 'out', label: title, tone: 'out' as const, items: findings.filter((f) => sev(f) === 'out').sort(byPoints) },
      { key: 'warn', label: t('À surveiller'), tone: 'warn' as const, items: findings.filter((f) => sev(f) === 'warn').sort(byPoints) },
    ].filter((g) => g.items.length),
    remarks: findings.filter((f) => f.penalty <= 0),
  };
}

export function IssueList({
  findings,
  title,
  empty,
  extra,
  passed,
  label,
}: {
  findings: Finding[];
  title?: string;
  empty?: ReactNode;
  extra?: (f: Finding) => ReactNode;
  /** what is fine, folded at the end of the same list */
  passed?: PassedCheck[];
  label?: string;
}) {
  const heading = title ?? t('À corriger');
  const { groups, remarks } = groupsOf(findings, heading);
  const [remarksOpen, setRemarksOpen] = useState(false);
  if (!groups.length && !remarks.length && !empty && !passed?.length) return null;
  let first = true;
  return (
    <section className="surface todo" aria-label={label ?? t('À traiter')}>
      {!groups.length && empty && (
        <>
          <h2 className="todo__group todo__group--ok">
            <span className="dot dot--ok" aria-hidden />
            {heading}
            <span className="todo__n">0</span>
          </h2>
          <div className="todo__open" style={{ background: 'none', paddingTop: 0 }}>
            {empty}
          </div>
        </>
      )}
      {groups.map((g) => (
        <div key={g.key}>
          <h2 className={`todo__group${g.tone !== 'n' ? ` todo__group--${g.tone}` : ''}`}>
            <span className={`dot${g.tone !== 'n' ? ` dot--${g.tone}` : ''}`} aria-hidden />
            {g.label}
            <span className="todo__n">{g.items.length}</span>
            {g.note && <span className="todo__note">{g.note}</span>}
          </h2>
          <ul className="todo__list" role="list" style={{ margin: 0, padding: 0, listStyle: 'none', borderTop: '1px solid var(--rule)' }}>
            {g.items.map((f, i) => {
              const open = first && g.tone !== 'n';
              if (open) first = false;
              return <IssueCard key={f.id + i} f={f} extra={extra?.(f)} defaultOpen={open} />;
            })}
          </ul>
        </div>
      ))}
      {remarks.length > 0 && (
        <>
          <button type="button" className="todo__more" aria-expanded={remarksOpen} onClick={() => setRemarksOpen((o) => !o)}>
            <span className="dot" aria-hidden />
            {plural(remarks.length, 'remarque sans effet sur la note', 'remarques sans effet sur la note')}
            <span className="todo__go">{remarksOpen ? t('Masquer') : t('Voir')}</span>
          </button>
          {remarksOpen && (
            <ul className="todo__list" role="list" style={{ margin: 0, padding: 0, listStyle: 'none', borderTop: '1px solid var(--rule)' }}>
              {remarks.map((f, i) => (
                <IssueCard key={f.id + i} f={f} extra={extra?.(f)} />
              ))}
            </ul>
          )}
        </>
      )}
      {passed && passed.length > 0 && <PassRows passed={passed} />}
    </section>
  );
}

function PassRows({ passed, title }: { passed: PassedCheck[]; title?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="todo__more" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="dot dot--ok" aria-hidden />
        <b>{title ?? plural(passed.length, 'contrôle réussi', 'contrôles réussis')}</b>
        <span className="todo__go">{open ? t('Masquer') : t('Voir')}</span>
      </button>
      {open && (
        <ul className="todo__passes">
          {passed.map((p, i) => (
            <li key={p.id + i}>
              <CheckCircle2 aria-hidden />
              <span>
                {p.title}
                {p.detail && <small>{p.detail}</small>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/* ---------- what is fine, on its own ---------- */
export function PassList({ passed, title }: { passed: PassedCheck[]; title?: string; limit?: number }) {
  if (!passed.length) return null;
  return (
    <section className="surface todo" aria-label={title ?? t('Ce qui va bien')}>
      <PassRows passed={passed} title={title ? t('{title} : {checks}', { title, checks: plural(passed.length, 'contrôle réussi', 'contrôles réussis') }) : undefined} />
    </section>
  );
}

/** Collapsible block for the technical tables, closed by default. */
export function Details({ title, children, defaultOpen = false, count }: { title: string; children: ReactNode; defaultOpen?: boolean; count?: ReactNode }) {
  return (
    <details className="details" open={defaultOpen}>
      <summary>
        <span className="details__title">{title}</span>
        {count && <span className="details__count">{count}</span>}
      </summary>
      <div className="details__body">{children}</div>
    </details>
  );
}

function shortRef(u: string) {
  try {
    const x = new URL(u);
    const rfc = /rfc(\d+)/i.exec(u);
    if (rfc && x.hostname.includes('rfc-editor')) return `RFC ${rfc[1]}`;
    return x.hostname.replace(/^www\./, '');
  } catch {
    return u;
  }
}
