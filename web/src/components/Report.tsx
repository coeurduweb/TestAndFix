// The lab-report vocabulary: report header with the result number, sections in small caps,
// rows "Contrôle | Mesuré | Référence | Écart", out-of-range rows weighted and expandable.
import { createContext, useContext, useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, Check, ChevronRight, RotateCw } from 'lucide-react';
import type { CheckResult, Finding, PassedCheck } from '../lib/types';
import { fmtDateTime, fmtMs, fmtPenalty, fmtScore, plural, scoreBand } from '../lib/format';
import { CodeBlock, CopyButton, Notice } from './ui';
import { IssueList, Verdict } from './Verdict';
import { msg, rich, t } from '../lib/i18n';

/* ---------- header ---------- */
export function ReportHeader({
  subject,
  meta,
  score,
  scoreLabel,
  pending,
  actions,
  findings,
  passed,
  sentence,
  unmeasured,
}: {
  unmeasured?: boolean;
  subject: ReactNode;
  meta?: { label: string; value: ReactNode }[];
  score?: number | null;
  scoreLabel?: ReactNode;
  pending?: boolean;
  actions?: ReactNode;
  /** When given, the verdict sentence and the score bar explain the score. */
  findings?: Finding[];
  passed?: PassedCheck[];
  sentence?: ReactNode;
}) {
  // v2 (2026-11-10): every result opens on the verdict band; scoreLabel is kept for compatibility
  void scoreLabel;
  return <Verdict subject={subject} facts={meta} score={score} pending={pending} actions={actions} findings={findings} passed={passed} sentence={sentence} unmeasured={unmeasured} />;
}

export function Score({ value, label, pending }: { value: number | null; label?: ReactNode; pending?: boolean }) {
  const band = value === null ? undefined : scoreBand(value);
  return (
    <div className={`score ${pending ? 'score--pending' : ''}`} data-band={band}>
      <div className="score__value" aria-label={value === null ? t('Note en cours de calcul') : t('Note : {score} sur 10', { score: fmtScore(value) })}>
        {value === null ? '…' : fmtScore(value)}
        <small>/10</small>
      </div>
      {label && <div className="score__label">{label}</div>}
    </div>
  );
}

/** "3 valeurs hors bornes · 9 conformes" */
export function scoreSummary(findings: Finding[], passed: PassedCheck[]): ReactNode {
  // red only for what is really out of range; amber alerts are counted apart
  const out = findings.filter((f) => f.penalty > 0 && deviationOf(f).kind === 'out').length;
  const warn = findings.filter((f) => f.penalty > 0 && deviationOf(f).kind === 'warn').length;
  return (
    <>
      {out > 0 ? <strong>{plural(out, 'valeur hors bornes', 'valeurs hors bornes')}</strong> : t('Aucune valeur hors bornes')}
      {warn > 0 && (
        <>
          {' · '}
          <span className="score__warn">{plural(warn, 'à surveiller', 'à surveiller')}</span>
        </>
      )}
      {' · '}
      {plural(passed.length, 'conforme', 'conformes')}
    </>
  );
}

export function MeasuredMeta(r: Pick<CheckResult, 'measuredAt' | 'ms'>) {
  return [
    { label: t('Mesuré le'), value: fmtDateTime(r.measuredAt) },
    ...(r.ms !== undefined ? [{ label: t('Durée'), value: fmtMs(r.ms) }] : []),
  ];
}

export function RerunButton({ onClick, busy }: { onClick: () => void; busy?: boolean }) {
  return (
    <button type="button" className="btn btn--sm" onClick={onClick} disabled={busy} aria-busy={busy || undefined}>
      <RotateCw aria-hidden className={busy ? 'spin' : undefined} />
      {t('Mesurer à nouveau')}
    </button>
  );
}

/* ---------- section ---------- */
export function LabSection({ title, children, count, id }: { title: string; children: ReactNode; count?: { out: number; total: number; warn?: number }; id?: string }) {
  return (
    <section className="lab-section" id={id} aria-labelledby={id ? `${id}-t` : undefined}>
      <div className="lab-section__head">
        <h2 className="lab-section__title" id={id ? `${id}-t` : undefined}>
          {title}
        </h2>
        {count && (
          <span className="lab-section__count">
            {count.out > 0 ? <b>{t('{n} hors bornes', { n: count.out })}</b> : count.warn ? <span className="score__warn">{t('{n} à surveiller', { n: count.warn })}</span> : t('conforme')}
            {count.out > 0 && count.warn ? <> · <span className="score__warn">{t('{n} à surveiller', { n: count.warn })}</span></> : null} · {plural(count.total, 'contrôle', 'contrôles')}
          </span>
        )}
      </div>
      {children}
    </section>
  );
}

/* ---------- table ---------- */
const ColumnsCtx = createContext<string[]>([]);
const defaultColumns = () => [t('Contrôle'), t('Mesuré'), t('Référence'), t('Écart')];

export function LabTable({ children, columns = defaultColumns() }: { children: ReactNode; columns?: string[] }) {
  return (
    <ColumnsCtx.Provider value={columns}>
    <div className="lab-table-wrap">
    <table className="lab-table">
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
    </div>
    </ColumnsCtx.Provider>
  );
}

export type DevKind = 'out' | 'warn' | 'ok' | 'info' | 'pending';

export interface Deviation {
  kind: DevKind;
  /** e.g. "1" for ↑ 1, "1,0" for a score penalty */
  text?: string;
  direction?: 'up' | 'down';
  label?: string;
}

export function Dev({ d }: { d: Deviation }) {
  if (d.kind === 'pending') return <span className="dev dev--info">{d.text ?? t('en cours')}</span>;
  if (d.kind === 'ok')
    return (
      <span className="dev dev--ok">
        <Check aria-hidden />
        {d.text ?? t('conforme')}
      </span>
    );
  if (d.kind === 'info')
    return (
      <span className="dev dev--info">
        <span className="dot" aria-hidden />
        {d.text ?? t('noté')}
      </span>
    );
  const Arrow = d.direction === 'up' ? ArrowUp : ArrowDown;
  return (
    <span className={`dev dev--${d.kind}`} aria-label={d.label}>
      <Arrow aria-hidden />
      {d.text}
    </span>
  );
}

export function LabRow({
  label,
  measured,
  reference,
  deviation,
  detail,
  defaultOpen = false,
}: {
  label: ReactNode;
  measured?: ReactNode;
  reference?: ReactNode;
  deviation: Deviation;
  detail?: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const kind = deviation.kind;
  const columns = useContext(ColumnsCtx);
  const refLabel = columns[2] === t('Référence') ? t('réf.') : columns[2] ? t('{name} :', { name: columns[2].toLowerCase() }) : undefined;
  return (
    <tbody>
      <tr className={`lab-row lab-row--${kind} ${detail ? 'lab-row--expandable' : ''}`} onClick={detail ? (e) => {
        if ((e.target as HTMLElement).closest('button, a')) return;
        setOpen((o) => !o);
      } : undefined}>
        <td className="c-check">
          {detail ? (
            <button type="button" className="lab-row__toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
              <ChevronRight aria-hidden />
              <span>{label}</span>
            </button>
          ) : (
            <span style={{ paddingLeft: 'calc(0.875rem + var(--s2))', display: 'inline-block' }}>{label}</span>
          )}
        </td>
        <td className="c-val">{measured}</td>
        <td className="c-ref" data-label={refLabel}>{reference}</td>
        <td className="c-dev">
          <Dev d={deviation} />
        </td>
      </tr>
      {detail && open && (
        <tr className="lab-detail">
          <td colSpan={4}>
            <div className="lab-detail__body">{detail}</div>
          </td>
        </tr>
      )}
    </tbody>
  );
}

/* ---------- findings ---------- */
export function deviationOf(f: Finding): Deviation {
  if (f.penalty <= 0) return { kind: 'info', text: t('noté') };
  const kind: DevKind = f.severity === 'critical' || f.severity === 'high' ? 'out' : 'warn';
  return { kind, text: fmtPenalty(f.penalty), direction: 'down', label: t('Retire {n} point de la note', { n: fmtPenalty(f.penalty) }) };
}

export function FindingDetail({ f, extra }: { f: Finding; extra?: ReactNode }) {
  return (
    <>
      {f.why && <p className="lab-detail__why">{f.why}</p>}
      {f.evidence && <CodeBlock code={f.evidence} label={t('Constaté')} />}
      {f.suggested && <CodeBlock code={f.suggested} label={t('Correction proposée')} tone="suggested" />}
      {f.fix.length > 0 && (
        <div>
          <div className="lab-detail__label">{t('Correction')}</div>
          <ol className="lab-detail__fix">
            {f.fix.map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ol>
        </div>
      )}
      {f.providerFix && (
        <div className="lab-detail__provider">
          {rich('<b>Chez {provider} :</b> ', { provider: providerName(f.providerFix.provider) }, { b: (c) => <strong>{c}</strong> })}
          {f.providerFix.text}
        </div>
      )}
      {(f.exampleBad || f.exampleGood) && (
        <div className="stack-sm">
          {f.exampleBad && <CodeBlock code={f.exampleBad} label={t('À éviter')} tone="bad" />}
          {f.exampleGood && <CodeBlock code={f.exampleGood} label={t('Exemple correct')} />}
        </div>
      )}
      {extra}
      {f.references.length > 0 && <References refs={f.references} />}
    </>
  );
}

export function FindingRow({ f, measured, reference, defaultOpen }: { f: Finding; measured?: ReactNode; reference?: ReactNode; defaultOpen?: boolean }) {
  const ev = measured ?? (f.evidence && f.evidence.length <= 60 && !f.evidence.includes('\n') ? f.evidence : undefined);
  return <LabRow label={f.title} measured={ev} reference={reference} deviation={deviationOf(f)} detail={<FindingDetail f={f} />} defaultOpen={defaultOpen} />;
}

export function PassedRow({ p, measured, reference }: { p: PassedCheck; measured?: ReactNode; reference?: ReactNode }) {
  return <LabRow label={p.title} measured={measured ?? p.detail} reference={reference} deviation={{ kind: 'ok' }} />;
}

/* ---------- families → sections ---------- */
// section names are msgids: sectionOf() translates them
const AUTH = msg('Authentification');
const INFRA = msg('Infrastructure');
const REPUTATION = msg('Réputation');
const CONTENT = msg('Contenu');
const UNSUB = msg('Désinscription et conformité');
export const SECTION_OF_FAMILY: Record<string, string> = {
  spf: AUTH, dkim: AUTH, dmarc: AUTH, arc: AUTH,
  bimi: AUTH, alignment: AUTH,
  rdns: INFRA, helo: INFRA, tls: INFRA, mx: INFRA,
  'mta-sts': INFRA, dnssec: INFRA, infrastructure: INFRA,
  blacklist: REPUTATION, reputation: REPUTATION, 'dmarc-report': msg('Sources d’envoi'),
  headers: msg('En-têtes'), content: CONTENT, html: CONTENT, links: msg('Liens'), images: CONTENT, attachments: msg('Pièces jointes'),
  unsubscribe: UNSUB, 'bulk-sender': UNSUB,
  spamassassin: msg('SpamAssassin'), sa: msg('SpamAssassin'),
  subdomains: msg('Sous-domaines'), ip: REPUTATION, phishing: msg('Phishing et logiciels malveillants'), redirects: msg('Redirections'),
};

export function sectionOf(family: string, explicit?: string): string {
  return explicit ?? t(SECTION_OF_FAMILY[family] ?? msg('Autres contrôles'));
}

/** Default rendering of any CheckResult (v2): what to fix with the fix in view, then what is fine. */
export function ResultSections({ result, title }: { result: Pick<CheckResult, 'findings' | 'passed'>; sectionTitle?: (family: string) => string; title?: string }) {
  if (!result.findings.length && !result.passed.length) return null;
  return (
    <>
      <IssueList findings={result.findings} title={title} passed={result.passed} />
    </>
  );
}

export function Unavailable({ items }: { items?: { source: string; reason: string }[] }) {
  if (!items?.length) return null;
  return (
    <div className="unavailable">
      <Notice tone="info" title={items.length > 1 ? t('{n} sources non interrogées', { n: items.length }) : t('Une source non interrogée')}>
        {t('La note est calculée sans elles.')}
        <ul>
          {items.map((u, i) => (
            <li key={i}>
              {rich('<b>{source}</b> : {reason}', { source: u.source, reason: u.reason }, { b: (c) => <strong>{c}</strong> })}
            </li>
          ))}
        </ul>
      </Notice>
    </div>
  );
}

/** Copyable permalink of the current page. */
export function ShareButton() {
  return <CopyButton text={typeof window !== 'undefined' ? window.location.href : ''} label={t('Copier le lien')} what={t('Lien copié')} />;
}

function References({ refs }: { refs: string[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? refs : refs.slice(0, 4);
  return (
    <div className="lab-detail__refs">
      <span className="muted">{t('Sources :')}</span>
      {shown.map((r) => (
        <a key={r} href={r} target="_blank" rel="noreferrer noopener">
          {shortUrl(r)}
        </a>
      ))}
      {refs.length > 4 && !all && (
        <button type="button" className="btn btn--sm btn--ghost" style={{ minHeight: 0, padding: 0 }} onClick={() => setAll(true)}>
          {t('et {n} autres', { n: refs.length - 4 })}
        </button>
      )}
    </div>
  );
}

/* ---------- helpers ---------- */
const PROVIDERS: Record<string, string> = {
  google_workspace: 'Google Workspace', microsoft_365: 'Microsoft 365', ovh: 'OVHcloud', o2switch: 'o2switch',
  cpanel: 'cPanel', plesk: 'Plesk', ionos: 'IONOS', gandi: 'Gandi', infomaniak: 'Infomaniak', zoho: 'Zoho Mail',
  proton: 'Proton Mail', brevo: 'Brevo', mailchimp: 'Mailchimp', mailjet: 'Mailjet', sendgrid: 'SendGrid',
  mailgun: 'Mailgun', amazon_ses: 'Amazon SES', postmark: 'Postmark', sparkpost: 'SparkPost', hubspot: 'HubSpot',
  salesforce: 'Salesforce', zendesk: 'Zendesk', campaign_monitor: 'Campaign Monitor', klaviyo: 'Klaviyo',
  fastmail: 'Fastmail', mailerlite: 'MailerLite', wordpress: 'WordPress', cloudflare_dns: 'Cloudflare DNS', postfix: 'Postfix', exim: 'Exim',
};
export const providerName = (k: string) => PROVIDERS[k] ?? k;

function shortUrl(u: string) {
  try {
    const x = new URL(u);
    const rfc = /rfc(\d+)/i.exec(u);
    if (x.hostname.includes('rfc-editor') && rfc) return `RFC ${rfc[1]}${x.hash ? ' ' + x.hash.replace('#section-', '§') : ''}`;
    return x.hostname.replace(/^www\./, '') + (x.pathname.length > 1 ? x.pathname.slice(0, 28) + (x.pathname.length > 28 ? '…' : '') : '');
  } catch {
    return u;
  }
}
