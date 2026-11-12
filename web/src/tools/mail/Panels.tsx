// Report panels other than the server sections: the Gmail / Yahoo / Microsoft matrix, the
// inventory of links and images, the limits of the measure, the analysis in progress.
import { Fragment, useState } from 'react';
import { Check, ChevronRight, Minus, X } from 'lucide-react';
import { FindingDetail, LabRow, LabTable, Unavailable, type Deviation } from '../../components/Report';
import { Skel } from '../../components/ui';
import { fmtMs } from '../../lib/format';
import { msg, rich, t, tn } from '../../lib/i18n';
import type { Finding } from '../../lib/types';
import { complianceCell, complianceOrder, humanError, humanReason, PROVIDERS, providerOfSource, type Cell } from './logic';
import type { ImageInfo, LinkInfo, MailReport, Requirement, StepState } from './types';

/* ---------- compliance ---------- */

function CellView({ c, applies }: { c: Cell; applies: boolean }) {
  if (c === 'ok')
    return (
      <span className="dev dev--ok">
        <Check aria-hidden />
        {t('conforme')}
      </span>
    );
  if (c === 'fail')
    return (
      <span className={`dev ${applies ? 'dev--out' : 'dev--warn'}`}>
        <X aria-hidden />
        {t('non conforme')}
      </span>
    );
  if (c === 'unknown')
    return (
      <span className="dev dev--info">
        <Minus aria-hidden />
        {t('non mesurable')}
      </span>
    );
  return <span className="mail-matrix__na">{t('non exigé')}</span>;
}

function RequirementRow({ req, finding, bulk }: { req: Requirement; finding?: Finding; bulk: boolean }) {
  const [open, setOpen] = useState(false);
  const failing = req.ok === false;
  const appliesNow = req.scope === 'all' || bulk;
  return (
    <tbody>
      <tr className={`lab-row ${failing ? (appliesNow ? 'lab-row--out' : 'lab-row--warn') : req.ok === null ? 'lab-row--info' : 'lab-row--ok'} lab-row--expandable`} onClick={(e) => !(e.target as HTMLElement).closest('a, button') && setOpen((o) => !o)}>
        <td className="c-check mail-matrix__req">
          <button type="button" className="lab-row__toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            <ChevronRight aria-hidden />
            <span>
              {req.label}
              <span className="mail-label__sub">{req.scope === 'bulk' ? t('envois en nombre, plus de 5 000 messages par jour') : t('tous les expéditeurs')}</span>
            </span>
          </button>
        </td>
        {PROVIDERS.map((p) => (
          <td key={p.id} className="mail-matrix__cell" data-label={p.name}>
            <CellView c={complianceCell(req, p.id)} applies={appliesNow} />
          </td>
        ))}
        <td className="mail-matrix__src">
          {req.sources.map((s, i) => (
            <Fragment key={s}>
              {i > 0 && ' · '}
              <a href={s} target="_blank" rel="noreferrer noopener">
                {providerOfSource(s)}
              </a>
            </Fragment>
          ))}
        </td>
      </tr>
      {open && (
        <tr className="lab-detail">
          <td colSpan={5}>
            <div className="lab-detail__body">
              <p>
                <span className="muted">{t('Mesuré : ')}</span>
                <span className="mono">{req.detail}</span>
              </p>
              {failing && !appliesNow && <p className="lab-detail__why">{t('Ce message n’a pas les marques d’un envoi en nombre : l’exigence ne s’applique qu’au-delà de 5 000 messages par jour vers le fournisseur.')}</p>}
              {finding && <FindingDetail f={finding} />}
            </div>
          </td>
        </tr>
      )}
    </tbody>
  );
}

export function ComplianceMatrix({ r }: { r: MailReport }) {
  const c = r.data.compliance;
  if (!c?.requirements.length) return null;
  const reqs = complianceOrder(c.requirements, c.isBulk);
  const byId = new Map(r.findings.map((f) => [f.id, f]));
  return (
    <>
      <p className="mail-note">
        {c.isBulk
          ? t('Traité comme un envoi en nombre ({reasons}) : les exigences des envois en nombre s’appliquent.', { reasons: c.bulkReasons.join(', ') })
          : t('Ce message n’a pas les marques d’un envoi en nombre (ni List-Unsubscribe, ni List-Id, ni plateforme d’envoi reconnue) : seules les exigences « tous les expéditeurs » s’appliquent.')}
      </p>
      <div className="mail-matrix-wrap">
        <table className="lab-table mail-matrix">
          <thead>
            <tr>
              <th scope="col" className="c-check">{t('Exigence')}</th>
              {PROVIDERS.map((p) => (
                <th scope="col" key={p.id}>
                  {p.name}
                </th>
              ))}
              <th scope="col">{t('Source')}</th>
            </tr>
          </thead>
          {reqs.map((q) => (
            <RequirementRow key={q.id} req={q} finding={q.situation ? byId.get(q.situation) : undefined} bulk={c.isBulk} />
          ))}
        </table>
      </div>
    </>
  );
}

/* ---------- links and images ---------- */

function checkDeviation(ch: LinkInfo['check'] | undefined, extra?: { warn?: string }): Deviation {
  if (!ch) return { kind: 'info', text: t('non visité') };
  if (ch.error || (ch.status ?? 0) >= 400) return { kind: 'out', direction: 'down', text: ch.error ? t('échec') : String(ch.status) };
  if (extra?.warn) return { kind: 'warn', direction: 'down', text: extra.warn };
  return { kind: 'ok', text: String(ch.status ?? 'ok') };
}

function statusText(ch: LinkInfo['check'] | undefined, scheme?: string): string {
  if (!ch) return scheme === 'mailto' ? t('adresse mailto') : scheme ? t('{scheme}, non visité', { scheme }) : t('sans destination');
  const n = ch.redirects.length;
  if (ch.error) {
    const reason = ch.reason ?? humanError(ch.error);
    return n ? tn(n, '{reason} après {n} redirection', '{reason} après {n} redirections', { reason }) : reason;
  }
  const http = n ? tn(n, 'HTTP {status} après {n} redirection', 'HTTP {status} après {n} redirections', { status: String(ch.status) }) : `HTTP ${ch.status}`;
  return `${http}${ch.ms ? ` · ${fmtMs(ch.ms)}` : ''}`;
}

function TechDetail({ ch }: { ch?: LinkInfo['check'] }) {
  if (!ch?.error) return null;
  return (
    <details className="mail-tech">
      <summary>{t('Détail technique')}</summary>
      <code>{ch.error}</code>
    </details>
  );
}

function Chain({ url, ch }: { url: string; ch: NonNullable<LinkInfo['check']> }) {
  return (
    <ol className="mail-chain">
      {[url, ...ch.redirects].map((u, i) => (
        <li key={i} className="mono">
          {u}
        </li>
      ))}
    </ol>
  );
}

const hostOf = (u: string) => {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
};

const shortUrl = (u: string) => (u.length > 72 ? `${u.slice(0, 69)}…` : u);

export function LinksAndImages({ r }: { r: MailReport }) {
  const links = r.data.links ?? [];
  const images = r.data.images ?? [];
  if (!links.length && !images.length) return null;
  return (
    <>
      {links.length > 0 && (
        <LabTable columns={[t('Lien'), t('Mesuré'), t('Référence'), t('Écart')]}>
          {links.map((l) => {
            const warn = l.mismatch ? t('trompeur') : l.shortener ? t('raccourci') : undefined;
            const ch = l.check;
            return (
              <LabRow
                key={l.url}
                label={
                  <span className="mail-label">
                    {l.text && l.text !== l.url ? l.text : <span className="mono">{shortUrl(l.url)}</span>}
                    {l.text && l.text !== l.url && <span className="mail-label__sub mono">{shortUrl(l.url)}</span>}
                  </span>
                }
                measured={statusText(ch, l.scheme)}
                reference={l.mismatch ? t('mène au domaine affiché, {domain}', { domain: l.mismatch }) : ch ? (ch.redirects.length ? t('HTTP 200, arrive sur {host}', { host: hostOf(ch.finalUrl ?? l.url) }) : 'HTTP 200') : l.scheme === 'mailto' ? undefined : t('une adresse https')}
                deviation={checkDeviation(ch, { warn })}
                detail={
                  ch?.redirects.length || l.mismatch || l.shortener || ch?.error ? (
                    <>
                      {l.mismatch && (
                        <p className="lab-detail__why">
                          {rich('Le texte affiche <m>{shown}</m> mais le lien mène à <m>{host}</m> : les filtres y voient un hameçonnage.', { shown: l.mismatch, host: l.host }, { m: (c) => <span className="mono">{c}</span> })}
                        </p>
                      )}
                      {l.shortener && <p className="lab-detail__why">{t('Lien raccourci : la destination réelle est cachée au lecteur et aux filtres.')}</p>}
                      {ch && ch.redirects.length > 0 && (
                        <div>
                          <div className="lab-detail__label">{t('Redirections suivies')}</div>
                          <Chain url={l.url} ch={ch} />
                        </div>
                      )}
                      <TechDetail ch={ch} />
                    </>
                  ) : undefined
                }
              />
            );
          })}
        </LabTable>
      )}
      {images.length > 0 && (
        <LabTable columns={[t('Image'), t('Mesuré'), t('Référence'), t('Écart')]}>
          {images.map((im: ImageInfo, i) => (
            <LabRow
              key={`${im.src}-${i}`}
              label={
                <span className="mail-label">
                  <span className="mono">{shortUrl(im.src) || t('sans source')}</span>
                  <span className="mail-label__sub">
                    {[im.width && im.height ? `${im.width} × ${im.height}` : undefined, im.tracking ? t('pixel de suivi') : undefined, im.alt === undefined ? t('sans texte alternatif') : im.alt === '' ? t('alt vide (décorative)') : t('alt\u00a0«\u00a0{alt}\u00a0»', { alt: im.alt })].filter(Boolean).join(' · ')}
                  </span>
                </span>
              }
              measured={statusText(im.check, im.src.startsWith('cid:') ? 'cid' : im.src.startsWith('data:') ? 'data' : undefined)}
              reference={t('HTTP 200, texte alternatif')}
              deviation={checkDeviation(im.check, { warn: im.alt === undefined && !im.tracking ? t('sans alt') : undefined })}
              detail={
                im.check && (im.check.redirects.length || im.check.error) ? (
                  <>
                    {im.check.redirects.length > 0 && <Chain url={im.src} ch={im.check} />}
                    <TechDetail ch={im.check} />
                  </>
                ) : undefined
              }
            />
          ))}
        </LabTable>
      )}
    </>
  );
}

/* ---------- limits ---------- */

const LIMIT_NAMES: Record<string, string> = {
  spf: 'SPF',
  dkim: 'DKIM',
  infrastructure: msg("Serveur d'envoi"),
  blacklists: msg('Listes noires'),
  spamassassin: 'SpamAssassin',
  content: msg('Contenu'),
};

export function Limits({ r }: { r: MailReport }) {
  const limits = r.data.limits ?? [];
  return (
    <>
      <ul className="mail-limits">
        {limits.map((l) => (
          <li key={l.check}>
            <strong>{LIMIT_NAMES[l.check] ? t(LIMIT_NAMES[l.check]) : l.check}</strong> : {l.reason}
          </li>
        ))}
        <li>
          {rich('<b>Note</b> : elle mesure ce message, pas la réputation de l’expéditeur chez chaque fournisseur. Une bonne note ne garantit pas l’arrivée en boîte de réception.', undefined, { b: (c) => <strong>{c}</strong> })}
        </li>
      </ul>
      <Unavailable items={r.unavailable?.map((u) => ({ ...u, reason: humanReason(u.reason) }))} />
    </>
  );
}

/* ---------- analysis in progress ---------- */

/** The steps of the analysis as a list that fills in, each with a lit dot, then skeleton rows where the results will be. */
export function AnalysisProgress({ steps, progress, title, cards = true }: { steps: Record<string, string>; progress?: Record<string, StepState>; title?: string; cards?: boolean }) {
  const ids = [...new Set([...Object.keys(steps), ...Object.keys(progress ?? {})])];
  const doneCount = ids.filter((id) => progress?.[id] && progress[id].state !== 'start').length;
  return (
    <section className="surface mr-progress" id="s-progress" aria-labelledby="progress-t">
      <h2 className="mr-progress__t" id="progress-t">
        <span className="dot dot--pending" aria-hidden />
        {title ?? t('Analyse en cours')}
        <span className="mr-progress__n">
          {doneCount}/{ids.length}
        </span>
      </h2>
      <div aria-live="polite" className="visually-hidden">
        {t('{done} étapes sur {total} terminées', { done: doneCount, total: ids.length })}
      </div>
      <ul className="mail-steps">
        {ids.map((id) => {
          const st = progress?.[id];
          const state = !st ? 'wait' : st.state;
          const dot = state === 'done' ? 'dot--ok' : state === 'error' ? 'dot--out' : state === 'start' ? 'dot--pending' : '';
          return (
            <li key={id} className={`mail-steps__item mail-steps__item--${state}`}>
              <span className={`dot ${dot}`} aria-hidden />
              <span>{st?.label ?? steps[id] ?? id}</span>
              <span className="mail-steps__state">{state === 'done' ? t('fait') : state === 'error' ? t('erreur') : state === 'skipped' ? t('ignoré') : state === 'start' ? t('en cours') : t('en attente')}</span>
            </li>
          );
        })}
      </ul>
      {cards && (
        <div className="mr-progress__skel" aria-hidden>
          {[0, 1, 2].map((i) => (
            <div key={i}>
              <Skel w="40%" />
              <Skel w="12%" />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

/** Closed-state summaries of the technical blocks. */
export function complianceCount(r: MailReport): { fails: number; total: number } | undefined {
  const c = r.data.compliance;
  if (!c?.requirements.length) return undefined;
  return { fails: c.requirements.filter((q) => q.ok === false && (q.scope === 'all' || c.isBulk)).length, total: c.requirements.length };
}
export function linksCount(r: MailReport): { bad: number; total: number } | undefined {
  const all = [...(r.data.links ?? []), ...(r.data.images ?? [])];
  if (!all.length) return undefined;
  return { bad: all.filter((x) => x.check && (x.check.error || (x.check.status ?? 0) >= 400)).length, total: all.length };
}
