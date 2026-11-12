// Domain scanner ("Signal", 2026-11-11): the verdict, then the work list across all sections (the
// successes folded into it), then the 13 sections as compact tiles (lit dot, name, measure in mono,
// link), and the measured rows of each section in one tabbed surface.
// The 13 sections still arrive live over SSE: skeleton tiles and cards until they land.
import { useMemo, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { ArrowRight } from 'lucide-react';
import { MeasuredMeta, providerName, ReportHeader, RerunButton, ShareButton, Unavailable } from '../../components/Report';
import { PassList } from '../../components/Verdict';
import { Notice, Skel } from '../../components/ui';
import { toDomain } from '../../lib/detect';
import { fmtMs } from '../../lib/format';
import { msg, rich, t } from '../../lib/i18n';
import type { Finding } from '../../lib/types';
import { useEventStream } from '../../lib/useEventStream';
import { MetricTable } from './MetricTable';
import { Issues, SkeletonCards, ToolEmpty, useRecent } from './common';
import type { DkimData, MxData, ScanSection, SectionId } from './model';
import { initialScan, lostPoints, scanReducer, sectionMetrics, SECTION_PAGE, tileState, tileSummary, type ScanState, type SectionContext, type TileState } from './rows';
import { isWeakKey, WeakKeyLink } from './WeakKeyLink';
import './domain.css';

const PAGE_LABEL: Partial<Record<SectionId, string>> = {
  mx: msg('Recherche MX'), spf: msg('Page SPF'), dkim: msg('Page DKIM'), dmarc: msg('Page DMARC'), bimi: msg('Page BIMI'), 'mta-sts': msg('Page MTA-STS'), dnssec: msg('Page DNSSEC'),
  ns: msg('Recherche NS'), soa: msg('Recherche SOA'), caa: msg('Recherche CAA'), smtp: msg('Page SMTP'), rdap: msg('Page RDAP'),
};
/** The same labels in lower case, for the middle of a sentence (not derived: the language decides its capitals). */
const PAGE_LABEL_LOWER: Partial<Record<SectionId, string>> = {
  mx: msg('recherche MX'), spf: msg('page SPF'), dkim: msg('page DKIM'), dmarc: msg('page DMARC'), bimi: msg('page BIMI'), 'mta-sts': msg('page MTA-STS'), dnssec: msg('page DNSSEC'),
  ns: msg('recherche NS'), soa: msg('recherche SOA'), caa: msg('recherche CAA'), smtp: msg('page SMTP'), rdap: msg('page RDAP'),
};

const STATE_LABEL: Record<TileState, string> = {
  out: msg('À corriger'),
  warn: msg('À surveiller'),
  ok: msg('Conforme'),
  info: msg('Conforme'),
  unavailable: msg('Non mesuré'),
  pending: msg('Mesure en cours'),
};
const DOT: Record<TileState, string> = { out: ' dot--out', warn: ' dot--warn', ok: ' dot--ok', info: ' dot--ok', unavailable: '', pending: '' };

const pageOf = (id: SectionId, domain: string) => SECTION_PAGE[id]?.replace('{d}', encodeURIComponent(domain));

function Tile({ id, title, s, ctx, onPick }: { id: SectionId; title: string; s?: ScanSection; ctx: SectionContext; onPick: (id: SectionId) => void }) {
  const st = tileState(s);
  const page = pageOf(id, ctx.domain);
  return (
    <article className="dm-tile" aria-busy={!s || undefined}>
      <h3 className="dm-tile__title">
        <span className={`dot${DOT[st]}`} role="img" aria-label={t(STATE_LABEL[st])} />
        <a href={`#d-${id}`} onClick={() => onPick(id)}>
          {t(title)}
        </a>
      </h3>
      <p className="dm-tile__line">{s ? tileSummary(s, ctx) || ' ' : <Skel w="70%" />}</p>
      {page && (
        <Link className="dm-more dm-tile__link" to={page}>
          {t(PAGE_LABEL[id] ?? '')}
          <ArrowRight aria-hidden />
        </Link>
      )}
    </article>
  );
}

/** Extra under a card of the scanner: where it comes from, and the generator for a weak key. */
function cardExtra(f: Finding, sections: Partial<Record<SectionId, ScanSection>>, order: ScanState['order'], domain: string): ReactNode {
  const same = (g: Finding) => g.id === f.id && (g.evidence ?? '') === (f.evidence ?? '');
  const sec = order.find((o) => sections[o.id]?.findings.some(same));
  const k = /^dkim\.key_(1024|below_1024)$/.test(f.id) ? (sections.dkim?.data as DkimData | null)?.keys.find((x) => (f.evidence ?? '').includes(x.name)) : undefined;
  const page = sec ? pageOf(sec.id, domain) : undefined;
  return (
    <>
      {k && <WeakKeyLink k={k} domain={domain} />}
      {sec && page && (
        <Link className="dm-more" to={page}>
          {t('Tout le détail sur la {page}', { page: t(PAGE_LABEL_LOWER[sec.id] ?? '') })}
          <ArrowRight aria-hidden />
        </Link>
      )}
    </>
  );
}

function SectionPanel({ id, title, s, ctx }: { id: SectionId; title: string; s: ScanSection; ctx: SectionContext }) {
  const rows = sectionMetrics(s, ctx);
  const extra =
    id === 'dkim'
      ? Object.fromEntries(((s.data as DkimData | null)?.keys ?? []).filter(isWeakKey).map((k) => [`key-${k.selector}`, <WeakKeyLink key={k.selector} k={k} domain={ctx.domain} />]))
      : undefined;
  const page = pageOf(id, ctx.domain);
  const ips = id === 'blacklist' ? ((s.data as { ips?: string[] } | null)?.ips ?? []).slice(0, 3) : [];
  return (
    <div id={`d-${id}`} className="dm-panel" role="tabpanel" aria-labelledby={`dt-${id}`} tabIndex={0}>
      <p className="dm-panel__head">
        <b>{t(title)}</b>
        <span className="mono">{tileSummary(s, ctx)}</span>
      </p>
      {rows.length > 0 ? <MetricTable rows={rows} extra={extra} /> : <PassList passed={s.passed} title={t('Contrôles réussis')} />}
      {s.unavailable && <Unavailable items={s.unavailable} />}
      <div className="dm-section-foot">
        {page && (
          <Link className="dm-more" to={page}>
            {t('{page} de {domain}', { page: t(PAGE_LABEL[id] ?? ''), domain: ctx.domain })}
            <ArrowRight aria-hidden />
          </Link>
        )}
        {ips.map((ip) => (
          <Link key={ip} className="dm-more" to={`/ip/${ip}`}>
            {t('Réputation de {ip}', { ip })}
            <ArrowRight aria-hidden />
          </Link>
        ))}
      </div>
    </div>
  );
}

/** One surface, one tab per section; opens on the first section that is not fine. */
function SectionTabs({ order, sections, ctx, selected, onSelect }: { order: ScanState['order']; sections: ScanState['sections']; ctx: SectionContext; selected?: SectionId; onSelect: (id: SectionId) => void }) {
  const arrived = order.filter((o) => sections[o.id]);
  const firstBad = arrived.find((o) => ['out', 'warn'].includes(tileState(sections[o.id])));
  const cur = arrived.find((o) => o.id === selected) ?? firstBad ?? arrived[0];
  if (!cur) return null;
  const onKey = (e: KeyboardEvent) => {
    const i = arrived.findIndex((o) => o.id === cur.id);
    const n = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? arrived.length - 1 : null;
    if (n === null) return;
    e.preventDefault();
    const target = arrived[(n + arrived.length) % arrived.length];
    onSelect(target.id);
    document.getElementById(`dt-${target.id}`)?.focus();
  };
  return (
    <div className="surface dm-tabs">
      <div className="dm-tabs__list" role="tablist" aria-label={t('Détail par section')} onKeyDown={onKey}>
        {arrived.map((o) => (
          <button key={o.id} id={`dt-${o.id}`} type="button" role="tab" aria-selected={o.id === cur.id} tabIndex={o.id === cur.id ? 0 : -1} onClick={() => onSelect(o.id)}>
            <span className={`dot${DOT[tileState(sections[o.id])]}`} aria-hidden />
            {t(o.title)}
          </button>
        ))}
      </div>
      <SectionPanel id={cur.id} title={cur.title} s={sections[cur.id]!} ctx={ctx} />
    </div>
  );
}

export default function DomainScanPage() {
  const { domain: raw } = useParams();
  const domain = raw ? toDomain(raw) : undefined;
  const url = domain ? `/api/domain/${encodeURIComponent(domain)}/stream` : null;
  const { state, status, restart } = useEventStream<ScanState>(url, scanReducer, initialScan);
  useRecent(domain, `/domaine/${domain}`, msg('Scanner'));

  const [picked, setPicked] = useState<SectionId>();
  const done = !!state.result;
  const received = Object.keys(state.sections).length;
  const nx = (state.sections.mx?.data as MxData | null)?.rcode === 'NXDOMAIN';
  const broken = !done && (status === 'error' || !!state.error);
  const arrived = state.order.map((o) => state.sections[o.id]).filter((s): s is ScanSection => !!s);
  // findings in arrival order while streaming, the server's sorted list once done
  const findings = useMemo(() => state.result?.findings ?? lostPoints(arrived).map((l) => l.finding).concat(arrived.flatMap((s) => s.findings.filter((f) => f.penalty <= 0))), [state.result, arrived]);
  const counts = useMemo(() => {
    const c: Record<TileState, number> = { out: 0, warn: 0, ok: 0, info: 0, unavailable: 0, pending: 0 };
    for (const o of state.order) c[tileState(state.sections[o.id])]++;
    return c;
  }, [state.order, state.sections]);

  if (!raw) {
    return (
      <ToolEmpty
        title={t('Scanner de domaine')}
        desc={t('Tout ce qui fait arriver les mails d’un domaine, en une mesure : MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DNSSEC, listes noires, SMTP et enregistrement.')}
        basePath="/domaine"
        examples={[{ domain: 'github.com' }, { domain: 'cnn.com' }, { domain: 'cloudflare.com' }]}
      />
    );
  }
  if (!domain) {
    return (
      <ToolEmpty title={t('Scanner de domaine')} desc={t('Tout ce qui fait arriver les mails d’un domaine, en une mesure.')} basePath="/domaine">
        <Notice tone="error" title={t('« {value} » n’est pas un nom de domaine', { value: raw })}>
          {t('Saisissez un nom comme exemple.fr ; une URL ou une adresse e-mail marchent aussi, le domaine en est extrait.')}
        </Notice>
      </ToolEmpty>
    );
  }

  const ctx: SectionContext = { domain, nx, providerName };
  const facts: { label: string; value: ReactNode }[] = [
    { label: t('Contrôles'), value: done ? t('{n} conformes sur {total}', { n: counts.ok + counts.info, total: state.order.length }) : t('{n} sur {total} arrivés', { n: received, total: state.order.length }) },
    ...(counts.out ? [{ label: t('À corriger'), value: String(counts.out) }] : []),
    ...(counts.warn ? [{ label: t('À surveiller'), value: String(counts.warn) }] : []),
    ...(state.result ? MeasuredMeta(state.result) : []),
  ];

  return (
    <div className="dm-report">
      <ReportHeader
        subject={<span className="mono">{domain}</span>}
        meta={facts}
        score={state.result?.score}
        findings={state.result?.findings}
        passed={state.result?.passed}
        sentence={nx && done ? t('{domain} n’existe pas dans le DNS : aucun message ne peut être reçu ni authentifié pour ce nom.', { domain }) : undefined}
        pending={!done && !broken}
        actions={
          <>
            <RerunButton onClick={restart} busy={!done && !broken && status !== 'idle'} />
            <ShareButton />
          </>
        }
      />
      <>
        {broken && (
          <Notice tone="error" title={received ? t('La mesure s’est interrompue en route') : t('Mesure impossible')}>
            {state.error ?? (received ? t('{n} sections sur {total} sont arrivées : elles restent affichées, sans note globale.', { n: received, total: state.order.length }) : t('Le serveur de TestAndFix n’a pas répondu au flux de mesure. Vérifiez qu’il tourne, puis relancez.'))}{' '}
            <button type="button" className="btn btn--sm" onClick={restart} style={{ marginLeft: 'var(--s2)' }}>
              {t('Relancer')}
            </button>
          </Notice>
        )}
        {nx && (
          <Notice tone="error" title={t('{domain} n’existe pas dans le DNS', { domain })}>
            {rich('Les serveurs de noms répondent NXDOMAIN : aucun message ne peut être reçu ni authentifié pour ce nom. Vérifiez l’orthographe, ou l’enregistrement du domaine chez son registrar (<whois>page Whois</whois>).', undefined, { whois: (c) => <Link to={`/whois/${domain}`}>{c}</Link> })}
          </Notice>
        )}

        {findings.length > 0 || (done && (state.result?.passed.length ?? 0) > 0) ? (
          <Issues findings={findings} passed={state.result?.passed} extra={(f) => cardExtra(f, state.sections, state.order, domain)} />
        ) : (
          !done && !broken && <SkeletonCards />
        )}

        <section className="block" aria-labelledby="tiles-t">
          <h2 className="block__title" id="tiles-t">
            {t('Les {n} contrôles', { n: state.order.length })}
          </h2>
          <div className="dm-tiles">
            {state.order.map((o) => (
              <Tile key={o.id} id={o.id} title={o.title} s={state.sections[o.id]} ctx={ctx} onPick={setPicked} />
            ))}
          </div>
        </section>

        {arrived.length > 0 && (
          <section className="block" aria-labelledby="tech-t">
            <h2 className="block__title" id="tech-t">
              {t('Détail par section')}
            </h2>
            <SectionTabs order={state.order} sections={state.sections} ctx={ctx} selected={picked} onSelect={setPicked} />
            {done && state.result?.ms !== undefined && (
              <p className="field__hint" style={{ marginTop: 'var(--s3)' }}>
                {t('Mesure complète en {ms} ; sections les plus lentes : {sections}.', {
                  ms: fmtMs(state.result.ms),
                  sections: arrived
                    .slice()
                    .sort((a, b) => b.ms - a.ms)
                    .slice(0, 3)
                    .map((s) => `${t(s.title)} ${fmtMs(s.ms)}`)
                    .join(', '),
                })}
              </p>
            )}
          </section>
        )}
      </>
    </div>
  );
}
