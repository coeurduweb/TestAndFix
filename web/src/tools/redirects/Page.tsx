// Redirections (/redirections?url=…, /redirections?liste=…), direction v2 « Clair et direct ».
// Without input: the hero (one big field, options folded under it, a list mode). With an URL: the
// verdict band, then the chain in large steps arriving live (click a step for its tabs Réponse,
// Requête, Corps, Temps, TLS), then what to fix with the Apache and nginx rules in view, what is
// fine, the variants of the site, and the technical measures folded. Options live in the URL:
// ua, uat, methode, cookies, h.
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { ArrowRight, CornerDownRight, GitCompareArrows, ListPlus } from 'lucide-react';
import { LabRow, LabTable, MeasuredMeta, ReportHeader, RerunButton, ShareButton, Unavailable, deviationOf, type Deviation } from '../../components/Report';
import { ToolHero } from '../../components/ToolHero';
import { IssueList, verdictSentence } from '../../components/Verdict';
import { Notice, Skel } from '../../components/ui';
import { post } from '../../lib/api';
import { fmtBytes, fmtMs, fmtScore, plural } from '../../lib/format';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult, Finding } from '../../lib/types';
import { BatchMode } from './BatchMode';
import { HopList } from './HopList';
import { apiQuery, readOptions, reasonOf, shortUrl, writeOptions, type TraceData, type TraceOptions, type VariantsData } from './model';
import { OptionsLine } from './OptionsBar';
import { useTrace } from './useTrace';
import { Url } from './Url';
import { traceValues } from './values';
import { VariantsSection } from './Variants';
import './redirects.css';

const EXAMPLES = ['http://github.com', 'google.fr', 'https://bit.ly/'];

/** Measured / expected line under an issue card. */
function Measured({ f, d }: { f: Finding; d: TraceData }) {
  const v = traceValues(f, d);
  if (!v.measured && !v.reference) return null;
  return (
    <p className="rd-measured">
      {v.measured && (
        <span>
          {rich('Mesuré <b>{value}</b>', { value: v.measured }, { b: (c) => <strong className="mono">{c}</strong> })}
        </span>
      )}
      {v.reference && (
        <span>
          {rich('attendu <b>{value}</b>', { value: v.reference }, { b: (c) => <strong className="mono">{c}</strong> })}
        </span>
      )}
    </p>
  );
}

function verdict(d: TraceData): ReactNode {
  const last = d.hops[d.hops.length - 1];
  const st = last.exchange.status;
  const codes = [...new Set(d.hops.filter((h) => h.redirect).map((h) => (h.redirect!.kind === 'http' ? String(h.exchange.status) : h.redirect!.kind === 'meta' ? 'meta refresh' : h.redirect!.kind === 'js' ? 'JavaScript' : 'Refresh')))];
  const n = d.redirects;
  const head = n === 0 ? t('Aucune redirection') : tn(n, '{n} redirection ({codes})', '{n} redirections ({codes})', { codes: codes.join(', ') });
  const strong = { s: (c: ReactNode) => <strong className="out-text">{c}</strong> };
  switch (d.stoppedBy) {
    case 'loop':
      return rich('<s>Boucle de redirections</s> : après {count}, la chaîne revient sur une adresse déjà visitée.', { count: tn(d.hops.length, '{n} requête', '{n} requêtes') }, strong);
    case 'max':
      return rich('<s>Chaîne sans fin</s> : arrêt après {n} requêtes, elle continue encore.', { n: d.max }, strong);
    case 'unsafe':
      return rich('<s>Arrêt au saut {n}</s> : {detail}', { n: last.index, detail: last.exchange.error?.message ?? '' }, strong);
    case 'error':
      return rich('<s>Arrêt au saut {n}</s> : {detail}', { n: last.index, detail: d.stopDetail ?? last.exchange.error?.message ?? '' }, strong);
    case 'scheme':
      return rich('{head}, puis <b>sortie du web</b> : {detail}', { head, detail: d.stopDetail ?? '' }, { b: (c) => <strong>{c}</strong> });
    case 'aborted':
      return t('Mesure interrompue.');
    default:
      {
        const vars = { head, status: `${st} ${reasonOf(st ?? 0, last.exchange.statusText)}`, url: shortUrl(d.final), time: fmtMs(d.totalMs) };
        const tags = {
          s: (c: ReactNode) => <strong className={st !== undefined && st >= 400 ? 'out-text' : undefined}>{c}</strong>,
          u: (c: ReactNode) => <span className="mono"><Url href={String(c)} /></span>,
        };
        return n > 0 ? rich('{head}, page finale <s>{status}</s> sur <u>{url}</u>, en {time}.', vars, tags) : rich('{head}, page finale <s>{status}</s>, en {time}.', vars, tags);
      }
  }
}

/** Deviation of a measured row: the worst finding among `ids`, else conform. */
function devFor(findings: Finding[], ids: string[], okText?: string): Deviation {
  const f = findings.find((x) => ids.includes(x.id) && x.penalty > 0);
  if (!f) return { kind: 'ok', text: okText };
  // the points are counted once, on the finding above: here only the direction
  const dev = deviationOf(f);
  return { kind: dev.kind, direction: 'down', text: t('hors bornes'), label: t('Hors bornes, voir « {title} »', { title: f.title }) };
}

function Measures({ r }: { r: CheckResult<TraceData> }) {
  const d = r.data;
  const last = d.hops[d.hops.length - 1].exchange;
  const fp = d.finalPage;
  const f = r.findings;
  const https = d.final.startsWith('https:');
  const b = last.body;
  return (
    <LabTable>
        <LabRow label={t('Statut final')} measured={last.status !== undefined ? `${last.status} ${reasonOf(last.status, last.statusText)}` : (last.error?.code ?? t('sans réponse'))} reference="2xx" deviation={devFor(f, ['redirects.final_error', 'redirects.redirect_to_error', 'redirects.unreachable', 'redirects.private_target', 'redirects.redirect_without_location', 'redirects.loop', 'redirects.too_many'])} />
        <LabRow label={t('Redirections')} measured={d.redirects} reference="≤ 2" deviation={devFor(f, ['redirects.chain_long', 'redirects.too_many', 'redirects.loop'])} />
        <LabRow label={t('Temps total de la chaîne')} measured={fmtMs(d.totalMs)} reference="≤ 3 s" deviation={d.totalMs > 3000 ? devFor(f, ['redirects.slow']) : { kind: 'ok' }} />
        <LabRow label={t('Premier octet de la page finale')} measured={fmtMs(last.timings.wait)} reference="≤ 800 ms" deviation={last.timings.wait > 800 ? devFor(f, ['redirects.slow']) : { kind: 'ok' }} />
        {https ? (
          <LabRow label="HSTS" measured={fp?.hsts?.raw ?? t('absent')} reference={t('≥ 1 an, sous-domaines')} deviation={devFor(f, ['redirects.hsts_missing', 'redirects.hsts_short', 'redirects.hsts_no_subdomains'])} />
        ) : (
          <LabRow label={t('Chiffrement')} measured={t('http, en clair')} reference="https" deviation={devFor(f, ['redirects.http_not_redirected'])} />
        )}
        {d.method === 'GET' && b?.mime?.includes('html') && last.status !== undefined && last.status >= 200 && last.status < 300 && (
          <>
            <LabRow label={t('Canonique')} measured={fp?.canonicalRaw ?? t('absente')} reference={t('URL finale')} deviation={devFor(f, ['redirects.canonical_missing', 'redirects.canonical_mismatch', 'redirects.canonical_relative'])} />
            <LabRow label={t('Robots')} measured={fp?.robots.length ? fp.robots.join(' · ') : t('aucune consigne')} reference={t('indexable')} deviation={devFor(f, ['redirects.final_noindex'])} />
            <LabRow label={t('Poids du HTML décompressé')} measured={b ? fmtBytes(b.decodedSize) : ''} reference={t('< 2 Mo (Googlebot)')} deviation={devFor(f, ['redirects.heavy_body'])} />
          </>
        )}
        {b && b.size > 0 && d.method === 'GET' && <LabRow label={t('Compression')} measured={b.contentEncoding ?? t('aucune')} reference={t('gzip, br ou zstd')} deviation={devFor(f, ['redirects.uncompressed'], b.contentEncoding ? t('conforme') : t('sans objet'))} />}
        {last.tls?.cert && <LabRow label={t('Certificat')} measured={tn(last.tls.cert.daysLeft, '{n} jour restant', '{n} jours restants')} reference={t('≥ 14 jours')} deviation={devFor(f, ['redirects.cert_invalid', 'redirects.cert_expiring'])} />}
        {fp?.h2 !== undefined && <LabRow label={t('HTTP/2 proposé (ALPN)')} measured={fp.h2 ? t('oui') : t('non')} reference={t('information')} deviation={{ kind: 'info', text: t('noté') }} />}
        {fp?.title && <LabRow label={t('Titre de la page')} measured={fp.title} deviation={{ kind: 'info', text: t('noté') }} />}
    </LabTable>
  );
}

/** A wrong scheme replaced by https, when the rest is a plain host. */
function fixedInput(raw: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(.+)$/i.exec(raw.trim());
  if (!m || /^https?:/i.test(raw.trim())) return null;
  return /^[^\s/]+\.[^\s/]+/.test(m[1]) ? `https://${m[1]}` : null;
}

/** Same rules as the server (normalizeUrlInput): refuse before opening a stream that would answer 400. */
function inputProblem(raw: string): string | null {
  const s = raw.trim().replace(/^[<"'(]+|[>"')]+$/g, '');
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s)?.[1]?.toLowerCase();
  if (scheme && scheme !== 'http' && scheme !== 'https') return t('Seules les adresses http:// et https:// se suivent (reçu {scheme}:).', { scheme });
  try {
    const u = new URL(scheme ? s : `https://${s}`);
    if (!u.hostname.includes('.') && !u.hostname.startsWith('[')) return t('« {raw} » n’a pas de nom de domaine complet : ajoutez l’extension (.fr, .com…).', { raw });
  } catch {
    return t('« {raw} » n’est pas une URL valide.', { raw });
  }
  return null;
}

function SingleTrace({ url, options, onOptions }: { url: string; options: TraceOptions; onOptions: (o: TraceOptions) => void }) {
  const problem = useMemo(() => inputProblem(url), [url]);
  const query = useMemo(() => (problem ? null : apiQuery(url, options)), [url, options, problem]);
  const trace = useTrace(query);
  const r = trace.result;
  const d = r?.data;
  const running = trace.status === 'running';
  const [variants, setVariants] = useState<{ loading: boolean; result: CheckResult<VariantsData> | null; error: unknown } | null>(null);
  const varRef = useRef<HTMLElement>(null);
  useEffect(() => setVariants(null), [url]);
  useEffect(() => {
    if (d) pushRecent({ value: d.start, path: `/redirections?url=${encodeURIComponent(d.start)}`, label: msg('Redirections') });
  }, [d]);

  const compare = async () => {
    setVariants({ loading: true, result: null, error: null });
    requestAnimationFrame(() => varRef.current?.scrollIntoView({ block: 'start', behavior: 'smooth' }));
    try {
      const res = await post<CheckResult<VariantsData>>('/api/redirects/variants', { url: d?.start ?? url, ua: options.ua === 'custom' ? options.uaText : options.ua });
      setVariants({ loading: false, result: res, error: null });
    } catch (e) {
      setVariants({ loading: false, result: null, error: e });
    }
  };
  const expected = useMemo(() => {
    try {
      const h = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^www\./, '');
      return [`http://${h}`, `https://${h}`, `http://www.${h}`, `https://www.${h}`];
    } catch {
      return [];
    }
  }, [url]);

  const start = d?.start ?? trace.hops[0]?.url ?? url;
  const final = d?.final;

  if (problem)
    return (
      <>
        <Notice tone="error" title={t('Adresse non suivie')}>
          {problem}{' '}
          {fixedInput(url) ? (
            <>
              {rich('Vouliez-vous dire <l>{fixed}</l> ?', { fixed: fixedInput(url)! }, { l: (c) => <Link className="mono" to={`/redirections?${writeOptions(new URLSearchParams({ url: fixedInput(url)! }), options).toString()}`}>{c}</Link> })}
            </>
          ) : (
            t('Corrigez la saisie ci-dessous.')
          )}
        </Notice>
        <RedirectsHero options={options} onOptions={onOptions} />
      </>
    );

  return (
    <div className="rd-result page-stack">
      <ReportHeader
        subject={
          <span className="rd-subject">
            <span className="mono"><Url href={shortUrl(start)} /></span>
            {final && final !== start && (
              <>
                <ArrowRight aria-hidden className="rd-subject__arrow" />
                <span className="visually-hidden"> {t('aboutit à')} </span>
                <span className="mono"><Url href={shortUrl(final)} /></span>
              </>
            )}
          </span>
        }
        meta={
          r && d
            ? [
                { label: t('Requêtes'), value: d.hops.length },
                { label: t('Redirections'), value: d.redirects },
                { label: t('URL finale'), value: <span className="mono rd-fact-url"><Url href={shortUrl(d.final)} /></span> },
                { label: t('Temps'), value: fmtMs(d.totalMs) },
              ]
            : running
              ? [{ label: t('Étapes reçues'), value: trace.hops.length }]
              : []
        }
        score={r?.score}
        findings={r?.findings}
        passed={r?.passed}
        pending={running}
        sentence={d && r ? <>{verdict(d)} {verdictSentence(r.findings, r.passed)}</> : undefined}
        actions={
          <>
            <RerunButton onClick={trace.rerun} busy={running} />
            <button type="button" className="btn btn--sm" onClick={compare} disabled={variants?.loading || running}>
              <GitCompareArrows aria-hidden />
              {t('Comparer les variantes')}
            </button>
            <ShareButton />
          </>
        }
      />
      <OptionsLine options={options} onChange={onOptions} />
      {trace.error && (
        <Notice tone="error" title={t('Suivi impossible')}>
          {trace.error} <button type="button" className="btn btn--sm" onClick={trace.rerun}>{t('Relancer')}</button>
        </Notice>
      )}
      {d?.bare && (
        <p className="rd-bare">
          <CornerDownRight aria-hidden />
          <span>
            {rich(
              'Saisie sans protocole : la mesure part de <m>{start}</m>. <l>Suivre aussi la version http</l> ou <b>comparer les quatre variantes</b>.',
              { start: d.start },
              {
                m: (c) => <span className="mono">{c}</span>,
                l: (c) => <Link to={`/redirections?${writeOptions(new URLSearchParams({ url: d.start.replace(/^https:/, 'http:') }), options).toString()}`}>{c}</Link>,
                b: (c) => <button type="button" className="rd-linkbtn" onClick={compare}>{c}</button>,
              },
            )}
          </span>
        </p>
      )}

      {running && !r && (
        <div className="issues" aria-busy="true">
          {[0, 1].map((i) => (
            <div key={i} className="issue">
              <Skel w="30%" />
              <Skel w="70%" />
              <Skel w="55%" />
            </div>
          ))}
        </div>
      )}

      {r && d && <IssueList findings={r.findings} passed={r.passed} extra={(f) => <Measured f={f} d={d} />} />}

      {(trace.hops.length > 0 || running) && (
        <section className="block" aria-labelledby="chain-t">
          <h2 className="block__title" id="chain-t">
            {t('La chaîne')}
            {trace.hops.length > 0 && <span className="rd-chipn">{plural(trace.hops.length, 'étape', 'étapes')}</span>}
          </h2>
          <HopList hops={trace.hops} running={running} autoOpen={r && trace.hops.length === 1 ? 1 : undefined} />
          <p className="rd-hint">{t('Cliquez une étape pour lire ses en-têtes, son corps HTML, ses temps et son certificat.')}</p>
        </section>
      )}

      {r && (
        <section className="block rd-varblock" aria-labelledby="var-t" ref={varRef}>
          <h2 className="block__title" id="var-t">{t('Variantes du site')}</h2>
          {variants ? (
            <VariantsSection result={variants.result} loading={variants.loading} error={variants.error} expected={expected} />
          ) : (
            <div className="rd-varcta">
              <p>{t('Les quatre façons de taper l’adresse (http ou https, avec ou sans www) doivent toutes aboutir à la même page, en une seule redirection permanente.')}</p>
              <button type="button" className="btn btn--primary" onClick={compare}>
                <GitCompareArrows aria-hidden />
                {t('Comparer les variantes')}
              </button>
            </div>
          )}
        </section>
      )}

      {r && d && d.stoppedBy === 'final' && (
        <section className="block" aria-label={t('Détails techniques')}>
          <details className="details" open>
            <summary>
              <span className="details__title">{t('Mesures de la page finale')}</span>
              <span className="details__count">{plural(r.passed.length, 'contrôle conforme', 'contrôles conformes')}</span>
            </summary>
            <div className="details__body">
              <Measures r={r} />
            </div>
          </details>
        </section>
      )}
      {r && <Unavailable items={r.unavailable} />}
      <p className="visually-hidden" aria-live="polite">
        {r ? t('Mesure terminée, note {score} sur 10.', { score: fmtScore(r.score) }) : running && trace.hops.length ? t('Étape {n} reçue : {status}.', { n: trace.hops.length, status: trace.hops[trace.hops.length - 1].exchange.status ?? t('erreur') }) : ''}
      </p>
    </div>
  );
}

/** Landing: the hero, the options folded under the field, and a list mode for many URLs. */
function RedirectsHero({ options, onOptions }: { options: TraceOptions; onOptions: (o: TraceOptions) => void }) {
  const navigate = useNavigate();
  const [listOpen, setListOpen] = useState(false);
  const [list, setList] = useState('');
  const lines = list.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const withOptions = (p: URLSearchParams) => writeOptions(p, options).toString();
  return (
    <ToolHero
      icon={CornerDownRight}
      title={t('Redirections')}
      desc={t('Où mène vraiment une adresse ? Chaque étape avec son statut, ses en-têtes, son HTML, ses temps et son certificat, sans aucun cache.')}
      basePath="/redirections"
      accept="any"
      label={t('URL ou domaine à suivre')}
      placeholder={t('exemple.fr ou https://exemple.fr/page')}
      examples={EXAMPLES}
      buildPath={(v) => `/redirections?${withOptions(new URLSearchParams({ url: v }))}`}
    >
      <div className="rd-herox">
        <OptionsLine options={options} onChange={onOptions} />
        <button type="button" className="btn btn--sm btn--ghost" aria-expanded={listOpen} onClick={() => setListOpen((o) => !o)}>
          <ListPlus aria-hidden />
          {listOpen ? t('Fermer la liste') : t('Vérifier une liste d’URL')}
        </button>
        {listOpen && (
          <form
            className="rd-listform"
            onSubmit={(e) => {
              e.preventDefault();
              if (lines.length) navigate(`/redirections?${withOptions(new URLSearchParams({ liste: lines.join('\n') }))}`);
            }}
          >
            <label className="field__label" htmlFor="rd-list">{t('Une URL par ligne, jusqu’à 100')}</label>
            <textarea id="rd-list" className="textarea textarea--mono" rows={6} value={list} spellCheck={false} onChange={(e) => setList(e.target.value)} placeholder={'exemple.fr\nhttp://exemple.fr/ancienne-page\nhttps://bit.ly/…'} />
            <button type="submit" className="btn btn--primary" disabled={!lines.length}>
              {lines.length > 1 ? t('Suivre les {n} URL', { n: lines.length }) : t('Suivre')}
            </button>
          </form>
        )}
      </div>
    </ToolHero>
  );
}

export default function RedirectsPage() {
  const [params, setParams] = useSearchParams();
  const url = params.get('url')?.trim() ?? '';
  const listRaw = params.get('liste') ?? '';
  const list = useMemo(() => listRaw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean), [listRaw]);
  const optKey = ['ua', 'uat', 'methode', 'cookies', 'h'].map((k) => params.get(k) ?? '').join('|');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const options = useMemo(() => readOptions(params), [optKey]);
  const setOptions = (o: TraceOptions) => setParams(writeOptions(params, o), { replace: false });

  // a pasted list in the single field becomes list mode
  if (url.includes('\n')) return <BatchMode urls={url.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)} options={options} onOptions={setOptions} />;
  if (list.length) return <div className="rd-page page-stack"><BatchMode urls={list} options={options} onOptions={setOptions} /></div>;
  if (!url) return <div className="rd-page page-stack"><RedirectsHero options={options} onOptions={setOptions} /></div>;
  return (
    <div className="rd-page page-stack">
      <SingleTrace key={url} url={url} options={options} onOptions={setOptions} />
    </div>
  );
}
