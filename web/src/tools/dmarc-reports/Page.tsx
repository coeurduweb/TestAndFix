// DMARC aggregate reports: drop .xml / .gz / .zip (here or anywhere in the app), they are sent at
// once; the analysis of the stored reports of the domain follows: verdict and policy advice first,
// alignment rates, daily volume, every source with its verdict and the fix for those to correct.
import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { FileBarChart, FileUp, Trash2, UploadCloud } from 'lucide-react';
import { ShareButton, Unavailable } from '../../components/Report';
import { Details, IssueList, PassList, Verdict } from '../../components/Verdict';
import { Empty, Notice, Skel } from '../../components/ui';
import { api } from '../../lib/api';
import { locale, rich, t, tn, msg } from '../../lib/i18n';
import { fmtBytes, fmtDateTime, fmtInt, plural } from '../../lib/format';
import { takePendingFiles, takePendingText } from '../../lib/pending';
import { pushRecent } from '../../lib/recent';
import type { CheckResult, Finding, PassedCheck } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { Segmented } from '../gen-spf/GenParts';
import { DailyBars, DailyTable } from './DailyBars';
import './reports.css';

/* ---------- server shapes (server/src/tools/dmarc-reports) ---------- */
type Verdict = 'aligned' | 'legit_unaligned' | 'forwarding' | 'spoofing';
interface SourceStat {
  ip: string;
  ptr: string | null;
  provider: { key: string; name: string } | null;
  messages: number;
  dmarcPass: number;
  spfAligned: number;
  dkimAligned: number;
  dkimDomains: string[];
  spfDomains: string[];
  verdict: Verdict;
  verdictLabel: string;
}
interface Aggregate {
  domain: string;
  from: string | null;
  to: string | null;
  reports: number;
  messages: number;
  dmarcPass: number;
  rates: { dmarc: number | null; spf: number | null; dkim: number | null };
  byDay: { day: string; reports: number; messages: number; dmarcPass: number }[];
  bySource: SourceStat[];
  byProvider: { key: string; name: string; sources: number; messages: number; dmarcRate: number | null }[];
  byOrg: { org: string; reports: number; messages: number; dmarcPass: number }[];
  dispositions: { none: number; quarantine: number; reject: number };
  byVerdict: Record<Verdict, number>;
  policy: { p: string; sp: string; np: string; pct: number | null; adkim: string; aspf: string; testing: string } | null;
}
interface Recommendation {
  current: string;
  target: 'none' | 'quarantine' | 'reject';
  change: boolean;
  headline: string;
  reasons: string[];
}
interface FileOutcome {
  file: string;
  status: 'imported' | 'duplicate' | 'error';
  error?: string;
  domain?: string;
  orgName?: string;
  dateBegin?: string;
  dateEnd?: string;
  messages?: number;
  sources?: number;
}
interface UploadData {
  files: FileOutcome[];
  summary: { files: number; imported: number; duplicates: number; errors: number; messages: number };
  domain: string | null;
}
interface QueryData {
  domain: string | null;
  aggregate: Aggregate | null;
  recommendation: Recommendation | null;
  findings: Finding[];
  passed: PassedCheck[];
  score: number | null;
  reports: { id: string; orgName: string; reportId: string; dateBegin: string | null; dateEnd: string | null; messages: number }[];
}
interface DomainRow {
  domain: string;
  reports: number;
  messages: number;
  from: string | null;
  to: string | null;
}

/* ---------- upload, including the files handed over by the global drop ---------- */
const ACCEPT = '.xml,.gz,.zip,.xml.gz,application/xml,text/xml,application/gzip,application/zip';

function uploadFiles(files: File[]) {
  const fd = new FormData();
  for (const f of files) fd.append('file', f, f.name);
  return api<CheckResult<UploadData>>('/api/dmarc-reports/upload', { method: 'POST', body: fd });
}

// Taken once per hand-over even if React mounts the page twice (StrictMode in development).
let boot: { files: File[]; promise: Promise<CheckResult<UploadData>> } | null = null;
function bootUpload() {
  if (!boot) {
    const files = takePendingFiles();
    const text = takePendingText('check:pending-dmarc');
    if (text?.trim()) files.push(new File([text], 'rapport-colle.xml', { type: 'text/xml' }));
    if (!files.length) return null;
    const b = { files, promise: uploadFiles(files) };
    boot = b;
    b.promise.finally(() => setTimeout(() => boot === b && (boot = null), 1000)).catch(() => undefined);
  }
  return boot;
}

/* ---------- helpers ---------- */
const pctOf = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 10 : null);
const fmtPct = (v: number | null) => (v === null ? t('n/d') : `${new Intl.NumberFormat(locale()).format(v)} %`);
const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : '');
const frDate = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale(), { timeZone: 'UTC', day: '2-digit', month: '2-digit', year: 'numeric' }).format(new Date(iso.slice(0, 10))) : '');
const minusDays = (iso: string, n: number) => new Date(Date.parse(iso.slice(0, 10)) - n * 86_400_000).toISOString().slice(0, 10);

const VERDICT_ORDER: Verdict[] = ['legit_unaligned', 'spoofing', 'forwarding', 'aligned'];


/* ---------- page ---------- */
export default function DmarcReportsPage() {
  const [params, setParams] = useSearchParams();
  const domain = params.get('domaine') ?? '';
  const preset = params.get('periode') ?? 'tout';
  const du = params.get('du') ?? '';
  const au = params.get('au') ?? '';
  const [domains, setDomains] = useState<DomainRow[] | null>(null);
  const [domainsErr, setDomainsErr] = useState<string | null>(null);
  const [sending, setSending] = useState<File[] | null>(null);
  const [upload, setUpload] = useState<CheckResult<UploadData> | null>(null);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [q, setQ] = useState<QueryData | null>(null);
  const [qAt, setQAt] = useState<string>('');
  const [qErr, setQErr] = useState<string | null>(null);
  const [qLoading, setQLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const [over, setOver] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [confirmDel, setConfirmDel] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const setP = useCallback(
    (patch: Record<string, string | null>) =>
      setParams(
        (p) => {
          const n = new URLSearchParams(p);
          for (const [k, v] of Object.entries(patch)) v ? n.set(k, v) : n.delete(k);
          return n;
        },
        { replace: true },
      ),
    [setParams],
  );

  const loadDomains = useCallback(() => {
    api<{ domains: DomainRow[] }>('/api/dmarc-reports/domains')
      .then((r) => {
        setDomains(r.domains);
        setDomainsErr(null);
      })
      .catch((e) => {
        setDomains([]);
        setDomainsErr(errorMessage(e));
      });
  }, []);

  const afterUpload = useCallback(
    (r: CheckResult<UploadData>) => {
      setUpload(r);
      setUploadErr(null);
      loadDomains();
      if (r.data.domain) setP({ domaine: r.data.domain, periode: null, du: null, au: null });
      setNonce((n) => n + 1);
    },
    [loadDomains, setP],
  );

  const send = useCallback(
    async (files: File[], promise?: Promise<CheckResult<UploadData>>) => {
      if (!files.length) return;
      setSending(files);
      setUploadErr(null);
      try {
        afterUpload(await (promise ?? uploadFiles(files)));
      } catch (e) {
        setUploadErr(errorMessage(e));
      } finally {
        setSending(null);
      }
    },
    [afterUpload],
  );

  useEffect(() => {
    loadDomains();
    const b = bootUpload();
    if (b) void send(b.files, b.promise);
  }, [loadDomains, send]);

  // No domain chosen: open the one with the most messages.
  useEffect(() => {
    if (!domain && domains?.length && !sending) setP({ domaine: domains[0].domain });
  }, [domain, domains, sending, setP]);

  const current = domains?.find((d) => d.domain === domain);
  const range = useMemo(() => {
    if (preset === 'dates') return { from: du, to: au };
    if (!current?.to || preset === 'tout') return { from: '', to: '' };
    const n = preset === '7' ? 6 : 29;
    return { from: minusDays(current.to, n), to: day(current.to) };
  }, [preset, du, au, current]);

  useEffect(() => {
    if (!domain) return;
    pushRecent({ value: domain, path: `/rapports-dmarc?domaine=${domain}`, label: msg('Rapports DMARC') });
    let alive = true;
    setQLoading(true);
    setQErr(null);
    const qs = new URLSearchParams({ domain });
    if (range.from) qs.set('from', range.from);
    if (range.to) qs.set('to', range.to);
    api<QueryData>(`/api/dmarc-reports?${qs}`)
      .then((r) => {
        if (!alive) return;
        setQ(r);
        setQAt(new Date().toISOString());
      })
      .catch((e) => alive && (setQErr(errorMessage(e)), setQ(null)))
      .finally(() => alive && setQLoading(false));
    return () => {
      alive = false;
    };
  }, [domain, range.from, range.to, nonce]);

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const files = Array.from(e.dataTransfer.files ?? []);
    if (files.length) void send(files);
  };

  const remove = async (id: string) => {
    try {
      await api(`/api/dmarc-reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
      setConfirmDel(null);
      loadDomains();
      setNonce((n) => n + 1);
    } catch (e) {
      setQErr(errorMessage(e));
    }
  };

  const agg = q?.aggregate && q.aggregate.messages > 0 ? q.aggregate : null;
  const hasData = !!agg;
  const compact = hasData || !!sending || (domains?.length ?? 0) > 0;

  const legit = agg ? agg.bySource.filter((s) => s.verdict === 'aligned' || s.verdict === 'legit_unaligned') : [];
  const legitMsgs = legit.reduce((n, s) => n + s.messages, 0);
  const legitPass = legit.reduce((n, s) => n + s.dmarcPass, 0);
  const legitSpf = legit.reduce((n, s) => n + s.spfAligned, 0);
  const legitDkim = legit.reduce((n, s) => n + s.dkimAligned, 0);
  const sources = agg
    ? [...agg.bySource].sort((a, b) => VERDICT_ORDER.indexOf(a.verdict) - VERDICT_ORDER.indexOf(b.verdict) || b.messages - a.messages)
    : [];
  const shownSources = showAll ? sources : sources.slice(0, 25);
  const policyNow = agg?.policy?.p ?? q?.recommendation?.current ?? 'none';
  const legitRate = pctOf(legitPass, legitMsgs);

  const fileInput = (
    <input
      ref={input}
      type="file"
      multiple
      accept={ACCEPT}
      className="dr-file"
      aria-label={t('Choisir des rapports DMARC (.xml, .gz, .zip)')}
      onChange={(e) => {
        const files = Array.from(e.target.files ?? []);
        e.target.value = '';
        void send(files);
      }}
    />
  );
  const dragProps = {
    onDragOver: (e: DragEvent) => {
      e.preventDefault();
      setOver(true);
    },
    onDragLeave: () => setOver(false),
    onDrop,
  };

  const uploadOutcome = upload && !sending && (() => {
    const sum = upload.data.summary;
    const errors = upload.data.files.filter((f) => f.status === 'error');
    const rest = upload.data.files.filter((f) => f.status !== 'error');
    const row = (f: FileOutcome, i: number) => (
      <li key={f.file + i} className={f.status === 'error' ? 'is-bad' : f.status === 'duplicate' ? 'is-watch' : 'is-ok'}>
        <span className="mono dr-files__name">{f.file}</span>
        <span className="dr-files__what">
          {f.status === 'error' ? f.error : `${f.orgName ?? '?'} · ${tn(f.messages ?? 0, '{n} message', '{n} messages')} · ${frDate(f.dateBegin)}${f.status === 'duplicate' ? ' · ' + t('déjà stocké, ignoré') : ''}`}
        </span>
      </li>
    );
    return (
      <section className="dr-upload surface" aria-live="polite">
        <p className="dr-upload__head">
          <span className={`dot ${sum.errors ? 'dot--out' : sum.duplicates ? 'dot--warn' : 'dot--ok'}`} aria-hidden />
          <strong>{plural(sum.files, 'fichier lu', 'fichiers lus')}</strong> : {plural(sum.imported, 'importé', 'importés')},{' '}
          {sum.duplicates === 1 ? t('1 doublon (déjà stocké, ignoré)') : sum.duplicates > 1 ? t('{n} doublons (déjà stockés, ignorés)', { n: sum.duplicates }) : t('{n} doublon', { n: sum.duplicates })}, {plural(sum.errors, 'erreur', 'erreurs')}
          {sum.messages ? ` · ${plural(sum.messages, 'nouveau message', 'nouveaux messages')}` : ''}.
        </p>
        {errors.length > 0 && <ul className="dr-files">{errors.map(row)}</ul>}
        {rest.length > 0 && (
          <Details title={rest.length === 1 ? t('Détail du fichier lu') : t('Détail des {n} fichiers lus', { n: rest.length })}>
            <ul className="dr-files">{rest.map(row)}</ul>
          </Details>
        )}
        <Unavailable items={upload.unavailable} />
      </section>
    );
  })();

  /* ---------- nothing stored yet: one task on the screen ---------- */
  if (!domain && !sending && domains !== null && domains.length === 0) {
    return (
      <div data-own-drop>
        <section className="hero">
          <span className="hero__icon">
            <FileBarChart aria-hidden />
          </span>
          <h1 className="hero__title">{t('Rapports DMARC')}</h1>
          <p className="hero__desc">{t("Qui envoie des mails en votre nom, ce qui est aligné, ce qu'il faut corriger. Déposez les rapports reçus sur votre adresse rua=.")}</p>
          <label className="dr-drop" data-over={over || undefined} {...dragProps}>
            <UploadCloud aria-hidden />
            <span className="dr-drop__title">{t('Déposez vos rapports ici')}</span>
            <span className="dr-drop__hint">{t(".xml, .gz ou .zip, plusieurs à la fois : l'analyse part dès le dépôt.")}</span>
            <span className="btn btn--primary dr-drop__btn">{t('Choisir des fichiers')}</span>
            {fileInput}
          </label>
          {uploadErr && <Notice tone="error" title={t('Dépôt refusé')}>{uploadErr} {t("Vérifiez qu'il s'agit bien de rapports agrégés (.xml, .gz ou .zip) et réessayez.")}</Notice>}
          {uploadOutcome}
          <p className="hero__hint">
            {rich("Où les trouver : l'adresse <m>rua=</m> de votre DMARC reçoit chaque jour un rapport par fournisseur (google.com, Outlook.com, Yahoo…), en pièce jointe .zip ou .gz. Pas encore d'adresse ? Le <l>générateur DMARC</l> en propose une. Rapports gardés 90 jours.", undefined, { m: (c) => <span className="mono">{c}</span>, l: (c) => <Link to="/generateurs/dmarc">{c}</Link> })}
          </p>
        </section>
      </div>
    );
  }

  return (
    <div data-own-drop className={over ? 'dr-page is-over' : 'dr-page'} {...dragProps}>
      <Verdict
        subject={<span className="mono">{domain || t('Rapports DMARC')}</span>}
        pending={(qLoading && !q) || (!!sending && !q)}
        score={hasData ? q?.score ?? undefined : undefined}
        findings={hasData ? q?.findings : undefined}
        passed={hasData ? q?.passed : undefined}
        sentence={hasData ? q?.recommendation?.headline : q && !qLoading ? t('Aucun message sur cette période.') : undefined}
        facts={
          agg
            ? [
                { label: t('Période'), value: t('{from} au {to}', { from: frDate(agg.from), to: frDate(agg.to) }) },
                { label: t('Rapports'), value: fmtInt(agg.reports) },
                { label: t('Messages'), value: fmtInt(agg.messages) },
                { label: t('Envois légitimes alignés'), value: fmtPct(legitRate) },
              ]
            : []
        }
        actions={
          <>
            <label className="btn dr-pick">
              <FileUp aria-hidden />
              {sending ? t('Envoi de {list}…', { list: plural(sending.length, 'fichier', 'fichiers') }) : t('Déposer d’autres rapports')}
              {fileInput}
            </label>
            {q?.recommendation?.change && (
              <Link className="btn" to={`/generateurs/dmarc?domaine=${encodeURIComponent(domain)}`}>
                {t('Passer à p={target}', { target: q.recommendation.target })}
              </Link>
            )}
            <ShareButton />
          </>
        }
      />

      {(domains?.length ?? 0) > 0 && current && (
        <div className="dr-bar">
          {domains!.length > 1 && (
            <div className="field">
              <label className="field__label" htmlFor="dr-domain">
                {t('Domaine')}
              </label>
              <select id="dr-domain" className="select input--mono" value={domain} onChange={(e) => setP({ domaine: e.target.value, periode: null, du: null, au: null })}>
                {domains!.map((d) => (
                  <option key={d.domain} value={d.domain}>
                    {t('{domain} ({n} rapports)', { domain: d.domain, n: d.reports })}
                  </option>
                ))}
              </select>
            </div>
          )}
          <Segmented
            label={t('Période · rapports stockés du {from} au {to}', { from: frDate(current.from), to: frDate(current.to) })}
            value={preset}
            onChange={(v) => setP({ periode: v === 'tout' ? null : v, du: v === 'dates' ? du || day(current.from) : null, au: v === 'dates' ? au || day(current.to) : null })}
            options={[
              { value: 'tout', label: t('Tout') },
              { value: '30', label: t('30 jours') },
              { value: '7', label: t('7 jours') },
              { value: 'dates', label: t('Dates') },
            ]}
          />
          {preset === 'dates' && (
            <div className="dr-dates">
              <div className="field">
                <label className="field__label" htmlFor="dr-du">{t('Du')}</label>
                <input id="dr-du" type="date" className="input" value={du} max={au || undefined} onChange={(e) => setP({ du: e.target.value })} />
              </div>
              <div className="field">
                <label className="field__label" htmlFor="dr-au">{t('Au')}</label>
                <input id="dr-au" type="date" className="input" value={au} min={du || undefined} onChange={(e) => setP({ au: e.target.value })} />
              </div>
            </div>
          )}
        </div>
      )}

      <div className="stack" style={{ gap: 'var(--s6)' }}>
        {uploadErr && <Notice tone="error" title={t('Dépôt refusé')}>{uploadErr} {t("Vérifiez qu'il s'agit bien de rapports agrégés (.xml, .gz ou .zip) et réessayez.")}</Notice>}
        {sending && (
          <div className="issues" aria-busy="true" aria-label={t('Envoi de {n} fichiers', { n: sending.length })}>
            {sending.slice(0, 3).map((f) => (
              <div key={f.name + f.size} className="issue">
                <span className="mono">{f.name} · {fmtBytes(f.size)}</span>
                <Skel w="60%" />
                <Skel w="40%" />
              </div>
            ))}
          </div>
        )}
        {uploadOutcome}
        {qErr && <Notice tone="error" title={t('Analyse impossible')}>{qErr} {t("Relancez la page ; si l'erreur se répète, consultez les journaux du serveur.")}</Notice>}
        {domainsErr && !qErr && <Notice tone="error" title={t('Rapports stockés illisibles')}>{domainsErr}</Notice>}
        {qLoading && !q && (
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
        {q && !agg && domain && !qLoading && current && (
          <Empty title={t('Aucun message sur cette période')}>{t("Choisissez « Tout » ou d'autres dates : les rapports de {domain} couvrent du {from} au {to}.", { domain, from: frDate(current.from), to: frDate(current.to) })}</Empty>
        )}

        {agg && q && (
          <>
            <IssueList findings={q.findings} title={t('Sources à corriger')} />

            {q.recommendation && q.recommendation.reasons.length > 0 && (
              <section className="block" aria-labelledby="reco-t">
                <h2 className="block__title" id="reco-t">
                  {q.recommendation.change ? t('Pourquoi passer de p={current} à p={target}', { current: q.recommendation.current, target: q.recommendation.target }) : t('Pourquoi rester en p={current}', { current: q.recommendation.current })}
                </h2>
                <div className="issue">
                  <ul className="issue__steps">
                    {q.recommendation.reasons.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                  <div>
                    <Link className="btn btn--sm" to={`/generateurs/dmarc?domaine=${encodeURIComponent(domain)}`}>
                      {t('Composer le DMARC de {domain}', { domain })}
                    </Link>
                  </div>
                </div>
              </section>
            )}


            <section className="block" aria-labelledby="kpi-t">
              <h2 className="block__title" id="kpi-t">{t('Chiffres clés')}</h2>
              <div className="dr-kpis surface">
                <Kpi label={t('Envois légitimes alignés DMARC')} value={fmtPct(legitRate)} tone={agg.byVerdict.legit_unaligned > 0 ? 'bad' : 'good'}
                  note={agg.byVerdict.legit_unaligned > 0 ? tn(agg.byVerdict.legit_unaligned, '{n} message légitime non aligné', '{n} messages légitimes non alignés') : t('cible : 100 %')} />
                <Kpi label={t('Signés DKIM alignés')} value={fmtPct(pctOf(legitDkim, legitMsgs))} tone={legitDkim < legitMsgs ? 'watch' : 'good'} note={t('seul alignement qui survit au transfert')} />
                <Kpi label={t('SPF aligné')} value={fmtPct(pctOf(legitSpf, legitMsgs))} note={t('SPF ou DKIM suffit à DMARC')} />
                <Kpi label={t('Usurpation probable')} value={fmtInt(agg.byVerdict.spoofing)} tone={agg.byVerdict.spoofing > 0 && policyNow === 'none' ? 'watch' : undefined}
                  note={agg.byVerdict.spoofing ? (policyNow === 'none' ? t('livrés : p=none ne les bloque pas') : t('traités par p={policy}', { policy: policyNow })) : t('aucun message')} />
                <Kpi label={t('Transfert probable')} value={fmtInt(agg.byVerdict.forwarding)} note={t('DKIM les protège')} />
              </div>
            </section>

            <PassList passed={q.passed} />

            <section className="block" aria-labelledby="tech-t">
              <h2 className="block__title" id="tech-t">{t('Détails')}</h2>
              <Details title={t('Volume par jour')} count={t('{n} jours', { n: agg.byDay.length })} defaultOpen>
                <DailyBars data={agg.byDay} />
                <div style={{ marginTop: 'var(--s4)' }}>
                  <Details title={t('Les mêmes chiffres en tableau')}>
                    <DailyTable data={agg.byDay} />
                  </Details>
                </div>
              </Details>
              <Details title={t("Toutes les sources d'envoi")} count={tn(sources.length, '{n} source', '{n} sources')}>
                <ul className="dr-sources">
                  {shownSources.map((x) => (
                    <li key={x.ip} className={`is-${x.verdict}`}>
                      <span className={`dot ${x.verdict === 'aligned' ? 'dot--ok' : x.verdict === 'legit_unaligned' ? 'dot--out' : x.verdict === 'spoofing' ? 'dot--warn' : ''}`} aria-hidden />
                      <span className="dr-sources__ip mono">{x.ip}</span>
                      <span className="dr-sources__who">
                        {x.provider?.name ?? t('fournisseur inconnu')}
                        <small>{x.ptr ?? t('sans PTR')}</small>
                      </span>
                      <span className="dr-sources__n mono">
                        {t('{n} msg', { n: x.messages })} · {fmtPct(pctOf(x.dmarcPass, x.messages))}
                      </span>
                      <span className={`tag ${VERDICT_TAG[x.verdict]}`}>{x.verdictLabel}</span>
                    </li>
                  ))}
                </ul>
                {sources.length > shownSources.length && (
                  <button type="button" className="btn btn--sm" style={{ marginTop: 'var(--s3)' }} onClick={() => setShowAll(true)}>
                    {t('Voir les {n} sources', { n: sources.length })}
                  </button>
                )}
              </Details>
              <Details title={t('Fournisseurs et rapporteurs')} count={t('{providers} fournisseurs, {orgs} rapporteurs', { providers: agg.byProvider.length, orgs: agg.byOrg.length })}>
                <div className="stack">
                  <div className="table-wrap">
                    <table className="data-table dr-stack">
                      <caption className="visually-hidden">{t("Volume par fournisseur d'envoi")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("Fournisseur d'envoi")}</th>
                          <th scope="col" className="num">{t('Sources')}</th>
                          <th scope="col" className="num">{t('Messages')}</th>
                          <th scope="col" className="num">{t('Alignés DMARC')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {agg.byProvider.map((p) => (
                          <tr key={p.key}>
                            <td>{p.name}</td>
                            <td className="num mono" data-label={t('Sources')}>{fmtInt(p.sources)}</td>
                            <td className="num mono" data-label={t('Messages')}>{fmtInt(p.messages)}</td>
                            <td className={`num mono ${p.dmarcRate !== null && p.dmarcRate < 100 ? 'out-text' : ''}`} data-label={t('Alignés DMARC')}>{fmtPct(p.dmarcRate)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="table-wrap">
                    <table className="data-table dr-stack">
                      <caption className="visually-hidden">{t('Rapports reçus par organisation')}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t('Rapporteur')}</th>
                          <th scope="col" className="num">{t('Rapports')}</th>
                          <th scope="col" className="num">{t('Messages')}</th>
                          <th scope="col" className="num">{t('Alignés DMARC')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {agg.byOrg.map((o) => (
                          <tr key={o.org}>
                            <td>{o.org}</td>
                            <td className="num mono" data-label={t('Rapports')}>{fmtInt(o.reports)}</td>
                            <td className="num mono" data-label={t('Messages')}>{fmtInt(o.messages)}</td>
                            <td className="num mono" data-label={t('Alignés DMARC')}>{fmtPct(pctOf(o.dmarcPass, o.messages))}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p className="field__hint">
                    {t('Traitement appliqué par les destinataires : none {none}, quarantine {quarantine}, reject {reject}.', { none: agg.dispositions.none, quarantine: agg.dispositions.quarantine, reject: agg.dispositions.reject })}
                  </p>
                </div>
              </Details>
              <Details title={t('Rapports stockés')} count={t('{n}, gardés 90 jours', { n: q.reports.length })}>
                <ul className="dr-files">
                  {q.reports.map((r) => (
                    <li key={r.id} className="is-ok dr-files--row">
                      <span className="dr-files__name">
                        {r.orgName} <span className="muted mono">{r.reportId.slice(0, 24)}</span>
                      </span>
                      <span className="dr-files__what mono">
                        {frDate(r.dateBegin)} · {t('{n} msg', { n: r.messages })}
                      </span>
                      {confirmDel === r.id ? (
                        <span className="dr-del">
                          <button type="button" className="btn btn--sm btn--danger" onClick={() => remove(r.id)}>
                            {t('Confirmer')}
                          </button>
                          <button type="button" className="btn btn--sm btn--ghost" onClick={() => setConfirmDel(null)}>
                            {t('Annuler')}
                          </button>
                        </span>
                      ) : (
                        <button type="button" className="btn btn--sm btn--ghost" onClick={() => setConfirmDel(r.id)} aria-label={t('Supprimer le rapport {org} du {date}', { org: r.orgName, date: frDate(r.dateBegin) })}>
                          <Trash2 aria-hidden /> {t('Supprimer')}
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </Details>
            </section>
          </>
        )}
      </div>
    </div>
  );
}

const VERDICT_TAG: Record<Verdict, string> = {
  aligned: 'tag--ok',
  legit_unaligned: 'tag--out',
  spoofing: 'tag--warn',
  forwarding: '',
};

function Kpi({ label, value, note, tone }: { label: string; value: string; note?: string; tone?: 'good' | 'watch' | 'bad' }) {
  return (
    <div className={`dr-kpi ${tone ? `dr-kpi--${tone}` : ''}`}>
      <span className="dr-kpi__label">{label}</span>
      <span className="dr-kpi__value">{value}</span>
      {note && <span className="dr-kpi__note">{note}</span>}
    </div>
  );
}
