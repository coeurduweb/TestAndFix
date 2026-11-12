// Vérifier un lien (/lien?url=...). The verdict in very large type with its reason, the redirect
// chain arriving hop by hop, the reputation sources in a table, the phishing signs as
// Mesuré / Référence rows. The checked page is never rendered and nothing is loaded from it:
// every URL of the chain is inert text with a Copy button, so a phishing link cannot be opened
// by a stray click. The headers and bodies of each hop belong to the Redirections tool.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { CornerDownRight, ExternalLink, Link2, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX, Upload } from 'lucide-react';
import { deviationOf, FindingDetail, LabRow, LabTable, RerunButton, ShareButton, Unavailable, type Deviation } from '../../components/Report';
import { ToolHero } from '../../components/ToolHero';
import { CopyButton, Notice, Skel } from '../../components/ui';
import { Details, IssueList, ScoreBar } from '../../components/Verdict';
import { ApiError } from '../../lib/api';
import { fmtDateTime, fmtMs, fmtScore, plural } from '../../lib/format';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { Finding } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { uniqueIds } from '../ip/model';
import { useSse } from '../ip/sse';
import {
  brokenDestination, dedupeLookalikes, fmtAge, initialLink, linkPath, linkReducer, liveAlerts, refang, scriptsOf, splitUrl, STOP_LABEL, VIA_LABEL,
  type Hop, type Intel, type LinkReport, type LinkState, type Lookalike, type PageFacts, type RdapAge, type StepEvent, type TlsInfo, type VtUrlData,
} from './model';
import './link.css';

/* ---------- findings handed out to the rows that explain them ---------- */
class FindingPool {
  private used = new Set<Finding>();
  constructor(readonly all: Finding[]) {}
  take(pred: (f: Finding) => boolean): Finding[] {
    const out = this.all.filter((f) => !this.used.has(f) && pred(f));
    out.forEach((f) => this.used.add(f));
    return out;
  }
  rest(): Finding[] {
    return this.all.filter((f) => !this.used.has(f));
  }
}
const worst = (fs: Finding[]): Deviation | undefined => {
  const f = [...fs].sort((a, b) => b.penalty - a.penalty)[0];
  return f ? deviationOf(f) : undefined;
};
function FindingDetails({ findings, extra }: { findings: Finding[]; extra?: ReactNode }) {
  if (!findings.length) return <>{extra}</>;
  return (
    <>
      {findings.map((f, i) => (
        <div key={f.id + i} className="stack-sm">
          {findings.length > 1 && <div className="lab-detail__label">{f.title}</div>}
          <FindingDetail f={f} />
        </div>
      ))}
      {extra}
    </>
  );
}

/* ---------- an URL as inert text ---------- */
function InertUrl({ url, domain, copy = true, label }: { url: string; domain?: string; copy?: boolean; label?: string }) {
  const p = splitUrl(url, domain);
  return (
    <span className="lk-url">
      <span className="lk-url__text mono" translate="no">
        <span className="lk-url__dim">{p.scheme}</span>
        {p.userinfo && <span className="lk-url__user">{p.userinfo}</span>}
        <span className="lk-url__dim">{p.sub}</span>
        <span className="lk-url__domain">{p.domain}</span>
        <span className="lk-url__dim">{p.rest}</span>
      </span>
      {copy && <CopyButton text={url} label={label ?? t('Copier')} what={t('Adresse copiée (ne l’ouvrez pas)')} />}
    </span>
  );
}

/* ---------- verdict ---------- */
const B = { b: (c: ReactNode) => <strong>{c}</strong> };
const VERDICT: Record<LinkReport['level'], { word: string; Icon: typeof ShieldCheck }> = {
  safe: { word: msg('Sûr'), Icon: ShieldCheck },
  suspicious: { word: msg('Suspect'), Icon: ShieldAlert },
  dangerous: { word: msg('Dangereux'), Icon: ShieldX },
};

const TONE: Record<LinkReport['level'], 'good' | 'watch' | 'bad'> = { safe: 'good', suspicious: 'watch', dangerous: 'bad' };

function VerdictHead({ state, running, url, restart }: { state: LinkState; running: boolean; url: string; restart: () => void }) {
  const r = state.result;
  const d = r?.data;
  const alerts = liveAlerts(state.events);
  const total = state.steps.length;
  const doneSteps = state.steps.filter((s) => state.events[s.id]).length;
  const level = d?.level;
  const v = level ? VERDICT[level] : null;
  const Icon = v?.Icon ?? ShieldQuestion;
  const tone = level ? TONE[level] : alerts.length ? 'bad' : 'pending';
  const consulted = d ? ['safebrowsing', 'virustotal', 'urlhaus', 'openphish', 'dnsbl'].filter((id) => state.events[id]?.status === 'ok').length : 0;
  const final = d?.final ?? state.hops[state.hops.length - 1]?.url;
  const start = d?.start ?? state.url ?? url;
  const broken = d ? brokenDestination(d.chain.hops) : null;
  return (
    <header className={`verdict verdict--${tone} lk-band`}>
      <div className="verdict__main">
        <div className="verdict__mood">
          <Icon aria-hidden className={!v && running ? 'spin' : undefined} />
          {v ? t('Verdict sur ce lien') : running ? t('Vérification en cours') : t('Vérification interrompue')}
        </div>
        <h1 className="verdict__subject lk-band__word" aria-live="polite">
          {v ? t(v.word) : alerts.length ? t('Déjà signalé') : t('Analyse en cours')}
        </h1>
        <p className="verdict__sentence lk-band__sentence">
          {d ? (
            broken ? (
              d.level === 'safe' ? (
                <>
                  {rich('<b>Mais la destination ne répond plus : {code}, {text}.</b>', { code: broken.code, text: broken.text }, B)} {d.reason}
                </>
              ) : (
                <>
                  {d.reason} {rich('<b>La destination ne répond plus : {code}, {text}.</b>', { code: broken.code, text: broken.text }, B)}
                </>
              )
            ) : (
              d.reason
            )
          ) : alerts.length ? (
            rich('<b>Signalé par {names}. Le verdict tombe à la fin de la vérification.</b>', { names: alerts.join(', ') }, B)
          ) : (
            t('{done} étapes sur {total} terminées. Le lien est suivi depuis le serveur de TestAndFix, jamais depuis votre navigateur.', { done: doneSteps, total: total || 11 })
          )}
        </p>
        <dl className="lk-target">
          <div>
            <dt>{t('Lien vérifié')}</dt>
            <dd>
              <InertUrl url={start} domain={state.hops[0]?.domain} label={t('Copier')} />
            </dd>
          </div>
          {final && final !== start && (
            <div>
              <dt>{t('Mène à')}</dt>
              <dd>
                <InertUrl url={final} domain={state.hops[state.hops.length - 1]?.domain} label={t('Copier')} />
              </dd>
            </div>
          )}
        </dl>
        {r && (
          <dl className="verdict__facts">
            <div>
              <dt>{t('Sources consultées')}</dt>
              <dd>{t('{n} sur 5', { n: consulted })}</dd>
            </div>
            <div>
              <dt>{t('Redirections')}</dt>
              <dd>{d!.chain.hops.filter((h) => h.next).length}</dd>
            </div>
            {d!.domains[0]?.ageDays !== undefined && (
              <div>
                <dt>{t('Âge du domaine')}</dt>
                <dd>{fmtAge(d!.domains[d!.domains.length - 1].ageDays ?? d!.domains[0].ageDays!)}</dd>
              </div>
            )}
          </dl>
        )}
        <div className="verdict__actions">
          <RerunButton onClick={restart} busy={running} />
          <ShareButton />
          <Link className="btn btn--sm" to={`/redirections?url=${encodeURIComponent(start)}`}>
            <CornerDownRight aria-hidden />
            {t('En-têtes de chaque requête')}
          </Link>
        </div>
      </div>
      <div className="verdict__score">
        <div className="verdict__number">
          {r?.score === undefined ? '…' : fmtScore(r.score)}
          <small>/10</small>
        </div>
        <ScoreBar score={r?.score ?? null} findings={uniqueIds(r?.findings) ?? []} onPick={(id) => document.getElementById(`issue-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })} />
      </div>
    </header>
  );
}

/* ---------- chain ---------- */
function statusClass(h: Hop): string {
  if (h.error || (h.status ?? 0) >= 400) return 'lk-status lk-status--bad';
  if ((h.status ?? 0) >= 300) return 'lk-status lk-status--redirect';
  return 'lk-status';
}

/** Same words as the Redirections tool: a hop is a redirection, the first request is not one. */
function chainCount(hops: Hop[]): string {
  const redirects = hops.filter((h) => h.next).length;
  return t('{requests}, {redirects}', { requests: plural(hops.length, 'requête', 'requêtes'), redirects: redirects ? plural(redirects, 'redirection', 'redirections') : t('aucune redirection') });
}

function Chain({ state, running, report }: { state: LinkState; running: boolean; report?: LinkReport }) {
  const hops = report?.chain.hops ?? state.hops;
  const chainDone = !!report || !!state.events.chain;
  const stopped = report?.chain.stoppedBy;
  return (
    <section className="block" aria-labelledby="chain-t">
      <h2 className="block__title" id="chain-t">
        {t('Où mène ce lien')}
        {hops.length > 0 && <span className="lk-chain__count">{chainCount(hops)}</span>}
      </h2>
      <ol className="lk-chain">
        {hops.map((h, i) => {
          const last = i === hops.length - 1 && chainDone;
          const bad = !!h.error || (h.status ?? 0) >= 400;
          return (
            <li key={h.index} className={`lk-step${bad ? ' lk-step--bad' : ''}${last && !bad ? ' lk-step--final' : ''}`}>
              <span className="lk-step__n" aria-hidden>
                {h.index}
              </span>
              <div className="lk-step__body">
                <div className="lk-step__top">
                  <span className={statusClass(h)}>{h.status ?? (h.error ? t('pas de réponse') : '?')}</span>
                  <span className="lk-step__via">
                    {h.via === 'start' ? t('lien de départ') : t('arrivée par {via}', { via: t(VIA_LABEL[h.via]) })}
                  </span>
                  {(h.via === 'js' || h.via === 'meta') && <span className="tag tag--warn">{t('redirection cachée')}</span>}
                  <span className="lk-step__meta mono">
                    {h.ip ?? ''}
                    {h.ip ? ' · ' : ''}
                    {fmtMs(h.ms)}
                  </span>
                </div>
                <InertUrl url={h.url} domain={h.domain} />
                {h.error && <p className="lk-step__err">{h.error}</p>}
                {last && !bad && h.contentType && <p className="lk-step__note">{h.server ? t('Page finale : {type}, serveur {server}', { type: h.contentType.split(';')[0], server: h.server }) : t('Page finale : {type}', { type: h.contentType.split(';')[0] })}</p>}
                {last && bad && !h.error && <p className="lk-step__err">{t('La destination ne répond plus : HTTP {status}.', { status: h.status })}</p>}
              </div>
            </li>
          );
        })}
        {!chainDone && running && (
          <li className="lk-step lk-step--pending">
            <span className="lk-step__n" aria-hidden>
              {hops.length + 1}
            </span>
            <div className="lk-step__body">
              <Skel w="40%" />
              <Skel w="70%" />
            </div>
          </li>
        )}
      </ol>
      {stopped && STOP_LABEL[stopped] && <p className="lk-note">{t(STOP_LABEL[stopped])}</p>}
      <p className="lk-note">
        {rich('Adresses affichées en texte, jamais en lien cliquable. Les en-têtes et le corps de chaque requête sont dans <a>Redirections</a>.', undefined, {
          a: (c) => <Link to={`/redirections?url=${encodeURIComponent(hops[0]?.url ?? state.url ?? '')}`}>{c}</Link>,
        })}
      </p>
    </section>
  );
}

/* ---------- reputation sources ---------- */
/** "clé GSB_API_KEY absente : ajoutez-la..." -> "clé GSB_API_KEY absente"; the whole text is in Unavailable. */
const shortReason = (r: string) => r.split(' : ')[0];

const SOURCES: { id: string; label: string; reference: string }[] = [
  { id: 'safebrowsing', label: 'Google Safe Browsing', reference: msg('aucune menace') },
  { id: 'virustotal', label: 'VirusTotal', reference: msg('moins de 2 moteurs') },
  { id: 'urlhaus', label: 'URLhaus', reference: msg('absent') },
  { id: 'openphish', label: 'OpenPhish', reference: msg('absent du flux') },
  { id: 'urlscan', label: 'urlscan.io', reference: msg('pas de verdict, historique') },
  { id: 'dnsbl', label: msg('Listes de domaines'), reference: msg('absent') },
];

function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a className="lk-ext" href={href} target="_blank" rel="noreferrer noopener">
      {children}
      <ExternalLink aria-hidden />
    </a>
  );
}

function sourceMeasure(id: string, data: unknown): ReactNode {
  if (id === 'safebrowsing') {
    const g = data as NonNullable<Intel['safebrowsing']>;
    return g.matches.length ? g.matches.map((m) => m.threatType).join(', ') : t('aucune menace connue ({n})', { n: plural(g.checked.length, 'adresse', 'adresses') });
  }
  if (id === 'virustotal') {
    const list = data as VtUrlData[];
    return (
      <span className="lk-lines">
        {list.map((v) => (
          <span key={v.url}>
            {v.found && v.stats
              ? t('{malicious} malveillant, {suspicious} suspect sur {total} moteurs', { malicious: v.stats.malicious, suspicious: v.stats.suspicious, total: v.stats.malicious + v.stats.suspicious + v.stats.harmless + v.stats.undetected })
              : v.submitted
                ? t('inconnu, soumis pour analyse')
                : t('jamais analysé')}
            {list.length > 1 && <span className="muted"> ({v.url === list[0].url ? t('lien') : t('destination')})</span>} <ExtLink href={v.link}>{t('fiche')}</ExtLink>
          </span>
        ))}
      </span>
    );
  }
  if (id === 'urlhaus') {
    const u = data as NonNullable<Intel['urlhaus']>;
    const listed = u.urls.filter((x) => x.listed);
    if (listed.length) return listed.map((x) => `${x.status ?? t('recensé')}${x.threat ? `, ${x.threat}` : ''}`).join(' ; ');
    if (u.host?.listed) return t('lien absent ; {n} autre(s) adresse(s) active(s) sur {host}', { n: u.host.onlineCount, host: u.host.host });
    return t('absent de la base');
  }
  if (id === 'openphish') {
    const o = data as NonNullable<Intel['openphish']>;
    if (o.exact.length) return t('présent dans le flux ({n} pages actives)', { n: o.feedSize });
    if (o.sameHost.length) return t('autres pages du même site dans le flux');
    return o.stale ? t('absent des {n} pages actives du flux (copie ancienne)', { n: o.feedSize }) : t('absent des {n} pages actives du flux', { n: o.feedSize });
  }
  if (id === 'urlscan') {
    const list = data as NonNullable<Intel['urlscan']>;
    return (
      <span className="lk-lines">
        {list.map((u) => (
          <span key={u.host}>
            {u.total >= 10000 ? t('{host} : plus de 10 000 analyses publiques', { host: u.host }) : tn(u.total, '{host} : {n} analyse publique', '{host} : {n} analyses publiques', { host: u.host })}
            {u.scans[0]?.time ? t(', dernière le {date}', { date: fmtDateTime(u.scans[0].time).split(' à ')[0] }) : ''} <ExtLink href={u.searchLink}>{t('recherche')}</ExtLink>
          </span>
        ))}
      </span>
    );
  }
  const dl = data as NonNullable<Intel['dnsbl']>;
  if (dl.listed.length) return dl.listed.map((h) => t('{target} sur {name} ({detail})', { target: h.target, name: h.name, detail: `${h.codes.join(', ')}${h.meaning ? ` ${h.meaning}` : ''}` })).join(' ; ');
  const inter = tn(dl.clean, '{n} interrogation', '{n} interrogations');
  return `${tn(dl.queried.length, '{list} absent de {inter}', '{list} absents de {inter}', { list: dl.queried.join(', '), inter })}${dl.refused.length ? tn(dl.refused.length, ', {n} requête refusée', ', {n} requêtes refusées') : ''}`;
}

const SOURCE_FINDINGS: Record<string, RegExp> = {
  safebrowsing: /^phishing\.safe_browsing$/,
  virustotal: /^phishing\.virustotal/,
  urlhaus: /^phishing\.urlhaus/,
  openphish: /^phishing\.openphish/,
  urlscan: /^$/,
  dnsbl: /^(links\.uribl_listed|blacklist\.spamhaus_dbl_abused|blacklist\.uribl_grey_red|blacklist\.query_blocked)$/,
};

function Sources({ state, report, pool, onSubmit, submitted }: { state: LinkState; report?: LinkReport; pool: FindingPool | null; onSubmit: () => void; submitted: boolean }) {
  return (
      <LabTable columns={[t('Source'), t('Résultat'), t('Référence'), t('Écart')]}>
        {SOURCES.map(({ id, label: rawLabel, reference: rawRef }) => {
          const label = t(rawLabel);
          const reference = t(rawRef);
          const ev: StepEvent | undefined = state.events[id];
          if (!ev && !report) return <LabRow key={id} label={label} measured={<Skel w="18ch" />} reference={reference} deviation={{ kind: 'pending' }} />;
          if (!ev || ev.status !== 'ok') {
            const reason = ev?.reason ?? t('non interrogée');
            return (
              <LabRow
                key={id}
                label={label}
                measured={<span className="muted">{t('non consultée')}</span>}
                reference={<span className="lk-reason" title={reason}>{shortReason(reason)}</span>}
                deviation={{ kind: 'info', text: /clé|_KEY/.test(reason) ? t('sans clé') : t('non consultée') }}
              />
            );
          }
          const fs = pool ? pool.take((f) => SOURCE_FINDINGS[id].test(f.id)) : [];
          const vtUnknown = id === 'virustotal' && (ev.data as VtUrlData[]).some((v) => !v.found && !v.submitted);
          const submitBox = vtUnknown && !submitted && (
            <div className="lk-submit">
              <p>
                {rich('<b>VirusTotal ne connaît pas ce lien.</b> Le soumettre lance une analyse par ses moteurs, mais rend l’adresse publique : elle devient lisible par tous les abonnés de VirusTotal, jeton ou identifiant compris. Ne le faites pas pour un lien personnel (réinitialisation de mot de passe, facture, lien de connexion).', undefined, B)}
              </p>
              <button type="button" className="btn btn--sm" onClick={onSubmit}>
                <Upload aria-hidden />
                {t('Soumettre à VirusTotal et relancer')}
              </button>
            </div>
          );
          const dev: Deviation = !report ? { kind: 'pending' } : worst(fs) ?? (id === 'urlscan' ? { kind: 'info', text: t('noté') } : vtUnknown ? { kind: 'info', text: t('inconnu') } : { kind: 'ok' });
          const hasOut = fs.some((f) => f.penalty >= 1);
          return (
            <LabRow
              key={id + (report ? '-r' : '')}
              label={label}
              measured={sourceMeasure(id, ev.data)}
              reference={reference}
              deviation={dev}
              detail={fs.length || submitBox ? <FindingDetails findings={fs} extra={submitBox || undefined} /> : undefined}
              defaultOpen={hasOut}
            />
          );
        })}
      </LabTable>
  );
}

/* ---------- phishing signs ---------- */
const KIND_TEXT: Record<Lookalike['kind'], string> = {
  homoglyph: msg('caractères qui imitent'),
  typo: msg('faute de frappe sur'),
  subdomain: msg('marque placée en sous-domaine'),
  word: msg('marque utilisée comme mot du domaine'),
  contains: msg('nom de la marque inclus'),
};

function Pending({ label, reference }: { label: string; reference?: ReactNode }) {
  return <LabRow label={label} measured={<Skel w="16ch" />} reference={reference} deviation={{ kind: 'pending' }} />;
}

function Signs({ state, report, pool }: { state: LinkState; report?: LinkReport; pool: FindingPool | null }) {
  const ev = state.events;
  const rows: ReactNode[] = [];

  // domain age
  const ages: LinkReport['domains'] = report?.domains ?? (ev.rdap?.status === 'ok' ? Object.entries(ev.rdap.data as Record<string, RdapAge>).map(([domain, a]) => ({ domain, ...a })) : []);
  if (!report && !ev.rdap) rows.push(<Pending key="age" label={t('Âge du domaine')} reference={t('30 jours au moins')} />);
  else if (!ages.length)
    rows.push(<LabRow key="age" label={t('Âge du domaine')} measured={<span className="muted">{t('non mesuré')}</span>} reference={<span className="lk-reason">{ev.rdap?.reason ?? t('adresse IP, pas de domaine')}</span>} deviation={{ kind: 'info', text: t('sans objet') }} />);
  for (const a of ages) {
    const fs = pool ? pool.take((f) => f.id === 'links.domain_recent' && !!f.evidence?.startsWith(a.domain + ' ')) : [];
    rows.push(
      <LabRow
        key={'age' + a.domain}
        label={ages.length > 1 ? t('Âge de {domain}', { domain: a.domain }) : t('Âge du domaine')}
        measured={
          a.ageDays !== undefined ? (
            <>
              {fmtAge(a.ageDays)}
              <span className="lk-sub">
                {a.created ? t(', créé le {date}', { date: fmtDateTime(a.created).split(' à ')[0] }) : ''}
                {a.registrar ? `, ${a.registrar}` : ''}
                {a.ageSource === 'urlscan.io' ? ` ${t('(selon urlscan.io)')}` : ''}
              </span>
            </>
          ) : (
            <span className="muted">{a.unavailable ? t('inconnu : {reason}', { reason: a.unavailable }) : t('inconnu')}</span>
          )
        }
        reference={t('30 jours au moins')}
        deviation={worst(fs) ?? (a.ageDays === undefined ? { kind: 'info', text: t('inconnu') } : !report ? { kind: 'pending' } : { kind: 'ok' })}
        detail={fs.length ? <FindingDetails findings={fs} /> : undefined}
        defaultOpen
      />,
    );
  }

  // look-alikes and punycode
  const heur = ev.heuristics?.data as { lookalikes: Lookalike[]; punycode: LinkReport['punycode'] } | undefined;
  const looks = report?.lookalikes ?? heur?.lookalikes;
  const puny = report?.punycode ?? heur?.punycode;
  if (!looks) rows.push(<Pending key="look" label={t('Sosie d’une marque')} reference={t('aucune marque imitée')} />);
  else if (!looks.length) rows.push(<LabRow key="look" label={t('Sosie d’une marque')} measured={<span className="muted">{t('aucune marque imitée')}</span>} reference={t('aucune marque imitée')} deviation={{ kind: 'ok' }} />);
  else
    for (const [i, { item: l, hosts }] of dedupeLookalikes(looks).entries()) {
      const shown = new Set(looks.filter((x) => hosts.includes(x.host)).map((x) => `${x.unicode ?? x.host} `));
      const fs = pool ? pool.take((f) => (f.id === 'phishing.brand_lookalike' || f.id === 'links.punycode_lookalike') && [...shown].some((p) => !!f.evidence?.startsWith(p))) : [];
      rows.push(
        <LabRow
          key={'look' + i}
          label={t('Sosie de {brand}', { brand: l.brandName })}
          measured={
            <>
              <span translate="no">{(l.unicode ?? l.host).replace(/^www\./, '')}</span>
              <span className="lk-sub">
                {' '}
                {t(KIND_TEXT[l.kind])} « {l.matched} »{l.phishingWord ? t(', avec « {word} »', { word: l.phishingWord }) : ''}
                {l.unicode ? t(', écrit {host} dans le lien', { host: l.host.replace(/^www\./, '') }) : ''}
              </span>
            </>
          }
          reference={t('officiel : {list}', { list: l.official.slice(0, 3).join(', ') })}
          deviation={worst(fs) ?? { kind: 'warn', direction: 'up', text: t('sosie') }}
          detail={fs.length ? <FindingDetails findings={fs.slice(0, 1)} /> : undefined}
          defaultOpen
        />,
      );
    }
  if (!puny) rows.push(<Pending key="puny" label={t('Nom en caractères internationaux')} reference={t('un seul alphabet')} />);
  else if (!puny.length) rows.push(<LabRow key="puny" label={t('Nom en caractères internationaux')} measured={<span className="muted">{t('aucun (nom ASCII)')}</span>} reference={t('un seul alphabet')} deviation={{ kind: 'ok' }} />);
  else
    for (const [i, p] of puny.filter((x, k, all) => all.findIndex((y) => y.label === x.label) === k).entries()) {
      const fs = pool ? pool.take((f) => f.id === 'links.punycode_lookalike' && !!f.evidence?.startsWith(p.label)) : [];
      rows.push(
        <LabRow
          key={'puny' + i}
          label={t('Nom en caractères internationaux')}
          measured={
            <>
              <span translate="no">{p.label}</span> <span className="lk-sub">{t('s’affiche')}</span> « <span translate="no">{p.unicode}</span> »
              <span className="lk-sub"> ({scriptsOf(p.unicode).join(` ${t('et')} `) || t('alphabet inconnu')})</span>
            </>
          }
          reference={t('un seul alphabet')}
          deviation={worst(fs) ?? (p.mixedScripts ? { kind: 'out', direction: 'up', text: t('alphabets mêlés') } : { kind: 'info', text: t('noté') })}
          detail={fs.length ? <FindingDetails findings={fs} /> : undefined}
        />,
      );
    }

  // link shortener in front of the destination
  const shortF = pool ? pool.take((f) => f.id === 'links.shortener') : [];
  if (report)
    rows.push(
      <LabRow
        key="short"
        label={t('Raccourcisseur de liens')}
        measured={shortF[0]?.evidence ?? t('aucun')}
        reference={t('destination lisible dans le lien')}
        deviation={worst(shortF) ?? { kind: 'ok' }}
        detail={shortF.length ? <FindingDetails findings={shortF} /> : undefined}
      />,
    );

  // forms on the final page
  const page: PageFacts | undefined = report?.page ?? (ev.page?.status === 'ok' ? (ev.page.data as PageFacts) : undefined);
  const pageDone = !!report || !!ev.page;
  const formF = pool ? pool.take((f) => f.id === 'phishing.credential_form' || f.id === 'phishing.form_on_page') : [];
  const titleF = pool ? pool.take((f) => f.id === 'phishing.title_brand_mismatch') : [];
  if (!pageDone) {
    rows.push(<Pending key="pw" label={t('Formulaire de mot de passe')} reference={t('aucun hors site officiel')} />);
    rows.push(<Pending key="card" label={t('Formulaire de carte bancaire')} reference={t('aucun hors site officiel')} />);
  } else if (!page) {
    rows.push(<LabRow key="pw" label={t('Formulaires de la page finale')} measured={<span className="muted">{t('page non lue')}</span>} reference={<span className="lk-reason">{ev.page?.reason ?? t('pas de page HTML en fin de chaîne')}</span>} deviation={{ kind: 'info', text: t('sans objet') }} />);
  } else {
    const formDev = (present: boolean): Deviation => (present ? worst(formF) ?? { kind: 'info', text: t('présent') } : { kind: 'ok', text: t('absent') });
    rows.push(
      <LabRow
        key={report ? 'pw-r' : 'pw'}
        label={t('Formulaire de mot de passe')}
        measured={page.passwordForm ? t('présent') : t('absent')}
        reference={t('aucun hors site officiel')}
        deviation={formDev(page.passwordForm)}
        detail={page.passwordForm && formF.length ? <FindingDetails findings={formF} /> : undefined}
        defaultOpen={formF.some((f) => f.penalty > 0)}
      />,
    );
    rows.push(
      <LabRow
        key="card"
        label={t('Formulaire de carte bancaire')}
        measured={page.cardForm ? (page.cardHints.length ? t('présent ({hints})', { hints: page.cardHints.slice(0, 3).join(', ') }) : t('présent')) : t('absent')}
        reference={t('aucun hors site officiel')}
        deviation={formDev(page.cardForm)}
        detail={!page.passwordForm && page.cardForm && formF.length ? <FindingDetails findings={formF} /> : undefined}
      />,
    );
    rows.push(
      <LabRow
        key="title"
        label={t('Titre de la page')}
        measured={page.title ? <span className="lk-title">« {page.title} »</span> : <span className="muted">{t('aucun')}</span>}
        reference={t('sans marque étrangère au domaine')}
        deviation={worst(titleF) ?? (page.brandsInTitle.length ? { kind: 'info', text: t('noté') } : { kind: 'ok' })}
        detail={titleF.length ? <FindingDetails findings={titleF} /> : undefined}
      />,
    );
  }

  // certificates
  const tls: TlsInfo[] = report?.tls ?? (ev.tls?.status === 'ok' ? (ev.tls.data as TlsInfo[]) : []);
  if (!report && !ev.tls) rows.push(<Pending key="tls" label={t('Certificat')} reference={t('valide pour le nom')} />);
  else if (!tls.length) rows.push(<LabRow key="tls" label={t('Certificat')} measured={<span className="muted">{t('aucun')}</span>} reference={<span className="lk-reason">{ev.tls?.reason ?? t('pas de requête en https joignable')}</span>} deviation={{ kind: 'info', text: t('sans objet') }} />);
  for (const tl of tls) {
    const fs = pool ? pool.take((f) => f.family === 'tls' && !!f.evidence?.startsWith(`${tl.host} (`)) : [];
    const bad = fs.filter((f) => f.penalty > 0);
    rows.push(
      <LabRow
        key={'tls' + tl.host}
        label={tls.length > 1 ? t('Certificat de {host}', { host: tl.host }) : t('Certificat')}
        measured={
          tl.error ? (
            <span className="muted">{tl.error}</span>
          ) : (
            <>
              {tl.expired ? t('expiré') : tl.selfSigned ? t('auto-signé') : !tl.nameMatches ? t('nom différent') : !tl.authorized ? t('non reconnu') : t('valide')}
              <span className="lk-sub">
                , {tl.issuerOrg ?? tl.issuer ?? t('émetteur inconnu')}
                {tl.ageDays !== undefined ? t(', émis il y a {age}', { age: fmtAge(tl.ageDays) }) : ''}
                {tl.daysLeft !== undefined && tl.daysLeft >= 0 ? t(', expire dans {age}', { age: fmtAge(tl.daysLeft) }) : ''}
              </span>
            </>
          )
        }
        reference={t('valide pour {host}', { host: tl.host })}
        deviation={worst(bad) ?? (tl.error ? { kind: 'info', text: t('non lu') } : !report ? { kind: 'pending' } : { kind: 'ok' })}
        detail={bad.length ? <FindingDetails findings={bad} /> : undefined}
      />,
    );
  }

  // hidden redirects
  const hops = report?.chain.hops ?? state.hops;
  const hidden = hops.filter((h) => h.next === 'js' || h.next === 'meta').length;
  const jsF = pool ? pool.take((f) => f.id === 'phishing.js_redirect') : [];
  if (report || ev.chain)
    rows.push(
      <LabRow
        key="js"
        label={t('Redirections par la page')}
        measured={hidden ? `${hidden} (${[report?.chain.jsRedirects ? t('{n} par script', { n: report.chain.jsRedirects }) : '', report?.chain.metaRefreshes ? t('{n} par meta refresh', { n: report.chain.metaRefreshes }) : ''].filter(Boolean).join(', ') || t('script ou meta')})` : t('aucune')}
        reference={t('aucune')}
        deviation={worst(jsF) ?? (hidden ? { kind: 'info', text: t('noté') } : { kind: 'ok' })}
        detail={jsF.length ? <FindingDetails findings={jsF} /> : undefined}
      />,
    );

  return (
      <LabTable>{rows}</LabTable>
  );
}

/* ---------- the report ---------- */
function LinkReportView({ url }: { url: string }) {
  const [submit, setSubmit] = useState(false);
  const req = useMemo(() => ({ url: `/api/link/stream?url=${encodeURIComponent(url)}${submit ? '&submit=1' : ''}` }), [url, submit]);
  const { state, status, error, restart } = useSse(req, url + (submit ? '#vt' : ''), linkReducer, initialLink);
  const running = status === 'open';
  const r = state.result;
  const d = r?.data;

  useEffect(() => {
    pushRecent({ value: url, path: linkPath(url), label: msg('Lien') });
  }, [url]);

  // urlscan.io and RDAP land in `unavailable` without a reason when they did answer (server
  // quirk reported 2026-11-10): only entries with a reason are real.
  const unavailable = (r?.unavailable ?? []).filter((u) => u.reason);
  if (error && !state.steps.length)
    return (
      <>
        <Notice tone={error instanceof ApiError && error.status === 400 ? 'warn' : 'error'} title={t('Vérification impossible')}>
          {errorMessage(error)}
        </Notice>
        <LinkHero />
      </>
    );

  return (
    <div className="lk-page page-stack">
      <VerdictHead state={state} running={running} url={url} restart={restart} />
      {error && (
        <Notice tone="error" title={t('Vérification incomplète')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={restart}>
            {t('Relancer')}
          </button>
        </Notice>
      )}
      <div className="page-stack">
        {r ? (
          <IssueList findings={r.findings.filter((f) => f.id !== 'links.broken')} passed={r.passed} />
        ) : (
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
        {Chain({ state, running, report: d })}
        <section className="page-stack" aria-label={t('Détails techniques')}>
          <Details title={t('Sources de réputation')} count={t('Safe Browsing, VirusTotal, URLhaus, OpenPhish, urlscan, listes de domaines')} defaultOpen>
            {Sources({ state, report: d, pool: null, onSubmit: () => setSubmit(true), submitted: submit })}
          </Details>
          <Details title={t('Signes de phishing, mesurés un par un')} count={t('âge, sosies, punycode, formulaires, certificat')}>
            {Signs({ state, report: d, pool: null })}
          </Details>
        </section>
        <Unavailable items={unavailable} />
      </div>
    </div>
  );
}

/* ---------- empty state ---------- */
function LinkHero() {
  return (
    <ToolHero
      icon={Link2}
      title={t('Vérifier un lien')}
      desc={t('Ce lien est-il sûr ? La chaîne des redirections suivie en direct depuis le serveur, six sources de réputation, l’âge du domaine, les sosies de marque. Le lien n’est jamais ouvert dans votre navigateur ; hxxp et [.] sont acceptés.')}
      basePath="/lien"
      accept="any"
      label={t('Lien à vérifier')}
      placeholder={t('https://exemple.fr/connexion')}
      examples={['github.com', 'bit.ly/github']}
      buildPath={(v) => linkPath(refang(v))}
    />
  );
}

export default function LinkPage() {
  const [params] = useSearchParams();
  const url = params.get('url')?.trim();
  if (url) return <LinkReportView key={url} url={url} />;
  return <LinkHero />;
}
