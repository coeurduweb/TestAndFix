// One IP (/ip/:ip): the measure starts on arrival and arrives live. Head: note and verdict (how
// many major lists list the address), then each listing with its delisting procedure, then every
// list as a row turning from skeleton to result, the network identity, the reputation services.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { ExternalLink } from 'lucide-react';
import { deviationOf, FindingDetail, LabRow, LabTable, RerunButton, ReportHeader, ShareButton, Unavailable, type Deviation } from '../../components/Report';
import { CopyButton, CodeBlock, Notice, Skel } from '../../components/ui';
import { Details, IssueCard, IssueList } from '../../components/Verdict';
import { ApiError } from '../../lib/api';
import { plural } from '../../lib/format';
import { locale, t, tn, msg } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { Finding } from '../../lib/types';
import { errorMessage } from '../../lib/useCheck';
import { countryName } from '../dns/fmt';
import { InvalidInput, IpHero } from './Form';
import {
  hitKind, initialSingle, uniqueIds, listingSummary, singleReducer, WEIGHT_LABEL,
  type AbuseIpdbData, type CymruData, type DnsblHit, type IpReport, type ListingSummary, type OtxData, type PtrData, type RipestatData, type SingleState, type VtIpData, type Weight,
} from './model';
import { useSse } from './sse';

/** Findings of the final result, handed out to the rows that show them; the rest go to "Autres constats". */
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

function FindingDetails({ findings, extra }: { findings: Finding[]; extra?: ReactNode }) {
  if (!findings.length && !extra) return null;
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

const worst = (fs: Finding[]): Deviation | undefined => {
  const f = [...fs].sort((a, b) => b.penalty - a.penalty)[0];
  return f ? deviationOf(f) : undefined;
};

export function WeightTag({ w }: { w: Weight }) {
  return <span className={`ipx-weight ipx-weight--${w}`}>{WEIGHT_LABEL[w] ? t(WEIGHT_LABEL[w]) : w}</span>;
}

/* ---------- listings, with the delisting procedure ---------- */
function DelistLink({ url, name }: { url?: string; name: string }) {
  if (!url) return null;
  return (
    <div className="ipx-delist">
      <a className="btn btn--sm" href={url} target="_blank" rel="noreferrer noopener">
        <ExternalLink aria-hidden />
        {t('Page de retrait de {name}', { name })}
      </a>
      <span className="mono muted ipx-delist__url">{url}</span>
    </div>
  );
}

/** Meaning of some of the codes of a hit: the server joins one label per code with ", ". */
function meaningOf(hit: DnsblHit, codes: string[]): string | undefined {
  const parts = hit.meaning?.split(', ');
  if (!parts || parts.length !== hit.codes.length) return hit.meaning;
  return codes.map((c) => parts[hit.codes.indexOf(c)]).filter(Boolean).join(', ') || hit.meaning;
}

export function ListingExtra({ hit, withTxt = true }: { hit: DnsblHit; withTxt?: boolean }) {
  return (
    <>
      {withTxt && hit.txt && <CodeBlock code={hit.txt} label={t('Motif publié par la liste (TXT)')} />}
      <DelistLink url={hit.delistUrl} name={hit.name} />
    </>
  );
}

/* ---------- every list ---------- */
type ListMeta = { zone: string; name: string; weight: Weight };

function ListItem({ l, h }: { l: ListMeta; h: DnsblHit | undefined }) {
  const k = hitKind(h);
  const [open, setOpen] = useState(false);
  const detail = k === 'listed' && h ? true : false;
  const dot =
    k === 'pending' ? 'dot--pending' : k === 'clean' ? 'dot--ok' : k === 'listed' ? (l.weight === 'major' ? 'dot--out' : l.weight === 'minor' ? 'dot--warn' : '') : '';
  const codes = h?.codes.join(', ') ?? '';
  const value =
    k === 'pending' ? <Skel w="10ch" /> : k === 'clean' ? t('absente') : k === 'listed' ? t('listée {codes}', { codes }) : k === 'scoring' ? t('score {codes}', { codes }) : k === 'refused' ? t('requête refusée') : shortError(h?.error);
  const small =
    k === 'listed' ? h!.meaning : k === 'scoring' ? t('score de réputation, donné à presque toutes les adresses') : k === 'refused' ? h!.meaning ?? t('requête refusée') : undefined;
  const body = (
    <>
      <span className={`dot ${dot}`} aria-hidden />
      <span className="nl__name">
        <span>
          {l.name} <WeightTag w={l.weight} />
        </span>
        {small && <small>{small}</small>}
      </span>
      <span className={`nl__val${k === 'listed' && l.weight === 'major' ? ' nl__val--out' : ''}${k === 'clean' ? ' nl__val--ok' : ''}`}>{value}</span>
      {detail ? <span className="nl__chev" aria-hidden /> : <span aria-hidden />}
    </>
  );
  return (
    <li className="nl__item">
      {detail ? (
        <button type="button" className="nl__row" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {body}
        </button>
      ) : (
        <div className="nl__row">{body}</div>
      )}
      {open && h && (
        <div className="nl__open">
          <ListingExtra hit={h} />
        </div>
      )}
    </li>
  );
}

/** Every list as a Signal row: a lit dot, the name and its weight, the answer on the right. */
export function ListRows({ lists, hits }: { lists: ListMeta[]; hits: Record<string, DnsblHit | undefined> }) {
  // the listed ones first, then the others in their own order
  const order = [...lists].sort((a, b) => Number(hitKind(hits[b.zone]) === 'listed') - Number(hitKind(hits[a.zone]) === 'listed'));
  return (
    <ul className="nl__list ipx-bl">
      {order.map((l) => (
        <ListItem key={l.zone} l={l} h={hits[l.zone]} />
      ))}
    </ul>
  );
}

function shortError(e?: string) {
  if (!e) return t('pas de réponse');
  if (/deadline|timeout|délai/i.test(e)) return t('délai dépassé');
  return e.length > 60 ? e.slice(0, 57) + '…' : e;
}

/* ---------- network ---------- */
function networkOf(state: SingleState, report?: IpReport): IpReport['network'] | undefined {
  if (report?.network) return report.network;
  const cy = state.events.cymru?.ok ? (state.events.cymru.data as CymruData) : undefined;
  const ri = state.events.ripestat?.ok ? (state.events.ripestat.data as RipestatData) : undefined;
  if (!cy && !ri) return undefined;
  const o = cy?.origins[0];
  const as = cy?.as.find((a) => a.asn === o?.asn);
  const v6 = state.ip?.includes(':');
  return {
    asn: o?.asn ?? ri?.holders[0]?.asn,
    asName: as?.name ?? ri?.holders[0]?.holder,
    prefix: o?.prefix ?? ri?.prefix,
    country: o?.country ?? ri?.country,
    registry: o?.registry,
    allocated: o?.allocated,
    peers: cy?.peers ?? [],
    city: ri?.city,
    abuseContacts: ri?.abuseContacts ?? [],
    announced: ri?.announced,
    visibility: v6 ? ri?.visibility?.v6 : ri?.visibility?.v4,
  };
}

function Pending({ label, reference }: { label: string; reference?: ReactNode }) {
  return <LabRow label={label} measured={<Skel w="14ch" />} reference={reference} deviation={{ kind: 'pending' }} />;
}

function NetworkSection({ ip, state, report, pool }: { ip: string; state: SingleState; report?: IpReport; pool: FindingPool | null }) {
  const ptrEv = state.events.ptr;
  const ptr: PtrData | undefined = report?.ptr ?? (ptrEv?.ok ? (ptrEv.data as PtrData) : undefined);
  const ptrDone = !!report || !!ptrEv;
  const net = networkOf(state, report);
  const cyDone = !!report || !!state.events.cymru;
  const riDone = !!report || !!state.events.ripestat;
  const ptrF = pool ? pool.take((f) => /^rdns\.(missing|ipv6_missing|temperror|multiple_ptr|generic_dynamic|generic_hosting)$/.test(f.id)) : [];
  const fcrF = pool ? pool.take((f) => f.id === 'rdns.fcrdns_mismatch' || f.id === 'rdns.ptr_target_nxdomain') : [];
  const annF = pool ? pool.take((f) => f.id === 'ip.prefix_not_announced') : [];
  return (
      <LabTable>
        {!ptrDone ? (
          <Pending label={t('Reverse DNS (PTR)')} reference={t('un nom propre au serveur')} />
        ) : !ptr ? (
          <LabRow label={t('Reverse DNS (PTR)')} measured={<span className="muted">{t('non lu')}</span>} reference={ptrEv?.reason} deviation={{ kind: 'info', text: t('sans réponse') }} />
        ) : (
          <LabRow
            key={report ? 'ptr-r' : 'ptr'}
            label={t('Reverse DNS (PTR)')}
            measured={ptr.names.length ? ptr.names.join(', ') : t('aucun ({rcode})', { rcode: ptr.rcode })}
            reference={t('un nom propre au serveur')}
            deviation={worst(ptrF) ?? (ptr.names.length ? { kind: 'ok', text: t('présent') } : { kind: 'out', direction: 'down', text: t('absent') })}
            detail={ptrF.length ? <FindingDetails findings={ptrF} extra={<CodeBlock code={ptr.query} label={t('Nom interrogé')} />} /> : undefined}
            defaultOpen={ptrF.some((f) => f.penalty >= 1)}
          />
        )}
        {!ptrDone ? (
          <Pending label={t('Confirmation (FCrDNS)')} reference={t('le nom renvoie à {ip}', { ip })} />
        ) : ptr && ptr.fcrdns.length ? (
          <LabRow
            label={t('Confirmation (FCrDNS)')}
            measured={ptr.fcrdns.map((f) => `${f.name} → ${f.ips.join(', ') || t('aucune adresse')}`).join(' ; ')}
            reference={t('le nom renvoie à {ip}', { ip })}
            deviation={worst(fcrF) ?? (ptr.confirmed ? { kind: 'ok', text: t('confirmé') } : { kind: 'out', direction: 'down', text: t('non confirmé') })}
            detail={fcrF.length ? <FindingDetails findings={fcrF} /> : undefined}
          />
        ) : (
          <LabRow label={t('Confirmation (FCrDNS)')} measured={<span className="muted">{t('sans objet, aucun PTR')}</span>} reference={t('le nom renvoie à {ip}', { ip })} deviation={{ kind: 'info', text: t('sans objet') }} />
        )}
        {!cyDone && !net ? (
          <>
            <Pending label={t('Système autonome (ASN)')} />
            <Pending label={t('Opérateur')} />
            <Pending label={t('Préfixe annoncé')} />
            <Pending label={t('Pays')} />
          </>
        ) : (
          <>
            <LabRow label={t('Système autonome (ASN)')} measured={net?.asn ? `AS${net.asn}` : <span className="muted">{t('inconnu')}</span>} reference={net?.registry ? t('registre {name}', { name: net.registry.toUpperCase() }) : undefined} deviation={{ kind: 'info', text: t('noté') }} />
            <LabRow label={t('Opérateur')} measured={net?.asName ?? <span className="muted">{t('inconnu')}</span>} deviation={{ kind: 'info', text: t('noté') }} />
            <LabRow
              label={t('Préfixe annoncé')}
              measured={net?.prefix ?? <span className="muted">{t('inconnu')}</span>}
              reference={net?.allocated ? t('alloué le {date}', { date: fmtDay(net.allocated) }) : undefined}
              deviation={worst(annF) ?? (net?.announced === false ? { kind: 'out', direction: 'down', text: t('non annoncé') } : net?.announced ? { kind: 'ok', text: t('annoncé') } : { kind: 'info', text: t('noté') })}
              detail={annF.length ? <FindingDetails findings={annF} /> : undefined}
            />
            <LabRow label={t('Pays')} measured={net?.country ? `${countryName(net.country)} (${net.country})${net.city ? `, ${net.city}` : ''}` : <span className="muted">{t('inconnu')}</span>} deviation={{ kind: 'info', text: t('noté') }} />
          </>
        )}
        {!riDone && !net?.abuseContacts.length ? (
          <>
            <Pending label={t('Contact d’abus')} />
            <Pending label={t('Visibilité du préfixe')} />
          </>
        ) : (
          <>
            <LabRow
              label={t('Contact d’abus')}
              measured={
                net?.abuseContacts.length ? (
                  <span className="ipx-contacts">
                    {net.abuseContacts.map((c) => (
                      <span key={c} className="ipx-contact">
                        {c}
                        <CopyButton text={c} label={t('Copier')} what={t('Adresse copiée')} />
                      </span>
                    ))}
                  </span>
                ) : (
                  <span className="muted">{t('aucun publié')}</span>
                )
              }
              reference={t('publié au registre')}
              deviation={net?.abuseContacts.length ? { kind: 'ok', text: t('publié') } : { kind: 'info', text: t('absent') }}
            />
            <LabRow
              label={t('Visibilité du préfixe')}
              measured={net?.visibility ? t('vu par {seeing} des {total} collecteurs RIPE RIS', { seeing: net.visibility.seeing, total: net.visibility.total }) : <span className="muted">{t('inconnue')}</span>}
              deviation={{ kind: 'info', text: t('noté') }}
            />
          </>
        )}
      </LabTable>
  );
}

const fmtDay = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit', year: 'numeric' });
};

/* ---------- reputation services ---------- */
function ServiceLink({ href, label }: { href: string; label: string }) {
  return (
    <a className="ipx-ext" href={href} target="_blank" rel="noreferrer noopener">
      {label}
      <ExternalLink aria-hidden />
    </a>
  );
}

function ReputationSection({ state, report, pool, unavailable }: { state: SingleState; report?: IpReport; pool: FindingPool | null; unavailable: { source: string; reason: string }[] }) {
  const rows: { id: 'abuseipdb' | 'virustotal' | 'otx'; label: string; reference: string }[] = [
    { id: 'abuseipdb', label: 'AbuseIPDB', reference: t('score < 25 %, aucun signalement') },
    { id: 'virustotal', label: 'VirusTotal', reference: t('aucun moteur ne la signale') },
    { id: 'otx', label: 'OTX AlienVault', reference: t('absente des collections') },
  ];
  const findingIds: Record<string, RegExp> = { abuseipdb: /^ip\.abuseipdb/, virustotal: /^ip\.virustotal/, otx: /^ip\.otx/ };
  return (
      <LabTable columns={[t('Service'), t('Mesuré'), t('Référence'), t('Écart')]}>
        {rows.map(({ id, label, reference }) => {
          const ev = state.events[id];
          const data = report?.sources[id] ?? (ev?.ok ? ev.data : undefined);
          const reason = ev?.reason ?? unavailable.find((u) => u.source === id)?.reason;
          if (!data && !ev && !report) return <Pending key={id} label={label} reference={reference} />;
          if (!data)
            return (
              <LabRow
                key={id}
                label={label}
                measured={<span className="muted">{t('non interrogé')}</span>}
                reference={<span className="ipx-reason" title={reason}>{(reason ?? t('source indisponible')).split(' : ')[0]}</span>}
                deviation={{ kind: 'info', text: /clé|key/i.test(reason ?? '') ? t('sans clé') : t('indisponible') }}
              />
            );
          const fs = pool ? pool.take((f) => findingIds[id].test(f.id)) : [];
          const bad = fs.find((f) => f.penalty > 0 || f.id === 'ip.otx_pulses');
          const { measured, link } = serviceMeasure(id, data);
          return (
            <LabRow
              key={id + (report ? '-r' : '')}
              label={label}
              measured={
                <>
                  {measured} <ServiceLink href={link} label={t('fiche')} />
                </>
              }
              reference={reference}
              deviation={!report ? { kind: 'pending' } : bad ? deviationOf(bad) : { kind: 'ok' }}
              detail={bad ? <FindingDetails findings={[bad]} /> : undefined}
              defaultOpen={!!bad && bad.penalty >= 1}
            />
          );
        })}
      </LabTable>
  );
}

function serviceMeasure(id: string, data: unknown): { measured: string; link: string } {
  if (id === 'abuseipdb') {
    const a = data as AbuseIpdbData;
    const extra = [a.isTor ? t('nœud Tor') : '', a.usageType ?? '', a.isp ?? ''].filter(Boolean).join(', ');
    const reports = plural(a.totalReports, 'signalement', 'signalements');
    return { measured: extra ? t('score {score} %, {reports} en {days} jours ({extra})', { score: a.score, reports, days: a.maxAgeDays, extra }) : t('score {score} %, {reports} en {days} jours', { score: a.score, reports, days: a.maxAgeDays }), link: a.link };
  }
  if (id === 'virustotal') {
    const v = data as VtIpData;
    const total = v.stats.malicious + v.stats.suspicious + v.stats.harmless + v.stats.undetected;
    return { measured: t('{malicious} malveillant, {suspicious} suspect sur {total} moteurs', { malicious: v.stats.malicious, suspicious: v.stats.suspicious, total }), link: v.link };
  }
  const o = data as OtxData;
  return {
    measured: o.validation.length ? t('marquée sûre ({names})', { names: o.validation.join(', ') }) : o.pulseCount ? plural(o.pulseCount, 'collection', 'collections') : t('aucune collection'),
    link: o.link,
  };
}

/* ---------- private address, nothing started ---------- */
function PrivateReport({ ip, report, findings }: { ip: string; report: IpReport; findings: Finding[] }) {
  const f = findings.find((x) => x.id === 'ip.not_public');
  return (
    <div className="ipx-page page-stack">
      {!f && (
        <Notice tone="warn" title={t('{ip} n’est pas une adresse publique', { ip })}>
          {report.range?.label ? t('C’est une {label} : aucune liste noire ne la connaît.', { label: report.range.label }) : t('C’est une adresse non publique : aucune liste noire ne la connaît.')}
        </Notice>
      )}
      {f && (
        <div className="issues ipx-private">
          <IssueCard f={f} extra={<p><Link to="/mail/analyse">{t('Lire l’adresse publique dans les en-têtes d’un message')}</Link></p>} />
        </div>
      )}
      <IpHero below />
    </div>
  );
}

/** The server refused the input (400) or could not start: no skeleton is left waiting. */
export function StartFailed({ value, error, onRetry }: { value: string; error: Error; onRetry: () => void }) {
  if (error instanceof ApiError && error.status === 400) return <InvalidInput value={value} reason={errorMessage(error)} />;
  return (
    <div className="ipx-page page-stack">
      <Notice tone="error" title={t('Mesure impossible')}>
        {errorMessage(error)}{' '}
        <button type="button" className="btn btn--sm" onClick={onRetry}>
          {t('Relancer')}
        </button>
      </Notice>
      <IpHero below />
    </div>
  );
}

/* ---------- page ---------- */
export function SingleIp({ ip }: { ip: string }) {
  const req = useMemo(() => ({ url: `/api/ip/${encodeURIComponent(ip)}/stream` }), [ip]);
  const { state, status, error, restart } = useSse(req, ip, singleReducer, initialSingle);
  const r = state.result;
  const d = r?.data;

  useEffect(() => {
    pushRecent({ value: ip, path: `/ip/${encodeURIComponent(ip)}`, label: msg('IP') });
  }, [ip]);

  const sum = listingSummary(state.lists, state.hits);
  const running = status === 'open';
  const unavailable = (r?.unavailable ?? []).filter((u) => u.reason);
  const ptr = d?.ptr ?? (state.events.ptr?.ok ? (state.events.ptr.data as PtrData) : undefined);
  const net = networkOf(state, d);
  const subject = state.ip ?? ip;

  if (error && !state.ip && !r) return <StartFailed value={ip} error={error} onRetry={restart} />;
  if (d && !d.public) return <PrivateReport ip={subject} report={d} findings={r!.findings} />;

  const listed = state.lists.map((l) => state.hits[l.zone]).filter((h): h is DnsblHit => hitKind(h) === 'listed');
  const facts = [
    { label: t('Listes majeures'), value: state.lists.length ? (r ? t('{a} sur {b}', { a: sum.majorListed, b: sum.majorTotal }) : t('{a} sur {b} pour l’instant', { a: sum.majorListed, b: sum.majorTotal })) : '…' },
    { label: t('Reverse DNS'), value: ptr ? ptr.names[0] ?? t('aucun') : '…' },
    ...(net?.asn ? [{ label: t('Réseau'), value: `AS${net.asn}${net.asName ? ` ${net.asName.split(/\s+-\s+|,/)[0]}` : ''}` }] : []),
    ...(net?.country ? [{ label: t('Pays'), value: countryName(net.country) }] : []),
  ];
  // the listing cards: final findings with their procedure, or the live hits while measuring
  const findings = r?.findings ?? [];
  const listingIds = new Set(d?.dnsbl?.listed.map((l) => l.situation) ?? []);
  const toFix = findings.filter((f) => f.penalty > 0).sort((a, b) => b.penalty - a.penalty);
  const remarks = findings.filter((f) => f.penalty <= 0);
  const hitOf = (f: Finding) => d?.dnsbl?.listed.find((l) => l.situation === f.id && f.evidence?.startsWith(l.query + ' '));

  return (
    <div className="ipx-page page-stack">
      <ReportHeader
        subject={<span className="mono">{subject}</span>}
        meta={facts}
        score={r?.score}
        findings={uniqueIds(r?.findings)}
        passed={r?.passed}
        pending={running && !r}
        sentence={r ? verdictText(sum, toFix.length - [...toFix].filter((f) => listingIds.has(f.id)).length) : undefined}
        actions={
          <>
            <RerunButton onClick={restart} busy={running} />
            <CopyButton text={subject} label={t('Copier l’IP')} what={t('IP copiée')} />
            <ShareButton />
          </>
        }
      />
      {error && (
        <Notice tone="error" title={r ? t('Mesure incomplète') : t('Mesure impossible')}>
          {errorMessage(error)}{' '}
          <button type="button" className="btn btn--sm" onClick={restart}>
            {t('Relancer')}
          </button>
        </Notice>
      )}

      {/* live: a card per listing as soon as a list answers, skeletons for what is still expected */}
      {!r && (
        <section className="block" aria-labelledby="live-t" aria-busy={running}>
          <h2 className="block__title" id="live-t">
            {listed.length ? t('À corriger') : t('Listes noires interrogées')}
            {listed.length > 0 && <span className="block__count">{listed.length}</span>}
          </h2>
          <div className="issues">
            {listed.map((h) => (
              <article key={h.zone} className={`issue issue--${h.weight === 'major' ? 'out' : 'warn'}`}>
                <h3 className="issue__title">{t('Inscrite sur {name}', { name: h.name })}</h3>
                <p className="issue__why">
                  {h.meaning
                    ? t('Code {codes} ({meaning}), liste {weight}. La procédure de retrait s’affiche à la fin de la mesure.', { codes: h.codes.join(', '), meaning: h.meaning, weight: t(WEIGHT_LABEL[h.weight]) })
                    : t('Code {codes}, liste {weight}. La procédure de retrait s’affiche à la fin de la mesure.', { codes: h.codes.join(', '), weight: t(WEIGHT_LABEL[h.weight]) })}
                </p>
                <ListingExtra hit={h} />
              </article>
            ))}
            {running && (
              <div className="issue ipx-progress">
                <p className="ipx-progress__text">
                  {state.lists.length ? t('{answered} listes sur {total} ont répondu', { answered: sum.answered, total: sum.total }) : t('Interrogation des listes noires')}
                </p>
                <div className="ipx-progress__bar" aria-hidden>
                  <span style={{ width: `${state.lists.length ? (sum.answered / sum.total) * 100 : 4}%` }} />
                </div>
                <Skel w="55%" />
              </div>
            )}
          </div>
        </section>
      )}

      {r && (
        <div className="page-stack">
          <IssueList
            findings={findings}
            passed={r.passed}
            extra={(f) => {
              const h = hitOf(f);
              return h ? <ListingExtra hit={h} withTxt={false} /> : undefined;
            }}
          />

          <section className="page-stack" aria-label={t('Détails techniques')}>
            <Details title={t('Listes noires, une par une')} count={tn(sum.listed, '{n} inscription sur {total}', '{n} inscriptions sur {total}', { total: state.lists.length })}>
              <BlacklistTable state={state} report={d} />
            </Details>
            <Details title={t('Identité réseau')} count={net?.asn ? `AS${net.asn}` : undefined}>
              {NetworkSection({ ip: subject, state, report: d, pool: null })}
            </Details>
            <Details title={t('Services de réputation')} count="AbuseIPDB, VirusTotal, OTX">
              {ReputationSection({ state, report: d, pool: null, unavailable })}
            </Details>
          </section>
          <Unavailable items={unavailable} />
        </div>
      )}

      {/* while measuring, the table of every list fills in live under the cards */}
      {!r && state.lists.length > 0 && (
        <section className="page-stack" aria-label={t('Détails techniques')}>
          <Details title={t('Listes noires, une par une')} count={`${sum.answered} / ${sum.total}`} defaultOpen>
            <BlacklistTable state={state} report={d} />
          </Details>
        </section>
      )}
    </div>
  );
}

function BlacklistTable({ state, report }: { state: SingleState; report?: IpReport }) {
  return (
    <>
      <div className="ipx-bl">
        <ListRows lists={state.lists} hits={state.hits} />
      </div>
      {report?.dnsbl && report.dnsbl.skipped.length > 0 && (
        <details className="ipx-skipped">
          <summary>{tn(report.dnsbl.skipped.length, '{n} liste non interrogée, et pourquoi', '{n} listes non interrogées, et pourquoi')}</summary>
          <ul>
            {report.dnsbl.skipped.map((s) => (
              <li key={s.zone}>
                <strong>{s.name}</strong> <span className="mono muted">{s.zone}</span> : {s.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

/** The sentence of the band: the listings first, in plain words. */
function verdictText(sum: ListingSummary, otherIssues: number): string {
  const others = otherIssues ? tn(otherIssues, 'Et {n} autre point à corriger, détaillés ci-dessous.', 'Et {n} autres points à corriger, détaillés ci-dessous.') : '';
  const join = (main: string, tail: string) => (tail ? `${main} ${tail}` : main);
  if (sum.majorListed)
    return join(t('Inscrite sur {n} des {total} listes noires majeures : une partie des destinataires refuse les mails de cette adresse. La procédure de retrait de chaque liste est ci-dessous.', { n: sum.majorListed, total: sum.majorTotal }), others);
  const minor = sum.minorListed + sum.infoListed;
  if (minor) return join(tn(minor, 'Absente des {total} listes majeures, mais inscrite sur {n} liste secondaire.', 'Absente des {total} listes majeures, mais inscrite sur {n} listes secondaires.', { total: sum.majorTotal }), others);
  const answered = sum.answered - sum.errors - sum.refused;
  return join(t('Absente des {n} listes noires qui ont répondu.', { n: answered }), others || t('Rien à corriger.'));
}
