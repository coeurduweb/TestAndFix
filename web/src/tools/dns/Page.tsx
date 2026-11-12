// Recherche DNS (/dns/:name?type=MX&mode=tous|serveur=1.1.1.1&dnssec=1), direction v2 « Clair et
// direct » (2026-11-10): without input a ToolHero; with input the band says the answer in one
// sentence, the records come next in large readable lines, then what to fix, what is fine, and the
// technical views (all authoritative servers, trace, dig) in Details.
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { ArrowRight, Copy, Globe2, Search, ShieldCheck } from 'lucide-react';
import { LabRow, LabTable, RerunButton, ShareButton, Unavailable } from '../../components/Report';
import { ToolHero } from '../../components/ToolHero';
import { CodeBlock, CopyButton, Field, Notice, Skel, SubmitButton } from '../../components/ui';
import { Details, IssueList } from '../../components/Verdict';
import { isIp, toDomain } from '../../lib/detect';
import { fmtDateTime, fmtMs, plural } from '../../lib/format';
import { msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import type { CheckResult, Finding } from '../../lib/types';
import { errorMessage, useCheck } from '../../lib/useCheck';
import { Band, type BandTone } from './Band';
import { fmtTtl } from './fmt';
import { IconCopy } from './IconCopy';
import {
  SUGGESTED_RESOLVERS, answerHeadline, answerSig, apiUrl, majorityAnswer, outcomeLabel, pagePath, readQuery, serverVerdict, sortRecords, zoneLabel,
  type DnsLookupData, type LookupQuery, type Mode, type RecordOut,
} from './lookup';
import { DNS_TYPES, PROPAGATION_TYPES, defaultType, isDnsName } from './rrtypes';
import { TypePicker } from './TypePicker';
import './dns.css';

const MODES: { id: Mode; label: string; hint: string }[] = [
  { id: 'authoritative', label: msg('Autoritaire'), hint: msg('Résolu depuis la racine, sans aucun cache') },
  { id: 'all', label: msg('Tous les autoritaires'), hint: msg('Chaque serveur de la zone interrogé, réponses et serials comparés') },
  { id: 'resolver', label: msg('Résolveur précis'), hint: msg('Ce que voit un résolveur, avec son cache') },
];

/** Does this answer belong to this query (name, type, mode and resolver)? */
function answers(d: DnsLookupData, q: LookupQuery): boolean {
  const sameName = isIp(q.name) ? d.ptr?.ip === q.name || d.name.endsWith('.arpa') : d.name === q.name;
  return sameName && d.type === q.type && d.mode === q.mode && (q.mode !== 'resolver' || d.server === q.server);
}

/* ---------- landing: ToolHero with the type ---------- */
function Landing({ warning }: { warning?: string }) {
  const [type, setType] = useState('');
  return (
    <>
      {warning && <Notice tone="warn" title={warning}>{t('Corrigez-le ci-dessous : lettres, chiffres, tirets et tirets bas, séparés par un seul point.')}</Notice>}
      <ToolHero
        icon={Search}
        title={t('Recherche DNS')}
        desc={t('La réponse des serveurs autoritaires, résolue depuis la racine, sans aucun cache. Ou celle d’un résolveur précis.')}
        basePath="/dns"
        accept="domain-or-ip"
        label={t('Nom ou adresse IP')}
        placeholder={t('exemple.fr, _dmarc.exemple.fr ou 8.8.8.8')}
        examples={['gmail.com', '_dmarc.gmail.com', 'github.com', '8.8.8.8']}
        buildPath={(v) => pagePath({ name: v, type: type || defaultType(v), mode: 'authoritative', dnssec: false })}
      >
        <div className="rr-hero-types">
          <TypePicker value={type || 'A'} types={DNS_TYPES} onChange={setType} label={t('Type')} />
          <p className="hero__hint">{t('Sans choix, le type suit le nom : PTR pour une IP, TXT pour _dmarc, SRV pour un service.')}</p>
        </div>
      </ToolHero>
    </>
  );
}

/* ---------- controls ---------- */
function ResolverField({ q, onPick }: { q: LookupQuery; onPick: (ip: string) => void }) {
  const [ip, setIp] = useState(q.server ?? '');
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setIp(q.server ?? ''), [q.server]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = ip.trim();
    if (!isIp(v)) {
      setErr(t('Adresse IPv4 ou IPv6 d’un résolveur public, par exemple 1.1.1.1.'));
      return;
    }
    setErr(null);
    onPick(v);
  };
  return (
    <form className="rr-resolver" onSubmit={submit}>
      <Field label={t('Résolveur')} error={err}>
        {(id, d) => (
          <input id={id} aria-describedby={d} className="input input--mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="1.1.1.1" spellCheck={false} autoComplete="off" inputMode="decimal" />
        )}
      </Field>
      <SubmitButton>{t('Interroger')}</SubmitButton>
      <div className="chips rr-resolver__chips" aria-label={t('Résolveurs suggérés')}>
        {SUGGESTED_RESOLVERS.map((r) => (
          <button key={r.ip} type="button" className="chip" aria-pressed={q.server === r.ip} onClick={() => onPick(r.ip)}>
            {r.label} <span className="mono">{r.ip}</span>
          </button>
        ))}
      </div>
    </form>
  );
}

function Controls({ q, set }: { q: LookupQuery; set: (p: Partial<LookupQuery>) => void }) {
  return (
    <div className="rr-controls">
      <TypePicker value={q.type} types={DNS_TYPES} onChange={(type) => set({ type })} />
      <div className="rr-picker" role="group" aria-label={t('Mode d’interrogation')}>
        <span className="rr-picker__label">{t('Mode')}</span>
        <div className="segmented rr-seg rr-seg--modes">
          {MODES.map((m) => (
            <button key={m.id} type="button" aria-pressed={q.mode === m.id} title={t(m.hint)} onClick={() => q.mode !== m.id && set({ mode: m.id, server: m.id === 'resolver' ? q.server ?? SUGGESTED_RESOLVERS[0].ip : undefined })}>
              {t(m.label)}
            </button>
          ))}
        </div>
      </div>
      <label className="rr-check">
        <input type="checkbox" checked={q.dnssec} onChange={(e) => set({ dnssec: e.target.checked })} />
        {t('Signatures DNSSEC')}
      </label>
      {q.mode === 'resolver' && <ResolverField q={q} onPick={(ip) => set({ server: ip, mode: 'resolver' })} />}
      <p className="field__hint rr-controls__hint">{t(MODES.find((m) => m.id === q.mode)!.hint)}.</p>
    </div>
  );
}

/* ---------- the answer, large ---------- */
function Records({ rows }: { rows: RecordOut[] }) {
  const own = rows.filter((r) => r.type !== 'RRSIG');
  const sigs = rows.filter((r) => r.type === 'RRSIG');
  return (
    <div className="rr-records">
      <ul className="rr-recs">
        {own.map((r, i) => (
          <li key={i} className="rr-rec">
            <span className="rr-rec__value mono">{r.value}</span>
            <span className="rr-rec__meta">
              <span className="tag">{r.type}</span>
              <span className="mono">{r.name}</span>
              <span>{t('TTL {ttl}', { ttl: fmtTtl(r.ttl) })}</span>
            </span>
            <IconCopy text={r.value} label={t('Copier {value}', { value: r.value.slice(0, 48) })} what={t('Valeur copiée')} />
          </li>
        ))}
      </ul>
      <div className="rr-records__foot">
        {own.length > 1 && <CopyButton text={own.map((r) => r.value).join('\n')} label={t('Copier les {n} valeurs', { n: own.length })} what={t('Valeurs copiées')} />}
        {sigs.length > 0 && <span className="field__hint">{t('{signatures} dans la sortie dig.', { signatures: plural(sigs.length, 'signature RRSIG', 'signatures RRSIG') })}</span>}
      </div>
    </div>
  );
}

const MONO = { m: (c: ReactNode) => <span className="mono">{c}</span>, n: (c: ReactNode) => <span className="mono rr-nowrap">{c}</span>, b: (c: ReactNode) => <strong>{c}</strong> };
/** Opening sentence of an NXDOMAIN answer: the name, the zone when known, who said so. */
function negHead(d: DnsLookupData): ReactNode {
  const v = { name: d.name, zone: d.zone, by: d.answeredBy };
  if (d.zone && d.answeredBy) return rich('<b>Le nom</b> <m>{name}</m> <b>n’existe pas</b> dans la zone <m>{zone}</m>, selon <n>{by}</n>.', v, MONO);
  if (d.zone) return rich('<b>Le nom</b> <m>{name}</m> <b>n’existe pas</b> dans la zone <m>{zone}</m>.', v, MONO);
  if (d.answeredBy) return rich('<b>Le nom</b> <m>{name}</m> <b>n’existe pas</b>, selon <n>{by}</n>.', v, MONO);
  return rich('<b>Le nom</b> <m>{name}</m> <b>n’existe pas</b>.', v, MONO);
}

function Negative({ d }: { d: DnsLookupData }) {
  const server = d.answeredBy?.replace(/\s*\(.*$/, '');
  return (
    <div className="issue issue--warn rr-negative">
      <p className="issue__why">
        {d.rcode === 'NXDOMAIN' ? (
          <>
            {negHead(d)} {t('Vérifiez l’orthographe ; s’il vient d’être créé, vérifiez que la zone est déléguée aux serveurs où vous l’avez ajouté.')}
          </>
        ) : d.rcode === 'NOERROR' ? (
          rich('<b>Le nom existe, mais n’a aucun enregistrement {type}.</b> Essayez un autre type, ou ajoutez l’enregistrement dans la zone {zone}.', { type: d.type, zone: d.zone ?? '' }, { b: (c) => <strong>{c}</strong> })
        ) : (
          rich('<b>{rcode} :</b> aucune réponse exploitable. Relancez ; si l’erreur se répète, comparez tous les autoritaires.', { rcode: d.rcode }, { b: (c) => <strong>{c}</strong> })
        )}
      </p>
      <CodeBlock
        label={t('Vérifier vous-même')}
        code={[`dig ${d.name} ${d.type} +trace`, d.zone ? `dig ${d.zone} NS +short` : null, server ? `dig @${server} ${d.name} ${d.type} +norecurse` : null].filter(Boolean).join('\n')}
      />
      <p className="issue__refs">
        {t('Sources :')}{' '}
        {d.rcode === 'NXDOMAIN' && (
          <>
            <a href="https://www.rfc-editor.org/rfc/rfc8020" target="_blank" rel="noreferrer noopener">RFC 8020</a>,{' '}
          </>
        )}
        <a href="https://www.rfc-editor.org/rfc/rfc2308" target="_blank" rel="noreferrer noopener">{t('RFC 2308 (réponses négatives)')}</a>
      </p>
    </div>
  );
}

/* ---------- reverse DNS: the answer for an IP, with its checks inline ---------- */
function Ptr({ d, findings }: { d: DnsLookupData; findings: Finding[] }) {
  const p = d.ptr;
  if (!p) return null;
  const confirmed = p.fcrdns.find((f) => f.matches);
  return (
    <section className="surface nl" aria-labelledby="ptr-t">
      <h2 className="nl__head" id="ptr-t">
        {t('Reverse DNS et FCrDNS')}
        <small>{confirmed ? t('confirmé') : t('non confirmé')}</small>
      </h2>
      <ul className="nl__list">
        <li className="nl__item">
          <div className="nl__row rr-ptr__row">
            <span className={`dot ${p.names.length ? 'dot--ok' : 'dot--out'}`} aria-hidden />
            <span className="nl__name">
              <span className="mono">{p.ip}</span>
              <small>{t('adresse interrogée')}</small>
            </span>
            <span className="nl__val rr-ptr__name">{p.names.join(', ') || t('aucun nom (PTR absent)')}</span>
            <span aria-hidden />
          </div>
        </li>
        {p.fcrdns.map((f) => (
          <li key={f.name} className="nl__item">
            <div className="nl__row rr-ptr__row">
              <span className={`dot ${f.matches ? 'dot--ok' : 'dot--out'}`} aria-hidden />
              <span className="nl__name">
                <span className="mono">{f.name}</span>
                <small>{f.matches ? t('revient vers {ip} (FCrDNS confirmé)', { ip: p.ip }) : t('ne revient pas vers {ip}', { ip: p.ip })}</small>
              </span>
              <span className="nl__val">{f.ips.join(', ') || t('aucune adresse')}</span>
              <span aria-hidden />
            </div>
          </li>
        ))}
      </ul>
      {findings.length > 0 && (
        <div className="rr-ptr__issues">
          <IssueList findings={findings} />
        </div>
      )}
    </section>
  );
}

/* ---------- technical views ---------- */
function AllAuthoritative({ d }: { d: DnsLookupData }) {
  const a = d.authoritative;
  if (!a) return null;
  const out = a.servers.filter((s) => serverVerdict(s, a).kind !== 'ok').length;
  const majorKey = JSON.stringify(majorityAnswer(a));
  const firstMajor = a.servers.findIndex((s) => !s.error && JSON.stringify(answerSig(s)) === majorKey);
  return (
    <Details title={t('Tous les autoritaires de {zone}', { zone: a.zone })} count={out ? t('{out} sur {total} en écart', { out, total: a.servers.length }) : t('{n} serveurs concordants', { n: a.servers.length })} defaultOpen>
      <LabTable columns={[t('Serveur'), t('Réponse'), t('Serial'), t('Écart')]}>
        {a.servers.map((s, i) => {
          const v = serverVerdict(s, a);
          const sameAsAbove = i > firstMajor && firstMajor >= 0 && !s.error && JSON.stringify(answerSig(s)) === majorKey;
          return (
            <LabRow
              key={s.ns + s.ip}
              label={
                <span className="rr-ns">
                  <span className="mono">{s.ns}</span> <span className="mono muted">{s.ip}</span>
                </span>
              }
              measured={
                s.error ? (
                  <span className="out-text">{s.error}</span>
                ) : s.rcode === 'NXDOMAIN' ? (
                  'NXDOMAIN'
                ) : s.answers.length && sameAsAbove ? (
                  <span className="muted">{t('même réponse que ci-dessus')}</span>
                ) : s.answers.length ? (
                  <span className="rr-multi">{sortRecords(s.answers).map((r) => `${r.type} ${r.value}`).join('\n')}</span>
                ) : (
                  <span className="muted">{t('aucune donnée')}</span>
                )
              }
              reference={
                <>
                  {s.serial ?? '?'}
                  {s.rtt !== undefined && <span className="muted"> · {fmtMs(s.rtt)}</span>}
                </>
              }
              deviation={v.kind === 'ok' ? { kind: 'ok', text: t('concorde') } : { kind: v.kind, text: v.text, direction: 'down' }}
            />
          );
        })}
      </LabTable>
    </Details>
  );
}

function Trace({ d }: { d: DnsLookupData }) {
  if (!d.trace.length) return null;
  const total = d.trace.reduce((sum, st) => sum + (st.rtt ?? 0), 0);
  return (
    <Details title={t('Trace de résolution')} count={t('{steps}, {ms}', { steps: plural(d.trace.length, 'étape', 'étapes'), ms: fmtMs(total) })}>
      <ol className="rr-trace">
        {d.trace.map((s, i) => (
          <li key={i} className={`rr-step rr-step--${s.outcome}`}>
            <span className="rr-step__zone">{zoneLabel(s.zone)}</span>
            <span className="rr-step__server">
              <span className="mono">{s.serverName ?? s.server}</span>
              {s.serverName && <span className="mono muted"> {s.server}</span>}
            </span>
            <span className="rr-step__out">{outcomeLabel(s)}</span>
            <span className="rr-step__rtt mono">{fmtMs(s.rtt)}</span>
          </li>
        ))}
      </ol>
      <p className="field__hint rr-trace__total">{t('Chaque serveur interrogé directement, sans résolveur ni cache.')}</p>
    </Details>
  );
}

/* ---------- page ---------- */
export default function DnsPage() {
  const { name: nameParam } = useParams();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const parsed = readQuery(nameParam, params);
  const invalid = !!parsed && !isDnsName(parsed.name);
  const q = invalid ? null : parsed;
  const url = q ? apiUrl(q) : null;
  const { data: r, error, loading, rerun } = useCheck<CheckResult<DnsLookupData>>(url);

  // tolerant URL: /dns/HTTPS://Exemple.FR/ becomes /dns/exemple.fr?type=A
  useEffect(() => {
    if (q && nameParam && q.name !== nameParam) navigate(pagePath(q), { replace: true });
  }, [q?.name, nameParam]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (q) pushRecent({ value: q.name, path: `/dns/${q.name}`, label: 'DNS' });
  }, [q?.name]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!q) return <Landing warning={invalid ? t('« {name} » n’est pas un nom DNS valide', { name: nameParam }) : undefined} />;

  const set = (patch: Partial<LookupQuery>) => navigate(pagePath({ ...q, ...patch }));
  // the previous answer stays in memory while the next one loads: show it only if it is this query's
  const d = r?.data && (!loading || answers(r.data, q)) ? r.data : undefined;
  const rows = d ? sortRecords([...d.answers, ...d.signatures]) : [];
  const head = d ? answerHeadline(d) : null;
  // reverse DNS checks live with the reverse DNS answer
  const inPtr = (family: string) => !!d?.ptr && family === 'rdns';
  const findings = d && r ? r.findings.filter((f) => !inPtr(f.family)) : [];
  const passed = d && r ? r.passed.filter((p) => !inPtr(p.family)) : [];
  const propagates = (PROPAGATION_TYPES as readonly string[]).includes(q.type);

  const tone: BandTone = !d ? (error ? 'bad' : 'pending') : head!.tone === 'ok' ? (findings.some((f) => f.penalty > 0) ? 'watch' : 'good') : head!.tone === 'warn' ? 'watch' : 'bad';
  const mood = !d ? (error ? t('Interrogation impossible') : t('Interrogation en cours')) : head!.tone === 'ok' ? t('Réponse trouvée') : d.rcode === 'NXDOMAIN' ? t('Ce nom n’existe pas') : d.rcode === 'NOERROR' ? t('Aucun enregistrement {type}', { type: d.type }) : t('Pas de réponse');
  const by = d?.answeredBy?.replace(/\s*\(.*$/, '') ?? '';
  const who = d?.mode === 'resolver' ? t('selon le résolveur {server}, depuis son cache', { server: d.server ?? q.server }) : d?.answeredBy ? (d.zone ? t('donnés par {by}, serveur autoritaire de {zone}', { by, zone: d.zone }) : t('donnés par {by}, serveur autoritaire', { by })) : '';
  const sentence = !d
    ? error
      ? errorMessage(error)
      : t('La réponse arrive.')
    : head!.tone === 'ok'
      ? `${tn(head!.count, '{n} enregistrement {type}', '{n} enregistrements {type}', { type: d.type })} ${t('pour {name}, {who}.', { name: isIp(q.name) ? q.name : d.name, who })}${d.cnames.length ? ` ${t('Alias suivis : {list}.', { list: d.cnames.join(' → ') })}` : ''}`
      : d.rcode === 'NXDOMAIN'
        ? d.zone
          ? t('{name} n’existe pas dans la zone {zone}.', { name: d.name, zone: d.zone })
          : t('{name} n’existe pas.', { name: d.name })
        : d.rcode === 'NOERROR'
          ? t('{name} existe, mais n’a pas d’enregistrement {type}.', { name: d.name, type: d.type })
          : t('{rcode} : aucune réponse exploitable.', { rcode: d.rcode });
  const minTtl = rows.filter((x) => x.type !== 'RRSIG').reduce<number | null>((m, x) => (m === null ? x.ttl : Math.min(m, x.ttl)), null);
  const facts = d && r
    ? [
        ...(d.zone ? [{ label: t('Zone'), value: <span className="mono">{d.zone}</span> }] : []),
        ...(minTtl !== null ? [{ label: d.mode === 'resolver' ? t('TTL restant') : t('TTL'), value: fmtTtl(minTtl) }] : []),
        ...(d.flags ? [{ label: t('Drapeaux'), value: ['qr', 'rd', ...Object.entries(d.flags).filter(([, v]) => v).map(([k]) => k)].join(' ') }] : []),
        { label: t('Mesuré le'), value: fmtDateTime(r.measuredAt) },
      ]
    : [];

  return (
    <div className="page-stack">
      <Band
        tone={tone}
        mood={mood}
        subject={
          <span className="rr-subject">
            <span className="mono">{isIp(q.name) ? q.name : d?.name ?? q.name}</span>
            <span className="tag tag--lab rr-subject__type">{q.type}</span>
          </span>
        }
        sentence={sentence}
        facts={facts}
        big={d ? head!.count : '…'}
        under={d ? (head!.count > 1 ? t('enregistrements {type}', { type: d.type }) : t('enregistrement {type}', { type: d.type })) : undefined}
        bigLabel={d ? `${head!.count} ${head!.text}` : t('Interrogation en cours')}
        actions={
          <>
            <RerunButton onClick={rerun} busy={loading} />
            <ShareButton />
            {propagates && (
              <Link className="btn btn--sm" to={`/propagation/${encodeURIComponent(q.name)}?type=${q.type}`}>
                <Globe2 aria-hidden />
                {t('Suivre la propagation')}
              </Link>
            )}
            {(q.type === 'DS' || q.type === 'DNSKEY') && toDomain(q.name) && (
              <Link className="btn btn--sm" to={`/dnssec/${encodeURIComponent(q.name)}`}>
                <ShieldCheck aria-hidden />
                {t('Chaîne DNSSEC')}
              </Link>
            )}
            {isIp(q.name) && (
              <Link className="btn btn--sm" to={`/ip/${encodeURIComponent(q.name)}`}>
                <ArrowRight aria-hidden />
                {t('Réputation de l’IP')}
              </Link>
            )}
          </>
        }
      />

      <Controls q={q} set={set} />

      {error && !d && (
        <Notice tone="error" title={t('Interrogation impossible')}>
          {errorMessage(error)} {t('Vérifiez l’orthographe du nom ; pour un nom de service, gardez les tirets bas (_sip._tcp.exemple.fr).')}
        </Notice>
      )}

      {!d && !error && (
        <section className="block" aria-busy="true" aria-label={t('Réponse')}>
          <div className="issue">
            <Skel w="40%" />
            <Skel w="65%" />
            <Skel w="50%" />
          </div>
        </section>
      )}

      {d && r && (
        <div className="page-stack">
          {d.ptr ? (
            <Ptr d={d} findings={r.findings.filter((f) => f.family === 'rdns')} />
          ) : (
            <section className="page-stack" aria-label={d.mode === 'resolver' ? t('Réponse du cache de {server}, TTL restants', { server: d.server }) : t('Réponse')}>
              {rows.some((x) => x.type !== 'RRSIG') ? <Records rows={rows} /> : <Negative d={d} />}
            </section>
          )}

          <IssueList findings={findings} passed={passed} />

          <section className="page-stack" aria-label={t('Détails techniques')}>
            {d.ptr && rows.length > 0 && (
              <Details title={t('Enregistrement PTR')} count={`${rows.length}`}>
                <Records rows={rows} />
              </Details>
            )}
            <AllAuthoritative d={d} />
            <Trace d={d} />
            <Details title={t('Sortie façon dig')} count={<><Copy aria-hidden className="rr-inline-ic" /> {t('copiable')}</>}>
              <div className="rr-dig">
                <CodeBlock code={d.dig} label={`dig ${d.name} ${d.type}`} copyLabel={t('Copier la sortie')} />
              </div>
            </Details>
          </section>
          <Unavailable items={r.unavailable} />
        </div>
      )}
    </div>
  );
}
