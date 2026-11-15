// Propagation DNS (/propagation/:name?type=MX&attendu=…&tout=1&continents=EU&regions=155&pays=FR&ip=6),
// interface « Signal » (validated 2026-11-11, docs/UI-SIGNAL.md). Without input: a ToolHero. With
// input, everything that matters holds in one screen, without scrolling (the user: "on doit
// scroller pour filtrer, c'est inacceptable"):
//   1. the tool bar: name, record type, the value the authoritative servers publish (editable in a
//      popover) and its TTL, Surveiller, Relancer;
//   2. the filters row: where to measure (continents with their flags, "Pays…" popover), which
//      resolvers, which network, which status (US-061, US-062);
//   3. the map (the big percentage, what it means, the arcs to every place asked, framed on our
//      server and the places listed) beside the list, which scrolls in its own panel.
// What to do and the technical details follow below. v2 (pastel band, pills, side column, drawer,
// map folded in the details) was refused: do not come back to it.
// "Surveiller" asks again, every 30 s, only the resolvers still late, until none is.
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { Check, Copy, Eye, Globe2, PencilLine, RotateCw, Search, Square, X } from 'lucide-react';
import 'flag-icons/css/flag-icons.min.css';
import { LabRow, LabTable } from '../../components/Report';
import { ToolHero } from '../../components/ToolHero';
import { copyText, Field, Notice, useToast } from '../../components/ui';
import { Details } from '../../components/Verdict';
import { post } from '../../lib/api';
import { fmtDateTime, fmtMs } from '../../lib/format';
import { locale, msg, rich, t, tn } from '../../lib/i18n';
import { pushRecent } from '../../lib/recent';
import { errorMessage, useCheck } from '../../lib/useCheck';
import { countryName, fmtClock, fmtCount, fmtIn, fmtPercent, fmtTtl } from '../dns/fmt';
import { cleanName, COMMON_TYPES, defaultType, isDnsName, pickType, PROPAGATION_TYPES, TYPE_HINT } from '../dns/rrtypes';
import { TypePicker } from '../dns/TypePicker';
import { DivergenceDetail, ExpectedDetail, LateIssue } from './explain';
import { STATUS_LABEL, StatusMark } from './marks';
import {
  answerKey, buildRows, realLate, cleanProvider, countRows, displayName, distinctAnswers, matchesFilter, referenceText, resolverList, rowStatus, sortRows, sortValues,
  valueText, watchTargets, type AuthorityEvent, type FilterId, type ResolversPayload, type Row, type SortKey,
} from './model';
import { FilterBar, type StatusFilter } from './FilterPanel';
import { continentChips, countryOptions, fold, regionOptions } from './places';
import { needsPeek, Peek, Records, usePeek } from './Peek';
import { Popover } from './Popover';
import { ResolverGroup } from './ResolverList';
import { facets as facetsOf, fallbackDefaults, hasPlaces, ipv6Available, readSelection, regionNamesOf, selectResolvers, serverDefaults, streamQuery, writeSelection, type Selection } from './selection';
import { usePropagationRun } from './useRun';
import '../dns/dns.css';
import './propagation.css';

const WorldMap = lazy(() => import('./WorldMap'));
const WATCH_MS = 30_000;

/* ---------- landing ---------- */
function Landing({ resolvers, warning }: { resolvers: ResolversPayload | null; warning?: string }) {
  const [type, setType] = useState('');
  const q = resolvers?.qualification;
  return (
    <>
      {warning && <Notice tone="warn" title={warning}>{t('Corrigez-le ci-dessous : lettres, chiffres, tirets et tirets bas, séparés par un seul point.')}</Notice>}
      <ToolHero
        icon={Globe2}
        title={t('Propagation DNS')}
        desc={t('Votre changement est-il vu partout ? Ce que répondent les résolveurs du monde, face à la valeur des serveurs autoritaires.')}
        basePath="/propagation"
        accept="domain-or-ip"
        label={t('Nom à suivre')}
        examples={['example.com', 'gmail.com', 'github.com', '_dmarc.gmail.com']}
        buildPath={(v) => `/propagation/${encodeURIComponent(v)}?type=${type || defaultType(v)}`}
      >
        <div className="rr-hero-types">
          <TypePicker value={type || 'A'} types={PROPAGATION_TYPES} onChange={setType} label={t('Type')} />
          {q && (
            <p className="hero__hint">
              {t('{total} résolveurs qualifiés dans {countries} pays, contrôlés le {date}. Une requête neuve par résolveur, aucun cache.', { total: fmtCount(resolvers!.total), countries: fmtCount(q.countries), date: fmtDateTime(q.finishedAt) })}
            </p>
          )}
        </div>
      </ToolHero>
    </>
  );
}

/* ---------- qualification not ready ---------- */
function QualificationState({ p, error, reload }: { p: ResolversPayload | null; error: unknown; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  // while the qualification runs (or has retained nobody yet), read the list again every 5 s
  useEffect(() => {
    if (!p || (!p.running && p.total)) return;
    const timer = setInterval(reload, 5000);
    return () => clearInterval(timer);
  }, [p, reload]);
  if (error) return <Notice tone="error" title={t('Liste des résolveurs indisponible')}>{errorMessage(error)}</Notice>;
  if (!p || p.total > 0) return null;
  if (p.running) {
    const pr = p.running.progress;
    return (
      <Notice tone="info" title={t('Qualification des résolveurs en cours')}>
        {pr?.done !== undefined && pr.total
          ? t('Démarrée le {date}, {done} sur {total} testés. Elle dure environ 2 min 30 ; la mesure partira dès qu’elle sera finie.', { date: fmtDateTime(p.running.startedAt), done: fmtCount(pr.done), total: fmtCount(pr.total) })
          : t('Démarrée le {date}. Elle dure environ 2 min 30 ; la mesure partira dès qu’elle sera finie.', { date: fmtDateTime(p.running.startedAt) })}
      </Notice>
    );
  }
  return (
    <Notice tone="warn" title={t('Aucun résolveur qualifié')}>
      {p.qualification?.note ? t('La qualification quotidienne n’a encore retenu aucun résolveur ({note}).', { note: p.qualification.note }) : t('La qualification quotidienne n’a encore retenu aucun résolveur.')}{' '}
      <button
        type="button"
        className="btn btn--sm"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await post('/api/propagation/qualify');
            setNote(t('Qualification lancée.'));
          } catch (e) {
            setNote(errorMessage(e));
          } finally {
            setBusy(false);
            reload();
          }
        }}
      >
        {t('Lancer la qualification')}
      </button>
      {note && <span className="muted"> {note}</span>}
    </Notice>
  );
}

/* ---------- expected value ---------- */
function ExpectedForm({ expected, authority, onApply }: { expected: string | null; authority?: AuthorityEvent; onApply: (v: string | null) => void }) {
  const auth = referenceText(authority);
  const [value, setValue] = useState(expected ?? auth);
  const [touched, setTouched] = useState(false);
  const lines = Math.min(5, Math.max(2, value.split('\n').length));
  const same = value.trim() === auth.trim();
  return (
    <form
      className="pp-expected"
      onSubmit={(e) => {
        e.preventDefault();
        const v = value.trim();
        onApply(v && v !== auth.trim() ? v : null);
      }}
    >
      <Field label={t('Valeur attendue')} hint={expected ? t('Les résolveurs sont comparés à cette valeur.') : t('Préremplie avec la réponse des autoritaires. Une valeur par ligne.')}>
        {(id, d) => (
          <textarea
            id={id}
            aria-describedby={d}
            className="textarea textarea--mono"
            rows={lines}
            value={value}
            autoFocus
            onChange={(e) => {
              setTouched(true);
              setValue(e.target.value);
            }}
            spellCheck={false}
            placeholder={authority ? t('aucune valeur publiée') : t('lecture des autoritaires…')}
          />
        )}
      </Field>
      <div className="pp-expected__actions">
        {expected && (
          <button type="button" className="btn btn--sm btn--ghost" onClick={() => onApply(null)}>
            <X aria-hidden />
            {t('Valeur des autoritaires')}
          </button>
        )}
        <button type="submit" className="btn btn--sm btn--primary" disabled={!expected && (same || !touched)}>
          {t('Comparer')}
        </button>
      </div>
    </form>
  );
}

/** "Attendu 203.0.113.10 · TTL 1 j": what the resolvers are compared to; a click edits it on the spot. */
function ExpectedChip({ expected, authority, onApply }: { expected: string | null; authority?: AuthorityEvent; onApply: (v: string | null) => void }) {
  const btn = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const ref = authority?.reference;
  const text = !authority
    ? t('lecture des autoritaires…')
    : ref!.kind === 'cname'
      ? t('alias vers {cname}', { cname: ref!.cname })
      : authority.authority.exists || ref!.source === 'expected'
        ? sortValues(ref!.values).join(', ') || t('aucune valeur')
        : t('nom absent');
  return (
    <>
      <button
        ref={btn}
        type="button"
        className="pp-expect"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        title={ref?.source === 'expected' ? t('Votre valeur attendue. Cliquez pour la modifier.') : t('D’après les serveurs autoritaires. Cliquez pour comparer à une autre valeur.')}
      >
        <span className="pp-expect__k">{ref?.source === 'expected' ? t('Votre valeur') : t('Attendu')}</span>
        <b className="mono">{text}</b>
        {ref?.ttl != null && <span className="pp-expect__ttl">· TTL {fmtTtl(ref.ttl)}</span>}
        <PencilLine aria-hidden />
      </button>
      <Popover anchor={btn} open={open} onClose={() => setOpen(false)} label={t('Valeur attendue')} width={420} className="pp-expect-pop">
        <ExpectedForm
          expected={expected}
          authority={authority}
          onApply={(v) => {
            setOpen(false);
            onApply(v);
          }}
        />
      </Popover>
    </>
  );
}

/** Name of the measure, editable in place: Enter measures the new name with the same type and places. */
function NameField({ name, onGo }: { name: string; onGo: (n: string) => void }) {
  const [v, setV] = useState(name);
  useEffect(() => setV(name), [name]);
  const c = cleanName(v);
  const bad = !!v.trim() && (!c || !isDnsName(c));
  return (
    <form
      className="pp-name"
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        if (c && !bad && c !== name) onGo(c);
      }}
    >
      <Globe2 aria-hidden />
      <input
        value={v}
        onChange={(e) => setV(e.target.value)}
        aria-label={t('Nom à suivre')}
        aria-invalid={bad || undefined}
        title={bad ? t('Pas un nom DNS valide') : t('Entrée pour mesurer ce nom')}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
      />
    </form>
  );
}

/** A, AAAA, CNAME, MX, TXT, NS as segments, the other types behind "…". */
function TypeSegments({ value, onChange }: { value: string; onChange: (ty: string) => void }) {
  const common = COMMON_TYPES.filter((ty) => (PROPAGATION_TYPES as readonly string[]).includes(ty));
  const others = PROPAGATION_TYPES.filter((ty) => !(COMMON_TYPES as readonly string[]).includes(ty));
  const isOther = (others as readonly string[]).includes(value);
  return (
    <div className="segmented pp-types" role="group" aria-label={t('Type d’enregistrement')}>
      {common.map((ty) => (
        <button key={ty} type="button" aria-pressed={value === ty} onClick={() => value !== ty && onChange(ty)} title={t(TYPE_HINT[ty])}>
          {ty}
        </button>
      ))}
      <label className="pp-types__more" data-on={isOther || undefined} title={t('Autre type')}>
        <span aria-hidden>{isOther ? value : '…'}</span>
        <select aria-label={t('Autre type d’enregistrement')} value={isOther ? value : ''} onChange={(e) => e.target.value && onChange(e.target.value)}>
          <option value="">{t('Autre type…')}</option>
          {others.map((ty) => (
            <option key={ty} value={ty}>
              {ty} : {t(TYPE_HINT[ty])}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

function CopyLink() {
  const toast = useToast();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn--icon btn--ghost"
      aria-label={t('Copier le lien')}
      title={t('Copier le lien')}
      onClick={async () => {
        if (await copyText(window.location.href)) {
          setDone(true);
          toast(t('Lien copié'));
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
    </button>
  );
}

/* ---------- technical views ---------- */
/** The expected value of the headline when it does not fit: its first record or how many, all of them on demand. */
function RefTruth({ values, ttl, expected }: { values: string[]; ttl: number | null; expected: boolean }) {
  const peek = usePeek();
  const btn = useRef<HTMLButtonElement>(null);
  const many = values.length > 1;
  return (
    <>
      <button
        ref={btn}
        type="button"
        className={`pp-truth pp-truth--peek ${many ? '' : 'mono'}`}
        aria-expanded={peek.open}
        aria-controls={peek.open ? 'peek-ref' : undefined}
        onClick={peek.toggle}
        onMouseEnter={() => peek.show()}
        onMouseLeave={peek.hide}
        onFocus={() => peek.show(0)}
        onBlur={(e) => !document.getElementById('peek-ref')?.contains(e.relatedTarget as Node) && peek.hide()}
      >
        {many ? tn(values.length, 'la valeur attendue', 'les {n} valeurs attendues') : values[0].length > 40 ? `${values[0].slice(0, 36)}…` : values[0]}
      </button>
      <Peek
        id="peek-ref"
        anchor={btn}
        state={peek}
        label={expected ? t('Votre valeur attendue') : t('Valeur attendue')}
        head={
          <>
            <b>{expected ? t('Votre valeur attendue') : t('Valeur des serveurs autoritaires')}</b>
            <span>
              {tn(values.length, '{n} enregistrement', '{n} enregistrements')}
              {ttl !== null && <> · TTL {fmtTtl(ttl)}</>}
            </span>
          </>
        }
      >
        <Records values={values} />
      </Peek>
    </>
  );
}

function ServersTable({ a }: { a: AuthorityEvent }) {
  return (
    <div className="table-wrap">
      <table className="data-table pp-servers">
        <thead>
          <tr>
            <th scope="col">{t('Serveur')}</th>
            <th scope="col">{t('Réponse')}</th>
            <th scope="col" className="num">TTL</th>
            <th scope="col" className="num">Serial</th>
            <th scope="col" className="num">{t('Latence')}</th>
          </tr>
        </thead>
        <tbody>
          {a.servers.map((s) => (
            <tr key={s.ns + s.ip}>
              <td>
                <span className="mono">{s.ns}</span> <span className="mono muted">{s.ip}</span>
              </td>
              <td className="mono rr-multi">{s.error ? <span className="out-text">{s.error}</span> : s.cname ? `→ ${s.cname}` : sortValues(s.values).join('\n') || s.rcode}</td>
              <td className="num mono">{s.ttl ?? ''}</td>
              <td className="num mono">{s.serial ?? ''}</td>
              <td className="num mono">{s.rtt !== null ? `${s.rtt} ms` : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DistinctTable({ rows }: { rows: Row[] }) {
  const list = useMemo(() => distinctAnswers(rows), [rows]);
  if (!list.length) return <p className="muted">{t('Aucune réponse reçue.')}</p>;
  const total = list.reduce((s, a) => s + a.count, 0);
  return (
    <LabTable columns={[t('Réponse'), t('Résolveurs (part)'), '', t('État')]}>
      {list.map((x) => {
        const settled = x.fresh + x.regional;
        const ok = settled >= x.count / 2;
        const text = x.cname && !x.values.length ? `→ ${x.cname}` : x.values.length ? sortValues(x.values).join('\n') : t('aucune donnée (vide)');
        return (
          <LabRow
            key={x.key}
            label={<span className="mono rr-multi pp-answer">{text}</span>}
            measured={`${fmtCount(x.count)} (${fmtPercent(Math.round((x.count / total) * 1000) / 10)})`}
            deviation={ok ? { kind: 'ok', text: x.regional > x.fresh ? t('régionale') : t('à jour') } : x.uncertain === x.count - settled ? { kind: 'warn', text: t('incertaine'), direction: 'down' } : { kind: 'out', text: t('ancienne'), direction: 'down' }}
          />
        );
      })}
    </LabTable>
  );
}

function Countdown({ at }: { at: number }) {
  const [, setT] = useState(0);
  useEffect(() => {
    const i = setInterval(() => setT((x) => x + 1), 1000);
    return () => clearInterval(i);
  }, []);
  return <strong className="mono">{fmtIn(at)}</strong>;
}

const FAILURE_LABEL: Record<string, string> = {
  no_answer: msg('sans réponse'),
  unstable: msg('instables'),
  refused: msg('refusent'),
  servfail: msg('SERVFAIL'),
  too_slow: msg('trop lents'),
  no_recursion: msg('sans récursion'),
  wrong_answer: msg('réponse fausse'),
  nxdomain_lie: msg('mentent sur NXDOMAIN'),
  geo_implausible: msg('lieu invraisemblable'),
  quarantined: msg('en quarantaine'),
};

function Method({ p }: { p: ResolversPayload }): ReactNode {
  const q = p.qualification!;
  const failures = Object.entries(q.failures).sort((a, b) => b[1] - a[1]);
  return (
    <div className="pp-method__body">
      <p>
        {t('Chaque jour, {tested} candidats sont testés depuis notre serveur avec des noms de contrôle ({names}) : réponse exacte, NXDOMAIN honnête sur un nom inexistant, stabilité sur plusieurs essais, latence. {passed} réussissent ; {total} sont retenus ({global} anycast, {local} locaux, au plus {perCountry} par pays et des opérateurs distincts), dont {dnssec} valident DNSSEC.', {
          tested: fmtCount(q.tested),
          names: q.checkNames.join(', '),
          passed: fmtCount(q.passed),
          total: fmtCount(p.total),
          global: fmtCount(q.qualifiedGlobal),
          local: fmtCount(q.qualifiedLocal),
          perCountry: p.perCountry,
          dnssec: fmtCount(q.dnssecValidating),
        })}
      </p>
      <p>
        {t('Écartés lors de la dernière qualification ({date}, {duration}) : {list}.', {
          date: fmtDateTime(q.finishedAt),
          duration: fmtMs(q.durationMs),
          list: failures.map(([k, n]) => `${fmtCount(n)} ${FAILURE_LABEL[k] ? t(FAILURE_LABEL[k]) : k}`).join(', '),
        })}
      </p>
      <p>
        {t('À la mesure, chaque résolveur reçoit une requête neuve (identifiant aléatoire, aucun cache de notre côté). Une réponse différente d’un résolveur local est recoupée en demandant aux autoritaires ce qu’ils donnent à son réseau (ECS) : une réponse géographique compte comme à jour, une réponse du même opérateur que la zone est régionale.')}
      </p>
    </div>
  );
}

/* ---------- page ---------- */
const FILTER_LABEL: Record<FilterId, string> = {
  all: msg('Tous'),
  fresh: msg('À jour'),
  regional: msg('Régionales'),
  stale: msg('En retard'),
  missing: msg('Absents'),
  rewritten: msg('Réécrits'),
  error: msg('Sans réponse'),
  pending: msg('En attente'),
};

export default function PropagationPage() {
  const { name: nameParam } = useParams();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const cleaned = cleanName(nameParam);
  const invalid = !!cleaned && !isDnsName(cleaned);
  const name = cleaned && !invalid ? cleaned : null;
  const type = pickType(params.get('type'), name ?? '', PROPAGATION_TYPES);
  const expected = params.get('attendu')?.trim() || null;
  const sel = readSelection(params);
  const where = streamQuery(sel);

  const resolversQ = useCheck<ResolversPayload>('/api/propagation/resolvers');
  const resolvers = resolversQ.data;
  const ready = !!resolvers && resolvers.total > 0;
  const { state, run } = usePropagationRun(ready ? name : null, type, expected, where);

  const [filter, setFilter] = useState<FilterId>('all');
  const [sortKey, setSortKey] = useState<SortKey>('place');
  const [highlight, setHighlight] = useState<string | null>(null);
  const [watching, setWatching] = useState(false);
  const [nextAt, setNextAt] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [givenUp, setGivenUp] = useState(0);
  const [find, setFind] = useState('');

  useEffect(() => {
    if (nameParam && name && name !== nameParam) navigate(`/propagation/${encodeURIComponent(name)}?${params.toString()}`, { replace: true });
  }, [name, nameParam]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (name) pushRecent({ value: name, path: `/propagation/${name}`, label: msg('Propagation') });
  }, [name]);
  useEffect(() => {
    setWatching(false);
    setGivenUp(0);
    setFilter('all');
    setNotice(null);
    setFind('');
    setHighlight(null);
  }, [name, type, expected, where]);

  const all = useMemo(() => resolverList(resolvers), [resolvers]);
  const defaults = useMemo(() => serverDefaults(resolvers, all) ?? fallbackDefaults(all), [resolvers, all]);
  const chosen = useMemo(() => selectResolvers(all, sel, defaults), [all, where, defaults]); // eslint-disable-line react-hooks/exhaustive-deps
  const done = state.phase === 'done';
  const running = state.phase === 'connecting' || state.phase === 'authority' || state.phase === 'resolvers';
  // skeleton rows for the selection; once done, only those really asked remain
  const rows = useMemo(() => {
    const r = buildRows(chosen, state);
    return done ? r.filter((x) => x.ev) : r;
  }, [chosen, state, done]);
  const counts = useMemo(() => countRows(rows), [rows]);
  const goodAnswers = useMemo(() => new Set(rows.filter((r) => r.ev && (r.ev.status === 'fresh' || r.ev.status === 'regional')).map((r) => answerKey(r.ev!))), [rows]);
  const isGood = useCallback((r: Row) => !!r.ev && r.ev.status === 'stale' && goodAnswers.has(answerKey(r.ev)), [goodAnswers]);
  const late = useMemo(() => realLate(rows), [rows]);
  const freshBy = useMemo(() => late.map((e) => e.refreshAt).filter((x): x is string => !!x).sort().at(-1) ?? null, [late]);
  const facets = useMemo(() => facetsOf(all, resolvers?.continents ?? {}, countryName, regionNamesOf(resolvers)), [all, resolvers]);
  const chips = useMemo(() => continentChips(all, resolvers?.continents ?? {}, countryName), [all, resolvers]);
  const countryOpts = useMemo(() => countryOptions(facets.countries, all, chips), [facets, all, chips]);
  const regionOpts = useMemo(() => regionOptions(facets.regions, all, chips), [facets, all, chips]);

  const setSel = (s: Selection) => setParams(writeSelection(params, s));
  const setExpected = (v: string | null) => {
    const q = new URLSearchParams(params);
    if (v) q.set('attendu', v);
    else q.delete('attendu');
    setParams(q);
  };
  const setType = (ty: string) => {
    const q = new URLSearchParams(params);
    q.set('type', ty);
    q.delete('attendu');
    setParams(q);
  };

  // watch mode: every 30 s, ask again only those not up to date, until none is late
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  // rounds in which each resolver failed (error, timeout): after 3, the watch stops asking it
  const failures = useRef<Record<string, number>>({});
  useEffect(() => {
    if (state.phase !== 'done') return;
    if (state.round === 0) failures.current = {};
    for (const r of rowsRef.current) {
      const st = r.ev?.status;
      if ((st === 'error' || st === 'timeout') && (state.scope === null || state.scope.includes(r.info.ip)))
        failures.current[r.info.ip] = (failures.current[r.info.ip] ?? 0) + 1;
    }
  }, [state.phase, state.round]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!watching || running) return;
    if (state.referenceChanged) {
      setNotice(t('La réponse des autoritaires a changé pendant la surveillance : tous les résolveurs sont interrogés de nouveau.'));
      run(null);
      return;
    }
    const c = countRows(rowsRef.current);
    if (state.phase === 'done' && c.answered > 0 && realLate(rowsRef.current).length === 0) {
      setWatching(false);
      setNextAt(null);
      const summary = t('{name} {type} : {pct} des résolveurs ayant répondu sont à jour.', { name, type, pct: fmtPercent(c.percentCertain) });
      setNotice(t('Surveillance terminée. {summary}', { summary }));
      try {
        if ('Notification' in window && Notification.permission === 'granted') new Notification(t('Propagation terminée'), { body: summary, tag: `propagation-${name}-${type}` });
      } catch {
        /* notifications unavailable */
      }
      return;
    }
    const at = Date.now() + WATCH_MS;
    setNextAt(at);
    const timer = setTimeout(() => {
      setNextAt(null);
      const w = watchTargets(rowsRef.current, failures.current);
      setGivenUp(w.givenUp.length);
      const ips = state.phase === 'error' && state.scope ? state.scope : w.ips;
      run(ips.length ? ips : null);
    }, WATCH_MS);
    return () => clearTimeout(timer);
  }, [watching, running, state.phase, state.round, state.referenceChanged]); // eslint-disable-line react-hooks/exhaustive-deps

  // the tab title carries the percentage while watching (useful in a background tab)
  useEffect(() => {
    if (!watching) return;
    const before = document.title;
    document.title = `${fmtPercent(counts.percentCertain) || '…'} · ${name} ${type}`;
    return () => {
      document.title = before;
    };
  }, [watching, counts.percentCertain, name, type]);

  const startWatch = async () => {
    setNotice(null);
    try {
      if ('Notification' in window && Notification.permission === 'default') await Notification.requestPermission();
    } catch {
      /* ignore */
    }
    setWatching(true);
  };

  const pick = (ip: string) => {
    setHighlight(ip);
    requestAnimationFrame(() => document.getElementById(`res-${ip}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }));
  };

  const describe = useCallback((r: Row) => {
    const st = rowStatus(r);
    const place = [r.info.city, countryName(r.info.country_code)].filter(Boolean).join(', ');
    const value = r.ev ? valueText(r.ev).replace(/\n/g, ', ') : '';
    return {
      title: cleanProvider(r.info.provider) || displayName(r.info),
      aria: [cleanProvider(r.info.provider) || displayName(r.info), place, t(STATUS_LABEL[st]), value].filter(Boolean).join(', '),
      body: (
        <dl className="pm-tip__dl">
          <dt>{t('Lieu')}</dt>
          <dd>{r.info.geoPrecision === 'country' ? t('{place} (ville inconnue)', { place }) : place}</dd>
          <dt>{t('Statut')}</dt>
          <dd>
            <StatusMark status={st} /> {t(STATUS_LABEL[st])}
          </dd>
          {value && (
            <>
              <dt>{t('Valeur')}</dt>
              <dd className="mono">{value}</dd>
            </>
          )}
          <dt>IP</dt>
          <dd className="mono">{r.info.ip}</dd>
        </dl>
      ),
    };
  }, []);

  if (!name) return <Landing resolvers={resolvers} warning={invalid ? t('« {name} » n’est pas un nom DNS valide', { name: nameParam }) : undefined} />;

  const authority = state.authority;
  const failed = state.phase === 'error' && !authority;
  const ref = authority?.reference;
  const refText = !authority
    ? null
    : ref!.kind === 'cname'
      ? t('l’alias vers {cname}', { cname: ref!.cname })
      : authority.authority.exists || ref!.source === 'expected'
        ? sortValues(ref!.values).join(', ')
        : t('l’absence du nom');
  const dv = authority?.divergence;
  // a real disagreement between the authoritative servers; rotation (dynamic) is a fact, not a fault
  const divergent = !!dv && !dv.dynamic && !dv.sameAnswerDifferentSerials && (dv.answers || dv.serials);
  const pct = counts.percentCertain;
  const tone = failed ? 'out' : running || !counts.answered ? 'wait' : late.length > 0 ? 'warn' : 'ok';
  const mood = failed ? t('Mesure impossible') : running ? t('Mesure en cours') : !counts.answered ? t('Aucune réponse') : late.length > 0 ? t('Propagation en cours') : t('Propagation terminée');
  const upToDate = counts.fresh + counts.regional;
  const certain = counts.answered - counts.uncertain;
  // several values or a long one (TXT, DKIM, MX): a button that opens all of them in full (Peek.tsx)
  const refValues = authority && ref!.kind !== 'cname' && (authority.authority.exists || ref!.source === 'expected') ? sortValues(ref!.values) : [];
  const value = refValues.length && needsPeek(refValues.join('\n')) ? <RefTruth values={refValues} ttl={ref!.ttl} expected={ref!.source === 'expected'} /> : <span className="mono pp-truth">{refText}</span>;
  const vtag = { v: () => value };
  const lateVars = { up: fmtCount(upToDate), certain: fmtCount(certain), n: fmtCount(late.length), time: freshBy ? fmtClock(freshBy) : '' };
  const line: ReactNode = failed
    ? state.error?.message ?? t('La mesure a échoué.')
    : !authority
      ? t('Lecture des serveurs autoritaires…')
      : running
        ? rich('<l>{done}</l> résolveurs sur {total} ont répondu', { done: fmtCount(counts.total - counts.pending), total: fmtCount(counts.total) }, { l: (c) => <span className="live">{c}</span> })
        : late.length > 0
          ? late.length > 1
            ? freshBy
              ? rich('{up} résolveurs sur {certain} voient <v></v> ; {n} servent encore l’ancienne, jusque vers {time}', lateVars, vtag)
              : rich('{up} résolveurs sur {certain} voient <v></v> ; {n} servent encore l’ancienne', lateVars, vtag)
            : freshBy
              ? rich('{up} résolveurs sur {certain} voient <v></v> ; {n} sert encore l’ancienne, jusque vers {time}', lateVars, vtag)
              : rich('{up} résolveurs sur {certain} voient <v></v> ; {n} sert encore l’ancienne', lateVars, vtag)
          : counts.regional
            ? rich('{up} résolveurs sur {certain} voient <v></v>, dont {regional} en réponse régionale', { ...lateVars, regional: fmtCount(counts.regional) }, vtag)
            : rich('{up} résolveurs sur {certain} voient <v></v>', lateVars, vtag);
  const when = state.done?.finishedAt ?? null;
  const meta = [
    when && !running ? t('Mesure du {date}', { date: fmtDateTime(when) }) : null,
    counts.error && !running ? t('{n} sans réponse', { n: fmtCount(counts.error) }) : null,
    counts.rewritten && !running ? t('{n} réécrits, non comptés', { n: fmtCount(counts.rewritten) }) : null,
    dv?.dynamic ? t('zone en rotation ou selon le lieu : chaque valeur des autoritaires compte comme à jour') : null,
  ].filter(Boolean);

  const filters: StatusFilter[] = (['all', 'fresh', 'regional', 'stale', 'missing', 'rewritten', 'error'] as FilterId[])
    .map((id) => ({ id, label: t(FILTER_LABEL[id]), n: id === 'all' ? counts.total : id === 'error' ? counts.error : counts[id as 'fresh'] }))
    .filter((f) => f.id === 'all' || f.n > 0 || filter === f.id);
  const places = hasPlaces(sel);
  const found = (r: Row) => !find.trim() || [countryName(r.info.country_code), r.info.city ?? '', r.info.provider ?? '', r.info.ip].some((v) => fold(v).includes(fold(find.trim())));
  const isLate = (r: Row) => !!r.ev && late.includes(r.ev);
  const shown = sortRows(rows.filter((r) => matchesFilter(r, filter) && found(r)), { key: sortKey === 'place' ? 'name' : sortKey, dir: sortKey === 'ttl' ? 'desc' : 'asc' });
  const anycast = shown.filter((r) => r.info.anycast);
  const local = shown.filter((r) => !r.info.anycast);
  const continents = resolvers?.continents ?? {};
  const byCont = [...new Set(local.map((r) => r.info.continent ?? '??'))].sort((a, b) => (continents[a] ?? a).localeCompare(continents[b] ?? b, locale()));
  const server = resolvers?.serverLocation;
  const near = server?.city ?? null;
  const hasTodo = !!authority && (authority.expectedMatchesAuthority === false || divergent || (!running && late.length > 0));

  // what the map frames: our server and the places of the list
  const placeNames = [
    ...chips.filter((c) => c.codes.every((x) => sel.continents.includes(x))).map((c) => c.name),
    ...sel.continents.filter((x) => !chips.some((c) => c.codes.includes(x))).map((x) => continents[x] ?? x),
    ...sel.regions.map((x) => regionOpts.find((o) => o.code === x)?.name ?? x),
    ...sel.countries.map(countryName),
  ];
  const zone = places
    ? t('{places} et {near}', { places: placeNames.length > 3 ? t('{n} lieux', { n: placeNames.length }) : placeNames.join(', '), near: near ?? t('notre serveur') })
    : filter !== 'all'
      ? t('notre serveur et les résolveurs « {filter} »', { filter: t(FILTER_LABEL[filter]).toLowerCase() })
      : t('notre serveur et les résolveurs');

  const legendExtra = (['regional', 'missing', 'rewritten'] as const).filter((s) => counts[s] > 0);

  return (
    <div data-phase={state.phase} className="pp">
      <div className="pp-screen">
        <section className="surface pp-top" aria-label={t('Mesure et filtres')}>
          <div className="pp-tool">
            <h1 className="visually-hidden">
              {t('Propagation DNS de {name} ({type})', { name, type })}
            </h1>
            <NameField
              name={name}
              onGo={(n) => {
                const q = new URLSearchParams(params);
                q.delete('attendu');
                navigate(`/propagation/${encodeURIComponent(n)}?${q.toString()}`);
              }}
            />
            <TypeSegments value={type} onChange={setType} />
            <ExpectedChip key={`${name}-${type}-${expected ?? ''}`} expected={expected} authority={authority} onApply={setExpected} />
            <span className="pp-grow" />
            <Link className="btn btn--icon btn--ghost" to={`/dns/${encodeURIComponent(name)}?type=${type}&mode=tous`} aria-label={t('Recherche DNS de ce nom')} title={t('Recherche DNS')}>
              <Search aria-hidden />
            </Link>
            <CopyLink />
            {watching ? (
              <button type="button" className="btn pp-watch--on" onClick={() => { setWatching(false); setNextAt(null); }}>
                <Square aria-hidden />
                {t('Arrêter')}
              </button>
            ) : (
              <button type="button" className="btn" onClick={startWatch} disabled={!done || late.length === 0} title={late.length === 0 ? t('Aucun résolveur en retard') : t('Relance toutes les 30 s les résolveurs encore en retard')}>
                <Eye aria-hidden />
                {t('Surveiller')}
              </button>
            )}
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => { setWatching(false); setNextAt(null); run(null); }}
              disabled={(running && !watching) || !ready}
              aria-busy={(running && !watching) || undefined}
            >
              <RotateCw aria-hidden className={running && !watching ? 'spin' : undefined} />
              {t('Relancer')}
            </button>
          </div>
          {ready && (
            <FilterBar
              sel={sel}
              onChange={setSel}
              chips={chips}
              countries={countryOpts}
              regions={regionOpts}
              families={facets.families}
              defaultCount={defaults.length}
              allCount={all.length}
              ipv6={ipv6Available(resolvers)}
              filters={filters}
              filter={filter}
              onFilter={setFilter}
            />
          )}
        </section>

        <QualificationState p={resolvers} error={resolversQ.error} reload={resolversQ.rerun} />

        {ready && (
          <div className="pp-main">
            <section className={`surface pp-map pp-map--${tone}`} aria-label={t('Résultat et carte')}>
              <div className="pp-head">
                <div className={`pp-pct pp-pct--${tone}`} role="img" aria-label={pct !== null ? (running ? t('{pct} des résolveurs ayant répondu sont à jour, mesure en cours', { pct: fmtPercent(pct) }) : t('{pct} des résolveurs ayant répondu sont à jour', { pct: fmtPercent(pct) })) : mood}>
                  {/* while the answers arrive, the share so far, in grey; the colour comes with the end of the measure */}
                  {pct !== null ? (
                    <>
                      {new Intl.NumberFormat(locale(), { maximumFractionDigits: running ? 0 : 1 }).format(pct)}
                      <small>%</small>
                    </>
                  ) : (
                    <span className="pp-pct__wait">…</span>
                  )}
                </div>
                <div className="pp-facts" role="status" aria-live="polite">
                  <b>{mood}</b>
                  <span>{line}</span>
                  {meta.length > 0 && <span className="pp-facts__meta">{meta.join(' · ')}</span>}
                  {watching && (
                    <span className="pp-facts__watch">
                      {running
                        ? t('Surveillance, passage {n} : relance de {count} résolveurs', { n: state.round + 1, count: fmtCount(state.scope?.length ?? counts.total) })
                        : nextAt
                          ? rich('Surveillance, passage {n} : {count} pas à jour, relance <c></c>', { n: state.round + 1, count: fmtCount(watchTargets(rows, failures.current).ips.length) }, { c: () => <Countdown at={nextAt} /> })
                          : t('Surveillance, passage {n} :', { n: state.round + 1 })}
                      {givenUp > 0 ? `. ${t('{n} sans réponse après 3 passes ne sont plus réinterrogés', { n: fmtCount(givenUp) })}` : ''}
                    </span>
                  )}
                  {notice && <span className="pp-facts__watch">{notice}</span>}
                  {hasTodo && (
                    <a className="pp-facts__todo" href="#pp-todo">
                      {t('Que faire ?')}
                    </a>
                  )}
                </div>
                <span className="pp-zone">{t('Cadrage : {zone}', { zone })}</span>
              </div>
              {failed ? (
                <div className="pp-map__fail">
                  <p>{state.error?.message}</p>
                  <button type="button" className="btn btn--primary" onClick={() => run(null)}>
                    <RotateCw aria-hidden />
                    {t('Relancer')}
                  </button>
                </div>
              ) : (
                <Suspense fallback={<div className="pm pm--loading" aria-hidden />}>
                  <WorldMap
                    rows={local}
                    anycast={anycast.length}
                    server={server && server.lat !== null && server.lon !== null ? { lat: server.lat, lon: server.lon, city: server.city } : null}
                    describe={describe}
                    highlight={highlight}
                    label={t('Carte : notre serveur et {n} résolveurs locaux. Flèches pour passer d’un lieu à l’autre, Entrée pour aller à sa ligne.', { n: fmtCount(local.length) })}
                    onPick={pick}
                  />
                </Suspense>
              )}
              <div className="pp-legend" aria-label={t('Légende')}>
                <span>
                  <StatusMark status="fresh" /> {t('à jour')}
                </span>
                {legendExtra.includes('regional') && (
                  <span>
                    <StatusMark status="regional" /> {t('régionale')}
                  </span>
                )}
                <span>
                  <StatusMark status="stale" /> {t('ancienne valeur')}
                </span>
                {legendExtra.includes('missing') && (
                  <span>
                    <StatusMark status="missing" /> {t('absent')}
                  </span>
                )}
                {legendExtra.includes('rewritten') && (
                  <span>
                    <StatusMark status="rewritten" /> {t('réécrit')}
                  </span>
                )}
                <span>
                  <StatusMark status="error" /> {t('sans réponse')}
                </span>
                <span>
                  <span className="pp-legend__home" aria-hidden />
                  {near ? t('notre serveur, {near}', { near }) : t('notre serveur')}
                  {anycast.length ? ` · ${t('{n} anycast répondent de là', { n: fmtCount(anycast.length) })}` : ''}
                </span>
              </div>
            </section>

            <section className="surface pp-list" aria-labelledby="res-t">
              <div className="pp-list__head">
                <h2 id="res-t">
                  {tn(shown.length, '{n} résolveur', '{n} résolveurs')}
                  {shown.length !== rows.length && <span> {t('sur {n}', { n: fmtCount(rows.length) })}</span>}
                </h2>
                {rows.length > 40 && (
                  <input className="input pp-find" type="search" value={find} onChange={(e) => setFind(e.target.value)} placeholder={t('Trouver')} aria-label={t('Trouver un pays, une ville, un opérateur ou une IP dans la liste')} />
                )}
                <label className="pp-sort">
                  <span className="visually-hidden">{t('Trier')}</span>
                  <select value={sortKey} onChange={(e) => setSortKey(e.target.value as SortKey)} aria-label={t('Trier la liste')}>
                    <option value="place">{t('tri : lieu')}</option>
                    <option value="status">{t('tri : état')}</option>
                    <option value="latency">{t('tri : latence')}</option>
                    <option value="ttl">{t('tri : TTL restant')}</option>
                  </select>
                </label>
              </div>
              <div className="pp-rows">
                <ResolverGroup title={t('Grands résolveurs publics, anycast')} rows={anycast} authority={authority} highlight={highlight} isGood={isGood} near={near} latency={sortKey === 'latency'} />
                {byCont.map((c) => (
                  <ResolverGroup
                    key={c}
                    title={continents[c] ?? t('Autres')}
                    rows={local.filter((r) => (r.info.continent ?? '??') === c)}
                    authority={authority}
                    highlight={highlight}
                    isGood={isGood}
                    isLate={isLate}
                    latency={sortKey === 'latency'}
                  />
                ))}
                {!shown.length && (
                  <p className="pp-empty">
                    {find.trim() ? t('Aucun résolveur ne correspond à « {q} ».', { q: find.trim() }) : t('Aucun résolveur dans cet état.')}{' '}
                    <button type="button" className="btn btn--sm" onClick={() => { setFilter('all'); setFind(''); }}>
                      {t('Tout afficher')}
                    </button>
                  </p>
                )}
                {!sel.all && !places && shown.length > 0 && (
                  <p className="pp-more">
                    {t('{n} résolveurs représentatifs sur {total}.', { n: fmtCount(chosen.length), total: fmtCount(all.length) })}{' '}
                    <button type="button" className="btn btn--sm" onClick={() => setSel({ ...sel, all: true })}>
                      {t('Interroger tout le monde')}
                    </button>
                  </p>
                )}
              </div>
            </section>
          </div>
        )}
      </div>

      {authority && hasTodo && (
        <section className="block" aria-labelledby="pp-todo-t" id="pp-todo">
          <h2 className="block__title" id="pp-todo-t">
            {t('À savoir')}
          </h2>
          <div className="issues">
            {authority.expectedMatchesAuthority === false && <ExpectedDetail a={authority} name={name} type={type} />}
            {divergent && <DivergenceDetail a={authority} name={name} type={type} />}
            {!running && <LateIssue late={late} name={name} type={type} authority={authority} />}
          </div>
        </section>
      )}

      {authority && (
        <section className="block" aria-labelledby="tech-t">
          <h2 className="block__title" id="tech-t">
            {t('Détails techniques')}
          </h2>
          <Details
            title={t('Serveurs autoritaires')}
            count={
              ref?.serial
                ? t('zone {zone}, {n} serveurs, serial {serial}', { zone: authority.zone, n: authority.servers.length, serial: ref.serial })
                : t('zone {zone}, {n} serveurs', { zone: authority.zone, n: authority.servers.length })
            }
            defaultOpen={divergent}
          >
            <ServersTable a={authority} />
          </Details>
          <Details title={t('Réponses distinctes')} count={`${distinctAnswers(rows).length}`}>
            <DistinctTable rows={rows} />
          </Details>
          {resolvers?.qualification && (
            <Details title={t('Méthode : comment les résolveurs sont qualifiés')} count={t('contrôle du {date}', { date: fmtDateTime(resolvers.qualification.finishedAt) })}>
              <Method p={resolvers} />
            </Details>
          )}
        </section>
      )}
    </div>
  );
}
