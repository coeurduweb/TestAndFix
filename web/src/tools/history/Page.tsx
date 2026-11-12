// History of the measures kept by the server (90 days): search, tool filter, pages of 50,
// each line reopens the tool on the same input, which measures again. Since 2026-11-11 the server
// keeps one notebook per browser (see /carnet): only this browser's measures are listed, and each
// line can be deleted after a confirmation in place.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { ChevronLeft, ChevronRight, LockKeyhole, Search, Trash2 } from 'lucide-react';
import { famClass, toolById } from '../../app/tools';
import { Empty, Notice, Skel } from '../../components/ui';
import { api } from '../../lib/api';
import { useToast } from '../../components/ui';
import { fmtDateTime, fmtInt, fmtRelative, fmtScore, scoreBand } from '../../lib/format';
import { locale, msg, rich, t, tn } from '../../lib/i18n';
import { errorMessage } from '../../lib/useCheck';
import './history.css';

interface Item {
  id: string;
  tool: string;
  input: string;
  at: string;
  score: number | null;
  summary: Record<string, unknown> | null;
}
interface Stats {
  results: number;
  mails: number;
  oldest: string | null;
  retentionDays: number;
}

const PAGE = 50;
const enc = encodeURIComponent;

/** Where to measure again: the tool page with the same input. */
function pathOf(it: Item): string {
  const tl = toolById(it.tool);
  const words = it.input.trim().split(/\s+/);
  switch (it.tool) {
    case 'mail':
      return `/mail/message/${enc(it.id)}`;
    case 'link':
      return `/lien?url=${enc(it.input)}`;
    case 'dmarc-reports':
      return `/rapports-dmarc?domaine=${enc(it.input)}`;
    case 'dns':
      // DNSSEC chains recorded by /api/dns/:name/dnssec before 2026-11-10 ("exemple.fr dnssec")
      if (words.length === 2 && words[1].toLowerCase() === 'dnssec') return `/dnssec/${enc(words[0])}`;
      return words.length === 2 && /^[a-z0-9]+$/i.test(words[1]) ? `/dns/${enc(words[0])}?type=${words[1].toUpperCase()}` : `/dns/${enc(words[0])}`;
    case 'propagation':
      return words.length === 2 && /^[a-z0-9]+$/i.test(words[1]) ? `/${it.tool}/${enc(words[0])}?type=${words[1].toUpperCase()}` : `/${it.tool}/${enc(words[0])}`;
    case 'ip':
      return /^[\d.:a-f/]+$/i.test(it.input) ? `/ip/${enc(it.input)}` : '/ip';
    case 'rdap': {
      // a list measured by the Whois tool keeps its names in the summary
      const list = it.summary?.domains;
      if (Array.isArray(list) && list.length) return list.length === 1 ? `/whois/${enc(String(list[0]))}` : `/whois?liste=${list.map((d) => enc(String(d))).join(',')}`;
      return words.length === 1 ? `/whois/${enc(words[0])}` : '/whois';
    }
  }
  if (!tl) return '/historique';
  if (tl.routes.some((r) => r.includes(':')) && words[0] && !/\s/.test(words[0])) return `${tl.path}/${enc(words[0])}`;
  return tl.path;
}

/** What was measured, as read: "exemple.fr · A" rather than "exemple.fr a". */
function display(it: Item): { text: string; tool: string } {
  const words = it.input.trim().split(/\s+/);
  if (it.tool === 'dns' && words.length === 2 && words[1].toLowerCase() === 'dnssec') return { text: words[0], tool: 'dnssec' };
  if ((it.tool === 'dns' || it.tool === 'propagation') && words.length === 2 && /^[a-z0-9]+$/i.test(words[1])) return { text: `${words[0]} · ${words[1].toUpperCase()}`, tool: it.tool };
  return { text: it.input || t('(sans objet)'), tool: it.tool };
}

const SEV: [string, string, string][] = [
  ['critical', msg('{n} critique'), msg('{n} critiques')],
  ['high', msg('{n} élevée'), msg('{n} élevées')],
  ['medium', msg('{n} moyenne'), msg('{n} moyennes')],
  ['low', msg('{n} faible'), msg('{n} faibles')],
  ['info', msg('{n} info'), msg('{n} info')],
];

function summaryText(it: Item): string {
  const s = it.summary;
  if (!s) return '';
  if (typeof s.subject === 'string') return s.status && s.status !== 'done' ? t('« {subject} », {status}', { subject: String(s.subject), status: String(s.status) }) : t('« {subject} »', { subject: String(s.subject) });
  if (Array.isArray(s.domains)) return tn(s.domains.length, '{n} domaine', '{n} domaines');
  if (typeof s.percentFresh === 'number') return t('{pct} % des résolveurs à jour', { pct: s.percentFresh });
  const f = s.findings as Record<string, number> | undefined;
  if (f && typeof f === 'object') {
    const parts = SEV.filter(([k]) => f[k]).map(([k, one, many]) => tn(f[k], one, many));
    const passed = typeof s.passed === 'number' && s.passed ? tn(s.passed, '{n} conforme', '{n} conformes') : '';
    return [parts.join(', '), passed].filter(Boolean).join(' · ');
  }
  return '';
}


function keptText(total: number | null, stats: Stats | null): ReactNode {
  const days = stats?.retentionDays ?? 90;
  const date = stats?.oldest ? fmtDateTime(stats.oldest).slice(0, 10) : '';
  const b = { b: (c: ReactNode) => <strong>{c}</strong> };
  if (total !== null) {
    const count = tn(total, '{n} mesure', '{n} mesures');
    return date
      ? rich("<b>{count}</b> gardées {days} jours puis effacées, la plus ancienne du {date}. Un clic sur l'objet mesure à nouveau.", { count, days, date }, b)
      : rich("<b>{count}</b> gardées {days} jours puis effacées. Un clic sur l'objet mesure à nouveau.", { count, days }, b);
  }
  return date
    ? t("Mesures gardées {days} jours puis effacées, la plus ancienne du {date}. Un clic sur l'objet mesure à nouveau.", { days, date })
    : t("Mesures gardées {days} jours puis effacées. Un clic sur l'objet mesure à nouveau.", { days });
}

function nothingFor(q: string, tool: string, days: number): ReactNode {
  const name = tool ? (toolById(tool) ? t(toolById(tool)!.title) : tool) : '';
  const quoted = <span className="mono">« {q} »</span>;
  if (q && tool) return rich('Rien pour <q>{q}</q> dans {tool} sur les {days} derniers jours.', { q, tool: name, days }, { q: () => quoted });
  if (q) return rich('Rien pour <q>{q}</q> sur les {days} derniers jours.', { q, days }, { q: () => quoted });
  return t('Rien pour {tool} sur les {days} derniers jours.', { tool: name, days });
}

function dayTitle(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const y = new Date(today);
  y.setDate(today.getDate() - 1);
  const same = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  if (same(d, today)) return t("Aujourd'hui");
  if (same(d, y)) return t('Hier');
  return d.toLocaleDateString(locale(), { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
}

export default function HistoryPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const tool = params.get('outil') ?? '';
  const page = Math.max(1, Number(params.get('page') ?? 1) || 1);
  const [text, setText] = useState(q);
  const [items, setItems] = useState<Item[] | null>(null);
  const [more, setMore] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [seen, setSeen] = useState<string[]>([]);
  const [asking, setAsking] = useState<string | null>(null);
  const [delErr, setDelErr] = useState<string | null>(null);
  const toast = useToast();

  /** Optimistic: the line goes at once, and comes back with an error if the server refuses. */
  const remove = async (it: Item) => {
    const before = items;
    setAsking(null);
    setDelErr(null);
    setItems((l) => l?.filter((x) => x.id !== it.id) ?? l);
    try {
      await api(`/api/history/${encodeURIComponent(it.id)}`, { method: 'DELETE' });
      setStats((st) => st && (it.tool === 'mail' ? { ...st, mails: Math.max(0, st.mails - 1) } : { ...st, results: Math.max(0, st.results - 1) }));
      toast(t('Mesure supprimée'));
    } catch (e) {
      // already gone (another device of the notebook deleted it): nothing to restore
      if ((e as { status?: number }).status === 404) return;
      setItems(before);
      setDelErr(errorMessage(e));
    }
  };

  const set = (patch: Record<string, string | null>) =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        for (const [k, v] of Object.entries(patch)) v ? n.set(k, v) : n.delete(k);
        return n;
      },
      { replace: true },
    );

  useEffect(() => setText(q), [q]);
  // search as you type, without a button
  useEffect(() => {
    const timer = setTimeout(() => text.trim() !== q && set({ q: text.trim() || null, page: null }), 300);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  useEffect(() => {
    api<Stats>('/api/history/stats').then(setStats).catch(() => undefined);
    api<{ items: Item[] }>('/api/history?limit=200')
      .then((r) => setSeen([...new Set(r.items.map((i) => i.tool))]))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    const qs = new URLSearchParams({ limit: String(PAGE + 1), offset: String((page - 1) * PAGE) });
    if (q) qs.set('q', q);
    if (tool) qs.set('tool', tool);
    api<{ items: Item[] }>(`/api/history?${qs}`)
      .then((r) => {
        if (!alive) return;
        setMore(r.items.length > PAGE);
        setItems(r.items.slice(0, PAGE));
      })
      .catch((e) => alive && (setErr(errorMessage(e)), setItems(null)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [q, tool, page]);

  const groups = useMemo(() => {
    const m = new Map<string, Item[]>();
    for (const it of items ?? []) {
      const k = dayTitle(it.at);
      if (!m.has(k)) m.set(k, []);
      m.get(k)!.push(it);
    }
    return [...m.entries()];
  }, [items]);

  const chips = [...new Set([...seen, ...(tool ? [tool] : [])])].sort((a, b) => { const ta = toolById(a); const tb = toolById(b); return (ta ? t(ta.title) : a).localeCompare(tb ? t(tb.title) : b, locale()); });
  const total = stats ? stats.results + stats.mails : null;

  return (
    <div className="hist">
      <header className="page-head">
        <h1 className="page-head__title">{t('Historique')}</h1>
        <p className="page-head__desc">
          {keptText(total, stats)}
        </p>
        <p className="hist-private">
          <LockKeyhole aria-hidden />
          <span>
            {t('Visible seulement depuis ce navigateur et vos appareils reliés.')} <Link to="/carnet">{t('Mon carnet')}</Link>
          </span>
        </p>
      </header>

      <div className="hist-filters">
        <div className="hist-search">
          <Search aria-hidden />
          <input id="h-q" className="input input--mono" aria-label={t("Rechercher dans l'historique")} value={text} placeholder={t('Rechercher un domaine, une IP, une adresse')} autoComplete="off" spellCheck={false}
            onChange={(e) => setText(e.target.value)} type="search" />
        </div>
        {chips.length > 0 && (
          <div className="chips hist-tools" role="group" aria-label={t('Filtrer par outil')}>
            <button type="button" className="chip" aria-pressed={!tool} onClick={() => set({ outil: null, page: null })}>
              {t('Tous')}
            </button>
            {chips.map((c) => {
              const meta = toolById(c);
              const Icon = meta?.icon;
              return (
                <button key={c} type="button" className="chip" aria-pressed={tool === c} onClick={() => set({ outil: tool === c ? null : c, page: null })}>
                  {Icon && <Icon aria-hidden />}
                  {meta ? t(meta.title) : c}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {delErr && <Notice tone="error" title={t('Suppression refusée')}>{delErr} {t('La mesure est toujours là.')}</Notice>}
      {err && <Notice tone="error" title={t('Historique illisible')}>{err} {t("Relancez la page ; si l'erreur se répète, consultez les journaux du serveur.")}</Notice>}

      {loading && !items && (
        <div className="hist-list surface" aria-busy="true" aria-label={t('Chargement')}>
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="hist-row">
              <span className="dot" />
              <span className="hist-main"><Skel w="18ch" /><Skel w="28ch" /></span>
              <Skel w="8ch" />
            </div>
          ))}
        </div>
      )}

      {items && items.length === 0 && (
        <Empty title={q || tool ? t('Aucune mesure ne correspond') : t('Aucune mesure pour l’instant')}>
          {q || tool ? (
            <>
              {nothingFor(q, tool, stats?.retentionDays ?? 90)}{' '}
              <button type="button" className="btn btn--sm" onClick={() => set({ q: null, outil: null, page: null })}>
                {t('Tout afficher')}
              </button>
            </>
          ) : (
            t('Collez un domaine, une IP ou une adresse dans la saisie du haut : chaque mesure apparaît ici.')
          )}
        </Empty>
      )}

      {items && items.length > 0 && (
        <div className="hist-groups" style={{ opacity: loading ? 0.6 : 1 }} aria-busy={loading || undefined}>
          {groups.map(([title, list]) => (
            <section key={title} className="block" aria-label={title}>
              <h2 className="block__title">{title}</h2>
              <ul className="hist-list surface">
                {list.map((it) => {
                  const d = display(it);
                  const meta = toolById(d.tool);
                  const Icon = meta?.icon;
                  const sum = summaryText(it);
                  const band = it.score === null ? null : scoreBand(it.score);
                  return (
                    <li key={it.id} className="hist-row" data-asking={asking === it.id || undefined}>
                      <span className={`dot ${band ? `dot--${band === 'ok' ? 'ok' : band === 'mid' ? 'warn' : 'out'}` : ''}`} aria-hidden />
                      <span className="hist-main">
                        <Link to={pathOf(it)} className="hist-obj mono" title={t('Mesurer à nouveau')}>
                          {d.text}
                        </Link>
                        <span className={`hist-sub ${famClass(meta?.group)}`}>
                          {Icon && <Icon aria-hidden />}
                          {meta ? t(meta.title) : d.tool}
                          {sum ? ` · ${sum}` : ''}
                        </span>
                      </span>
                      <span className="hist-when" title={fmtDateTime(it.at)}>
                        {fmtDateTime(it.at).slice(-8, -3)}
                        <small>{fmtRelative(it.at)}</small>
                      </span>
                      <span className={`hist-score ${band ? `is-${band}` : ''}`} aria-label={it.score === null ? t('sans note') : t('note {score} sur 10', { score: fmtScore(it.score) })}>
                        {it.score === null ? t('n/d') : fmtScore(it.score)}
                      </span>
                      {asking === it.id ? (
                        <span className="hist-ask" role="group" aria-label={t('Supprimer {name}', { name: d.text })}>
                          <span>Supprimer cette mesure ?</span>
                          <button type="button" className="btn btn--sm btn--danger" onClick={() => remove(it)}>
                            {t('Supprimer')}
                          </button>
                          <button type="button" className="btn btn--sm btn--ghost" onClick={() => setAsking(null)} autoFocus>
                            {t('Annuler')}
                          </button>
                        </span>
                      ) : (
                        <button type="button" className="btn btn--icon btn--ghost hist-del" aria-label={t('Supprimer {name} de l’historique', { name: d.text })} title={t('Supprimer de l’historique')} onClick={() => setAsking(it.id)}>
                          <Trash2 aria-hidden />
                        </button>
                      )}
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
          <nav className="hist-pages" aria-label={t('Pages')}>
            <span className="field__hint">
              {!q && !tool && total !== null
                ? t('Mesures {from} à {to} sur {total}', { from: (page - 1) * PAGE + 1, to: (page - 1) * PAGE + items.length, total })
                : t('Mesures {from} à {to}', { from: (page - 1) * PAGE + 1, to: (page - 1) * PAGE + items.length })}
            </span>
            <span className="hist-pages__btns">
              <button type="button" className="btn" disabled={page <= 1} onClick={() => set({ page: page > 2 ? String(page - 1) : null })}>
                <ChevronLeft aria-hidden /> {t('Plus récentes')}
              </button>
              <button type="button" className="btn" disabled={!more} onClick={() => set({ page: String(page + 1) })}>
                {t('Plus anciennes')} <ChevronRight aria-hidden />
              </button>
            </span>
          </nav>
        </div>
      )}
    </div>
  );
}
