// Cache flush on two machines: the server that runs check (through its backend, which holds the
// agent token) and this workstation (the browser calls the local agent on 127.0.0.1 directly).
// Agent protocol: agent/README.md (GET /health without token, POST /flush with a bearer token).
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { KeyRound, RotateCw, Trash2 } from 'lucide-react';
import { CodeBlock, Field, Notice, Skel } from '../../components/ui';
import { api, ApiError } from '../../lib/api';
import { fmtDateTime } from '../../lib/format';
import { locale, msg, rich, t, tn } from '../../lib/i18n';
import { Checks, More, Segmented } from '../gen-spf/GenParts';
import '../gen-spf/gen.css';
import './caches.css';

type What = 'all' | 'dns' | 'pages';
interface Health {
  ok: boolean;
  agent?: string;
  version?: string;
  authenticated: boolean;
  host?: string;
  min_interval?: number;
  /** installed with --dns-only (shared server): the page cache is never dropped there */
  dns_only?: boolean;
}
interface FlushAction {
  target: string;
  status: 'flushed' | 'absent' | 'failed' | 'skipped';
  detail?: string;
}
interface FlushResult {
  host?: string;
  distro?: string;
  kernel?: string;
  init?: string;
  dry_run?: boolean;
  actions?: FlushAction[];
  page_cache?: { before_kb?: number; after_kb?: number; status: FlushAction['status']; detail?: string };
  ok: boolean;
  exit_code?: number;
  error?: string;
  stderr?: string;
  retry_after?: number;
}
interface Outcome {
  at: string;
  http: number;
  body: FlushResult;
}

const TOKEN_KEY = 'check:agent-token';
const URL_KEY = 'check:agent-url';
const DEFAULT_AGENT = 'http://127.0.0.1:47625';

const read = (k: string) => {
  try {
    return localStorage.getItem(k) ?? '';
  } catch {
    return '';
  }
};
const write = (k: string, v: string) => {
  try {
    if (v) localStorage.setItem(k, v);
    else localStorage.removeItem(k);
  } catch {
    /* storage unavailable: kept for this page only */
  }
};

const STATUS: Record<FlushAction['status'], { label: string }> = {
  flushed: { label: msg('purgé') },
  absent: { label: msg('absent') },
  failed: { label: msg('échec') },
  skipped: { label: msg('ignoré') },
};
const body = (w: What) => ({ dns: w !== 'pages', page_cache: w !== 'dns' });
const actionLabel = (w: What) => (w === 'all' ? t('Vider les caches DNS et le cache de pages') : w === 'dns' ? t('Vider les caches DNS') : t('Vider le cache de pages'));
const mb = (kb?: number) => (kb === undefined ? '?' : t('{n} Mo', { n: Math.round(kb / 1024).toLocaleString(locale()) }));
const MONO = { m: (c: ReactNode) => <span className="mono">{c}</span> };

/** What the agent said, service by service. */
function FlushReport({ o }: { o: Outcome }) {
  const b = o.body;
  if (o.http === 429)
    return <Notice tone="warn" title={t('Purge refusée : trop rapprochée')}>{b.retry_after ? t("L'agent accepte une purge toutes les 10 secondes : réessayez dans {n} s.", { n: b.retry_after }) : t("L'agent accepte une purge toutes les 10 secondes.")}</Notice>;
  if (o.http === 401) return <Notice tone="error" title={t('Jeton refusé')}>{t("Le jeton ne correspond pas à celui de l'agent. Recopiez-le (sudo cat /etc/check-agent/token).")}</Notice>;
  if (!b.actions && !b.page_cache) {
    const sudo = o.http === 502;
    return (
      <Notice tone="error" title={sudo ? t("Échec : l'agent n'a pas pu lancer la purge en root") : t('Échec de la purge (HTTP {status})', { status: o.http })}>
        {sudo
          ? t("L'agent tourne, mais le script de purge n'a rien renvoyé : en général sudo a refusé (agent lancé à la main, sans la règle sudoers). Installez-le avec install.sh, qui crée l'utilisateur dédié et la règle sudoers :")
          : b.error ?? t('Réponse inattendue.')}
        {b.stderr && <code style={{ display: 'block', marginTop: 'var(--s2)', overflowWrap: 'anywhere' }}>{b.stderr}</code>}
        {sudo && (
          <div style={{ marginTop: 'var(--s3)' }}>
            <CodeBlock code={`cd agent && sudo ./install.sh --origin ${location.origin}`} label={t('Installation')} />
          </div>
        )}
      </Notice>
    );
  }
  const absent = (b.actions ?? []).filter((a) => a.status === 'absent');
  const failed = (b.actions ?? []).filter((a) => a.status === 'failed').length + (b.page_cache?.status === 'failed' ? 1 : 0);
  return (
    <div className="stack-sm">
      <p className="field__hint">
        {(() => {
          const v = {
            head: b.dry_run ? t('Simulation terminée') : b.ok ? t('Purge terminée') : tn(failed, 'Purge terminée avec {n} échec', 'Purge terminée avec {n} échecs'),
            date: fmtDateTime(o.at),
            where: `${b.host ? ` ${t('sur {host}', { host: b.host })}` : ''}${b.distro ? ` (${b.distro}${b.init ? `, ${b.init}` : ''})` : ''}`,
          };
          return b.dry_run ? t('{head} le {date}{where} : rien n’a été vidé.', v) : t('{head} le {date}{where}.', v);
        })()}
      </p>
      <Checks
        items={[
          ...(b.actions ?? []).filter((a) => a.status !== 'absent').map((a) => ({
            key: a.target,
            tone: a.status === 'failed' ? ('bad' as const) : a.status === 'flushed' ? ('ok' as const) : ('watch' as const),
            main: <><strong className="mono">{a.target}</strong> <span className="ca-detail">{a.detail}</span></>,
            note: b.dry_run && a.status === 'skipped' ? t('simulé') : STATUS[a.status] ? t(STATUS[a.status].label) : a.status,
          })),
          ...(b.page_cache
            ? [{
                key: 'page-cache',
                tone: b.page_cache.status === 'failed' ? ('bad' as const) : b.page_cache.status === 'flushed' ? ('ok' as const) : ('watch' as const),
                main: <><strong>{t('Cache de pages du noyau')}</strong> <span className="ca-detail">{b.page_cache.status === 'flushed' ? `${mb(b.page_cache.before_kb)} → ${mb(b.page_cache.after_kb)}` : b.page_cache.detail}</span></>,
                note: b.dry_run && b.page_cache.status === 'skipped' ? t('simulé') : STATUS[b.page_cache.status] ? t(STATUS[b.page_cache.status].label) : undefined,
              }]
            : []),
        ]}
      />
      {absent.length > 0 && <p className="field__hint">{t('Absents de cette machine ({n}) : {list}.', { n: absent.length, list: absent.map((a) => a.target).join(', ') })}</p>}
    </div>
  );
}

/* ---------- server ---------- */
function ServerBlock({ what }: { what: What }) {
  const [st, setSt] = useState<{ available: boolean; reason?: string; detail?: string; health?: Health } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<Outcome | null>(null);
  const load = useCallback(() => {
    setErr(null);
    api<{ available: boolean; reason?: string; detail?: string; health?: Health }>('/api/caches/server')
      .then(setSt)
      .catch((e) => setErr(e instanceof ApiError ? `HTTP ${e.status}` : t('serveur injoignable')));
  }, []);
  useEffect(load, [load]);
  const dnsOnly = Boolean(st?.health?.dns_only);
  // on a dns-only host, "DNS et pages" flushes the DNS part only; "Pages seul" is not offered
  const serverWhat: What = dnsOnly ? 'dns' : what;
  const flush = async () => {
    setBusy(true);
    try {
      const r = await api<FlushResult>('/api/caches/server/flush', { method: 'POST', json: body(serverWhat) });
      setOut({ at: new Date().toISOString(), http: 200, body: r });
    } catch (e) {
      const ae = e as ApiError;
      setOut({ at: new Date().toISOString(), http: ae.status ?? 0, body: { ok: false, ...((ae.body as object) ?? {}), error: (ae.body as { error?: string })?.error ?? ae.message } });
    } finally {
      setBusy(false);
      load();
    }
  };
  const h = st?.health;
  return (
    <section className="gen-card surface" aria-labelledby="ca-srv-t">
      <h2 className="gen-card__title" id="ca-srv-t">{t('Serveur de TestAndFix')}</h2>
      <div className="ca-block">
        <Checks
          items={[
            { key: 'agent', tone: !st ? ('watch' as const) : st.available ? ('ok' as const) : ('bad' as const), main: <strong>{t('Agent du serveur')}</strong>,
              note: !st ? t('vérification…') : st.available ? t('joignable') : st.reason === 'not_configured' ? t('non configuré') : t('injoignable') },
            ...(h ? [{ key: 'auth', tone: h.authenticated ? ('ok' as const) : ('bad' as const), main: <strong>{t('Authentifié')}</strong>, note: h.authenticated ? t('oui') : t('jeton refusé') }] : []),
            ...(h?.host ? [{ key: 'host', tone: 'ok' as const, main: rich('Machine <m>{host}</m>', { host: h.host }, MONO), note: h.version ? t('agent {version}', { version: h.version }) : undefined }] : []),
            ...(dnsOnly ? [{ key: 'dnsonly', tone: 'watch' as const, main: <strong>{t('Caches DNS seulement')}</strong>, note: t('serveur partagé : le cache de pages n’est jamais vidé ici') }] : []),
          ]}
        />
        {err && <Notice tone="error" title={t('État inconnu')}>{t("Le serveur de TestAndFix n'a pas répondu ({err}).", { err })}</Notice>}
        {st && !st.available && (
          <Notice tone="info" title={st.reason === 'not_configured' ? t("L'agent du serveur n'est pas configuré") : t("L'agent du serveur ne répond pas")}>
            {st.reason === 'not_configured' ? (
              <>{t("Sur la machine hôte, installez l'agent à l'écoute du pont Docker, puis donnez au conteneur son adresse et son jeton (variables CHECK_AGENT_URL et CHECK_AGENT_TOKEN), et redémarrez-le :")}</>
            ) : (
              <>{st.detail ? t("Adresse configurée injoignable ({detail}). Vérifiez que le service check-agent tourne sur l'hôte et que le pare-feu laisse passer le réseau Docker :", { detail: st.detail }) : t("Adresse configurée injoignable. Vérifiez que le service check-agent tourne sur l'hôte et que le pare-feu laisse passer le réseau Docker :")}</>
            )}
            <div style={{ marginTop: 'var(--s3)' }} className="stack-sm">
              <CodeBlock code={`cd agent && sudo ./install.sh --bind 172.17.0.1 --origin ${location.origin}`} label={t("Sur l'hôte")} />
              <CodeBlock code={'CHECK_AGENT_URL=http://172.17.0.1:47625\nCHECK_AGENT_TOKEN=<contenu de /etc/check-agent/token>'} label={t('Environnement du conteneur')} />
            </div>
          </Notice>
        )}
        <div className="ca-actions">
          <button type="button" className="btn btn--primary" disabled={!st?.available || busy || (dnsOnly && what === 'pages')} aria-busy={busy || undefined} onClick={flush}>
            <Trash2 aria-hidden /> {actionLabel(serverWhat)}
          </button>
          <button type="button" className="btn btn--ghost" onClick={load}>
            <RotateCw aria-hidden /> {t('Vérifier')}
          </button>
        </div>
        <div role="status" aria-live="polite">{out && <FlushReport o={out} />}</div>
      </div>
    </section>
  );
}

/* ---------- workstation ---------- */
type LocalState = { kind: 'unchecked' } | { kind: 'checking' } | { kind: 'down' } | { kind: 'origin' } | { kind: 'up'; health: Health };

function LocalBlock({ what }: { what: What }) {
  const [token, setToken] = useState(() => read(TOKEN_KEY));
  const [tokenText, setTokenText] = useState('');
  const [agent, setAgent] = useState(() => read(URL_KEY) || DEFAULT_AGENT);
  const [agentText, setAgentText] = useState(agent);
  const [st, setSt] = useState<LocalState>(() => (read(TOKEN_KEY) ? { kind: 'checking' } : { kind: 'unchecked' }));
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<Outcome | null>(null);

  const check = useCallback(async () => {
    setSt((s) => (s.kind === 'up' ? s : { kind: 'checking' }));
    try {
      const r = await fetch(`${agent}/health`, { headers: token ? { Authorization: `Bearer ${token}` } : {}, cache: 'no-store', signal: AbortSignal.timeout(4000) });
      if (r.status === 403) return setSt({ kind: 'origin' });
      const h = (await r.json()) as Health;
      setSt({ kind: 'up', health: h });
    } catch {
      setSt({ kind: 'down' });
    }
  }, [agent, token]);
  // probe 127.0.0.1 on load only once a token is saved: otherwise only on « Vérifier »
  useEffect(() => {
    if (!token) return;
    void check();
    // the agent may have been installed in another window meanwhile
    const onFocus = () => void check();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [check]);

  const flush = async () => {
    setBusy(true);
    try {
      const r = await fetch(`${agent}/flush`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body(what)),
        signal: AbortSignal.timeout(90_000),
      });
      let b: FlushResult = { ok: false };
      try {
        b = (await r.json()) as FlushResult;
      } catch {
        /* no JSON */
      }
      setOut({ at: new Date().toISOString(), http: r.status, body: b });
    } catch (e) {
      setOut({ at: new Date().toISOString(), http: 0, body: { ok: false, error: t('Agent injoignable pendant la purge ({message}).', { message: (e as Error).message }) } });
    } finally {
      setBusy(false);
    }
  };

  const saveToken = (v: string) => {
    const tok = v.trim();
    setToken(tok);
    write(TOKEN_KEY, tok);
    setTokenText('');
  };
  const h = st.kind === 'up' ? st.health : null;
  const authed = !!h?.authenticated;

  return (
    <section className="gen-card surface" aria-labelledby="ca-loc-t">
      <h2 className="gen-card__title" id="ca-loc-t">{t('Ce poste')}</h2>
      <div className="ca-block">
        <Checks
          items={[
            {
              key: 'agent',
              tone: st.kind === 'up' ? ('ok' as const) : st.kind === 'unchecked' || st.kind === 'checking' ? ('watch' as const) : ('bad' as const),
              main: <><strong>{t('Agent local')}</strong> <span className="mono ca-detail gen-nw">{agent.replace(/^https?:\/\//, '')}</span></>,
              note: st.kind === 'checking' ? t('vérification…') : st.kind === 'unchecked' ? t('pas encore vérifié') : st.kind === 'up' ? t('joignable') : st.kind === 'origin' ? t('origine refusée') : t('ne répond pas'),
            },
            ...(h ? [{ key: 'auth', tone: authed ? ('ok' as const) : ('bad' as const), main: <strong>{t('Authentifié')}</strong>, note: authed ? t('oui') : token ? t('jeton refusé') : t('pas de jeton') }] : []),
            ...(h?.host ? [{ key: 'host', tone: 'ok' as const, main: rich('Machine <m>{host}</m>', { host: h.host }, MONO), note: h.version ? t('agent {version}', { version: h.version }) : undefined }] : []),
          ]}
        />

        {(st.kind === 'down' || st.kind === 'unchecked') && (
          <Notice tone="info" title={st.kind === 'down' ? t("L'agent ne répond pas : installez-le sur ce poste (Linux)") : t("Pour vider les caches de ce poste (Linux), installez l'agent une fois")}>
            {t('Depuis le dossier agent de TestAndFix, une fois : il écoute sur 127.0.0.1, ne vide que des caches et exige un jeton.')}
            <div style={{ marginTop: 'var(--s3)' }} className="stack-sm">
              <CodeBlock code={`cd agent && sudo ./install.sh --origin ${location.origin}`} label={t('Installation')} />
              <CodeBlock code="sudo cat /etc/check-agent/token" label={t('Puis le jeton, à coller ci-dessous')} />
            </div>
          </Notice>
        )}
        {st.kind === 'origin' && (
          <Notice tone="error" title={t("L'agent refuse cette page (origine)")}>
            {t("Il n'accepte que l'origine donnée à l'installation. Réinstallez-le avec exactement celle-ci :")}
            <div style={{ marginTop: 'var(--s3)' }}>
              <CodeBlock code={`cd agent && sudo ./install.sh --origin ${location.origin}`} label={t('Réinstallation')} />
            </div>
          </Notice>
        )}

        {(!authed || !token) && st.kind !== 'origin' && (
          <form className="gen-row" onSubmit={(e) => { e.preventDefault(); saveToken(tokenText); }}>
            <Field label={t("Jeton de l'agent")} hint={t('Gardé dans ce navigateur seulement. Il ne permet que de vider des caches.')}>
              {(id, d) => (
                <input id={id} aria-describedby={d} className="input input--mono" type="password" autoComplete="off" value={tokenText} placeholder={token ? t('jeton enregistré, refusé : recollez-le') : t('collez le jeton')}
                  onChange={(e) => setTokenText(e.target.value)} onPaste={(e) => { const pasted = e.clipboardData.getData('text'); if (pasted.trim().length >= 16) { e.preventDefault(); saveToken(pasted); } }} />
              )}
            </Field>
            <button type="submit" className="btn" style={{ marginBottom: '1.35rem' }} disabled={!tokenText.trim()}>
              <KeyRound aria-hidden /> {t('Enregistrer')}
            </button>
          </form>
        )}

        <div className="ca-actions">
          <button type="button" className="btn btn--primary" disabled={!authed || busy} aria-busy={busy || undefined} onClick={flush}>
            <Trash2 aria-hidden /> {actionLabel(what)}
          </button>
          <button type="button" className="btn btn--ghost" onClick={() => void check()}>
            <RotateCw aria-hidden /> {t('Vérifier')}
          </button>
          {token && (
            <button type="button" className="btn btn--ghost" onClick={() => { saveToken(''); setOut(null); }}>
              {t('Oublier le jeton')}
            </button>
          )}
        </div>
        <div role="status" aria-live="polite">{out && <FlushReport o={out} />}</div>

        <p className="field__hint">
          {t("Chrome peut demander d'autoriser l'accès au réseau local la première fois (une page web qui joint 127.0.0.1) : acceptez, l'agent répond au contrôle Private Network Access.")}
        </p>
        <More summary={t("Adresse de l'agent")}>
          <form className="gen-row" onSubmit={(e) => {
            e.preventDefault();
            const v = agentText.trim().replace(/\/$/, '') || DEFAULT_AGENT;
            setAgent(v);
            write(URL_KEY, v === DEFAULT_AGENT ? '' : v);
          }}>
            <Field label="URL" hint={t("Par défaut {url}. À changer seulement si l'agent écoute sur un autre port.", { url: DEFAULT_AGENT })}>
              {(id, d) => <input id={id} aria-describedby={d} className="input input--mono" value={agentText} onChange={(e) => setAgentText(e.target.value)} />}
            </Field>
            <button type="submit" className="btn" style={{ marginBottom: '1.35rem' }}>{t('Utiliser')}</button>
          </form>
        </More>
      </div>
    </section>
  );
}

export default function CachesPage() {
  const [what, setWhat] = useState<What>('all');
  return (
    <div className="ca">
      <header className="page-head">
        <h1 className="page-head__title">{t('Vider les caches')}</h1>
        <p className="page-head__desc">{t("Caches DNS (résolveur système, dnsmasq, unbound, BIND…) et cache de pages du noyau, sur le serveur de TestAndFix et sur ce poste, par l'agent check-agent.")}</p>
      </header>
      <div className="ca-body">
        <Segmented<What>
          label={t('À vider')}
          value={what}
          onChange={setWhat}
          options={[
            { value: 'all', label: t('DNS et pages') },
            { value: 'dns', label: t('DNS seul') },
            { value: 'pages', label: t('Pages seul') },
          ]}
          hint={t('Le script ne touche à aucune configuration, ne supprime aucun fichier et n’arrête aucun service : il ne fait que vider.')}
        />
        <div className="ca-grid">
          <ServerBlock what={what} />
          <LocalBlock what={what} />
        </div>
      </div>
    </div>
  );
}
