// One hop unfolded in place: tabs Réponse, Requête, Corps, Temps, TLS.
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { CopyButton } from '../../components/ui';
import { msg, rich, t, tn } from '../../lib/i18n';
import { fmtBytes, fmtDateTime, fmtMs } from '../../lib/format';
import { CodeView } from './CodeView';
import { IconCopy } from './IconCopy';
import { reasonOf, type Hop, type HttpExchange } from './model';

/** Headers worth the eye in a redirect diagnosis. */
const KEY_HEADERS = new Set(['location', 'cache-control', 'set-cookie', 'strict-transport-security', 'content-type', 'server', 'x-robots-tag', 'link', 'refresh', 'content-encoding', 'expires', 'vary']);

type TabId = 'response' | 'request' | 'body' | 'timing' | 'tls';

export function HopDetail({ hop }: { hop: Hop }) {
  const ex = hop.exchange;
  const tabs: { id: TabId; label: string }[] = [
    { id: 'response', label: msg('Réponse') },
    { id: 'request', label: msg('Requête') },
    { id: 'body', label: msg('Corps') },
    { id: 'timing', label: msg('Temps') },
    ...(ex.tls ? [{ id: 'tls' as TabId, label: 'TLS' }] : []),
  ];
  const [tab, setTab] = useState<TabId>(ex.status === undefined ? 'request' : 'response');
  const base = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : e.key === 'Home' ? -i : e.key === 'End' ? tabs.length - 1 - i : 0;
    if (!d) return;
    e.preventDefault();
    const n = (i + d + tabs.length) % tabs.length;
    setTab(tabs[n].id);
    refs.current[n]?.focus();
  };
  return (
    <div className="rd-detail">
      <div className="rd-tabs" role="tablist" aria-label={t('Détail du saut {n}', { n: hop.index })}>
        {tabs.map((tb, i) => (
          <button
            key={tb.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${base}-${tb.id}`}
            aria-selected={tab === tb.id}
            aria-controls={`${base}-${tb.id}-p`}
            tabIndex={tab === tb.id ? 0 : -1}
            className="rd-tab"
            onClick={() => setTab(tb.id)}
            onKeyDown={(e) => onKey(e, i)}
          >
            {t(tb.label)}
            {tb.id === 'response' && ex.rawHeaders.length > 0 && <span className="rd-tab__n">{ex.rawHeaders.length}</span>}
            {tb.id === 'body' && ex.body && ex.body.size > 0 && <span className="rd-tab__n">{fmtBytes(ex.body.size)}</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${base}-${tab}-p`} aria-labelledby={`${base}-${tab}`} className="rd-panel">
        {tab === 'response' && <ResponseTab ex={ex} />}
        {tab === 'request' && <RequestTab ex={ex} hop={hop} />}
        {tab === 'body' && <BodyTab ex={ex} />}
        {tab === 'timing' && <TimingTab ex={ex} hop={hop} />}
        {tab === 'tls' && ex.tls && <TlsTab ex={ex} />}
      </div>
    </div>
  );
}

function HeaderTable({ headers, highlight }: { headers: [string, string][]; highlight?: boolean }) {
  return (
    <dl className="rd-headers">
      {headers.map(([k, v], i) => {
        const key = highlight && KEY_HEADERS.has(k.toLowerCase());
        return (
          <div key={i} className={`rd-h ${key ? 'rd-h--key' : ''}`}>
            <dt>{k}</dt>
            <dd>
              <span>{v}</span>
              <IconCopy text={`${k}: ${v}`} label={t('Copier l’en-tête {name}', { name: k })} what={t('{name} copié', { name: k })} />
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

function ResponseTab({ ex }: { ex: HttpExchange }) {
  if (ex.status === undefined)
    return (
      <div className="stack-sm">
        <p className="out-text rd-strong">{t('Aucune réponse : {message}', { message: ex.error?.message ?? t('erreur inconnue') })}</p>
        <p className="muted">
          {ex.ip
            ? rich('Code : <m>{code}</m> · adresse visée <m>{ip}</m>', { code: ex.error?.code ?? '', ip: ex.ip }, { m: (c) => <span className="mono">{c}</span> })
            : rich('Code : <m>{code}</m>', { code: ex.error?.code ?? '' }, { m: (c) => <span className="mono">{c}</span> })}
        </p>
      </div>
    );
  const statusLine = `HTTP/${ex.httpVersion ?? '1.1'} ${ex.status} ${reasonOf(ex.status, ex.statusText)}`;
  const raw = [statusLine, ...ex.rawHeaders.map(([k, v]) => `${k}: ${v}`)].join('\n');
  return (
    <div className="stack-sm">
      <div className="rd-panel__head">
        <code className="rd-statusline">{statusLine}</code>
        <span className="muted rd-small">
          {ex.ip}:{ex.port}
          {ex.cnames?.length ? ` · ${t('via {cnames}', { cnames: ex.cnames.join(' → ') })}` : ''}
        </span>
        <CopyButton text={raw} label={t('Copier tout')} what={t('En-têtes de réponse copiés')} />
      </div>
      <p className="rd-small muted">{t('En-têtes bruts, dans l’ordre et la casse reçus. En gras : ceux qui comptent pour une redirection.')}</p>
      <HeaderTable headers={ex.rawHeaders} highlight />
    </div>
  );
}

function curlOf(ex: HttpExchange): string {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const h = ex.requestHeaders.filter(([k]) => !['host', 'connection'].includes(k.toLowerCase()));
  return [`curl -sS -D - -o /dev/null${ex.method === 'HEAD' ? ' -I' : ''}`, ...h.map(([k, v]) => `  -H ${q(`${k}: ${v}`)}`), `  ${q(ex.url)}`].join(' \\\n');
}

function RequestTab({ ex, hop }: { ex: HttpExchange; hop: Hop }) {
  const raw = [ex.requestLine, ...ex.requestHeaders.map(([k, v]) => `${k}: ${v}`)].join('\n');
  return (
    <div className="stack-sm">
      <div className="rd-panel__head">
        <code className="rd-statusline">{ex.requestLine}</code>
        <span className="muted rd-small">
          {hop.cookiesSent > 0 ? tn(hop.cookiesSent, '{n} cookie renvoyé', '{n} cookies renvoyés') : t('aucun cookie renvoyé')}
        </span>
        <CopyButton text={raw} label={t('Copier tout')} what={t('Requête copiée')} />
        <CopyButton text={curlOf(ex)} label={t('Copier en curl')} what={t('Commande curl copiée')} />
      </div>
      <p className="rd-small muted">{t('Exactement ce qui est parti sur la connexion, connexion neuve, sans cache. Aucun corps envoyé.')}</p>
      <HeaderTable headers={ex.requestHeaders} />
    </div>
  );
}

const CHARSET_SRC: Record<string, string> = { header: 'Content-Type', meta: msg('balise meta'), bom: 'BOM', default: msg('par défaut') };

function BodyTab({ ex }: { ex: HttpExchange }) {
  const b = ex.body;
  if (ex.method === 'HEAD') return <p className="muted">{t('Méthode HEAD : le corps n’est pas demandé. Repassez en GET dans les options pour le lire.')}</p>;
  if (!b) return <p className="muted">{t('Pas de réponse, donc pas de corps.')}</p>;
  if (b.size === 0) return <p className="muted">{b.contentType ? t('Corps vide (0 octet), {type}.', { type: b.contentType }) : t('Corps vide (0 octet).')}</p>;
  const meta = (
    <>
      <span className="mono">{b.mime ?? t('type inconnu')}</span>
      {b.charset && <> · {rich('<m>{charset}</m> ({source})', { charset: b.charset, source: t(CHARSET_SRC[b.charsetSource ?? 'default']) }, { m: (c) => <span className="mono">{c}</span> })}</>}
      {' · '}
      {b.sizeComplete ? t('{size} reçus', { size: fmtBytes(b.size) }) : t('{size} et plus reçus', { size: fmtBytes(b.size) })}
      {b.contentEncoding && <>, {rich('<m>{encoding}</m>, {size} décompressés', { encoding: b.contentEncoding, size: fmtBytes(b.decodedSize) }, { m: (c) => <span className="mono">{c}</span> })}</>}
      {b.truncated && <strong className="rd-warn"> · {t('lecture arrêtée à 2 Mo')}</strong>}
      {b.storedCut && <strong className="rd-warn"> · {t('copie d’historique coupée à 256 Ko')}</strong>}
    </>
  );
  if (b.decodeError) return <p className="out-text">{b.decodeError}</p>;
  if (!b.isText || b.text === undefined)
    return (
      <div className="stack-sm">
        <p className="rd-small">{meta}</p>
        <p className="muted">{t('Contenu binaire : premiers octets en hexadécimal.')}</p>
        {b.hexPreview && <pre className="rd-hex mono">{b.hexPreview}</pre>}
      </div>
    );
  return <CodeView text={b.text} isHtml={!!b.mime?.includes('html')} meta={meta} />;
}

const PHASES: { key: keyof HttpExchange['timings']; label: string; tone: string }[] = [
  { key: 'dns', label: 'DNS', tone: 'dns' },
  { key: 'connect', label: msg('Connexion'), tone: 'tcp' },
  { key: 'tls', label: 'TLS', tone: 'tls' },
  { key: 'wait', label: msg('Attente'), tone: 'wait' },
  { key: 'download', label: msg('Téléchargement'), tone: 'dl' },
];

export function Waterfall({ tm }: { tm: HttpExchange['timings'] }) {
  const sum = PHASES.reduce((n, p) => n + tm[p.key], 0) || 1;
  return (
    <div className="rd-wf" role="img" aria-label={PHASES.map((p) => `${t(p.label)} ${fmtMs(tm[p.key])}`).join(', ')}>
      {PHASES.map((p) => (tm[p.key] > 0 ? <span key={p.key} className={`rd-wf__seg rd-wf__seg--${p.tone}`} style={{ flexGrow: tm[p.key] / sum }} /> : null))}
    </div>
  );
}

function TimingTab({ ex, hop }: { ex: HttpExchange; hop: Hop }) {
  const tm = ex.timings;
  return (
    <div className="stack-sm">
      <Waterfall tm={tm} />
      <table className="rd-tt">
        <tbody>
          {PHASES.map((p) => (
            <tr key={p.key}>
              <th scope="row">
                <span className={`rd-dot rd-wf__seg--${p.tone}`} aria-hidden />
                {t(p.label)}
              </th>
              <td className="mono">{fmtMs(tm[p.key])}</td>
              <td className="muted rd-small">{t(PHASE_HINT[p.key])}</td>
            </tr>
          ))}
          <tr className="rd-tt__total">
            <th scope="row">{t('Total')}</th>
            <td className="mono">{fmtMs(tm.total)}</td>
            <td className="muted rd-small">{t('commencé à +{time} dans la chaîne', { time: fmtMs(hop.startedAt) })}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

const PHASE_HINT: Record<string, string> = {
  dns: msg('résolution depuis les serveurs racine, sans cache (un navigateur profite souvent du cache de son résolveur)'),
  connect: msg('ouverture de la connexion TCP'),
  tls: msg('poignée de main TLS'),
  wait: msg('de l’envoi de la requête au premier octet de la réponse'),
  download: msg('réception du corps'),
};

function TlsTab({ ex }: { ex: HttpExchange }) {
  const tls = ex.tls!;
  const c = tls.cert;
  const rows: [string, ReactNode, ('ok' | 'out' | 'warn')?][] = [
    [t('Protocole'), tls.protocol],
    [t('Chiffrement'), tls.cipher],
    [t('ALPN négocié'), tls.alpn ? t('{alpn} (TestAndFix ne propose que http/1.1)', { alpn: tls.alpn }) : t('aucun')],
    [t('Chaîne de confiance'), tls.chainValid ? t('reconnue') : t('non reconnue : {error}', { error: tls.chainError ?? '' }), tls.chainValid ? 'ok' : 'out'],
    [t('Nom couvert'), tls.nameValid ? t('oui, {host}', { host: ex.host }) : t('non : {error}', { error: tls.nameError ?? '' }), tls.nameValid ? 'ok' : 'out'],
  ];
  if (c) {
    rows.push(
      [t('Sujet'), c.subject + (c.subjectOrg ? ` (${c.subjectOrg})` : '')],
      [t('Émetteur'), c.issuer + (c.issuerOrg ? ` (${c.issuerOrg})` : '')],
      [t('Noms (SAN)'), c.san.join(', ')],
      [t('Valide du'), fmtDateTime(c.validFrom)],
      [t('Valide jusqu’au'), fmtDateTime(c.validTo)],
      [t('Jours restants'), String(c.daysLeft), c.daysLeft < 0 ? 'out' : c.daysLeft < 14 ? 'warn' : 'ok'],
      [t('Chaîne envoyée'), c.chain.join(t(', puis '))],
      [t('Clé'), c.keyBits ? t('{n} bits', { n: c.keyBits }) : undefined],
      [t('Numéro de série'), c.serial],
      [t('Empreinte SHA-256'), c.fingerprint256],
    );
  }
  return (
    <dl className="rd-kv">
      {rows.filter(([, v]) => v !== undefined && v !== '').map(([k, v, tone]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd className={tone === 'out' ? 'out-text rd-strong' : tone === 'warn' ? 'rd-warn' : undefined}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}
