// The path of the message: the relays of the Received chain, oldest first, with the encryption
// and the delay of each hand-off. The only drawing of the report.
import { Lock, LockOpen, CircleHelp } from 'lucide-react';
import { CodeBlock } from '../../components/ui';
import { fmtDateTime, plural } from '../../lib/format';
import { locale, t, tn } from '../../lib/i18n';
import { buildPath, fmtDelay, fmtWhen, type PathLeg } from './logic';
import type { Hop } from './types';

/** a hand-off slower than this is set in bold amber (presentation only, no point lost) */
const SLOW_SEC = 300;

function Leg({ leg, n }: { leg: PathLeg; n: number }) {
  const state = leg.tls === true ? 'tls' : leg.tls === false ? 'clear' : 'unknown';
  const Icon = state === 'tls' ? Lock : state === 'clear' ? LockOpen : CircleHelp;
  const proto = state === 'tls' ? (leg.protocol ?? 'TLS') : state === 'clear' ? t('en clair') : t('non indiqué');
  const slow = leg.delaySec !== null && leg.delaySec >= SLOW_SEC;
  return (
    <div className="mail-path__leg" data-state={state}>
      <span className="mail-path__proto">
        <Icon aria-hidden />
        <span>
          <span className="visually-hidden">{t('Saut {n} : ', { n })}</span>
          {proto}
        </span>
      </span>
      <span className="mail-path__line" aria-hidden />
      <span className={`mail-path__delay ${slow ? 'mail-path__delay--slow' : ''}`}>
        {leg.delaySec === null ? (leg.at ? <span className="muted">{fmtTime(leg.at)}</span> : '') : `+${fmtDelay(leg.delaySec)}`}
      </span>
    </div>
  );
}

const fmtTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

export function PathView({ hops, date, receivedBy }: { hops: Hop[]; date?: string; receivedBy?: string }) {
  if (!hops.length) {
    return (
      <>
        <p className="mail-note">{t('Aucun en-tête Received : le message ne dit pas par où il est passé (en-têtes copiés sans leurs lignes de transport ?).')}</p>
      </>
    );
  }
  const p = buildPath(hops, date);
  const last = p.nodes.length - 1;
  const role = (i: number) => (i === 0 ? t('origine') : i === last ? (receivedBy && p.nodes[i].name.toLowerCase().includes(receivedBy) ? t('réception TestAndFix') : t('réception')) : t('relais {n}', { n: i }));
  const facts = [
    plural(p.legs.length, 'transmission', 'transmissions'),
    p.totalSec !== null ? t('transit {delay} du premier au dernier relais', { delay: fmtDelay(p.totalSec) }) : undefined,
    p.sinceDate !== null && p.sinceDate >= 0 ? t('{delay} entre l’en-tête Date et le premier relais', { delay: fmtDelay(p.sinceDate) }) : undefined,
  ].filter(Boolean);
  return (
    <>
      <div className="mail-path-wrap">
        <ol className="mail-path" aria-label={t('Serveurs traversés, du plus ancien au plus récent')}>
          {p.nodes.map((node, i) => (
            <li key={i} className="mail-path__step">
              {i > 0 && <Leg leg={p.legs[i - 1]} n={i} />}
              <div className={`mail-path__node ${i === 0 ? 'mail-path__node--origin' : ''} ${i === last ? 'mail-path__node--end' : ''}`}>
                <span className="mail-path__role">{role(i)}</span>
                <span className="mail-path__name">{node.name}</span>
                {((node.ip && node.ip !== node.name.replace(/^\[|\]$/g, '')) || node.ptr) && (
                  <span className="mail-path__ip">
                    {node.ip !== node.name.replace(/^\[|\]$/g, '') ? node.ip : ''}
                    {node.ptr && node.ptr !== node.name ? `${node.ip ? ' · ' : ''}${node.ptr}` : ''}
                  </span>
                )}
                {node.aliases.length > 0 && <span className="mail-path__alias">{t('annoncé {names}', { names: node.aliases.join(', ') })}</span>}
              </div>
            </li>
          ))}
        </ol>
      </div>
      <p className="mail-path__facts">
        {facts.join(' · ')}
        {p.plaintextLegs > 0 && (
          <>
            {' · '}
            <strong className="out-text">{plural(p.plaintextLegs, 'transmission en clair', 'transmissions en clair')}</strong>
          </>
        )}
        {p.unknownTlsLegs > 0 && ` · ${tn(p.unknownTlsLegs, 'chiffrement non indiqué pour {n} transmission', 'chiffrement non indiqué pour {n} transmissions')}`}
      </p>
      <details className="mail-raw">
        <summary>{hops.length > 1 ? t('Détail des {n} en-têtes Received', { n: hops.length }) : t('Détail de l’en-tête Received')}</summary>
        <div className="table-wrap">
          <table className="data-table mail-hops">
            <thead>
              <tr>
                <th scope="col">{t('Saut')}</th>
                <th scope="col">{t('De')}</th>
                <th scope="col">{t('Par')}</th>
                <th scope="col">{t('Protocole')}</th>
                <th scope="col">{t('Horodatage')}</th>
                <th scope="col" className="num">{t('Délai')}</th>
              </tr>
            </thead>
            <tbody>
              {[...hops].sort((a, b) => a.index - b.index).map((h) => (
                <tr key={h.index}>
                  <td className="mono">{h.index}</td>
                  <td className="mono">
                    {h.from ?? h.helo ?? ''}
                    {h.ip && <span className="muted"> [{h.ip}]</span>}
                  </td>
                  <td className="mono">{h.by ?? ''}</td>
                  <td className="mono">
                    {h.with ?? ''}
                    {h.tlsDetail ? <span className="muted"> {h.tlsDetail}</span> : ''}
                  </td>
                  <td className="mono">{h.at ? fmtDateTime(h.at) : ''}</td>
                  <td className="mono num">{h.delaySec === null || h.delaySec === undefined ? '' : fmtDelay(h.delaySec)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <CodeBlock code={[...hops].sort((a, b) => b.index - a.index).map((h) => `Received: ${h.raw}`).join('\n')} label={t('Tels que reçus, du plus récent au plus ancien')} />
      </details>
    </>
  );
}

/** "3 transmissions · 7 s · 1 en clair", for the closed state of the block. */
export function pathCount(hops: Hop[]): string {
  if (!hops.length) return t('parcours inconnu');
  const p = buildPath(hops);
  return [plural(p.legs.length, 'transmission', 'transmissions'), p.totalSec !== null ? fmtDelay(p.totalSec) : undefined, p.plaintextLegs ? t('{n} en clair', { n: p.plaintextLegs }) : undefined].filter(Boolean).join(' · ');
}

/** The path in the side column of the report: one line per server, the encryption and delay of each hand-off. */
export function PathCard({ hops, date, receivedAt }: { hops: Hop[]; date?: string; receivedAt?: number }) {
  if (!hops.length) return <p className="mr-card__none">{t('Aucun en-tête Received : le message ne dit pas par où il est passé.')}</p>;
  const p = buildPath(hops, date);
  const last = p.nodes.length - 1;
  return (
    <ol className="mr-hops" aria-label={t('Serveurs traversés, du plus ancien au plus récent')}>
      {p.nodes.map((node, i) => {
        const leg = i > 0 ? p.legs[i - 1] : undefined;
        const ip = node.ip && node.ip !== node.name.replace(/^\[|\]$/g, '') ? node.ip : undefined;
        const sub = [node.ptr && node.ptr !== node.name ? node.ptr : undefined, ip].filter(Boolean).join(' · ');
        return (
          <li key={i} className="mr-hop" data-end={i === last || undefined}>
            <i aria-hidden />
            <div>
              <b>
                {node.name}
                {leg && (
                  <em data-state={leg.tls === true ? 'tls' : leg.tls === false ? 'clear' : 'unknown'}>
                    {leg.tls === true ? (leg.protocol ?? 'TLS') : leg.tls === false ? t('en clair') : t('chiffrement non indiqué')}
                    {leg.delaySec !== null && leg.delaySec > 0 ? ` · +${fmtDelay(leg.delaySec)}` : ''}
                  </em>
                )}
              </b>
              {sub && <span>{sub}</span>}
              {i === last && receivedAt !== undefined && <span>{t('reçu le {when}', { when: fmtWhen(receivedAt) })}</span>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
