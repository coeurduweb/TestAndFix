// The two indicators of a mail report, side by side (asked by the user on 2026-11-11): the sender's
// technical setup (domain, DNS, authentication, server, reputation) and the composition of the
// message (headers, text, HTML, links, images, attachments). Each gives the points it lost, its
// counts by effect on delivery and six key checks read from the report. A click filters the list.
import { Check, Mail, ShieldCheck } from 'lucide-react';
import { fmtPenalty } from '../../lib/format';
import { msg, t, tn } from '../../lib/i18n';
import { axisStatus, keyChecks, type KeyCheck } from './logic';
import type { Indicators, MailReport } from './types';

export type Axis = 'sender' | 'message';

const AXES: { id: Axis; name: string; what: string; Icon: typeof Mail }[] = [
  { id: 'sender', name: msg('Expéditeur'), what: msg('Domaine, DNS, authentification, serveur, réputation'), Icon: ShieldCheck },
  { id: 'message', name: msg('Message'), what: msg('En-têtes, texte, HTML, liens, images, pièces jointes'), Icon: Mail },
];

function Checks({ checks }: { checks: KeyCheck[] }) {
  return (
    <span className="mr-checks">
      {checks.map((c) => (
        <span key={c.key} className="mr-check" data-lit={c.lit}>
          <span className="mr-check__k">
            {t(c.key)}
            {c.lit !== 'n' && <span className="visually-hidden">{c.lit === 'ok' ? t(', bon') : c.lit === 'warn' ? t(', risque') : t(', bloquant')}</span>}
          </span>
          <span className="mr-check__v" title={c.value}>
            {c.value}
          </span>
        </span>
      ))}
    </span>
  );
}

/**
 * Each card is an on/off filter of the list (user, 2026-11-14: « on ne sait pas bien quand on clique si
 * on active ou pas »). The former link changed its words with the state (« Voir les points de
 * l'expéditeur » then « Afficher tous les points », the opposite action): it is now a tick box with a
 * fixed label, the selected card has a blue ring and a tick, the other one steps back.
 */
export function IndicatorPair({
  r,
  ind,
  picked,
  onPick,
  listId,
  counts,
  theirs,
}: {
  r: MailReport;
  ind: Indicators;
  picked: Axis | null;
  onPick: (a: Axis | null) => void;
  listId: string;
  /** points of each axis in the list, so the card and the list agree */
  counts: Record<Axis, number>;
  /** points of each axis only the sending service can act on (not in the status line of the server) */
  theirs: Record<Axis, number>;
}) {
  const checks = keyChecks(r);
  return (
    <div className="mr-axes" role="group" aria-label={t('Deux indicateurs : expéditeur et message')}>
      {AXES.map(({ id, name, what, Icon }) => {
        const s = ind[id];
        const st = axisStatus(s, theirs[id]);
        const on = picked === id;
        return (
          <button
            key={id}
            type="button"
            className={`surface mr-axis mr-axis--${id}`}
            aria-pressed={on}
            aria-controls={listId}
            onClick={() => onPick(on ? null : id)}
          >
            <span className="mr-axis__head">
              <span className="mr-axis__ico" aria-hidden>
                <Icon />
              </span>
              <span className="mr-axis__id">
                <span className="mr-axis__name">{t(name)}</span>
                <span className="mr-axis__what">{t(what)}</span>
              </span>
              <span className="mr-axis__pts">
                {s.lost > 0 ? `−${fmtPenalty(s.lost)}` : '0'}
                <small>{t('pt')}</small>
                <span className="visually-hidden">{s.lost >= 2 ? t(' perdus') : t(' perdu')}</span>
              </span>
            </span>
            <span className="mr-axis__status" data-lit={st.lit}>
              <span className={`dot dot--${st.lit}`} aria-hidden />
              {st.text}
            </span>
            <Checks checks={checks[id]} />
            <span className="mr-axis__filter">
              <span className="mr-switch" aria-hidden>
                <Check />
              </span>
              <span className="mr-axis__filter-t">
                {counts[id] === 0
                  ? id === 'sender'
                    ? t('Aucun point de l’expéditeur')
                    : t('Aucun point du message')
                  : id === 'sender'
                  ? tn(counts[id], 'Seulement le point de l’expéditeur', 'Seulement les {n} points de l’expéditeur')
                  : tn(counts[id], 'Seulement le point du message', 'Seulement les {n} points du message')}
              </span>
              <span className="mr-axis__state">{on ? t('Filtre actif') : t('Filtre inactif')}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
