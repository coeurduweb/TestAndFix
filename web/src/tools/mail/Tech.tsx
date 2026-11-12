// The technical data of the report in tabs, instead of a long stack of folded sections (asked on
// 2026-11-11: less on screen, nothing lost). Every server section has a tab; the compliance matrix,
// the inventory of links and images, the path, the source and the limits of the measure too.
import { useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { fmtScore } from '../../lib/format';
import { msg, t } from '../../lib/i18n';
import { ComplianceMatrix, complianceCount, Limits, LinksAndImages, linksCount } from './Panels';
import { PathView } from './PathView';
import { SourceView } from './Preview';
import { displaySections, ReportSections } from './Sections';
import type { MailReport } from './types';

interface Tab {
  id: string;
  label: string;
  small?: ReactNode;
  body: () => ReactNode;
}

/** Server sections grouped by tab; a section this list does not know gets its own tab. */
const GROUPS: { id: string; label: string; sections: string[] }[] = [
  { id: 'auth', label: msg('Authentification'), sections: ['auth'] },
  { id: 'serveur', label: msg('Serveur, réputation'), sections: ['infrastructure', 'blacklists', 'reputation'] },
  { id: 'spamassassin', label: msg('SpamAssassin'), sections: ['spamassassin'] },
  { id: 'contenu', label: msg('Contenu'), sections: ['content', 'attachments', 'unsubscribe'] },
  { id: 'liens', label: msg('Liens et images'), sections: ['links'] },
  { id: 'entetes', label: msg('En-têtes'), sections: ['headers'] },
];

export function TechTabs({ r, messageId, receivedBy, rawUrl }: { r: MailReport; messageId: string; receivedBy?: string; /** where the raw message is read (a shared report reads it through its link) */ rawUrl?: string }) {
  const present = new Set(displaySections(r).map((s) => s.id));
  const sa = r.data.spamassassin;
  const lk = linksCount(r);
  const comp = complianceCount(r);
  const known = new Set(GROUPS.flatMap((g) => g.sections).concat('compliance'));
  const tabs: Tab[] = [];
  for (const g of GROUPS) {
    const ids = g.sections.filter((s) => present.has(s));
    const extra = g.id === 'liens' && lk;
    if (!ids.length && !extra) continue;
    tabs.push({
      id: g.id,
      label: t(g.label),
      small: g.id === 'spamassassin' ? (sa?.available && sa.score !== undefined ? fmtScore(sa.score) : undefined) : g.id === 'liens' && lk ? lk.total : undefined,
      body: () => (
        <>
          {g.id === 'liens' && <LinksAndImages r={r} />}
          <ReportSections r={r} only={ids} />
        </>
      ),
    });
    if (g.id === 'liens' && comp)
      tabs.push({ id: 'exigences', label: t('Exigences Gmail, Yahoo'), body: () => <ComplianceMatrix r={r} /> });
  }
  for (const s of displaySections(r).filter((x) => !known.has(x.id))) tabs.push({ id: s.id, label: s.title, body: () => <ReportSections r={r} only={[s.id]} /> });
  tabs.push({ id: 'parcours', label: t('Parcours'), body: () => <PathView hops={r.data.hops} date={r.data.message.date} receivedBy={receivedBy} /> });
  tabs.push({ id: 'source', label: t('Source'), body: () => <SourceView messageId={messageId} url={rawUrl} /> });
  tabs.push({ id: 'limites', label: t('Limites'), small: r.unavailable?.length || undefined, body: () => <Limits r={r} /> });

  const [on, setOn] = useState(tabs[0].id);
  const cur = tabs.find((t) => t.id === on) ?? tabs[0];
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = tabs.findIndex((t) => t.id === cur.id);
    const next = e.key === 'ArrowRight' ? (i + 1) % tabs.length : e.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
    if (next < 0) return;
    e.preventDefault();
    setOn(tabs[next].id);
    refs.current[tabs[next].id]?.focus();
  };
  return (
    <section className="surface mr-tech" aria-labelledby="mr-tech-t" id="s-tech">
      <h2 className="visually-hidden" id="mr-tech-t">
        {t('Données techniques')}
      </h2>
      <div className="mr-tabs" role="tablist" aria-label={t('Données techniques')}>
        {tabs.map((t) => (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[t.id] = el;
            }}
            type="button"
            role="tab"
            id={`mr-tab-${t.id}`}
            aria-selected={t.id === cur.id}
            aria-controls={`mr-panel-${t.id}`}
            tabIndex={t.id === cur.id ? 0 : -1}
            onClick={() => setOn(t.id)}
            onKeyDown={onKey}
          >
            {t.label}
            {t.small !== undefined && <small>{t.small}</small>}
          </button>
        ))}
      </div>
      <div className="mr-panel" role="tabpanel" id={`mr-panel-${cur.id}`} aria-labelledby={`mr-tab-${cur.id}`} tabIndex={0}>
        {cur.body()}
      </div>
    </section>
  );
}
