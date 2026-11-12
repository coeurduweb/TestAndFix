// Aggregation, per-source verdicts, findings and policy recommendation from stored reports.
import { t, tPlural, msg, locale } from '../../i18n.js';
import { explain, type Finding } from '../../knowledge/engine.js';
import type { PassedCheck } from '../types.js';
import type { ParsedReport, ReportRecord } from './parse.js';
import { isForwarderPtr, providerByDkimDomain, providerByKey, providerByPtr, type Provider } from './providers.js';

export type Verdict = 'aligned' | 'legit_unaligned' | 'forwarding' | 'spoofing';

export const VERDICT_LABELS: Record<Verdict, string> = {
  aligned: msg('Légitime alignée'),
  legit_unaligned: msg('Légitime non alignée (à corriger)'),
  forwarding: msg('Transfert (forwarding) probable'),
  spoofing: msg('Usurpation probable'),
};

export interface StoredReport {
  id: string;
  createdAt: number;
  domain: string;
  report: ParsedReport;
}

export interface SourceStat {
  ip: string;
  ptr: string | null;
  provider: { key: string; name: string } | null;
  messages: number;
  dmarcPass: number;
  spfAligned: number;
  dkimAligned: number;
  /** Raw auth_results (not the aligned ones): the mechanism passed for some domain. */
  spfPassAny: number;
  dkimPassAny: number;
  dispositions: Record<string, number>;
  dkimDomains: string[];
  spfDomains: string[];
  verdict: Verdict;
  verdictLabel: string;
}

export interface Aggregate {
  domain: string;
  /** ISO timestamps of the covered period. */
  from: string | null;
  to: string | null;
  reports: number;
  messages: number;
  dmarcPass: number;
  spfAligned: number;
  dkimAligned: number;
  /** Percentages 0..100, one decimal; null when there is no message. */
  rates: { dmarc: number | null; spf: number | null; dkim: number | null };
  byDay: { day: string; reports: number; messages: number; dmarcPass: number; spfAligned: number; dkimAligned: number; dmarcRate: number | null }[];
  bySource: SourceStat[];
  byProvider: { key: string; name: string; sources: number; messages: number; dmarcPass: number; dmarcRate: number | null }[];
  byOrg: { org: string; reports: number; messages: number; dmarcPass: number }[];
  dispositions: { none: number; quarantine: number; reject: number };
  byVerdict: Record<Verdict, number>;
  /** Policy published in the most recent report. */
  policy: { p: string; sp: string; np: string; pct: number | null; adkim: string; aspf: string; testing: string } | null;
}

export interface Recommendation {
  current: string;
  /** What to publish next. */
  target: 'none' | 'quarantine' | 'reject';
  /** true when `target` differs from the published policy. */
  change: boolean;
  /** Short statement in French. */
  headline: string;
  /** Measured figures backing the decision. */
  reasons: string[];
  figures: {
    messages: number;
    days: number;
    legitMessages: number;
    legitAlignedRate: number | null;
    legitUnalignedMessages: number;
    spoofingMessages: number;
    forwardingMessages: number;
  };
}

const pct1 = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 10 : null);
const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const fmtN = (n: number) => n.toLocaleString(locale()).replace(/ | /g, ' ');
const fmtPct = (v: number | null) => (v === null ? t('n/d') : String(v).replace('.', ',') + ' %');

interface Acc {
  ip: string;
  ptr: string | null;
  messages: number;
  dmarcPass: number;
  spfAligned: number;
  dkimAligned: number;
  spfPassAny: number;
  dkimPassAny: number;
  dispositions: Record<string, number>;
  dkimDomains: Map<string, number>;
  spfDomains: Map<string, number>;
  dkimProvider: Map<string, number>;
}

/** Pure verdict for one source from its totals. */
export function verdictFor(s: {
  messages: number; dmarcPass: number; spfAligned: number; dkimAligned: number; spfPassAny: number; dkimPassAny: number;
  ptr: string | null; provider: Provider | undefined;
}): Verdict {
  if (s.messages <= 0) return 'aligned';
  const half = s.messages / 2;
  if (isForwarderPtr(s.ptr)) return 'forwarding';
  if (s.dmarcPass / s.messages >= 0.95) {
    // DKIM carries the message but SPF fails for most of it: typical of a relay, unless we know the sender.
    if (!s.provider && s.spfAligned < half && s.spfPassAny < half && s.dkimAligned >= half && s.dkimPassAny >= half) return 'forwarding';
    return 'aligned';
  }
  if (s.provider) return 'legit_unaligned';
  if (s.spfAligned < half && s.dkimPassAny >= half) return 'forwarding';
  return 'spoofing';
}

export function aggregate(rows: StoredReport[], domain: string): Aggregate {
  const sel = rows.filter((r) => r.domain === domain).sort((a, b) => a.report.dateBegin - b.report.dateBegin);
  const accs = new Map<string, Acc>();
  const days = new Map<string, Aggregate['byDay'][number]>();
  const orgs = new Map<string, { org: string; reports: number; messages: number; dmarcPass: number }>();
  const disp: Record<string, number> = { none: 0, quarantine: 0, reject: 0 };
  let messages = 0, dmarcPass = 0, spfAligned = 0, dkimAligned = 0;
  let min = Infinity, max = 0;

  for (const { report } of sel) {
    if (report.dateBegin) min = Math.min(min, report.dateBegin);
    max = Math.max(max, report.dateEnd || report.dateBegin);
    const day = dayOf(report.dateBegin || report.dateEnd || Date.now());
    const dRow = days.get(day) ?? { day, reports: 0, messages: 0, dmarcPass: 0, spfAligned: 0, dkimAligned: 0, dmarcRate: null };
    dRow.reports++;
    days.set(day, dRow);
    const oRow = orgs.get(report.orgName) ?? { org: report.orgName || 'inconnu', reports: 0, messages: 0, dmarcPass: 0 };
    oRow.reports++;
    orgs.set(report.orgName, oRow);

    for (const rec of report.records) {
      const n = rec.count;
      const pass = rec.spfAligned || rec.dkimAligned ? n : 0;
      messages += n; dmarcPass += pass;
      if (rec.spfAligned) spfAligned += n;
      if (rec.dkimAligned) dkimAligned += n;
      disp[rec.disposition] = (disp[rec.disposition] ?? 0) + n;
      dRow.messages += n; dRow.dmarcPass += pass;
      if (rec.spfAligned) dRow.spfAligned += n;
      if (rec.dkimAligned) dRow.dkimAligned += n;
      oRow.messages += n; oRow.dmarcPass += pass;

      const a: Acc = accs.get(rec.ip) ?? {
        ip: rec.ip, ptr: null, messages: 0, dmarcPass: 0, spfAligned: 0, dkimAligned: 0, spfPassAny: 0, dkimPassAny: 0,
        dispositions: {}, dkimDomains: new Map(), spfDomains: new Map(), dkimProvider: new Map(),
      };
      accs.set(rec.ip, a);
      if (rec.ptr) a.ptr = rec.ptr;
      a.messages += n; a.dmarcPass += pass;
      if (rec.spfAligned) a.spfAligned += n;
      if (rec.dkimAligned) a.dkimAligned += n;
      if (rec.spf.some((s) => s.result === 'pass')) a.spfPassAny += n;
      if (rec.dkim.some((s) => s.result === 'pass')) a.dkimPassAny += n;
      a.dispositions[rec.disposition] = (a.dispositions[rec.disposition] ?? 0) + n;
      for (const k of rec.dkim) {
        if (!k.domain) continue;
        a.dkimDomains.set(k.domain, (a.dkimDomains.get(k.domain) ?? 0) + n);
        const p = providerByDkimDomain(k.domain);
        if (p) a.dkimProvider.set(p.key, (a.dkimProvider.get(p.key) ?? 0) + n);
      }
      for (const s of rec.spf) if (s.domain) a.spfDomains.set(s.domain, (a.spfDomains.get(s.domain) ?? 0) + n);
    }
  }

  const bySource: SourceStat[] = [...accs.values()].map((a) => {
    const byPtr = providerByPtr(a.ptr);
    const topDkim = [...a.dkimProvider.entries()].sort((x, y) => y[1] - x[1])[0]?.[0];
    const provider = byPtr ?? (topDkim ? providerByKey(topDkim) : undefined);
    const verdict = verdictFor({ ...a, provider });
    return {
      ip: a.ip, ptr: a.ptr,
      provider: provider ? { key: provider.key, name: provider.name } : null,
      messages: a.messages, dmarcPass: a.dmarcPass, spfAligned: a.spfAligned, dkimAligned: a.dkimAligned,
      spfPassAny: a.spfPassAny, dkimPassAny: a.dkimPassAny,
      dispositions: a.dispositions,
      dkimDomains: [...a.dkimDomains.keys()].slice(0, 5),
      spfDomains: [...a.spfDomains.keys()].slice(0, 5),
      verdict, verdictLabel: t(VERDICT_LABELS[verdict]),
    };
  }).sort((x, y) => y.messages - x.messages);

  const provs = new Map<string, Aggregate['byProvider'][number]>();
  for (const s of bySource) {
    const key = s.provider?.key ?? 'unknown';
    const p = provs.get(key) ?? { key, name: s.provider?.name ?? t('Fournisseur inconnu'), sources: 0, messages: 0, dmarcPass: 0, dmarcRate: null };
    p.sources++; p.messages += s.messages; p.dmarcPass += s.dmarcPass;
    provs.set(key, p);
  }
  const byVerdict: Record<Verdict, number> = { aligned: 0, legit_unaligned: 0, forwarding: 0, spoofing: 0 };
  for (const s of bySource) byVerdict[s.verdict] += s.messages;

  const latest = sel[sel.length - 1]?.report.policy;
  return {
    domain,
    from: Number.isFinite(min) ? new Date(min).toISOString() : null,
    to: max ? new Date(max).toISOString() : null,
    reports: sel.length, messages, dmarcPass, spfAligned, dkimAligned,
    rates: { dmarc: pct1(dmarcPass, messages), spf: pct1(spfAligned, messages), dkim: pct1(dkimAligned, messages) },
    byDay: [...days.values()].sort((x, y) => x.day.localeCompare(y.day)).map((d) => ({ ...d, dmarcRate: pct1(d.dmarcPass, d.messages) })),
    bySource,
    byProvider: [...provs.values()].map((p) => ({ ...p, dmarcRate: pct1(p.dmarcPass, p.messages) })).sort((x, y) => y.messages - x.messages),
    byOrg: [...orgs.values()].sort((x, y) => y.messages - x.messages),
    dispositions: { none: disp.none ?? 0, quarantine: disp.quarantine ?? 0, reject: disp.reject ?? 0 },
    byVerdict,
    policy: latest ? { p: latest.p, sp: latest.sp, np: latest.np, pct: latest.pct, adkim: latest.adkim, aspf: latest.aspf, testing: latest.testing } : null,
  };
}

export function recommend(agg: Aggregate): Recommendation {
  const current = agg.policy?.p ?? 'none';
  const v = agg.byVerdict;
  const legit = v.aligned + v.legit_unaligned;
  const days = agg.from && agg.to ? Math.max(1, Math.round((Date.parse(agg.to) - Date.parse(agg.from)) / 86_400_000)) : 0;
  const rate = pct1(v.aligned, legit);
  const figures = {
    messages: agg.messages, days, legitMessages: legit, legitAlignedRate: rate,
    legitUnalignedMessages: v.legit_unaligned, spoofingMessages: v.spoofing, forwardingMessages: v.forwarding,
  };
  const base = (target: Recommendation['target'], headline: string, reasons: string[]): Recommendation => ({
    current, target, change: target !== current, headline, reasons, figures,
  });
  const measured = t('{messages} messages sur {days}', { messages: fmtN(agg.messages), days: tPlural(days, '{n} jour', '{n} jours') });
  if (current === 'reject') {
    return base('reject', t('Votre politique reject est déjà la plus protectrice : gardez-la.'), [
      tPlural(v.spoofing, "Mesuré : {measured}, {n} message d'usurpation probable bloqué ou à bloquer.", "Mesuré : {measured}, {n} messages d'usurpation probable bloqués ou à bloquer.", { measured, n: fmtN(v.spoofing) }),
      ...(v.legit_unaligned ? [tPlural(v.legit_unaligned, 'Attention : {n} message légitime non aligné est rejeté, corrigez-les.', 'Attention : {n} messages légitimes non alignés sont rejetés, corrigez-les.', { n: fmtN(v.legit_unaligned) })] : []),
    ]);
  }
  if (agg.messages < 100 || days < 7) {
    return base(current === 'quarantine' ? 'quarantine' : 'none', t("Rester pour l'instant sur votre politique actuelle : les rapports déposés sont trop peu nombreux pour décider."), [
      t('Mesuré : {measured}. Il faut au moins 100 messages et 7 jours de rapports pour juger.', { measured }),
      t('Déposez les rapports des prochaines semaines pour affiner cette recommandation.'),
    ]);
  }
  if (v.legit_unaligned > 0) {
    return base(current === 'quarantine' ? 'quarantine' : 'none', t('Rester en {policy} le temps de corriger les envois légitimes non alignés.', { policy: current }), [
      tPlural(v.legit_unaligned, 'Mesuré : {measured}, dont {n} message légitime non aligné (alignement des envois légitimes : {rate}).', 'Mesuré : {measured}, dont {n} messages légitimes non alignés (alignement des envois légitimes : {rate}).', { measured, n: fmtN(v.legit_unaligned), rate: fmtPct(rate) }),
      t('Passer à {policy} maintenant ferait mettre en spam ou rejeter ces messages.', { policy: current === 'none' ? 'quarantine' : 'reject' }),
      t('Corrigez les sources signalées (SPF ou DKIM), puis déposez de nouveaux rapports.'),
    ]);
  }
  if (current === 'none') {
    if (days < 14) {
      return base('none', t('Rester en none encore quelques jours : la période observée est courte.'), [
        t("Mesuré : {measured}, aucun envoi légitime non aligné. Deux semaines d'observation sont recommandées avant quarantine.", { measured }),
      ]);
    }
    return base('quarantine', t('Vous pouvez passer à quarantine.'), [
      t('Mesuré : {measured}, alignement des envois légitimes {rate}, aucun envoi légitime non aligné.', { measured, rate: fmtPct(rate) }),
      tPlural(v.spoofing, "{n} message d'usurpation probable serait mis en quarantaine.", "{n} messages d'usurpation probable seraient mis en quarantaine.", { n: fmtN(v.spoofing) }),
      ...(v.forwarding ? [tPlural(v.forwarding, "{n} message de transfert probable peut être affecté : c'est un effet connu du transfert.", "{n} messages de transfert probable peuvent être affectés : c'est un effet connu du transfert.", { n: fmtN(v.forwarding) })] : []),
      t('Pour une transition prudente, publiez d’abord la nouvelle politique avec t=y (mode test de la RFC 9989), suivez les rapports quelques jours, puis retirez t=y.'),
    ]);
  }
  // quarantine
  if (days < 28) {
    return base('quarantine', t("Rester en quarantine jusqu'à quatre semaines d'observation."), [
      t('Mesuré : {measured}, aucun envoi légitime non aligné. Quatre semaines sans anomalie sont recommandées avant reject.', { measured }),
    ]);
  }
  return base('reject', t('Vous pouvez passer à reject.'), [
    t('Mesuré : {measured}, alignement des envois légitimes {rate}, aucun envoi légitime non aligné.', { measured, rate: fmtPct(rate) }),
    tPlural(v.spoofing, "{n} message d'usurpation probable serait rejeté.", "{n} messages d'usurpation probable seraient rejetés.", { n: fmtN(v.spoofing) }),
    ...(v.forwarding ? [tPlural(v.forwarding, '{n} message de transfert probable sera refusé par certains destinataires.', '{n} messages de transfert probable seront refusés par certains destinataires.', { n: fmtN(v.forwarding) })] : []),
  ]);
}

const MAX_PER_VERDICT = 10;

export function buildFindings(agg: Aggregate): { findings: Finding[]; passed: PassedCheck[] } {
  const findings: Finding[] = [];
  const passed: PassedCheck[] = [];
  const domain = agg.domain;
  const policy = agg.policy?.p ?? 'none';
  const ev = (s: SourceStat) =>
    tPlural(s.messages, 'IP {ip}{ptr}, {n} message, SPF aligné {spf}, DKIM aligné {dkim}', 'IP {ip}{ptr}, {n} messages, SPF aligné {spf}, DKIM aligné {dkim}', { ip: s.ip, ptr: s.ptr ? `, PTR ${s.ptr}` : '', n: fmtN(s.messages), spf: fmtPct(pct1(s.spfAligned, s.messages)), dkim: fmtPct(pct1(s.dkimAligned, s.messages)) });
  const count: Record<string, number> = {};

  for (const s of agg.bySource) {
    if (s.verdict === 'aligned') continue;
    count[s.verdict] = (count[s.verdict] ?? 0) + 1;
    if (count[s.verdict] > MAX_PER_VERDICT) continue;
    const prov = s.provider ? providerByKey(s.provider.key) : undefined;
    const name = s.provider?.name ?? t("l'outil qui envoie depuis cette adresse");
    const vars = { domain, ip: s.ip, ptr: s.ptr ?? t('aucun'), provider: name, value: s.messages };
    if (s.verdict === 'legit_unaligned') {
      const spfMissing = s.spfAligned === 0;
      const dkimMissing = s.dkimAligned === 0;
      const fix: string[] = [];
      let suggested: string | undefined;
      if (dkimMissing) fix.push(prov?.dkimHint ? t(prov.dkimHint) : t("Activez la signature DKIM de {domain} chez {name}, avec {domain} comme domaine de signature (d=), puis publiez l'enregistrement TXT ou CNAME fourni.", { domain, name }));
      if (spfMissing) {
        if (prov?.spfInclude) {
          suggested = `include:${prov.spfInclude}`;
          fix.push(t("Ajoutez include:{include} à l'enregistrement SPF de {domain} (sans créer un second enregistrement SPF), et faites utiliser à {name} un domaine d'enveloppe (MAIL FROM) sur {domain}, car le SPF n'est aligné que dans ce cas.", { include: prov.spfInclude, domain, name }));
        } else {
          fix.push(prov?.spfHint ? t(prov.spfHint) : t("Autorisez l'adresse {ip} dans le SPF de {domain} et faites utiliser à {name} un domaine d'enveloppe sur {domain}.", { ip: s.ip, domain, name }));
        }
      }
      if (!fix.length) fix.push(t("Vérifiez que le domaine de signature DKIM et le domaine d'enveloppe de {name} sont {domain} ou l'un de ses sous-domaines.", { name, domain }));
      findings.push(explain({
        id: 'dmarc-report.legit_unaligned', vars, provider: s.provider?.key, suggested, evidence: ev(s),
        fallback: {
          family: 'dmarc', severity: 'high', penalty: 1,
          title: t("Un envoi légitime de {name} n'est pas aligné DMARC ({ip})", { name, ip: s.ip }),
          why: tPlural(s.messages, "{n} message envoyé au nom de {domain} depuis {ip} ({name}) échouent à l'alignement DMARC. Avec une politique quarantine ou reject, ils iraient en spam ou seraient refusés.", "{n} messages envoyés au nom de {domain} depuis {ip} ({name}) échouent à l'alignement DMARC. Avec une politique quarantine ou reject, ils iraient en spam ou seraient refusés.", { n: fmtN(s.messages), domain, ip: s.ip, name }),
          fix,
        },
      }));
    } else if (s.verdict === 'forwarding') {
      findings.push(explain({
        id: 'dmarc-report.forwarding', vars, evidence: ev(s),
        fallback: {
          family: 'dmarc', severity: 'info', penalty: 0,
          title: t('Transfert probable depuis {source}', { source: s.ptr ?? s.ip }),
          why: tPlural(s.messages, '{n} message arrive par une adresse qui relaie du courrier : le SPF échoue à cause du transfert, ce qui est normal, tandis que le DKIM reste valide.', '{n} messages arrivent par une adresse qui relaie du courrier : le SPF échoue à cause du transfert, ce qui est normal, tandis que le DKIM reste valide.', { n: fmtN(s.messages) }),
          fix: [
            t('Ne cherchez pas à autoriser {ip} dans votre SPF : ce serait ouvrir votre domaine à un relais que vous ne maîtrisez pas.', { ip: s.ip }),
            t("Vérifiez que tous vos envois sont signés en DKIM avec {domain} : c'est la seule protection qui survit au transfert.", { domain }),
          ],
        },
      }));
    } else {
      findings.push(explain({
        id: 'dmarc-report.spoofing', vars, evidence: ev(s),
        fallback: {
          family: 'dmarc', severity: policy === 'none' ? 'medium' : 'low', penalty: policy === 'none' ? 0.5 : 0,
          title: t('Usurpation probable de {domain} depuis {ip}', { domain, ip: s.ip }),
          why: tPlural(s.messages, "{n} message prétend venir de {domain} depuis {ip}{ptr}, une source que vous n'avez pas autorisée : ni le SPF ni le DKIM ne sont alignés.", "{n} messages prétendent venir de {domain} depuis {ip}{ptr}, une source que vous n'avez pas autorisée : ni le SPF ni le DKIM ne sont alignés.", { n: fmtN(s.messages), domain, ip: s.ip, ptr: s.ptr ? ` (${s.ptr})` : '' }),
          fix: policy === 'none'
            ? [
              t("Si vous ne reconnaissez pas {ip}, aucun envoi légitime n'en dépend : passez à p=quarantine puis p=reject quand les envois légitimes sont alignés, pour que ces messages soient bloqués.", { ip: s.ip }),
              t("Si vous reconnaissez cet envoi, identifiez l'outil concerné et configurez son SPF et son DKIM pour {domain}.", { domain }),
            ]
            : [
              t("La politique {policy} traite ces messages. Si vous reconnaissez cet envoi, identifiez l'outil concerné et configurez son SPF et son DKIM pour {domain}.", { policy, domain }),
            ],
        },
      }));
    }
  }
  const hidden = Object.values(count).reduce((n, c) => n + Math.max(0, c - MAX_PER_VERDICT), 0);
  if (hidden) {
    findings.push(explain({
      id: 'dmarc-report.more_sources', vars: { value: hidden },
      fallback: { family: 'dmarc', severity: 'info', penalty: 0, title: tPlural(hidden, 'Une autre source non alignée non détaillée', '{n} autres sources non alignées non détaillées'), why: t('Seules les sources les plus volumineuses de chaque catégorie sont détaillées. Consultez le tableau des sources pour la liste complète.'), fix: [] },
    }));
  }
  if (agg.messages > 0 && agg.messages < 100) {
    findings.push(explain({
      id: 'dmarc-report.low_volume', vars: { value: agg.messages },
      fallback: { family: 'dmarc', severity: 'info', penalty: 0, title: t('Volume de rapports encore faible'), why: tPlural(agg.messages, 'Seulement {n} message couvert : les taux mesurés ne sont pas encore représentatifs.', 'Seulement {n} messages couverts : les taux mesurés ne sont pas encore représentatifs.', { n: fmtN(agg.messages) }), fix: [t('Déposez les rapports des prochaines semaines.')] },
    }));
  }
  const aligned = agg.bySource.filter((s) => s.verdict === 'aligned');
  if (aligned.length) {
    passed.push({
      id: 'dmarc-report.aligned_sources', family: 'dmarc', title: tPlural(aligned.length, 'Une source légitime alignée DMARC', '{n} sources légitimes alignées DMARC'),
      detail: tPlural(agg.byVerdict.aligned, '{n} message, alignement global {rate}.', '{n} messages, alignement global {rate}.', { n: fmtN(agg.byVerdict.aligned), rate: fmtPct(agg.rates.dmarc) }),
    });
  }
  return { findings, passed };
}
