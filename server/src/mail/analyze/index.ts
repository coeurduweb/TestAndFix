// Mail test analysis: one received message in, one CheckResult out (score /10, findings with
// their personalised fix, passed checks, unavailable sources, and the detailed data).
import { simpleParser, type AddressObject } from 'mailparser';
import { scoreOf, sortFindings } from '../../knowledge/engine.js';
import { detectProviders, type DetectedProvider } from '../../lib/provider.js';
import type { CheckResult } from '../../tools/types.js';
import { bodyParts, firstHeader, headerValues, parseRaw } from '../mime.js';
import { findOrigin, parseHops } from '../received.js';
import { noMailFrom, runAuth } from './auth.js';
import { Collector, SECTION_TITLES, type SectionId } from './collect.js';
import { runContent } from './content.js';
import { domainOf, firstAddress, runHeaders } from './headers.js';
import { runInfra } from './infra.js';
import { runLinks } from './links.js';
import { runBlacklists, runSpamassassin } from './reputation.js';
import { BULK_ESP } from './thresholds.js';
import { isPublicIp } from '../../lib/net.js';
import { runCompliance, runUnsubscribe } from './unsubscribe.js';
import { classifyFindings, indicatorsOf, type Indicators } from './impact.js';
import type { AnalyzeDeps, AnalyzeInput, MessageFacts, StepContext } from './types.js';
import { msg, t } from '../../i18n.js';

export type { AnalyzeDeps, AnalyzeInput } from './types.js';

/** French msgids of the step labels: translate with stepLabel() / stepLabels() at use time. */
export const STEPS: Record<string, string> = {
  parse: msg('Lecture du message'),
  auth: msg('Authentification (SPF, DKIM, DMARC, ARC, BIMI)'),
  infrastructure: msg("Serveur d'envoi (reverse DNS, HELO, TLS)"),
  spamassassin: msg('SpamAssassin'),
  links: msg('Liens et images'),
  blacklists: msg('Listes noires'),
  content: msg('Contenu et en-têtes'),
  compliance: msg('Exigences Gmail, Yahoo, Microsoft'),
};

/** Label of a step in the current language. */
export const stepLabel = (id: string): string => (STEPS[id] ? t(STEPS[id]) : id);
/** All the step labels in the current language (sent to the interface). */
export const stepLabels = (): Record<string, string> => Object.fromEntries(Object.keys(STEPS).map((id) => [id, stepLabel(id)]));

export interface SectionSummary {
  id: SectionId;
  title: string;
  /** points lost in this section */
  lost: number;
  status: 'ok' | 'warning' | 'error' | 'info';
  findings: string[];
  passed: string[];
}

export interface MailReportData {
  via: AnalyzeInput['via'];
  receivedAt: string;
  envelope: {
    clientIp?: string;
    ipSource: 'smtp' | 'xforward' | 'received' | 'none';
    ipReason?: string;
    helo?: string;
    mailFrom?: string;
    rcptTo: string[];
    tls?: MessageFacts['tls'];
  };
  message: {
    from?: string;
    fromName?: string;
    fromDomain?: string;
    subject?: string;
    date?: string;
    messageId?: string;
    to?: string;
    replyTo?: string;
    size: number;
  };
  provider?: DetectedProvider;
  providerCandidates: DetectedProvider[];
  isBulk: boolean;
  bulkReasons: string[];
  /** checks made less reliable by the way the message reached us */
  limits: { check: string; reason: string }[];
  hostAddedHeaders?: string[];
  hops: ReturnType<typeof parseHops>;
  sections: SectionSummary[];
  /** points by section, then each finding with the points it costs (US-025) */
  scoring: { total: number; lost: number; lines: { id: string; title: string; section: SectionId; penalty: number }[] };
  /** delivery verdict and the two indicators, sender and message (2026-11-11) */
  indicators: Indicators;
  [k: string]: unknown;
}

export type MailReport = CheckResult<MailReportData>;

function addressOf(a: AddressObject | AddressObject[] | undefined): { address?: string; name?: string; count: number } {
  const list = (Array.isArray(a) ? a : a ? [a] : []).flatMap((x) => x.value ?? []);
  const flat = list.flatMap((v) => (v.group ? v.group : [v]));
  return { address: flat[0]?.address?.toLowerCase(), name: flat[0]?.name, count: flat.length };
}

async function buildFacts(input: AnalyzeInput, now: Date): Promise<MessageFacts> {
  const parsed = parseRaw(input.raw);
  const H = parsed.headers;
  const mp = await simpleParser(input.raw, { skipHtmlToText: true, skipTextToHtml: true, skipImageLinks: true, skipTextLinks: true });
  const from = addressOf(mp.from);
  const { text, html, attachments, inline } = bodyParts(parsed.root);
  const hops = parseHops(headerValues(H, 'received'));

  // SMTP: what our server saw. Otherwise: the first external relay of the Received chain.
  let ip: string | undefined;
  let helo: string | undefined;
  let ipSource: MessageFacts['ipSource'] = 'none';
  let tls: MessageFacts['tls'];
  let ipReason: string | undefined;
  if (input.via === 'smtp' && input.clientIp) {
    ip = input.clientIp;
    helo = input.helo;
    // behind a trusted relay (XFORWARD) the client and its TLS are those of the original connection
    ipSource = input.tls?.ipSource === 'xforward' ? 'xforward' : 'smtp';
    tls = {
      used: input.tls ? (input.tls.used ?? true) : false,
      protocol: input.tls?.protocol,
      cipher: input.tls?.cipher,
      source: input.tls?.source === 'relay' ? 'relay' : 'smtp',
    };
  } else {
    const origin = findOrigin(hops, input.receiverDomains);
    if (origin) {
      ip = origin.ip;
      helo = origin.helo;
      ipSource = 'received';
      ipReason = origin.reason;
      const proto = /\b(TLSv?1(?:\.[0-3])?|SSLv3)\b/i.exec(origin.hop.tlsDetail ?? '')?.[1];
      tls = {
        used: origin.hop.tls,
        protocol: proto ? proto.replace(/^TLS1/i, 'TLSv1') : undefined,
        cipher: origin.hop.tlsDetail?.split(' ').find((x) => /_|-/.test(x)),
        source: 'received',
      };
    }
  }
  // MAIL FROM: what the client sent (smtp), else the Return-Path written at final delivery
  const returnPath = firstAddress(firstHeader(H, 'return-path'));
  const envelopeFrom = (input.mailFrom ?? returnPath ?? '').toLowerCase() || undefined;
  const envelopeKnown = input.via === 'smtp' || returnPath !== undefined;
  const fromDomain = domainOf(from.address);

  const dkimDomains = headerValues(H, 'dkim-signature')
    .map((v) => /(?:^|;)\s*d=([^;\s]+)/i.exec(v)?.[1]?.toLowerCase())
    .filter((d): d is string => !!d);
  const hmap = new Map<string, string[]>();
  for (const h of H) hmap.set(h.key, [...(hmap.get(h.key) ?? []), h.value]);
  const providers = detectProviders({
    dkimDomains,
    headers: hmap,
    helo,
    ptr: hops.map((h) => h.fromPtr).filter((x): x is string => !!x),
    messageId: firstHeader(H, 'message-id'),
    returnPath: envelopeFrom,
  });

  const bulkReasons: string[] = [];
  if (firstHeader(H, 'list-unsubscribe')) bulkReasons.push(t('en-tête List-Unsubscribe'));
  if (firstHeader(H, 'list-id')) bulkReasons.push(t('en-tête List-Id'));
  const prec = firstHeader(H, 'precedence');
  if (prec && /^(bulk|list)$/i.test(prec.trim())) bulkReasons.push(`Precedence: ${prec.trim()}`);
  if (firstHeader(H, 'feedback-id')) bulkReasons.push(t('en-tête Feedback-ID'));
  const esp = providers.find((p) => BULK_ESP.has(p.key));
  if (esp) bulkReasons.push(t('envoyé par {name}', { name: esp.name }));

  const facts: MessageFacts = {
    input,
    parsed,
    headers: H,
    text,
    html,
    attachments,
    inline,
    fromAddress: from.address,
    fromName: from.name,
    fromDomain,
    fromCount: from.count,
    envelopeFrom,
    envelopeDomain: domainOf(envelopeFrom) ?? (helo && !envelopeFrom && envelopeKnown ? helo.toLowerCase() : undefined),
    envelopeKnown,
    subject: mp.subject,
    hops,
    ip,
    ipSource,
    helo,
    tls,
    isBulk: bulkReasons.length > 0,
    bulkReasons,
    provider: providers[0],
    providers,
    ipReason,
    headersOnly: parsed.body.toString('latin1').trim().length === 0,
    receivedAt: input.receivedAt ?? now,
  };
  return facts;
}

/** Headers added above the origin hop: written by the mailbox host, not by the sender. */
function hostAdded(facts: MessageFacts): string[] {
  const origin = facts.hops.find((h) => h.ip === facts.ip);
  if (!origin) return [];
  const idx = facts.headers.findIndex((h) => h.key === 'received' && h.value === origin.raw);
  return idx <= 0 ? [] : [...new Set(facts.headers.slice(0, idx).map((h) => h.name))];
}

export async function analyzeMessage(input: AnalyzeInput, deps: AnalyzeDeps): Promise<MailReport> {
  const started = performance.now();
  const now = deps.now?.() ?? new Date();
  const progress = deps.progress ?? (() => {});
  const step = async <T>(id: string, fn: () => Promise<T> | T): Promise<T | undefined> => {
    progress(id, stepLabel(id), 'start');
    try {
      const out = await fn();
      progress(id, stepLabel(id), 'done');
      return out;
    } catch (e) {
      progress(id, stepLabel(id), 'error', (e as Error).message);
      c.missing(stepLabel(id), t('Ce contrôle a échoué : les autres résultats restent valables'), (e as Error).message);
      return undefined;
    }
  };

  const c = new Collector();
  progress('parse', stepLabel('parse'), 'start');
  const facts = await buildFacts(input, now);
  progress('parse', stepLabel('parse'), 'done');
  const sc: StepContext = { facts, deps, c, data: {} };
  c.vars = {
    domain: facts.fromDomain,
    envelope_domain: facts.envelopeDomain ?? (facts.envelopeKnown ? undefined : noMailFrom()),
    // a private or local IP is never written into a fix (« autorisez l'IP 127.0.0.1 »)
    ip: facts.ip && isPublicIp(facts.ip) ? facts.ip : undefined,
    helo: facts.helo,
    provider: facts.provider?.name,
  };
  c.provider = facts.provider?.key;

  // reliability of the checks depending on how the message reached us
  const hostHeaders = input.via === 'imap' ? hostAdded(facts) : [];
  if (input.via !== 'smtp') {
    const imap = input.via === 'imap';
    if (facts.ip) {
      const ip = facts.ip;
      const origin = facts.ipReason ?? t('premier relais externe');
      c.limit('spf', imap
        ? t("Message reçu par la boîte attrape-tout : l'IP {ip} est déduite des Received ({origin}), pas observée.", { ip, origin })
        : t("Message importé : l'IP {ip} est déduite des Received ({origin}), pas observée.", { ip, origin }));
      c.limit('infrastructure', imap
        ? t("Message reçu par la boîte attrape-tout : reverse DNS, HELO et TLS sont ceux du premier relais externe d'après les Received.")
        : t("Message importé : reverse DNS, HELO et TLS sont ceux du premier relais externe d'après les Received."));
      c.limit('blacklists', imap
        ? t("Message reçu par la boîte attrape-tout : listes noires interrogées pour l'IP déduite des Received.")
        : t("Message importé : listes noires interrogées pour l'IP déduite des Received."));
    }
    if (imap) {
      c.limit('dkim', t("L'hébergeur de la boîte a pu modifier le message (objet marqué, pied de page) : une signature DKIM cassée peut venir de lui."));
      c.limit('spamassassin', hostHeaders.length
        ? t("SpamAssassin lit aussi les en-têtes ajoutés par l'hébergeur ({headers}).", { headers: hostHeaders.slice(0, 8).join(', ') })
        : t("SpamAssassin lit aussi les en-têtes ajoutés par l'hébergeur."));
      c.limit('content', t("L'hébergeur a pu réécrire les liens ou ajouter du contenu."));
    } else {
      c.limit('dkim', t('Un message importé doit être le source complet et inchangé : une copie retouchée casse la signature DKIM.'));
    }
  }

  if (facts.headersOnly) {
    c.missing(t('Contenu'), t('Seuls les en-têtes ont été fournis : contenu, liens, images et pièces jointes ne sont pas contrôlés'));
    c.limit('dkim', t('Sans le corps du message, la signature DKIM ne peut pas être vérifiée entièrement.'));
  }
  await step('content', () => {
    runHeaders(sc);
    if (!facts.headersOnly) runContent(sc);
  });

  const [auth, infra] = await Promise.all([
    step('auth', () => runAuth(sc)),
    step('infrastructure', () => runInfra(sc)),
    step('spamassassin', () => runSpamassassin(sc)),
    (async () => {
      const links = facts.headersOnly ? undefined : await step('links', () => runLinks(sc));
      await step('blacklists', () => runBlacklists(sc, links?.linkDomains ?? []));
    })(),
  ]);

  // refine the provider with the SPF record and the real reverse DNS
  const refined = detectProviders({
    dkimDomains: auth?.sigs.map((s) => s.domain),
    spfRecord: auth?.spfRecord,
    headers: new Map(facts.headers.reduce((m, h) => m.set(h.key, [...(m.get(h.key) ?? []), h.value]), new Map<string, string[]>())),
    ptr: [...(infra?.ptrs ?? []), ...facts.hops.map((h) => h.fromPtr).filter((x): x is string => !!x)],
    helo: facts.helo,
    messageId: firstHeader(facts.headers, 'message-id'),
    returnPath: facts.envelopeFrom,
  });
  if (refined[0] && refined[0].key !== facts.provider?.key) {
    facts.provider = refined[0];
    c.setProvider(refined[0].key, refined[0].name);
  }

  await step('compliance', () => {
    const u = runUnsubscribe(sc, auth?.sigs ?? []);
    if (auth)
      runCompliance(sc, {
        spfResult: auth.spfResult,
        sigs: auth.sigs,
        alignment: auth.alignment,
        dmarcRecord: auth.dmarcRecord,
        dmarcPolicy: auth.dmarcPolicy,
        fcrdns: infra?.fcrdns,
        oneClick: u.oneClick,
        unsubCovered: u.covered,
        hasHttpsUnsub: u.hasHttpsUnsub,
      });
  });

  // The image ratio is already counted by SpamAssassin when one of its HTML_IMAGE rules fired:
  // our own check keeps its explanation but not a second penalty.
  const imageRule = (sc.data.spamassassin as { rules?: { name: string; score: number }[] } | undefined)?.rules?.find((r) => /^HTML_IMAGE_(ONLY|RATIO)_/.test(r.name) && r.score > 0);
  const heavy = c.findings.find((f) => f.id === 'images.image_heavy');
  if (imageRule && heavy) {
    heavy.penalty = 0;
    heavy.evidence = [heavy.evidence, t('Déjà compté par SpamAssassin ({rule}) : pas de seconde pénalité.', { rule: imageRule.name })].filter(Boolean).join('\n');
  }
  const sa = sc.data.spamassassin as { available?: boolean; score?: number; threshold?: number; isSpam?: boolean } | undefined;
  if (sa?.available && sa.isSpam)
    c.add('spamassassin.over_threshold', {
      vars: { value: sa.score, rule_score: sa.threshold },
      evidence: t('Score SpamAssassin {score} pour un seuil de {threshold}', { score: sa.score, threshold: sa.threshold }),
      fallback: { title: t('SpamAssassin classe ce message en spam'), family: 'spamassassin', severity: 'critical', penalty: 0 },
    });
  const compliance = sc.data.compliance as { isBulk?: boolean; requirements?: { id: string; ok: boolean | null; scope: string }[] } | undefined;
  const failingRequirements = (compliance?.requirements ?? []).filter((r) => r.ok === false && (r.scope === 'all' || compliance?.isBulk)).map((r) => r.id);
  classifyFindings(c.findings, { failingRequirements, saOverThreshold: !!sa?.isSpam });
  // the SpamAssassin verdict belongs to the side that carries most of its points
  const over = c.findings.find((f) => f.id === 'spamassassin.over_threshold');
  if (over) {
    const pts = (axis: string) => c.findings.filter((f) => f.family === 'spamassassin' && f.axis === axis).reduce((t, f) => t + Math.max(0, f.penalty), 0);
    over.axis = pts('sender') > pts('message') ? 'sender' : 'message';
  }
  const findings = sortFindings(c.findings) as typeof c.findings;
  const score = scoreOf(findings);
  const sections: SectionSummary[] = (Object.keys(SECTION_TITLES) as SectionId[]).map((id) => {
    const fs = c.findings.filter((f) => f.section === id);
    const lost = Math.round(fs.reduce((n, f) => n + Math.max(0, f.penalty), 0) * 10) / 10;
    const worst = fs.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'error' : lost > 0 ? 'warning' : fs.length ? 'info' : 'ok';
    return { id, title: t(SECTION_TITLES[id]), lost, status: worst, findings: fs.map((f) => f.id), passed: c.passed.filter((p) => p.section === id).map((p) => p.id) };
  });
  const lines = findings.filter((f) => f.penalty > 0).map((f) => ({ id: f.id, title: f.title, section: f.section, penalty: f.penalty }));

  const data: MailReportData = {
    via: input.via,
    receivedAt: facts.receivedAt.toISOString(),
    envelope: {
      clientIp: facts.ip,
      ipSource: facts.ipSource,
      ipReason: facts.ipReason,
      helo: facts.helo,
      mailFrom: facts.envelopeFrom,
      rcptTo: input.rcptTo ?? [],
      tls: facts.tls,
    },
    message: {
      from: facts.fromAddress,
      fromName: facts.fromName,
      fromDomain: facts.fromDomain,
      subject: facts.subject,
      date: firstHeader(facts.headers, 'date'),
      messageId: firstHeader(facts.headers, 'message-id'),
      to: firstHeader(facts.headers, 'to'),
      replyTo: firstHeader(facts.headers, 'reply-to'),
      size: input.raw.length,
    },
    provider: facts.provider,
    providerCandidates: refined.slice(0, 5),
    isBulk: facts.isBulk,
    bulkReasons: facts.bulkReasons,
    limits: c.limits,
    hostAddedHeaders: hostHeaders.length ? hostHeaders : undefined,
    hops: facts.hops,
    sections,
    scoring: { total: score, lost: Math.round((10 - score) * 10) / 10, lines },
    indicators: indicatorsOf(findings),
    ...sc.data,
  };
  if (facts.provider && !c.vars.provider) c.vars.provider = facts.provider.name;
  return {
    tool: 'mail',
    input: facts.fromAddress ?? facts.fromDomain ?? '',
    measuredAt: new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString(),
    score,
    findings,
    passed: c.passed,
    unavailable: c.unavailable,
    data,
    ms: Math.round(performance.now() - started),
  };
}

