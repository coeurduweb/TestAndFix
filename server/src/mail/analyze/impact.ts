// Effect of each finding on delivery, and what it is about (asked by the user on 2026-11-11: « séparer
// ce qui est bloquant pour la livraison de ce qui est suspicieux », and two indicators, the sender's
// technical setup and the composition of the message).
//
// impact
//   blocking  the message will not reach the inbox: refused, or put in the spam folder almost surely.
//             Critical findings, unmet Gmail / Yahoo / Microsoft requirements that apply to this
//             message (and the findings that cause them), SpamAssassin over its threshold.
//   spam      raises the risk of the spam folder: medium and high findings.
//   advice    worth improving, no notable effect on the delivery of this message: low and info
//             findings, and every finding that costs no point.
// A situation can set `impact:` or `axis:` in the base when the default is wrong.
import { knowledge, type Axis, type Finding, type Impact } from '../../knowledge/engine.js';

const SENDER_FAMILIES = new Set([
  'spf', 'dkim', 'dmarc', 'arc', 'bimi', 'alignment', 'rdns', 'helo', 'blacklist', 'tls', 'mta-sts',
  'dnssec', 'mx', 'reputation', 'infrastructure', 'ip', 'bulk-sender',
]);
/** SpamAssassin entries are filed by theme: these files test the sender, the others the message. */
const SA_SENDER_FILES = new Set(['spamassassin-auth.yaml', 'spamassassin-relay.yaml', 'spamassassin-reputation.yaml']);
/** SpamAssassin rules without an entry: sender rules by their name. */
const SA_SENDER_RULE = /^(sa\.)?(rcvd_|spf_|dkim_|dmarc_|arc_|rdns_|helo_|dnswl|forged_.*rcvd|dyn|dos_)/i;

export function axisOf(f: Pick<Finding, 'id' | 'family'>): Axis {
  const s = knowledge().get(f.id);
  if (s?.axis) return s.axis;
  if (f.family === 'spamassassin') return s?.file ? (SA_SENDER_FILES.has(s.file) ? 'sender' : 'message') : SA_SENDER_RULE.test(f.id) ? 'sender' : 'message';
  return SENDER_FAMILIES.has(f.family) ? 'sender' : 'message';
}

export interface ImpactContext {
  /** Gmail / Yahoo / Microsoft requirements unmet by this message and applicable to it. */
  failingRequirements: string[];
  saOverThreshold: boolean;
  /** SpamAssassin points of each SA finding, the message total and its threshold (when SpamAssassin ran). */
  sa?: { total: number; threshold: number; ruleScore: Map<string, number> };
}

/**
 * A SpamAssassin rule raises the risk of the spam folder only when it weighs: one point or more, or
 * a message total already at 40 % of the threshold. Below that it is advice (user, 2026-11-12: a
 * person-to-person Gmail message, 0.5 point for a threshold of 5, was told it "may land in spam" because
 * of its signature image).
 */
export const SA_RISK_RULE = 1;
export const SA_RISK_SHARE = 0.4;

/** Findings that cause an unmet requirement: they block, not only the requirement's own entry. */
const REQUIREMENT_CAUSES: Record<string, (f: Finding) => boolean> = {
  spf_or_dkim: (f) => f.family === 'spf' || f.family === 'dkim',
  spf: (f) => f.family === 'spf',
  dkim: (f) => f.family === 'dkim',
  dmarc: (f) => f.family === 'dmarc',
  alignment: (f) => f.family === 'alignment',
  ptr: (f) => f.family === 'rdns',
  tls: (f) => f.family === 'tls',
  format: (f) => /^headers\.(from_missing|from_multiple|date_missing|message_id_missing|duplicate_single_instance)$/.test(f.id),
  one_click: (f) => f.family === 'unsubscribe',
  outlook: (f) => f.family === 'spf' || f.family === 'dkim' || f.family === 'dmarc' || f.family === 'alignment',
};

const SERIOUS = new Set(['critical', 'high', 'medium']);

export function impactOf(f: Finding, ctx: ImpactContext): Impact {
  const s = knowledge().get(f.id);
  if (s?.impact) return s.impact;
  if (f.family === 'bulk-sender') return 'blocking'; // only added when the requirement applies and fails
  if (f.severity === 'critical') return 'blocking';
  if (f.penalty <= 0) return 'advice';
  if (SERIOUS.has(f.severity) && ctx.failingRequirements.some((r) => REQUIREMENT_CAUSES[r]?.(f))) return 'blocking';
  if (ctx.saOverThreshold && f.family === 'spamassassin' && (f.severity === 'high' || f.severity === 'medium')) return 'blocking';
  const ruleScore = ctx.sa?.ruleScore.get(f.id);
  if (ctx.sa && ruleScore !== undefined && !ctx.saOverThreshold && ruleScore < SA_RISK_RULE && ctx.sa.total < SA_RISK_SHARE * ctx.sa.threshold) return 'advice';
  return SERIOUS.has(f.severity) ? 'spam' : 'advice';
}

export function classifyFindings<F extends Finding>(findings: F[], ctx: ImpactContext): F[] {
  for (const f of findings) {
    f.axis = axisOf(f);
    f.impact = impactOf(f, ctx);
  }
  return findings;
}

export interface AxisSummary {
  /** points lost by the findings of this axis */
  lost: number;
  blocking: number;
  spam: number;
  advice: number;
  /** worst impact present, or ok */
  status: Impact | 'ok';
}

export interface Indicators {
  /** blocking when one finding blocks, spam when one raises the risk, else ok */
  verdict: 'blocking' | 'spam' | 'ok';
  sender: AxisSummary;
  message: AxisSummary;
}

export function indicatorsOf(findings: Finding[]): Indicators {
  const sum = (axis: Axis): AxisSummary => {
    const fs = findings.filter((f) => f.axis === axis);
    // what only the sending service can act on is not counted as an improvement for the sender
    const n = (i: Impact) => fs.filter((f) => f.impact === i && !(i === 'advice' && f.outOfReach)).length;
    const out = { lost: Math.round(fs.reduce((t, f) => t + Math.max(0, f.penalty), 0) * 10) / 10, blocking: n('blocking'), spam: n('spam'), advice: n('advice') };
    return { ...out, status: out.blocking ? 'blocking' : out.spam ? 'spam' : out.advice ? 'advice' : 'ok' };
  };
  const sender = sum('sender');
  const message = sum('message');
  const verdict = sender.blocking + message.blocking ? 'blocking' : sender.spam + message.spam ? 'spam' : 'ok';
  return { verdict, sender, message };
}

/** Hosts run by a sending service: what their HELO or reverse DNS lacks is theirs to fix. */
const PROVIDER_HOSTS: [RegExp, string][] = [
  [/(^|\.)(google|googlemail)\.com$/, 'Google'],
  [/(^|\.)(outlook|hotmail)\.com$/, 'Microsoft'],
  [/(^|\.)amazonses\.com$/, 'Amazon SES'],
  [/(^|\.)sendgrid\.net$/, 'SendGrid'],
  [/(^|\.)mailgun\.(org|net)$/, 'Mailgun'],
  [/(^|\.)mailjet\.com$/, 'Mailjet'],
  [/(^|\.)(sendinblue|brevo)\.com$/, 'Brevo'],
  [/(^|\.)(mcsv\.net|mcdlv\.net|rsgsv\.net|mandrillapp\.com)$/, 'Mailchimp'],
  [/(^|\.)sparkpostmail\.com$/, 'SparkPost'],
  [/(^|\.)mtasv\.net$/, 'Postmark'],
  [/(^|\.)zoho\.(com|eu)$/, 'Zoho'],
  [/(^|\.)protonmail\.ch$/, 'Proton'],
];
/** Webmails that write the HTML themselves, recognised by their Message-ID. */
const COMPOSERS: [RegExp, string][] = [
  [/@mail\.gmail\.com>?\s*$/i, 'Gmail'],
  [/\.(outlook|prod\.outlook)\.com>?\s*$/i, 'Outlook'],
];
const HOST_FINDINGS = /^(spf\.helo_|helo\.|rdns\.)/;
const MARKUP_FINDINGS = new Set(['html.no_doctype', 'html.lang_missing']);

/**
 * Advice the sender cannot act on: the HELO of a sending service's server, the markup a webmail
 * writes (user, 2026-11-12: "Le nom de serveur mail-ed1-f46.google.com n'a pas de SPF" was listed as
 * an improvement of a Gmail message). Only advice is marked: a real problem stays in front.
 */
export function markOutOfReach(findings: Finding[], facts: { helo?: string; ptr?: string; headers: { key: string; value: string }[] }) {
  const host = [facts.helo, facts.ptr].filter((h): h is string => !!h).map((h) => h.toLowerCase().replace(/\.$/, ''));
  const service = PROVIDER_HOSTS.find(([re]) => host.some((h) => re.test(h)))?.[1];
  const mid = facts.headers.find((h) => h.key === 'message-id')?.value ?? '';
  const composer = COMPOSERS.find(([re]) => re.test(mid))?.[1];
  for (const f of findings) {
    if (f.impact !== 'advice') continue;
    if (service && HOST_FINDINGS.test(f.id)) f.outOfReach = service;
    else if (composer && MARKUP_FINDINGS.has(f.id)) f.outOfReach = composer;
  }
}
