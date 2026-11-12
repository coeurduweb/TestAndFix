// Accumulates the findings of one analysis. One finding per situation id: a second detection of
// the same id (our own check and the SpamAssassin rule mapped to it) adds its evidence instead of
// counting the penalty twice.
import { explain, fill, knowledge, type ExplainInput, type Finding, type Severity, type Vars } from '../../knowledge/engine.js';
import type { PassedCheck } from '../../tools/types.js';
import { msg } from '../../i18n.js';

export interface AddOptions {
  vars?: Vars;
  evidence?: string;
  suggested?: string;
  penalty?: number;
  severity?: Severity;
  fallback: NonNullable<ExplainInput['fallback']>;
  /** Report section, when it differs from the one derived from the family. */
  section?: SectionId;
}

export type SectionId =
  | 'auth'
  | 'infrastructure'
  | 'spamassassin'
  | 'blacklists'
  | 'headers'
  | 'content'
  | 'links'
  | 'attachments'
  | 'unsubscribe'
  | 'compliance';

/** French msgids: translate with t() where shown. */
export const SECTION_TITLES: Record<SectionId, string> = {
  auth: msg('Authentification'),
  infrastructure: msg("Serveur d'envoi"),
  spamassassin: msg('SpamAssassin'),
  blacklists: msg('Listes noires'),
  headers: msg('En-têtes'),
  content: msg('Contenu'),
  links: msg('Liens et images'),
  attachments: msg('Pièces jointes'),
  unsubscribe: msg('Désinscription'),
  compliance: msg('Exigences Gmail, Yahoo, Microsoft'),
};

const FAMILY_SECTION: Record<string, SectionId> = {
  spf: 'auth',
  dkim: 'auth',
  dmarc: 'auth',
  arc: 'auth',
  bimi: 'auth',
  alignment: 'auth',
  rdns: 'infrastructure',
  helo: 'infrastructure',
  tls: 'infrastructure',
  infrastructure: 'infrastructure',
  'mta-sts': 'infrastructure',
  mx: 'infrastructure',
  dnssec: 'infrastructure',
  spamassassin: 'spamassassin',
  sa: 'spamassassin',
  blacklist: 'blacklists',
  reputation: 'blacklists',
  headers: 'headers',
  content: 'content',
  html: 'content',
  images: 'links',
  links: 'links',
  attachments: 'attachments',
  unsubscribe: 'unsubscribe',
  'bulk-sender': 'compliance',
};

export function sectionOf(family: string): SectionId {
  return FAMILY_SECTION[family] ?? 'content';
}

export class Collector {
  private byId = new Map<string, Finding & { section: SectionId }>();
  private varsById = new Map<string, Vars>();
  readonly passed: (PassedCheck & { section: SectionId })[] = [];
  /** reason: French, for the interface; detail: technical message, when there is one */
  readonly unavailable: { source: string; reason: string; detail?: string }[] = [];
  /** Checks whose result is less reliable (message received through a mailbox, imported). */
  readonly limits: { check: string; reason: string }[] = [];
  /** Base variables shared by every finding (domain, ip, provider…). */
  vars: Vars = {};
  provider?: string;

  add(id: string, o: AddOptions): Finding {
    const vars = { ...this.vars, ...o.vars };
    const existing = this.byId.get(id);
    if (existing) {
      if (o.evidence && !existing.evidence?.includes(o.evidence))
        existing.evidence = [existing.evidence, o.evidence].filter(Boolean).join('\n');
      if (o.suggested && !existing.suggested) existing.suggested = o.suggested;
      if (o.penalty !== undefined && o.penalty > existing.penalty) existing.penalty = o.penalty;
      return existing;
    }
    const f = explain({
      id,
      vars,
      provider: this.provider,
      suggested: o.suggested,
      evidence: o.evidence,
      penalty: o.penalty,
      severity: o.severity,
      fallback: o.fallback,
    });
    const withSection = { ...f, section: o.section ?? sectionOf(f.family) };
    this.byId.set(id, withSection);
    this.varsById.set(id, vars);
    return withSection;
  }

  /** Provider known only after the DNS steps: add its specific fix to the findings already made. */
  setProvider(key: string | undefined, name?: string) {
    this.provider = key;
    this.vars.provider = name ?? key;
    for (const [id, f] of this.byId) {
      const text = key ? knowledge().get(id)?.fix_by_provider?.[key] : undefined;
      f.providerFix = text ? { provider: key!, text: fill(text, { ...this.varsById.get(id), provider: name ?? key }) } : undefined;
    }
  }

  has(id: string) {
    return this.byId.has(id);
  }

  pass(id: string, family: string, title: string, detail?: string, section?: SectionId) {
    if (this.passed.some((p) => p.id === id)) return;
    this.passed.push({ id, family, title, detail, section: section ?? sectionOf(family) });
  }

  missing(source: string, reason: string, detail?: string) {
    if (!this.unavailable.some((u) => u.source === source)) this.unavailable.push(detail ? { source, reason, detail } : { source, reason });
  }

  limit(check: string, reason: string) {
    if (!this.limits.some((l) => l.check === check)) this.limits.push({ check, reason });
  }

  get findings(): (Finding & { section: SectionId })[] {
    return [...this.byId.values()];
  }
}
