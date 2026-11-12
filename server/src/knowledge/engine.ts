// Knowledge base of situations (knowledge/situations/*.yaml) and the template engine that
// turns a detected situation + measured values into a personalised explanation and fix.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { currentLang, msg, t, type Lang } from '../i18n.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Situation {
  id: string;
  family: string;
  severity: Severity;
  penalty: number;
  detect?: { signal?: string; notes?: string };
  sa_rules?: string[];
  title: string;
  why: string;
  fix: string[];
  fix_by_provider?: Record<string, string>;
  example_bad?: string;
  example_good?: string;
  references?: string[];
  /** Effect on delivery, when the default derived from severity is wrong (mail reports). */
  impact?: Impact;
  /** What the finding is about, when the default derived from the family is wrong. */
  axis?: Axis;
  /** Source file, set at load (the spamassassin family is split by theme across files). */
  file?: string;
}

/** blocking: the message will not reach the inbox; spam: raises the risk of the spam folder;
 *  advice: worth improving, no notable effect on the delivery of this message. */
export type Impact = 'blocking' | 'spam' | 'advice';
/** sender: domain, DNS, authentication, sending server, reputation; message: what was written. */
export type Axis = 'sender' | 'message';

export type Vars = Record<string, string | number | undefined | null>;

export interface Finding {
  id: string;
  family: string;
  severity: Severity;
  /** Points removed from the /10 score (0 for info and passed checks). */
  penalty: number;
  title: string;
  why: string;
  fix: string[];
  /** Fix for the provider detected in this context, when the base has one. */
  providerFix?: { provider: string; text: string };
  exampleBad?: string;
  exampleGood?: string;
  /** Computed corrected value (record, header…) ready to copy. */
  suggested?: string;
  references: string[];
  /** Raw evidence shown under the finding (record seen, header value, rule score…). */
  evidence?: string;
  /** true when the situation id is unknown to the base and the text came from the analyzer. */
  fallback?: boolean;
  /** Mail reports only, set by classifyFindings. */
  impact?: Impact;
  /** Mail reports: what an advice finding would cost if it counted (it does not, see mail/analyze/index.ts). */
  advicePenalty?: number;
  /** Mail reports: advice only the named service can act on (its server, its webmail's markup). */
  outOfReach?: string;
  axis?: Axis;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = path.resolve(here, '..', '..', '..', 'knowledge', 'situations');

let cache: Map<string, Situation> | undefined;
let saIndex: Map<string, Situation> | undefined;

export function loadKnowledge(dir = DEFAULT_DIR): Map<string, Situation> {
  const map = new Map<string, Situation>();
  const sa = new Map<string, Situation>();
  if (!fs.existsSync(dir)) return map;
  for (const file of fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const docs = YAML.parse(fs.readFileSync(path.join(dir, file), 'utf8')) as Situation[] | { situations?: Situation[] } | null;
    const list = Array.isArray(docs) ? docs : (docs?.situations ?? []);
    for (const s of list) {
      if (!s?.id || !s.title) continue;
      s.fix = Array.isArray(s.fix) ? s.fix.map(String) : s.fix ? [String(s.fix)] : [];
      s.penalty = Number(s.penalty ?? 0);
      s.file = file;
      map.set(s.id, s);
      for (const r of s.sa_rules ?? []) sa.set(r.toUpperCase(), s);
    }
  }
  cache = map;
  saIndex = sa;
  return map;
}

/** The texts of a situation that are translated (knowledge/i18n/<lang>/<file>.yaml, keyed by id). */
export type SituationText = Partial<Pick<Situation, 'title' | 'why' | 'fix' | 'fix_by_provider'>>;
export const I18N_DIR = path.resolve(DEFAULT_DIR, '..', 'i18n');
const localized = new Map<Lang, Map<string, Situation>>();

export function loadTranslations(lang: Lang, dir = I18N_DIR): Map<string, SituationText> {
  const out = new Map<string, SituationText>();
  const d = path.join(dir, lang);
  if (!fs.existsSync(d)) return out;
  for (const file of fs.readdirSync(d).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const doc = YAML.parse(fs.readFileSync(path.join(d, file), 'utf8')) as Record<string, SituationText> | null;
    for (const [id, tr] of Object.entries(doc ?? {})) if (tr && typeof tr === 'object') out.set(id, tr);
  }
  return out;
}

/** The base in the language of the request: French as written, else its translation, else English, else French. */
export function knowledge(): Map<string, Situation> {
  const base = cache ?? loadKnowledge();
  const lang = currentLang();
  if (lang === 'fr') return base;
  let map = localized.get(lang);
  if (!map) {
    const own = loadTranslations(lang);
    const en = lang === 'en' ? own : loadTranslations('en');
    map = new Map();
    for (const [id, s] of base) {
      const tr = { ...en.get(id), ...own.get(id) };
      map.set(id, {
        ...s,
        title: tr.title || s.title,
        why: tr.why || s.why,
        fix: Array.isArray(tr.fix) && tr.fix.length === s.fix.length ? tr.fix.map(String) : s.fix,
        fix_by_provider: s.fix_by_provider ? { ...s.fix_by_provider, ...tr.fix_by_provider } : undefined,
      });
    }
    localized.set(lang, map);
  }
  return map;
}

export function situationForSaRule(rule: string): Situation | undefined {
  if (!saIndex) loadKnowledge();
  const s = saIndex!.get(rule.toUpperCase());
  return s ? knowledge().get(s.id) : knowledge().get('sa.' + rule.toLowerCase());
}

/** Replace {var} placeholders. A sentence whose variable is unknown keeps a neutral wording. */
export function fill(text: string | undefined, vars: Vars): string {
  if (!text) return '';
  return text
    .replace(/(?<!%)\{(\w+)\}/g, (_m, k: string) => { // %{VAR} is Apache syntax, never a template variable
      const v = vars[k];
      return v === undefined || v === null || v === '' ? `‹${k}›` : String(v);
    })
    .replace(/‹(\w+)›/g, (_m, k: string, at: number, all: string) => {
      // "L'IP {ip}" with an unknown IP must not read "L'IP l'IP d'envoi": after its own noun, only the complement
      const after = AFTER_NOUN[currentLang()]?.[k];
      if (after && new RegExp(`(?:^|[\\s'’])${after[0]} $`, 'i').test(all.slice(Math.max(0, at - 24), at))) return after[1];
      return t(PLACEHOLDER_WORDS[k] ?? UNKNOWN_VALUE);
    })
    .trim();
}

/** Noun that may already precede a placeholder in a sentence, and the complement used after it (French, the source). */
const PLACEHOLDER_AFTER_NOUN: Record<string, [string, string]> = {
  ip: ['IP', "d'envoi"],
  helo: ['HELO', 'annoncé'],
  ptr: ['PTR', 'annoncé'],
  domain: ['domaine', 'concerné'],
  selector: ['sélecteur', 'concerné'],
  url: ['lien', 'concerné'],
  list_name: ['liste', 'concernée'],
};
/** Same, per language: "The domain {domain}" with an unknown domain reads "The domain in question", not "The domain your domain". */
const AFTER_NOUN: Partial<Record<string, Record<string, [string, string]>>> = {
  fr: PLACEHOLDER_AFTER_NOUN,
  en: {
    ip: ['IP', 'in question'],
    helo: ['HELO', 'announced'],
    ptr: ['PTR', 'announced'],
    domain: ['domain', 'in question'],
    selector: ['selector', 'in question'],
    url: ['link', 'in question'],
    list_name: ['list', 'in question'],
  },
};

const UNKNOWN_VALUE = msg('votre valeur');

/** French msgids, translated through i18n/server.<lang>.json. */
const PLACEHOLDER_WORDS: Record<string, string> = {
  domain: msg('votre domaine'),
  envelope_domain: msg("le domaine d'enveloppe"),
  dkim_domain: msg('le domaine de signature'),
  selector: msg('votre sélecteur'),
  ip: msg("l'IP d'envoi"),
  ptr: msg('le nom inverse'),
  helo: msg('le nom HELO'),
  provider: msg("votre outil d'envoi"),
  list_name: msg('la liste'),
  url: msg('le lien'),
  rule: msg('la règle'),
};

export interface ExplainInput {
  id: string;
  vars?: Vars;
  /** Detected sending provider key (google_workspace, brevo…), for fix_by_provider. */
  provider?: string;
  suggested?: string;
  evidence?: string;
  /** Overrides when the analyzer knows better (e.g. score computed from the SA rule). */
  penalty?: number;
  severity?: Severity;
  /** Text used when the id is not in the base. */
  fallback?: { title: string; why?: string; fix?: string[]; family?: string; severity?: Severity; penalty?: number };
}

export function explain(input: ExplainInput): Finding {
  const vars: Vars = { ...input.vars, suggested_record: input.suggested ?? input.vars?.suggested_record };
  const s = knowledge().get(input.id);
  if (!s) {
    const f = input.fallback ?? { title: input.id };
    return {
      id: input.id,
      family: f.family ?? input.id.split('.')[0],
      severity: input.severity ?? f.severity ?? 'medium',
      penalty: input.penalty ?? f.penalty ?? 0,
      title: fill(f.title, vars),
      why: fill(f.why, vars),
      fix: (f.fix ?? []).map((x) => fill(x, vars)),
      suggested: input.suggested,
      evidence: input.evidence,
      references: [],
      fallback: true,
    };
  }
  const providerText = input.provider ? s.fix_by_provider?.[input.provider] : undefined;
  // `fallback` only applies when the id is missing from the base. An analyzer that computes severity
  // from context (list weight, current policy…) passes it at top level, which wins over the base.
  return {
    id: s.id,
    family: s.family,
    severity: input.severity ?? s.severity,
    penalty: input.penalty ?? s.penalty,
    title: fill(s.title, vars),
    why: fill(s.why, vars),
    fix: s.fix.map((x) => fill(x, vars)),
    providerFix: providerText ? { provider: input.provider!, text: fill(providerText, vars) } : undefined,
    exampleBad: s.example_bad ? fill(s.example_bad, vars) : undefined,
    exampleGood: s.example_good ? fill(s.example_good, vars) : undefined,
    suggested: input.suggested,
    references: s.references ?? [],
    evidence: input.evidence,
  };
}

const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.penalty - a.penalty || a.id.localeCompare(b.id));
}

/** Score out of 10: 10 minus the penalties, floored at 0, one decimal. */
export function scoreOf(findings: Finding[]): number {
  const lost = findings.reduce((n, f) => n + (f.penalty > 0 ? f.penalty : 0), 0);
  return Math.max(0, Math.round((10 - lost) * 10) / 10);
}
