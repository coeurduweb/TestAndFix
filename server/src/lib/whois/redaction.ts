// Is a contact value real, hidden, or a privacy service standing in for the holder?
//
// Heuristics, not a standard: the patterns below are the placeholders seen in real answers
// (recorded in fixtures/: "REDACTED FOR PRIVACY", "REDACTED REGISTRANT", Netim's "Please use the
// online form ...", Afnic's anonymised holder "Ano Nymous" with "anonymous: YES", proxy
// organisations such as "ProxyDom"). The structured signal, when a server gives it, wins: RDAP's
// "redacted" member (RFC 9537 §4.2) and Afnic's "anonymous:" attribute.

const PLACEHOLDER =
  /redacted|not disclosed|non divulgu|data protected|withheld|statutory masking|gdpr|privacy|confidential|hidden|masked|ano nymous|anonymi[sz]ed|^please\b|^contact (the )?registrar|query the rdds|not available|^n\/a$|^none$|^-+$/i;

/** A value that stands for "hidden" rather than a real name, organisation or address. */
export function isPlaceholder(v: string | undefined): boolean {
  if (v === undefined) return false;
  const s = v.trim();
  return !!s && PLACEHOLDER.test(s);
}

// Organisations that register on behalf of the real holder: names built on these words.
const PRIVACY_ORG = /privacy|proxy|whoisguard|withheld for|protection service|identity protect|domains by proxy|anonymi[sz]/i;

export function isPrivacyOrg(v: string | undefined): boolean {
  return !!v && PRIVACY_ORG.test(v);
}

/** An e-mail field that holds a web form or a sentence instead of an address. */
export function emailOrForm(v: string | undefined): { email?: string; contactUrl?: string; hidden: boolean } {
  if (!v) return { hidden: false };
  const s = v.trim();
  if (!s) return { hidden: false };
  const url = /https?:\/\/[^\s<>"]+/i.exec(s)?.[0];
  if (/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(s) && !isPlaceholder(s.split('@')[0] ?? '')) return { email: s, hidden: false };
  if (url) return { contactUrl: url.replace(/[.,;)]+$/, ''), hidden: true };
  return { hidden: true };
}

/** RFC 9537 redacted names ("Registrant Name", "Tech Email") as role and field. */
export function redactedField(name: string): { role: 'registrant' | 'admin' | 'tech'; field: 'name' | 'org' | 'email' } | undefined {
  const m = /^(registrant|admin(?:istrative)?|tech(?:nical)?)\s+(name|organi[sz]ation|email|e-mail)\b/i.exec(name.trim());
  if (!m) return undefined;
  const r = m[1].toLowerCase();
  const role = r.startsWith('admin') ? 'admin' : r.startsWith('tech') ? 'tech' : 'registrant';
  const f = m[2].toLowerCase();
  return { role, field: f.startsWith('organ') ? 'org' : f.startsWith('e') ? 'email' : 'name' };
}
