// RDAP domain answer (RFC 9083) read into a PartyRecord: dates from events, statuses mapped to EPP
// codes (RFC 8056), registrar entity (ICANN RDAP Response Profile 2.2 §2.4: fn, publicIds "IANA
// Registrar ID", links rel "about" whose value is the registrar's RDAP base URL), reseller entity
// (§2.5), contacts with redaction (RFC 9537 "redacted" member, entity remarks "redacted for
// privacy", empty vCard values, placeholders) and the registrar's own RDAP URL (ICANN RDAP
// Technical Implementation Guide 2.2 §3.2: links rel "related" in the registry answer).
import { normalizeStatuses } from './epp.js';
import { emailOrForm, isPlaceholder, isPrivacyOrg, redactedField } from './redaction.js';
import type { Contact, ContactRole, Party, PartyRecord } from './types.js';

export type ParsedRdap = Omit<PartyRecord, 'party' | 'protocol' | 'server' | 'raw' | 'url'>;

interface VcardEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: [string, [string, Record<string, unknown>, string, unknown][]];
  publicIds?: { type: string; identifier: string }[];
  links?: { rel?: string; href?: string; value?: string; type?: string }[];
  entities?: VcardEntity[];
  remarks?: { title?: string; type?: string; description?: string[] }[];
  port43?: string;
}

function vcardValues(e: VcardEntity, field: string): unknown[] {
  return (e.vcardArray?.[1] ?? []).filter((x) => x[0] === field).map((x) => x[3]);
}

function vcardText(e: VcardEntity, field: string): string | undefined {
  const v = vcardValues(e, field)[0];
  if (v === undefined || v === null) return undefined;
  const s = Array.isArray(v) ? v.filter(Boolean).join(', ') : String(v);
  return s;
}

/** Every entity, nested ones included (contacts can sit under the registrar). */
function flatten(list: VcardEntity[] | undefined, depth = 0): VcardEntity[] {
  if (!list || depth > 3) return [];
  return list.flatMap((e) => [e, ...flatten(e.entities, depth + 1)]);
}

const ROLE: Record<string, ContactRole> = { registrant: 'registrant', administrative: 'admin', technical: 'tech' };

function contactOf(e: VcardEntity, role: ContactRole, redactedFields: Set<string>): Contact {
  const c: Contact = { role, redacted: [] };
  // "Redacted for privacy" remarks (Netim), Afnic's "contact restricted publication: YES"
  const remarkRedacted = (e.remarks ?? []).some(
    (r) => /redact|withheld|not disclosed/i.test(`${r.title ?? ''} ${r.type ?? ''}`) || (/restricted publication/i.test(r.type ?? '') && /^yes$/i.test(r.description?.[0]?.trim() ?? '')),
  );
  const name = vcardText(e, 'fn');
  const org = vcardText(e, 'org');
  const email = vcardText(e, 'email');
  const uri = vcardText(e, 'contact-uri');
  const hidden = (field: 'name' | 'org' | 'email', v: string | undefined) =>
    redactedFields.has(`${role}:${field}`) || isPlaceholder(v) || ((v === undefined || !v.trim()) && remarkRedacted);
  const declared = (f: string) => redactedFields.has(`${role}:${f}`);
  if (name?.trim() && !isPlaceholder(name) && !declared('name')) c.name = name.trim();
  else if (hidden('name', name)) c.redacted.push('name');
  if (declared('org') && !org?.trim()) c.redacted.push('org');
  else if (org?.trim() && isPrivacyOrg(org) && !/redacted/i.test(org)) {
    c.org = org.trim();
    c.privacyService = true;
  } else if (org?.trim() && !isPlaceholder(org)) c.org = org.trim();
  else if (hidden('org', org)) c.redacted.push('org');
  const e2 = emailOrForm(email);
  if (e2.email && !declared('email')) c.email = e2.email;
  else if (hidden('email', email) || e2.hidden || uri) c.redacted.push('email');
  const url = e2.contactUrl ?? (uri && /^https?:/i.test(uri) ? uri : undefined);
  if (url) c.contactUrl = url;
  if (!c.privacyService && c.name && isPrivacyOrg(c.name)) c.privacyService = true;
  return c;
}

const FIELD_OF = (name: string): 'name' | 'org' | 'email' | undefined =>
  /e-?mail/i.test(name) ? 'email' : /organi[sz]ation|\borg\b/i.test(name) ? 'org' : /name|\bfn\b/i.test(name) && !/street|city|province|country|registrar/i.test(name) ? 'name' : undefined;

/**
 * Contact fields declared redacted (RFC 9537 §4.2), as "role:field". The role comes from the name
 * ("Registrant Name", ICANN profile Appendix E) or from the path: "$.entities[1]..." (Afnic) or a
 * filter on roles ("$.entities[?(@.roles[0]=='registrant')]...", Netim).
 */
export function redactionTargets(json: Record<string, unknown>, top: VcardEntity[]): Set<string> {
  const out = new Set<string>();
  for (const r of (json.redacted as { name?: { description?: string; type?: string }; prePath?: string; postPath?: string }[]) ?? []) {
    const label = r.name?.type ?? r.name?.description ?? '';
    const named = redactedField(label);
    if (named) {
      out.add(`${named.role}:${named.field}`);
      continue;
    }
    const field = FIELD_OF(label);
    if (!field) continue;
    const path = r.prePath ?? r.postPath ?? '';
    const idx = /^\$\.entities\[(\d+)\]/.exec(path)?.[1];
    const roleInPath = /roles\[0\]\s*==\s*'(\w+)'/.exec(path)?.[1];
    const roles = idx !== undefined ? (top[Number(idx)]?.roles ?? []) : roleInPath ? [roleInPath] : [];
    for (const role of roles) if (ROLE[role]) out.add(`${ROLE[role]}:${field}`);
  }
  return out;
}

export function parseRdapJson(json: Record<string, unknown>, party: Party): ParsedRdap {
  const events = ((json.events as { eventAction?: string; eventDate?: string }[]) ?? []).filter((e) => e.eventAction && e.eventDate);
  const ev = (...actions: string[]) => {
    for (const a of actions) {
      const d = events.find((e) => e.eventAction!.toLowerCase() === a)?.eventDate;
      if (d) return d;
    }
    return undefined;
  };
  const top = (json.entities as VcardEntity[]) ?? [];
  const entities = flatten(top);
  const reg = entities.find((e) => e.roles?.includes('registrar'));
  const abuse = reg?.entities?.find((e) => e.roles?.includes('abuse'));
  const about = reg?.links?.find((l) => l.rel === 'about');
  const regUrl = about?.href ?? reg?.links?.find((l) => l.href && !/rdap/i.test(l.href))?.href ?? (reg ? vcardText(reg, 'url') : undefined);
  const rdapBase = about?.value && /^https:\/\//i.test(about.value) && about.value !== about.href ? about.value : undefined;
  const reseller = entities.find((e) => e.roles?.includes('reseller'));
  const resellerName = reseller ? vcardText(reseller, 'fn')?.trim() || vcardText(reseller, 'org')?.trim() : undefined;

  const redactedFields = redactionTargets(json, top);
  const contacts: Contact[] = [];
  for (const role of ['registrant', 'administrative', 'technical']) {
    const e = top.find((x) => x.roles?.includes(role)) ?? entities.find((x) => x.roles?.includes(role));
    const r = ROLE[role];
    if (e) contacts.push(contactOf(e, r, redactedFields));
    else if ([...redactedFields].some((k) => k.startsWith(`${r}:`))) contacts.push({ role: r, redacted: ['name', 'org', 'email'].filter((f) => redactedFields.has(`${r}:${f}`)) as Contact['redacted'] });
  }

  const related = ((json.links as { rel?: string; href?: string; type?: string }[]) ?? []).find(
    (l) => l.rel === 'related' && l.href && /^https:\/\//i.test(l.href) && (!l.type || /rdap/i.test(l.type)),
  )?.href;
  const ns = ((json.nameservers as { ldhName?: string }[]) ?? []).map((n) => (n.ldhName ?? '').toLowerCase().replace(/\.$/, '')).filter(Boolean);
  return {
    created: ev('registration'),
    updated: ev('last changed'),
    expires: party === 'registrar' ? ev('registrar expiration', 'expiration') : ev('expiration'),
    status: normalizeStatuses((json.status as string[]) ?? []),
    registryStatus: [],
    registrar: reg
      ? {
          name: vcardText(reg, 'fn') || undefined,
          ianaId: reg.publicIds?.find((p) => /iana/i.test(p.type))?.identifier,
          url: regUrl,
          rdapBase,
          whoisServer: reg.port43,
          abuseEmail: abuse ? vcardText(abuse, 'email') : undefined,
        }
      : undefined,
    reseller: resellerName && !isPlaceholder(resellerName) ? resellerName : undefined,
    contacts,
    nameservers: [...new Set(ns)],
    dnssec: (json.secureDNS as { delegationSigned?: boolean } | undefined)?.delegationSigned,
    registrarRdapUrl: party === 'registry' ? related : undefined,
  };
}
