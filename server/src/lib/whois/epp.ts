// Domain status codes: EPP codes (RFC 5731 §2.3, grace periods of RFC 3915 §3.1) and the RDAP
import { msg, t } from '../../i18n.js';
// spellings mapped to them (RFC 8056 §2: "clientTransferProhibited" is "client transfer prohibited",
// "ok" is "active"). Plain French meanings follow ICANN's registrant page "EPP Status Codes | What Do
// They Mean, and Why Should I Know?" (https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en,
// read on 2026-11-12). RDAP values without an EPP counterpart come from RFC 9083 §10.2.2.

export type StatusKind = 'lock' | 'bad' | 'info';

export interface StatusInfo {
  /** Canonical code: EPP camelCase when one exists, the RDAP value otherwise. */
  code: string;
  /** True for an EPP code (RFC 5731 / RFC 3915), false for a registry or RDAP-only value. */
  epp: boolean;
  /** Who sets it, for EPP codes: the registry (server*) or the registrar (client*). */
  setBy?: 'registre' | 'bureau';
  kind: StatusKind;
  meaning: string;
}

const EPP: Record<string, Omit<StatusInfo, 'code' | 'epp'>> = {
  ok: { kind: 'info', meaning: msg('statut normal : aucune opération en attente, aucune interdiction') },
  inactive: { kind: 'bad', meaning: msg('aucun serveur de noms associé : le domaine n’est pas publié dans le DNS et ne résout pas') },
  addPeriod: { kind: 'info', setBy: 'registre', meaning: msg('période de grâce juste après la création') },
  autoRenewPeriod: { kind: 'info', setBy: 'registre', meaning: msg('renouvelé automatiquement par le registre à l’échéance ; si vous ne voulez pas le garder, voyez vite votre bureau d’enregistrement') },
  renewPeriod: { kind: 'info', setBy: 'registre', meaning: msg('période de grâce après un renouvellement demandé par le bureau d’enregistrement') },
  transferPeriod: { kind: 'info', setBy: 'registre', meaning: msg('période de grâce après un transfert réussi vers un nouveau bureau d’enregistrement') },
  pendingCreate: { kind: 'info', setBy: 'registre', meaning: msg('création demandée, en cours de traitement') },
  pendingRenew: { kind: 'info', setBy: 'registre', meaning: msg('renouvellement demandé, en cours de traitement') },
  pendingTransfer: { kind: 'info', setBy: 'registre', meaning: msg('transfert vers un autre bureau d’enregistrement en cours') },
  pendingUpdate: { kind: 'info', setBy: 'registre', meaning: msg('modification demandée, en cours de traitement') },
  pendingRestore: { kind: 'bad', setBy: 'registre', meaning: msg('restauration demandée pendant la période de rédemption, en attente des justificatifs (environ sept jours)') },
  redemptionPeriod: { kind: 'bad', setBy: 'registre', meaning: msg('suppression demandée : le domaine est gardé 30 jours, encore récupérable auprès du bureau d’enregistrement') },
  pendingDelete: { kind: 'bad', setBy: 'registre', meaning: msg('suppression en cours : sans restauration, le domaine sera purgé puis libre à l’enregistrement') },
  serverDeleteProhibited: { kind: 'lock', setBy: 'registre', meaning: msg('suppression bloquée par le registre (rare : litige, demande du titulaire ou rédemption)') },
  serverHold: { kind: 'bad', setBy: 'registre', meaning: msg('retiré du DNS par le registre : le domaine ne résout plus') },
  serverRenewProhibited: { kind: 'bad', setBy: 'registre', meaning: msg('renouvellement bloqué par le registre (rare : litige ou suppression en cours)') },
  serverTransferProhibited: { kind: 'lock', setBy: 'registre', meaning: msg('transfert bloqué par le registre (rare : litige, demande du titulaire ou rédemption)') },
  serverUpdateProhibited: { kind: 'lock', setBy: 'registre', meaning: msg('modification bloquée par le registre (rare : litige, demande du titulaire ou rédemption)') },
  clientDeleteProhibited: { kind: 'lock', setBy: 'bureau', meaning: msg('le registre refuse toute suppression : protège contre une suppression non autorisée') },
  clientHold: { kind: 'bad', setBy: 'bureau', meaning: msg('retiré du DNS à la demande du bureau d’enregistrement : le domaine ne résout plus (litige, impayé ou suppression)') },
  clientRenewProhibited: { kind: 'bad', setBy: 'bureau', meaning: msg('le registre refuse tout renouvellement (rare : litige ou suppression en cours)') },
  clientTransferProhibited: { kind: 'lock', setBy: 'bureau', meaning: msg('le registre refuse tout transfert : protège contre un transfert non autorisé') },
  clientUpdateProhibited: { kind: 'lock', setBy: 'bureau', meaning: msg('le registre refuse toute modification : protège contre une modification non autorisée') },
};

/** RDAP status values without an EPP counterpart (RFC 9083 §10.2.2). */
const RDAP_ONLY: Record<string, Omit<StatusInfo, 'code' | 'epp'>> = {
  validated: { kind: 'info', meaning: msg('données de l’objet vérifiées comme exactes') },
  'renew prohibited': { kind: 'bad', meaning: msg('renouvellement interdit') },
  'update prohibited': { kind: 'lock', meaning: msg('modification interdite') },
  'transfer prohibited': { kind: 'lock', meaning: msg('transfert interdit') },
  'delete prohibited': { kind: 'lock', meaning: msg('suppression interdite') },
  proxy: { kind: 'info', meaning: msg('enregistré par un tiers (service mandataire)') },
  private: { kind: 'info', meaning: msg('informations non destinées au public') },
  removed: { kind: 'info', meaning: msg('une partie des informations a été retirée') },
  obscured: { kind: 'info', meaning: msg('une partie des informations a été modifiée pour ne pas les révéler') },
  associated: { kind: 'info', meaning: msg('objet associé à d’autres objets du registre') },
  locked: { kind: 'lock', meaning: msg('modifications impossibles') },
};

const byCompact = new Map(Object.keys(EPP).map((k) => [k.toLowerCase(), k]));

/**
 * Canonical form of a status as written by a WHOIS or RDAP server: "clientTransferProhibited
 * https://icann.org/epp#clientTransferProhibited", "client transfer prohibited" and
 * "CLIENT_TRANSFER_PROHIBITED" all give "clientTransferProhibited"; RDAP "active" gives "ok"
 * (RFC 8056 §2). Anything else is kept, lowercased, as a registry-specific status.
 */
export function canonicalStatus(raw: string): string | undefined {
  const s = String(raw ?? '').trim().replace(/\s+\(?https?:\/\/\S+\)?\s*$/i, '').trim();
  if (!s) return undefined;
  const compact = s.toLowerCase().replace(/[\s_-]+/g, '');
  if (compact === 'active') return 'ok';
  const epp = byCompact.get(compact);
  if (epp) return epp;
  return s.toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ');
}

export function statusInfo(code: string): StatusInfo {
  const epp = EPP[code];
  if (epp) return { code, epp: true, ...epp, meaning: t(epp.meaning) };
  const rdap = RDAP_ONLY[code];
  if (rdap) return { code, epp: false, ...rdap, meaning: t(rdap.meaning) };
  return { code, epp: false, kind: 'info', meaning: t('statut propre à ce registre') };
}

/** Canonical, deduplicated, EPP codes first. "ok" is dropped when another EPP code is present. */
export function normalizeStatuses(list: string[]): string[] {
  const out: string[] = [];
  for (const raw of list) {
    const c = canonicalStatus(raw);
    if (c && !out.includes(c)) out.push(c);
  }
  const eppCodes = out.filter((c) => EPP[c]);
  // RFC 5731 §2.3: "ok" cannot be combined with any other status; RDAP servers still often send
  // "active" next to prohibitions (RFC 8056 maps it back to "ok"), which would read as a contradiction.
  const keep = eppCodes.length > 1 ? out.filter((c) => c !== 'ok') : out;
  return keep.sort((a, b) => Number(!EPP[a]) - Number(!EPP[b]));
}

export const isEpp = (code: string) => !!EPP[code];
