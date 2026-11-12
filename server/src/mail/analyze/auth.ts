// SPF, DKIM, DMARC, ARC, BIMI with mailauth, on our own resolver (no cache), plus the alignment
// between From, d= and MAIL FROM computed and shown even when the domain has no DMARC record.
import { authenticate, spf as spfCheck } from 'mailauth';
import net from 'node:net';
import { orgDomain } from '../received.js';
import { providerInfo } from '../../lib/provider.js';
import { FREEMAIL } from './thresholds.js';
import { isPublicIp } from '../../lib/net.js';
import type { StepContext } from './types.js';
import { t } from '../../i18n.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = Record<string, any>;

export interface DkimSignatureInfo {
  domain: string;
  selector: string;
  algo?: string;
  result: string;
  comment?: string;
  keyBits?: number;
  signedHeaders: string[];
  bodyLengthLimit?: number;
  unsignedBytes?: number;
  testing: boolean;
  aligned: 'strict' | 'relaxed' | false;
  signTime?: string | null;
  expires?: string | null;
  record?: string;
  warnings?: string[];
}

export interface AlignmentInfo {
  fromDomain?: string;
  /** adkim / aspf of the DMARC record, relaxed by default */
  mode: { spf: 'relaxed' | 'strict'; dkim: 'relaxed' | 'strict' };
  spf: {
    domain?: string;
    /** false: no public IP or no MAIL FROM, SPF was not evaluated (not a failure) */
    evaluated: boolean;
    result: string;
    /** what the interface shows for SPF in the alignment table */
    label: string;
    pass: boolean;
    aligned: 'strict' | 'relaxed' | false;
    alignedUnderMode: boolean;
  };
  dkim: { domain: string; selector: string; pass: boolean; aligned: 'strict' | 'relaxed' | false; alignedUnderMode: boolean }[];
  /** SPF or DKIM passes and aligns under the record's mode: DMARC would pass */
  aligned: boolean;
}

export function alignmentOf(a: string | undefined, b: string | undefined): 'strict' | 'relaxed' | false {
  if (!a || !b) return false;
  const x = a.toLowerCase().replace(/\.$/, '');
  const y = b.toLowerCase().replace(/\.$/, '');
  if (x === y) return 'strict';
  const ox = orgDomain(x);
  return ox && ox === orgDomain(y) ? 'relaxed' : false;
}

/** Shown in place of the envelope domain when an imported message has no Return-Path. */
export const noMailFrom = () => t('aucun MAIL FROM (message importé)');

/** Domain values coming from libraries can be missing, empty or the string "undefined". */
export function cleanDomain(d: unknown): string | undefined {
  if (typeof d !== 'string') return undefined;
  const v = d.trim().toLowerCase().replace(/\.$/, '');
  return v && v !== 'undefined' && v !== 'null' && v.includes('.') ? v : undefined;
}

/**
 * Headers written by check when SPF was not evaluated: Received-SPF none with the reason, and the
 * spf= entry of Authentication-Results replaced (mailauth would say temperror and postmaster@undefined).
 */
export function spfNoneHeaders(headers: string, mta: string, reason: string): string {
  const fields = headers.split(/\r?\n(?![ \t])/).filter((f) => f.trim());
  return fields
    .map((f) => {
      const unfolded = f.replace(/\r?\n[ \t]+/g, ' ');
      if (/^Received-SPF:/i.test(unfolded)) return `Received-SPF: none (${mta}: ${reason})`;
      if (/^Authentication-Results:/i.test(unfolded)) return unfolded.replace(/\bspf=[a-z]+(?:\s*\([^)]*\))?[^;]*/i, `spf=none (${reason})`);
      return unfolded;
    })
    .join('\r\n') + '\r\n';
}

export function parseTags(record: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (record ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return out;
}

const DMARC_ORDER = ['v', 'p', 'sp', 'np', 'adkim', 'aspf', 'pct', 't', 'rua', 'ruf', 'fo', 'ri', 'psd'];

export function buildDmarc(tags: Record<string, string>): string {
  const keys = [...DMARC_ORDER.filter((k) => tags[k] !== undefined), ...Object.keys(tags).filter((k) => !DMARC_ORDER.includes(k))];
  return keys.map((k) => `${k}=${tags[k]}`).join('; ');
}

/** SPF record with the fixes we can compute: qualifier of all, include of the provider, sending IP. */
export function suggestSpf(
  record: string | undefined,
  opts: { include?: string; ip?: string; addSender: boolean },
): string | undefined {
  const add: string[] = [];
  if (opts.addSender) {
    if (opts.include) add.push(`include:${opts.include}`);
    else if (opts.ip && net.isIPv4(opts.ip)) add.push(`ip4:${opts.ip}`);
    else if (opts.ip && net.isIPv6(opts.ip)) add.push(`ip6:${opts.ip}`);
  }
  if (!record) return add.length ? `v=spf1 ${add.join(' ')} ~all` : undefined;
  const terms = record.trim().split(/\s+/);
  if (!/^v=spf1$/i.test(terms[0] ?? '')) return undefined;
  let changed = false;
  const body = terms.slice(1).map((t) => {
    if (/^[+?]?all$/i.test(t)) {
      changed = true;
      return '~all';
    }
    return t;
  });
  const missing = add.filter((a) => !body.some((t) => t.toLowerCase() === a.toLowerCase()));
  if (missing.length) {
    const at = body.findIndex((t) => /^[-~+?]?all$/i.test(t) || /^redirect=/i.test(t));
    body.splice(at === -1 ? body.length : at, 0, ...missing);
    changed = true;
  }
  if (!body.some((t) => /^[-~+?]?all$/i.test(t) || /^redirect=/i.test(t))) {
    body.push('~all');
    changed = true;
  }
  return changed ? ['v=spf1', ...body].join(' ') : undefined;
}

function spfAllQualifier(record: string | undefined): string | undefined {
  const m = /(?:^|\s)([-~+?]?)all(?:\s|$)/i.exec(record ?? '');
  return m ? m[1] || '+' : undefined;
}

export async function runAuth(sc: StepContext) {
  const { facts, deps, c } = sc;
  const ip = facts.ip;
  const sender = facts.envelopeFrom ?? '';
  // SPF is not evaluated without a public IP or without a MAIL FROM: mailauth is then given no
  // IP (so DMARC never counts an SPF result) and the headers we write say spf=none and why.
  const spfSkip = !ip
    ? facts.input.via === 'smtp' ? t("IP d'envoi inconnue") : t("message importé, pas d'IP")
    : !isPublicIp(ip)
      ? t('IP locale')
      : !facts.envelopeKnown
        ? t('message importé, pas de MAIL FROM')
        : undefined;
  const res = (await authenticate(facts.input.raw, {
    ip: spfSkip ? undefined : ip,
    helo: facts.helo,
    sender: sender || undefined,
    mta: deps.config.mail.domain,
    resolver: deps.resolver as any,
    trustReceived: false,
  })) as unknown as Any;

  const envelopeDomain = facts.envelopeDomain;
  const fromDomain = facts.fromDomain;

  /* ---------------- SPF ---------------- */
  const spf = (res.spf || undefined) as Any | undefined;
  const spfResult: string = spf?.status?.result ?? 'none';
  const spfRecord: string | undefined = spf?.rr;
  const lookups = spf?.lookups?.count as number | undefined;
  c.vars.spf_record = spfRecord;
  c.vars.lookup_count = lookups;
  const provInfo = providerInfo(facts.provider?.key);
  const spfData: Any = {
    result: ip ? spfResult : 'unavailable',
    domain: facts.envelopeKnown ? (cleanDomain(spf?.domain) ?? envelopeDomain) : undefined,
    identity: !facts.envelopeKnown ? 'unknown' : sender ? 'mailfrom' : 'helo',
    comment: spf?.status?.comment,
    record: spfRecord,
    lookups: spf?.lookups,
  };
  if (!ip) {
    c.missing('SPF', t("IP d'envoi inconnue : aucun Received exploitable dans ce message"));
    spfData.result = 'unavailable';
  } else if (!isPublicIp(ip)) {
    // local test or private network: what SPF says about this address means nothing outside
    c.missing('SPF', t('{ip} est une adresse privée ou locale : SPF non évalué', { ip }));
    spfData.result = 'unavailable';
  } else if (!facts.envelopeKnown) {
    c.missing('SPF', t("Adresse d'enveloppe (MAIL FROM) inconnue : le message n'a pas de Return-Path"));
    spfData.result = 'unavailable';
  } else {
    const spfEvidence = [spf?.status?.comment, spfRecord ? t('Enregistrement : {record}', { record: spfRecord }) : undefined].filter(Boolean).join('\n');
    const addSender = spfResult === 'fail' || spfResult === 'softfail' || spfResult === 'neutral' || spfResult === 'none';
    const suggested = suggestSpf(spfRecord, { include: provInfo?.spfInclude, ip, addSender });
    const comment = String(spf?.status?.comment ?? '');
    switch (spfResult) {
      case 'pass':
        c.pass('spf.pass', 'spf', t('SPF valide pour {domain}', { domain: spf?.domain ?? envelopeDomain }), t('{ip} autorisée', { ip }));
        break;
      case 'fail':
        c.add('spf.fail', {
          evidence: spfEvidence,
          suggested,
          fallback: { title: t("Le SPF de {envelope_domain} n'autorise pas {ip}"), family: 'spf', severity: 'critical', penalty: 2.5 },
        });
        break;
      case 'softfail':
        c.add('spf.softfail', {
          evidence: spfEvidence,
          suggested,
          fallback: { title: t("Le SPF de {envelope_domain} n'autorise pas {ip} (softfail)"), family: 'spf', severity: 'high', penalty: 1 },
        });
        break;
      case 'neutral':
        c.add(spfAllQualifier(spfRecord) === '?' ? 'spf.neutral_all' : 'spf.neutral', {
          evidence: spfEvidence,
          suggested,
          fallback: { title: t('Le SPF de {envelope_domain} ne se prononce pas sur {ip}'), family: 'spf', severity: 'medium', penalty: 0.5 },
        });
        break;
      case 'none':
        c.add('spf.missing', {
          evidence: spfEvidence,
          suggested,
          fallback: { title: t("{envelope_domain} n'a pas d'enregistrement SPF"), family: 'spf', severity: 'high', penalty: 1.5 },
        });
        break;
      case 'permerror': {
        const id = /too many dns lookups|lookup limit|maximum (?:dns )?lookups/i.test(comment)
          ? 'spf.lookup_limit'
          : /void/i.test(comment)
            ? 'spf.void_lookup_limit'
            : /multiple|more than one/i.test(comment)
              ? 'spf.multiple_records'
              : 'spf.syntax_error';
        c.add(id, {
          evidence: spfEvidence,
          suggested,
          fallback: { title: t('Le SPF de {envelope_domain} est en erreur permanente'), family: 'spf', severity: 'critical', penalty: 2 },
        });
        break;
      }
      case 'temperror':
        c.add('spf.temperror', {
          evidence: spfEvidence,
          fallback: { title: t('Le SPF de {envelope_domain} n’a pas pu être lu (erreur DNS temporaire)'), family: 'spf', severity: 'medium', penalty: 0.5 },
        });
        break;
    }
    // record-level checks
    const q = spfAllQualifier(spfRecord);
    if (spfRecord && q === '+')
      c.add('spf.plus_all', {
        evidence: spfRecord,
        suggested: suggestSpf(spfRecord, { addSender: false }),
        fallback: { title: t('Le SPF de {envelope_domain} autorise le monde entier (+all)'), family: 'spf', severity: 'critical', penalty: 2 },
      });
    if (spfRecord && !q && !/redirect=/i.test(spfRecord))
      c.add('spf.no_all', {
        evidence: spfRecord,
        suggested: suggestSpf(spfRecord, { addSender: false }),
        fallback: { title: t('Le SPF de {envelope_domain} ne se termine pas par all'), family: 'spf', severity: 'medium', penalty: 0.5 },
      });
    if (spfRecord && /(^|\s)[-~+?]?ptr(:|\s|$)/i.test(spfRecord))
      c.add('spf.ptr_mechanism', { evidence: spfRecord, fallback: { title: t('Le SPF utilise le mécanisme ptr, déconseillé'), family: 'spf', severity: 'low', penalty: 0.3 } });
    if (net.isIPv6(ip) && ['fail', 'softfail', 'neutral'].includes(spfResult) && /(^|\s)[+]?ip4:/i.test(spfRecord ?? '') && !/(^|\s)[+]?ip6:/i.test(spfRecord ?? ''))
      c.add('infrastructure.ipv6_not_in_spf', { evidence: spfRecord, fallback: { title: t('Le message est parti en IPv6, absente du SPF'), family: 'infrastructure', severity: 'low', penalty: 0.2 } });
    if (lookups !== undefined && (lookups === 9 || lookups === 10) && spfResult !== 'permerror')
      c.add('spf.lookup_limit_near', {
        evidence: t('{n} requêtes DNS sur 10', { n: lookups }),
        fallback: { title: t('Le SPF de {envelope_domain} est proche de la limite de 10 requêtes'), family: 'spf', severity: 'low', penalty: 0.2 },
      });
  }

  // HELO identity (RFC 7208 §2.3), checked on its own when the HELO is a name
  if (ip && isPublicIp(ip) && facts.helo && /\./.test(facts.helo) && !/^\[/.test(facts.helo) && !net.isIP(facts.helo)) {
    try {
      const h = (await spfCheck({
        sender: `postmaster@${facts.helo}`,
        ip,
        helo: facts.helo,
        mta: deps.config.mail.domain,
        resolver: deps.resolver as any,
      })) as unknown as Any;
      const r = h?.status?.result as string | undefined;
      spfData.helo = { result: r, comment: h?.status?.comment, record: h?.rr };
      if (r === 'fail' || r === 'softfail')
        c.add('spf.helo_fail', {
          evidence: h?.status?.comment,
          fallback: { title: t("Le SPF du nom HELO {helo} n'autorise pas {ip}"), family: 'spf', severity: 'low', penalty: 0.3 },
        });
      else if (r === 'none')
        c.add('spf.helo_none', { fallback: { title: t("Le nom HELO {helo} n'a pas de SPF"), family: 'spf', severity: 'info', penalty: 0 } });
      else if (r === 'pass') c.pass('spf.helo_pass', 'spf', t('SPF du nom HELO {helo} valide', { helo: facts.helo }));
    } catch {
      /* HELO SPF is informative */
    }
  }

  /* ---------------- DMARC record (read before DKIM alignment) ---------------- */
  const dmarc = (res.dmarc || undefined) as Any | undefined;
  const dmarcRecord: string | undefined = dmarc?.rr;
  const dmarcTags = parseTags(dmarcRecord);
  c.vars.dmarc_record = dmarcRecord;
  const mode = {
    spf: (dmarcTags.aspf === 's' ? 'strict' : 'relaxed') as 'strict' | 'relaxed',
    dkim: (dmarcTags.adkim === 's' ? 'strict' : 'relaxed') as 'strict' | 'relaxed',
  };

  /* ---------------- DKIM ---------------- */
  const sigs: DkimSignatureInfo[] = ((res.dkim?.results ?? []) as Any[])
    .filter((r) => r.signingDomain)
    .map((r) => {
      const aligned = alignmentOf(r.signingDomain, fromDomain);
      return {
        domain: r.signingDomain,
        selector: r.selector,
        algo: r.algo,
        result: r.status?.result,
        comment: r.status?.comment,
        keyBits: r.modulusLength,
        signedHeaders: (Array.isArray(r.signingHeaders?.keys) ? (r.signingHeaders.keys as string[]) : String(r.signingHeaders?.keys ?? '').split(':'))
          .map((k) => k.trim().toLowerCase())
          .filter(Boolean),
        bodyLengthLimit: r.canonBodyLengthLimited ? r.canonBodyLengthLimit : undefined,
        unsignedBytes: r.status?.underSized,
        testing: !!r.status?.testing,
        aligned,
        signTime: r.signTime,
        expires: r.expiresAfter,
        record: r.rr,
        warnings: r.status?.warnings,
      };
    });
  const passing = sigs.filter((s) => s.result === 'pass');
  const firstSig = passing.find((s) => s.aligned) ?? passing[0] ?? sigs[0];
  if (firstSig) {
    c.vars.dkim_domain = firstSig.domain;
    c.vars.selector = firstSig.selector;
  }
  if (!sigs.length) {
    c.add('dkim.missing', {
      fallback: {
        title: t("Le message n'est pas signé DKIM"),
        why: t('Sans signature DKIM, les destinataires ne peuvent pas vérifier que le message vient bien de {domain} ni qu’il n’a pas été modifié.'),
        fix: [t("Activez la signature DKIM dans l'outil qui envoie les messages de {domain}, puis publiez la clé publique dans le DNS.")],
        family: 'dkim',
        severity: 'high',
        penalty: 1.5,
      },
    });
  }
  for (const s of sigs) {
    const v = { dkim_domain: s.domain, selector: s.selector, value: s.keyBits };
    const ev = [`d=${s.domain} s=${s.selector} a=${s.algo ?? '?'} : ${s.result}${s.comment ? ` (${s.comment})` : ''}`, s.record ? t('Clé : {key}', { key: `${s.record.slice(0, 120)}${s.record.length > 120 ? '…' : ''}` }) : undefined]
      .filter(Boolean)
      .join('\n');
    const comment = (s.comment ?? '').toLowerCase();
    if (s.result === 'pass') {
      c.pass(`dkim.pass.${s.domain}.${s.selector}`, 'dkim', t('Signature DKIM valide (d={domain}, s={selector})', { domain: s.domain, selector: s.selector }), s.keyBits ? t('clé de {bits} bits', { bits: s.keyBits }) : undefined);
    } else if (comment.includes('no key')) {
      c.add('dkim.key_not_found', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM {selector}._domainkey.{dkim_domain} est introuvable'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (comment.includes('invalid public key')) {
      c.add(/(^|;)\s*p=\s*(;|$)/.test(s.record ?? '') ? 'dkim.key_revoked' : 'dkim.key_syntax_error', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM publiée pour {selector}._domainkey.{dkim_domain} est invalide ou révoquée'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (comment.includes('body hash') && facts.headersOnly) {
      // the body was not provided: nothing to conclude
    } else if (comment.includes('body hash')) {
      c.add('dkim.body_hash_mismatch', { vars: v, evidence: ev, fallback: { title: t('Le corps du message a été modifié après la signature DKIM'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (comment.includes('expired')) {
      c.add('dkim.signature_expired', { vars: v, evidence: ev, fallback: { title: t('La signature DKIM de {dkim_domain} a expiré'), family: 'dkim', severity: 'high', penalty: 1 } });
    } else if (comment.includes('from field not signed')) {
      c.add('dkim.from_not_signed', { vars: v, evidence: ev, fallback: { title: t("La signature DKIM ne couvre pas l'en-tête From"), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (comment.includes('inappropriate key algorithm') || comment.includes('inappropriate hash algorithm')) {
      c.add('dkim.key_algorithm_mismatch', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM ne correspond pas à l’algorithme de la signature'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (s.result === 'policy' && comment.includes('weak')) {
      c.add('dkim.key_below_1024', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM de {dkim_domain} est trop courte ({value} bits)'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    } else if (s.result === 'temperror') {
      c.add('dkim.key_dns_temperror', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM de {dkim_domain} n’a pas pu être lue (erreur DNS)'), family: 'dkim', severity: 'medium', penalty: 0.5 } });
    } else {
      c.add('dkim.signature_invalid', { vars: v, evidence: ev, fallback: { title: t('La signature DKIM de {dkim_domain} est invalide'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    }
    if (s.keyBits && s.keyBits < 1024 && s.result !== 'policy')
      c.add('dkim.key_below_1024', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM de {dkim_domain} est trop courte ({value} bits)'), family: 'dkim', severity: 'high', penalty: 1.5 } });
    else if (s.keyBits && s.keyBits >= 1024 && s.keyBits < 2048)
      c.add('dkim.key_1024', { vars: v, evidence: ev, fallback: { title: t('La clé DKIM de {dkim_domain} fait {value} bits'), why: t('Une clé RSA de 2048 bits est recommandée ; 1024 bits reste accepté mais offre une marge faible.'), family: 'dkim', severity: 'low', penalty: 0.2 } });
    if (s.algo === 'rsa-sha1')
      c.add('dkim.rsa_sha1', { vars: v, evidence: ev, fallback: { title: t('La signature DKIM utilise rsa-sha1, abandonné'), family: 'dkim', severity: 'medium', penalty: 0.7 } });
    if (s.bodyLengthLimit !== undefined)
      c.add('dkim.length_tag', {
        vars: { ...v, value: s.bodyLengthLimit },
        evidence: `l=${s.bodyLengthLimit}${s.unsignedBytes ? `, ${t('{n} octets non signés', { n: s.unsignedBytes })}` : ''}`,
        fallback: { title: t('La signature DKIM ne couvre que le début du corps (l=)'), family: 'dkim', severity: s.unsignedBytes ? 'medium' : 'low', penalty: s.unsignedBytes ? 0.7 : 0.3 },
      });
    if (s.testing)
      c.add('dkim.key_testing_flag', { vars: v, evidence: s.record, fallback: { title: t('La clé DKIM de {dkim_domain} est en mode test (t=y)'), family: 'dkim', severity: 'low', penalty: 0.2 } });
    if (s.signTime && Date.parse(s.signTime) > (deps.now?.() ?? new Date()).getTime() + 300_000)
      c.add('dkim.timestamp_future', { vars: v, evidence: `t=${s.signTime}`, fallback: { title: t('La signature DKIM est datée dans le futur'), family: 'dkim', severity: 'low', penalty: 0.3 } });
    if (s.result === 'pass') {
      const important = ['subject', 'date', 'to', 'message-id'];
      const missing = important.filter((h) => !s.signedHeaders.includes(h));
      if (missing.length >= 2)
        c.add('dkim.headers_not_signed', {
          vars: { ...v, value: missing.join(', ') },
          evidence: `h=${s.signedHeaders.join(':')}`,
          fallback: { title: t('La signature DKIM ne couvre pas {value}'), family: 'dkim', severity: 'low', penalty: 0.2 },
        });
    }
  }

  /* ---------------- Alignment ---------------- */
  // an imported message without Return-Path has no MAIL FROM: SPF is not evaluated, not failed
  const spfPass = facts.envelopeKnown && !!ip && isPublicIp(ip) && spfResult === 'pass';
  const spfIdentityDomain = facts.envelopeKnown ? (cleanDomain(spf?.domain) ?? envelopeDomain) : undefined;
  const spfLabel = !facts.envelopeKnown
    ? t('SPF non évalué : {reason}', { reason: noMailFrom() })
    : !ip
      ? t("SPF non évalué : IP d'envoi inconnue")
      : !isPublicIp(ip)
        ? t('SPF non évalué : {ip} est une adresse privée ou locale', { ip })
        : spfPass
          ? t('SPF valide pour {domain}', { domain: spfIdentityDomain ?? t('un domaine inconnu') })
          : t('SPF non valide pour {domain}', { domain: spfIdentityDomain ?? t('un domaine inconnu') });
  const spfAligned = alignmentOf(spfIdentityDomain, fromDomain);
  const underMode = (a: 'strict' | 'relaxed' | false, m: 'strict' | 'relaxed') => (m === 'strict' ? a === 'strict' : a !== false);
  const alignment: AlignmentInfo = {
    fromDomain,
    mode,
    spf: {
      domain: spfIdentityDomain,
      evaluated: !spfSkip,
      result: spfSkip ? 'not_evaluated' : spfResult,
      label: spfSkip ? t('SPF non évalué ({reason})', { reason: spfSkip }) : spfPass ? t('SPF valide pour {domain}', { domain: spfIdentityDomain }) : t('SPF ne passe pas ({result})', { result: spfResult }),
      pass: spfPass,
      aligned: spfAligned,
      alignedUnderMode: spfPass && underMode(spfAligned, mode.spf),
    },
    dkim: sigs.map((s) => ({
      domain: s.domain,
      selector: s.selector,
      pass: s.result === 'pass',
      aligned: s.aligned,
      alignedUnderMode: s.result === 'pass' && underMode(s.aligned, mode.dkim),
    })),
    aligned: false,
  };
  alignment.aligned = alignment.spf.alignedUnderMode || alignment.dkim.some((d) => d.alignedUnderMode);
  if (fromDomain) {
    if (spfPass && !underMode(spfAligned, mode.spf))
      c.add('alignment.spf_not_aligned', {
        vars: { envelope_domain: spfIdentityDomain },
        evidence: t('From : {from} / MAIL FROM : {mailfrom} ({mode})', { from: fromDomain, mailfrom: spfIdentityDomain, mode: mode.spf === 'strict' ? t('alignement strict exigé') : t('alignement relâché') }),
        fallback: { title: t("Le SPF passe pour {envelope_domain}, qui n'est pas aligné avec {domain}"), family: 'alignment', severity: 'low', penalty: 0.3 },
      });
    const dkimPassNotAligned = alignment.dkim.filter((d) => d.pass && !d.alignedUnderMode);
    // signed only with the sending provider's own domain: the provider-specific entry explains it better
    const espOnly = !!facts.provider && dkimPassNotAligned.some((d) => facts.provider!.evidence.some((e) => e.includes(`d=${d.domain}`)));
    if (dkimPassNotAligned.length && !alignment.dkim.some((d) => d.alignedUnderMode))
      c.add(espOnly ? 'dkim.esp_domain_only' : 'alignment.dkim_not_aligned', {
        vars: { dkim_domain: dkimPassNotAligned[0].domain, selector: dkimPassNotAligned[0].selector },
        evidence: t('From : {from} / d={d}', { from: fromDomain, d: dkimPassNotAligned.map((d) => d.domain).join(', ') }),
        fallback: { title: t("La signature DKIM valide (d={dkim_domain}) n'est pas alignée avec {domain}"), family: 'alignment', severity: 'medium', penalty: 0.7 },
      });
    // with a DMARC record, the failure is reported once, as dmarc.fail
    if (!alignment.aligned && (!dmarcRecord || !res.dmarc))
      c.add('alignment.none_aligned', {
        vars: {
          envelope_domain: spfIdentityDomain ?? (facts.envelopeKnown ? undefined : noMailFrom()),
          dkim_domain: sigs[0]?.domain ?? t('aucune signature DKIM'),
        },
        evidence: t('From : {from} ; {spf} ; DKIM {dkim}', {
          from: fromDomain,
          spf: spfLabel,
          dkim: passing.length ? passing.map((s) => t('valide pour {domain}', { domain: s.domain })).join(', ') : t('absent ou invalide'),
        }),
        fallback: {
          title: t('Ni SPF ni DKIM ne valident {domain}'),
          why: t("DMARC exige qu'au moins SPF ou DKIM passe pour le domaine du From (ou un domaine du même organisme). Ce message échouerait DMARC."),
          family: 'alignment',
          severity: 'high',
          penalty: 1.5,
        },
      });
    else c.pass('alignment.ok', 'alignment', t('From aligné ({by})', { by: alignment.dkim.some((d) => d.alignedUnderMode) ? 'DKIM' : 'SPF' }), fromDomain);
  }

  /* ---------------- DMARC ---------------- */
  const dmarcResult: string = dmarc ? (dmarc.status?.result ?? 'none') : 'skipped';
  const dmarcData: Any = {
    result: dmarcResult,
    skipReason: res.dmarcSkipReason,
    policy: dmarc?.policy,
    p: dmarc?.p,
    sp: dmarc?.sp,
    np: dmarc?.np,
    testMode: dmarc?.testMode,
    record: dmarcRecord,
    policyDomain: dmarc?.policyDomain,
    orgDomain: dmarc?.domain,
    tags: dmarcTags,
  };
  const dmarcDomain = dmarc?.policyDomain ?? orgDomain(fromDomain) ?? fromDomain;
  const ruaDefault = `mailto:dmarc@${orgDomain(fromDomain) ?? fromDomain}`;
  if (!dmarc) {
    // From header unusable: reported by the header checks (from_missing / from_multiple)
  } else if (dmarcResult === 'none' || !dmarcRecord) {
    const sub = !!fromDomain && !!orgDomain(fromDomain) && orgDomain(fromDomain) !== fromDomain;
    c.add(sub ? 'dmarc.subdomain_no_policy' : 'dmarc.missing', {
      vars: { value: `_dmarc.${orgDomain(fromDomain) ?? fromDomain}` },
      suggested: buildDmarc({ v: 'DMARC1', p: 'none', rua: ruaDefault }),
      fallback: {
        title: t("{domain} n'a pas d'enregistrement DMARC"),
        why: t('Gmail, Yahoo et Microsoft exigent un enregistrement DMARC pour les envois en nombre ; sans lui, rien ne protège {domain} contre l’usurpation.'),
        fix: [t('Publiez un enregistrement TXT sur _dmarc.{domain} avec la valeur proposée.')],
        family: 'dmarc',
        severity: 'high',
        penalty: 1.5,
      },
    });
  } else {
    if (dmarcResult === 'pass') c.pass('dmarc.pass', 'dmarc', t('DMARC valide (p={p})', { p: dmarc.p }), dmarcRecord);
    else if (dmarcResult === 'fail') {
      // a consumer mailbox domain (gmail.com…) in From sent through other servers: specific entry
      const freemail = !!fromDomain && FREEMAIL.has(fromDomain);
      const id = freemail ? 'alignment.freemail_from' : dmarc.policy === 'reject' ? 'dmarc.fail_reject' : dmarc.policy === 'quarantine' ? 'dmarc.fail_quarantine' : 'dmarc.fail_none';
      c.add(id, {
        vars: { value: dmarc.policy },
        evidence: `${dmarcRecord}\n${t('Politique appliquée : {policy}', { policy: dmarc.policy })}`,
        fallback: { title: t('Le message échoue DMARC (politique {value})'), family: freemail ? 'alignment' : 'dmarc', severity: dmarc.policy === 'none' ? 'high' : 'critical', penalty: dmarc.policy === 'none' ? 1 : 2.5 },
      });
    }
    else if (dmarcResult === 'temperror')
      c.add('dmarc.temperror', { evidence: dmarc.error, fallback: { title: t("DMARC n'a pas pu être évalué (erreur DNS)"), family: 'dmarc', severity: 'medium', penalty: 0.5 } });

    if (dmarc.p === 'none')
      c.add('dmarc.policy_none', {
        evidence: dmarcRecord,
        suggested: alignment.aligned ? buildDmarc({ ...dmarcTags, p: 'quarantine' }) : undefined,
        fallback: { title: t('La politique DMARC de {domain} est p=none'), family: 'dmarc', severity: 'low', penalty: 0.2 },
      });
    if (dmarc.testMode)
      c.add('dmarc.testing_flag', { evidence: dmarcRecord, suggested: buildDmarc(Object.fromEntries(Object.entries(dmarcTags).filter(([k]) => k !== 't'))), fallback: { title: t('DMARC de {domain} en mode test (t=y)'), family: 'dmarc', severity: 'low', penalty: 0.2 } });
    if (!dmarcTags.p && dmarcRecord)
      c.add('dmarc.policy_invalid', { evidence: dmarcRecord, suggested: buildDmarc({ ...dmarcTags, v: 'DMARC1', p: 'none' }), fallback: { title: t('Le DMARC de {domain} n’a pas de politique p= valide'), family: 'dmarc', severity: 'medium', penalty: 1 } });
    if (!dmarcTags.rua)
      c.add('dmarc.rua_missing', {
        evidence: dmarcRecord,
        suggested: buildDmarc({ ...dmarcTags, rua: ruaDefault }),
        fallback: { title: t('Le DMARC de {domain} ne demande aucun rapport (rua)'), family: 'dmarc', severity: 'low', penalty: 0.1 },
      });
    const strength = (x?: string) => (x === 'reject' ? 2 : x === 'quarantine' ? 1 : 0);
    const badRua = (dmarcTags.rua ?? '').split(',').map((u) => u.trim()).filter((u) => u && !/^(mailto|https):/i.test(u));
    if (badRua.length)
      c.add('dmarc.rua_invalid_uri', { vars: { value: badRua.join(', ') }, evidence: dmarcRecord, suggested: buildDmarc({ ...dmarcTags, rua: ruaDefault }), fallback: { title: t('Adresse de rapport DMARC invalide'), family: 'dmarc', severity: 'low', penalty: 0.3 } });
    if (dmarcTags.pct === '0' && strength(dmarc.p) > 0)
      c.add('dmarc.pct_zero', { evidence: dmarcRecord, fallback: { title: t('pct=0 : la politique DMARC ne s’applique à aucun message'), family: 'dmarc', severity: 'low', penalty: 0.3 } });
    if (strength(dmarc.p) > 0 && dmarcTags.sp && strength(dmarcTags.sp) < strength(dmarc.p))
      c.add('dmarc.sp_weaker', { evidence: dmarcRecord, fallback: { title: t('Les sous-domaines de {domain} ne sont pas protégés (sp=none)'), family: 'dmarc', severity: 'low', penalty: 0.2 } });
    if (dmarcTags.pct && dmarcTags.pct !== '100' && dmarcTags.pct !== '0' && strength(dmarc.p) > 0)
      c.add('dmarc.pct_partial', { vars: { value: dmarcTags.pct }, evidence: dmarcRecord, fallback: { title: t('pct={value} : DMARC ne s’applique qu’à une partie des messages'), family: 'dmarc', severity: 'info', penalty: 0 } });
  }
  dmarcData.policyRecordName = dmarcDomain ? `_dmarc.${dmarcDomain}` : undefined;

  /* ---------------- ARC ---------------- */
  const arc = (res.arc || undefined) as Any | undefined;
  const arcData = { result: arc?.status?.result ?? 'none', comment: arc?.status?.comment, instance: arc?.i || 0 };
  if (arcData.result === 'fail') c.add('arc.chain_fail', { evidence: arc?.status?.comment, fallback: { title: t('La chaîne ARC est invalide'), family: 'arc', severity: 'medium', penalty: 0.5 } });
  else if (arcData.result === 'pass') {
    c.pass('arc.pass', 'arc', t('Chaîne ARC valide ({n} relais)', { n: arcData.instance }));
    if (dmarcResult === 'fail') c.add('arc.valid_untrusted', { fallback: { title: t('ARC valide mais DMARC échoue'), family: 'arc', severity: 'info', penalty: 0 } });
  }

  /* ---------------- BIMI ---------------- */
  const bimi = (res.bimi || undefined) as Any | undefined;
  const bimiData = {
    result: bimi?.status?.result ?? 'none',
    comment: bimi?.status?.comment,
    location: bimi?.location,
    authority: bimi?.authority,
    record: bimi?.rr,
  };
  if (bimiData.result === 'pass') {
    c.pass('bimi.pass', 'bimi', t('BIMI publié'), bimiData.location);
    if (!bimiData.authority)
      c.add('bimi.no_certificate', { evidence: bimiData.record, fallback: { title: t('BIMI sans certificat VMC ou CMC'), why: t('Gmail n’affiche le logo BIMI qu’avec un certificat de marque (VMC ou CMC) référencé par a=.'), family: 'bimi', severity: 'info', penalty: 0 } });
  } else if (bimiData.result === 'fail')
    c.add('bimi.syntax_invalid', { evidence: [bimiData.comment, bimiData.record].filter(Boolean).join('\n'), fallback: { title: t('L’enregistrement BIMI de {domain} est invalide'), family: 'bimi', severity: 'low', penalty: 0.2 } });
  else if (bimiData.result === 'declined') c.add('bimi.declined', { evidence: bimiData.record, fallback: { title: t('{domain} refuse explicitement BIMI'), family: 'bimi', severity: 'info', penalty: 0 } });
  else if (bimiData.result === 'none' && dmarcResult === 'pass')
    c.add('bimi.missing', { fallback: { title: t("{domain} n'a pas d'enregistrement BIMI"), family: 'bimi', severity: 'info', penalty: 0 } });

  sc.data.auth = {
    spf: spfData,
    dkim: sigs,
    dmarc: dmarcData,
    alignment,
    arc: arcData,
    bimi: bimiData,
    authenticationResults: typeof res.headers === 'string' ? (spfSkip ? spfNoneHeaders(res.headers, deps.config.mail.domain, spfSkip) : res.headers) : undefined,
  };
  return { spfResult, spfRecord, sigs, alignment, dmarcResult, dmarcRecord, dmarcPolicy: dmarc?.p as string | undefined };
}
