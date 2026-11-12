// Header fields: presence and form of Message-ID, Date, From, Reply-To, Sender, To, Subject,
// MIME-Version, line length, encodings (RFC 5322, RFC 2045-2047).
import { decodeWords, firstHeader, headerValues, walk } from '../mime.js';
import { orgDomain } from '../received.js';
import { FREEMAIL, T } from './thresholds.js';
import type { StepContext } from './types.js';
import { t } from '../../i18n.js';

const SINGLE = ['date', 'from', 'sender', 'reply-to', 'to', 'cc', 'bcc', 'message-id', 'in-reply-to', 'references', 'subject'];

export function domainOf(addr: string | undefined): string | undefined {
  const m = /@([^@\s>]+)>?\s*$/.exec(addr ?? '');
  return m ? m[1].toLowerCase().replace(/\.$/, '') : undefined;
}

/** First addr-spec of an address header. Good enough for Reply-To and Sender checks. */
export function firstAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(value);
  if (angle) return angle[1];
  const bare = /([^\s<>",;:]+@[^\s<>",;:]+)/.exec(value);
  return bare?.[1];
}

function countEmoji(s: string): number {
  return (s.match(/\p{Extended_Pictographic}/gu) ?? []).length;
}

export function runHeaders(sc: StepContext) {
  const { facts, c } = sc;
  const H = facts.headers;
  const count = (k: string) => H.filter((h) => h.key === k).length;
  const data: Record<string, unknown> = {};
  sc.data.headers = data;

  // Message-ID
  const mid = firstHeader(H, 'message-id');
  data.messageId = mid;
  if (!mid) c.add('headers.message_id_missing', { fallback: { title: t('Le message n’a pas de Message-ID'), family: 'headers', severity: 'medium', penalty: 0.7 } });
  else {
    const m = /^<([^<>@\s]+)@([^<>@\s]+)>$/.exec(mid.trim());
    if (!m) c.add('headers.message_id_malformed', { vars: { value: mid }, evidence: mid, fallback: { title: t('Message-ID mal formé'), family: 'headers', severity: 'low', penalty: 0.3 } });
    else if (/^(localhost|localhost\.localdomain|localdomain|[\d.]+|\[[\d.]+\])$/i.test(m[2]) || !m[2].includes('.'))
      c.add('headers.message_id_localhost', { vars: { value: m[2] }, evidence: mid, fallback: { title: t('Message-ID généré avec un nom de machine local'), family: 'headers', severity: 'low', penalty: 0.3 } });
    else c.pass('headers.message_id', 'headers', t('Message-ID présent et bien formé'), mid);
  }

  // Date
  const date = firstHeader(H, 'date');
  data.date = date;
  if (!date) c.add('headers.date_missing', { fallback: { title: t('Le message n’a pas d’en-tête Date'), family: 'headers', severity: 'high', penalty: 1 } });
  else {
    const ts = Date.parse(date.replace(/\([^)]*\)/g, '').trim());
    const rfc = /^\s*(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s*)?\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}(?::\d{2})?\s+(?:[+-]\d{4}|UT|GMT|[ECMP][SD]T|Z)/i.test(date);
    if (!Number.isFinite(ts) || !rfc) c.add('headers.date_malformed', { evidence: date, fallback: { title: t('En-tête Date mal formé'), family: 'headers', severity: 'low', penalty: 0.3 } });
    if (Number.isFinite(ts)) {
      const recv = facts.receivedAt.getTime();
      const skew = ts - recv;
      data.dateSkewSec = Math.round(skew / 1000);
      if (skew > T.maxDateSkewFutureMs)
        c.add('headers.date_future', { vars: { value: t('{n} min', { n: Math.round(skew / 60000) }) }, evidence: date, fallback: { title: t('Le message est daté dans le futur'), family: 'headers', severity: 'medium', penalty: 0.5 } });
      else if (-skew > T.maxDateSkewPastMs)
        c.add('headers.date_too_old', { vars: { value: t('{n} h', { n: Math.round(-skew / 3600000) }) }, evidence: date, fallback: { title: t('Le message est daté bien avant sa réception'), family: 'headers', severity: 'medium', penalty: 0.5 } });
      else if (rfc) c.pass('headers.date', 'headers', t('Date présente et cohérente'), date);
    }
  }

  // From
  const froms = headerValues(H, 'from');
  data.from = froms[0];
  if (!froms.length || !facts.fromAddress)
    c.add('headers.from_missing', { fallback: { title: t('Le message n’a pas d’expéditeur (From)'), family: 'headers', severity: 'critical', penalty: 3 } });
  else if (froms.length > 1 || facts.fromCount > 1)
    c.add('headers.from_multiple', { evidence: froms.join('\n'), fallback: { title: t('Plusieurs adresses dans From'), family: 'headers', severity: 'high', penalty: 1 } });
  else {
    const name = facts.fromName?.trim() ?? '';
    if (!name) c.add('headers.from_no_display_name', { fallback: { title: t('From sans nom affiché'), family: 'headers', severity: 'low', penalty: 0.1 } });
    else {
      const inName = /[^\s<>"@]+@([^\s<>"@]+\.[a-z]{2,})/i.exec(name);
      if (inName && orgDomain(inName[1]) !== orgDomain(facts.fromDomain))
        c.add('headers.from_display_name_has_address', { vars: { value: name }, evidence: froms[0], fallback: { title: t('Le nom affiché contient une autre adresse'), family: 'headers', severity: 'high', penalty: 1.5 } });
    }
    c.pass('headers.from', 'headers', t('From présent et unique'), decodeWords(froms[0]).text);
  }

  // Reply-To, Sender, Return-Path
  const replyTo = firstAddress(firstHeader(H, 'reply-to'));
  const rtDomain = domainOf(replyTo);
  data.replyTo = replyTo;
  if (rtDomain && facts.fromDomain && orgDomain(rtDomain) !== orgDomain(facts.fromDomain)) {
    if (FREEMAIL.has(rtDomain) && !FREEMAIL.has(facts.fromDomain))
      c.add('headers.reply_to_freemail', { vars: { value: replyTo }, evidence: `Reply-To : ${replyTo}`, fallback: { title: t('Les réponses partent vers une messagerie gratuite'), family: 'headers', severity: 'medium', penalty: 0.7 } });
    else
      c.add('headers.reply_to_other_domain', { vars: { value: replyTo }, evidence: `Reply-To : ${replyTo}`, fallback: { title: t('Reply-To sur un autre domaine que From'), family: 'headers', severity: 'low', penalty: 0.3 } });
  }
  const sender = firstAddress(firstHeader(H, 'sender'));
  if (sender && facts.fromDomain && orgDomain(domainOf(sender)) !== orgDomain(facts.fromDomain))
    c.add('headers.sender_inconsistent', { vars: { value: sender }, evidence: `Sender : ${sender}`, fallback: { title: t('Sender sur un autre domaine que From'), family: 'headers', severity: 'low', penalty: 0.2 } });
  if (facts.envelopeDomain && facts.fromDomain && orgDomain(facts.envelopeDomain) !== orgDomain(facts.fromDomain))
    c.add('headers.return_path_other_domain', { evidence: `MAIL FROM : ${facts.envelopeFrom}`, fallback: { title: t('Adresse de retour sur un autre domaine'), family: 'headers', severity: 'info', penalty: 0 } });

  // To
  const to = firstHeader(H, 'to');
  if (!to && !count('cc')) c.add('headers.to_missing', { fallback: { title: t('Pas de destinataire visible (To)'), family: 'headers', severity: 'low', penalty: 0.3 } });
  else if (to && /undisclosed[- ]recipients|destinataires inconnus|recipient list suppressed/i.test(to))
    c.add('headers.to_undisclosed', { evidence: to, fallback: { title: t('Destinataires masqués'), family: 'headers', severity: 'medium', penalty: 0.5 } });
  if (count('bcc')) c.add('headers.bcc_visible', { fallback: { title: t('Un en-tête Bcc est visible'), family: 'headers', severity: 'low', penalty: 0.2 } });

  // Subject
  const subjRaw = firstHeader(H, 'subject');
  if (subjRaw === undefined) c.add('headers.subject_missing', { fallback: { title: t('Le message n’a pas d’objet'), family: 'headers', severity: 'medium', penalty: 0.5 } });
  else {
    const { text: subj, invalid } = decodeWords(subjRaw);
    data.subject = subj;
    if (!subj.trim()) c.add('headers.subject_empty', { fallback: { title: t('Objet vide'), family: 'headers', severity: 'medium', penalty: 0.5 } });
    else {
      const letters = subj.replace(/[^\p{L}]/gu, '');
      const upper = subj.replace(/[^\p{Lu}]/gu, '');
      if (letters.length >= T.subjectCapsMinLetters && upper.length / letters.length >= T.subjectCapsRatio)
        c.add('headers.subject_all_caps', { evidence: subj, fallback: { title: t('Objet en majuscules'), family: 'headers', severity: 'medium', penalty: 0.5 } });
      const emoji = countEmoji(subj);
      if (emoji > T.subjectMaxEmoji) c.add('headers.subject_emoji_excess', { vars: { value: emoji }, evidence: subj, fallback: { title: t('Trop d’emoji dans l’objet'), family: 'headers', severity: 'low', penalty: 0.3 } });
      if (/^\s*(re|tr|fw|fwd)\s*:/i.test(subj) && !count('in-reply-to') && !count('references'))
        c.add('headers.subject_fake_reply', { evidence: subj, fallback: { title: t('Faux « Re: » dans l’objet'), family: 'headers', severity: 'medium', penalty: 0.7 } });
    }
    if (invalid)
      c.add('headers.subject_encoding_broken', { evidence: subjRaw.slice(0, 200), fallback: { title: t('Objet mal encodé'), family: 'headers', severity: 'medium', penalty: 0.5 } });
  }

  // Duplicates
  const dups = SINGLE.filter((k) => count(k) > 1);
  if (dups.length)
    c.add('headers.duplicate_single_instance', { vars: { value: dups.join(', ') }, evidence: dups.map((k) => `${k} ×${count(k)}`).join(', '), fallback: { title: t('En-têtes en double : {value}'), family: 'headers', severity: 'medium', penalty: 0.7 } });

  // X-Mailer
  const xm = firstHeader(H, 'x-mailer') ?? '';
  if (/PHPMailer/i.test(xm) || count('x-php-originating-script'))
    c.add('headers.x_mailer_phpmailer', { vars: { value: xm || 'X-PHP-Originating-Script' }, evidence: xm, fallback: { title: t('Envoyé par un script PHP'), family: 'headers', severity: 'low', penalty: 0.3 } });

  // Received count, Precedence
  const rc = count('received');
  if (rc > T.maxReceivedHops) c.add('headers.received_too_many', { vars: { value: rc }, fallback: { title: t('{value} en-têtes Received'), family: 'headers', severity: 'low', penalty: 0.3 } });
  const prec = firstHeader(H, 'precedence');
  if (prec && /^(bulk|junk|list)$/i.test(prec.trim()))
    c.add('headers.precedence_bulk', { vars: { value: prec }, fallback: { title: t('Precedence: {value}'), family: 'headers', severity: 'low', penalty: 0.1 } });

  // MIME
  const hasCT = count('content-type') > 0;
  const body8 = facts.parsed.body.some((b) => b > 0x7f);
  if (!count('mime-version') && (hasCT || body8))
    c.add('headers.mime_version_missing', { fallback: { title: t('MIME-Version absent'), family: 'headers', severity: 'medium', penalty: 0.5 } });

  // line length (RFC 5322 §2.1.1)
  data.maxLineLength = facts.parsed.maxLineLength;
  if (facts.parsed.maxLineLength > T.maxLineLength)
    c.add('headers.line_too_long', {
      vars: { value: facts.parsed.maxLineLength },
      evidence: t('{n} ligne(s) de plus de 998 caractères, la plus longue en fait {max}', { n: facts.parsed.longLines, max: facts.parsed.maxLineLength }),
      fallback: { title: t('Lignes de plus de 998 caractères'), family: 'headers', severity: 'high', penalty: 1 },
    });

  // headers size, 8-bit in headers
  data.headerBytes = facts.parsed.headerBytes;
  if (facts.parsed.headerBytes > T.maxHeadersBytes)
    c.add('headers.headers_oversized', { vars: { value: t('{n} Ko', { n: Math.round(facts.parsed.headerBytes / 1024) }) }, fallback: { title: t('En-têtes très volumineux'), family: 'headers', severity: 'low', penalty: 0.3 } });
  const raw8 = H.filter((h) => /[\x80-\xff]/.test(h.raw) && !['received', 'authentication-results'].includes(h.key));
  if (raw8.length)
    c.add('headers.raw_8bit_in_headers', { vars: { value: raw8.map((h) => h.name).join(', ') }, fallback: { title: t('Caractères non encodés dans les en-têtes'), family: 'headers', severity: 'medium', penalty: 0.5 } });

  // charset and transfer encoding of each part
  walk(facts.parsed.root, (p) => {
    if (p.children.length) {
      if (!['7bit', '8bit', 'binary'].includes(p.cte))
        c.add('headers.cte_inconsistent', { vars: { value: t('{type} en {cte}', { type: p.contentType, cte: p.cte }) }, fallback: { title: t('Encodage de transfert incohérent'), family: 'headers', severity: 'medium', penalty: 0.5 } });
      return;
    }
    if (p.cte === '7bit' && p.has8bit)
      c.add('headers.cte_inconsistent', { vars: { value: t('{type} déclaré 7bit avec des octets 8 bits', { type: p.contentType }) }, fallback: { title: t('Encodage de transfert incohérent'), family: 'headers', severity: 'medium', penalty: 0.5 } });
    if (p.contentType.startsWith('text/')) {
      const decoded8 = p.decoded.some((b) => b > 0x7f);
      if (!p.charsetDeclared && decoded8)
        c.add('headers.charset_missing', { fallback: { title: t('Jeu de caractères non déclaré'), family: 'headers', severity: 'low', penalty: 0.3 } });
      if (p.invalidUtf8)
        c.add('headers.charset_mismatch', { vars: { value: t('{type} déclaré utf-8', { type: p.contentType }) }, fallback: { title: t('Jeu de caractères incorrect'), family: 'headers', severity: 'medium', penalty: 0.5 } });
    }
  });
}
