// Pure logic of the mail test pages: ordering of what costs points, the message path, the
// live stream reducer, the compliance matrix, the preview document. Tested in logic.test.ts.
import type { Finding, PassedCheck } from '../../lib/types';
import type { Deviation } from '../../components/Report';
import { fmtPenalty, plural } from '../../lib/format';
import { locale, msg, t, tn } from '../../lib/i18n';
import type {
  AddressInfo, AxisSummary, Hop, Indicators, MailReport, MailReportData, MessageSummary, ProviderId, Requirement, StepState, StoredReport,
} from './types';

/* ---------- what costs points ---------- */

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Findings that cost points, the most expensive first (then the most severe, then by title). */
export function lostPoints<F extends Pick<Finding, 'penalty' | 'severity' | 'title'>>(findings: F[]): F[] {
  return findings
    .map((f, i) => ({ f, i }))
    .filter(({ f }) => f.penalty > 0)
    .sort(
      (a, b) =>
        b.f.penalty - a.f.penalty ||
        (SEVERITY_RANK[a.f.severity] ?? 9) - (SEVERITY_RANK[b.f.severity] ?? 9) ||
        a.i - b.i,
    )
    .map(({ f }) => f);
}

/** Findings of a section, costly ones first, free notes last. */
export function sectionOrder<F extends Pick<Finding, 'penalty' | 'severity' | 'title'>>(findings: F[]): F[] {
  return [...lostPoints(findings), ...findings.filter((f) => f.penalty <= 0)];
}

export const sumPenalty = (fs: Pick<Finding, 'penalty'>[]) => Math.round(fs.reduce((n, f) => n + Math.max(0, f.penalty), 0) * 10) / 10;

/** Deviation of a row that groups several findings: the sum of their points, red if one is severe. */
export function groupDeviation(fs: Pick<Finding, 'penalty' | 'severity'>[], okText = t('conforme')): Deviation {
  const lost = sumPenalty(fs);
  if (lost <= 0) return fs.length ? { kind: 'info', text: t('noté') } : { kind: 'ok', text: okText };
  const severe = fs.some((f) => f.penalty > 0 && (f.severity === 'critical' || f.severity === 'high'));
  return { kind: severe ? 'out' : 'warn', direction: 'down', text: fmtPenalty(lost), label: t('Retire {n} point de la note', { n: fmtPenalty(lost) }) };
}

/** Split the findings and passed checks of a section between explicit rows (by id prefix) and the rest. */
export function takeByPrefix<T extends { id: string }>(items: T[], prefixes: string[], used: Set<string>): T[] {
  const out = items.filter((x) => !used.has(x.id) && prefixes.some((p) => x.id.startsWith(p)));
  for (const x of out) used.add(x.id);
  return out;
}

/* ---------- the message path ---------- */

export interface PathNode {
  name: string;
  ip?: string;
  ptr?: string;
  aliases: string[];
}
export interface PathLeg {
  tls: boolean | null;
  protocol?: string;
  cipher?: string;
  with?: string;
  at?: string;
  /** seconds since the previous relay; null when one of the two times is missing */
  delaySec: number | null;
}
export interface MessagePath {
  nodes: PathNode[];
  legs: PathLeg[];
  /** seconds between the Date header and the first relay */
  sinceDate: number | null;
  /** seconds between the first and the last relay */
  totalSec: number | null;
  plaintextLegs: number;
  unknownTlsLegs: number;
}

const clean = (s: string | undefined) => s?.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '') || undefined;

/** "TLSv1.3" → "TLS 1.3" */
export function tlsName(protocol: string | undefined): string | undefined {
  if (!protocol) return undefined;
  const m = /^(TLS|SSL)v?(\d(?:\.\d)?)$/i.exec(protocol.trim());
  return m ? `${m[1].toUpperCase()} ${m[2]}` : protocol;
}

function splitTls(detail: string | undefined): { protocol?: string; cipher?: string } {
  if (!detail) return {};
  const parts = detail.split(/\s+/);
  const protocol = parts.find((p) => /^(TLS|SSL)v?\d/i.test(p));
  const cipher = parts.find((p) => p !== protocol && /[_-]/.test(p));
  return { protocol: tlsName(protocol), cipher };
}

/**
 * Received fields (oldest first) to a chain of servers. Consecutive hops are joined when the
 * "from" of a hop is the "by" of the previous one; a different name is kept as an alias of the
 * same relay rather than drawn as a hand-off nobody measured.
 */
export function buildPath(hops: Hop[], dateHeader?: string): MessagePath {
  const sorted = [...hops].sort((a, b) => a.index - b.index);
  const nodes: PathNode[] = [];
  const legs: PathLeg[] = [];
  sorted.forEach((h, i) => {
    const fromName = h.from ?? h.helo ?? h.ip ?? t('expéditeur');
    if (i === 0) nodes.push({ name: fromName, ip: h.ip, ptr: h.fromPtr, aliases: [] });
    else {
      const prev = nodes[nodes.length - 1];
      if (!prev.ip && h.ip) prev.ip = h.ip;
      if (!prev.ptr && h.fromPtr) prev.ptr = h.fromPtr;
      const fn = clean(fromName);
      if (fn && fn !== clean(prev.name) && fn !== clean(prev.ip) && !prev.aliases.some((a) => clean(a) === fn)) prev.aliases.push(fromName);
    }
    const tl = splitTls(h.tlsDetail);
    legs.push({ tls: h.tls, protocol: tl.protocol, cipher: tl.cipher, with: h.with, at: h.at, delaySec: i === 0 ? null : (h.delaySec ?? null) });
    nodes.push({ name: h.by ?? t('serveur inconnu'), aliases: [] });
  });
  const first = sorted[0]?.at ? Date.parse(sorted[0].at) : NaN;
  const last = sorted.length ? Date.parse(sorted[sorted.length - 1].at ?? '') : NaN;
  const date = dateHeader ? Date.parse(dateHeader) : NaN;
  return {
    nodes,
    legs,
    sinceDate: Number.isFinite(first) && Number.isFinite(date) ? Math.round((first - date) / 1000) : null,
    totalSec: Number.isFinite(first) && Number.isFinite(last) && sorted.length > 1 ? Math.round((last - first) / 1000) : null,
    plaintextLegs: legs.filter((l) => l.tls === false).length,
    unknownTlsLegs: legs.filter((l) => l.tls === null).length,
  };
}

/** 0 → "< 1 s", 75 → "1 min 15 s", 7300 → "2 h 2 min". Negative values are clock skew. */
export function fmtDelay(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || !Number.isFinite(sec)) return '';
  const s = Math.abs(Math.round(sec));
  let out: string;
  if (s < 1) out = t('< 1 s');
  else if (s < 60) out = t('{n} s', { n: s });
  else if (s < 3600) out = s % 60 ? t('{m} min {s} s', { m: Math.floor(s / 60), s: s % 60 }) : t('{m} min', { m: Math.floor(s / 60) });
  else if (s < 86400) out = Math.floor((s % 3600) / 60) ? t('{h} h {m} min', { h: Math.floor(s / 3600), m: Math.floor((s % 3600) / 60) }) : t('{h} h', { h: Math.floor(s / 3600) });
  else out = t('{d} j {h} h', { d: Math.floor(s / 86400), h: Math.floor((s % 86400) / 3600) });
  return sec < 0 && s >= 1 ? t('{delay} en arrière', { delay: out }) : out;
}

/* ---------- compliance matrix ---------- */

export const PROVIDERS: { id: ProviderId; name: string }[] = [
  { id: 'gmail', name: 'Gmail' },
  { id: 'yahoo', name: 'Yahoo' },
  { id: 'microsoft', name: 'Microsoft' },
];

export type Cell = 'ok' | 'fail' | 'unknown' | 'not-required';

export function complianceCell(r: Requirement, p: ProviderId): Cell {
  if (!r.providers.includes(p)) return 'not-required';
  return r.ok === true ? 'ok' : r.ok === false ? 'fail' : 'unknown';
}

/** Failures that apply to this message first, then the other failures, what is met, what cannot be measured. */
export function complianceOrder(reqs: Requirement[], bulk = true): Requirement[] {
  const rank = (r: Requirement) => (r.ok === false ? (r.scope === 'all' || bulk ? 0 : 1) : r.ok === null ? 3 : 2);
  return reqs.map((r, i) => ({ r, i })).sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i).map(({ r }) => r);
}

export function providerOfSource(url: string): string {
  try {
    const h = new URL(url).hostname;
    if (h.includes('google')) return 'Google';
    if (h.includes('yahoo')) return 'Yahoo';
    if (h.includes('microsoft')) return 'Microsoft';
    return h.replace(/^www\./, '');
  } catch {
    return url;
  }
}

/* ---------- previous message (comparison) ---------- */

/** The newest analysed message received before `current`, other than itself. */
export function findPrevious(current: Pick<MessageSummary, 'id' | 'receivedAt'>, candidates: MessageSummary[]): MessageSummary | undefined {
  const at = Date.parse(current.receivedAt);
  return candidates
    .filter((m) => m.id !== current.id && m.status === 'done' && Date.parse(m.receivedAt) <= at)
    .sort((a, b) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt))[0];
}

/* ---------- live stream ---------- */

export interface StreamState {
  address?: AddressInfo;
  /** newest first */
  messages: MessageSummary[];
  steps: Record<string, string>;
  progress: Record<string, Record<string, StepState>>;
  reports: Record<string, StoredReport>;
  errors: Record<string, string>;
  /** last message announced by the stream (not by the initial state) */
  arrived?: string;
  /** the server sent its first state */
  ready: boolean;
}

export const initialStream: StreamState = { messages: [], steps: {}, progress: {}, reports: {}, errors: {}, ready: false };

const byNewest = (a: MessageSummary, b: MessageSummary) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt);

function upsert(list: MessageSummary[], m: MessageSummary): MessageSummary[] {
  const i = list.findIndex((x) => x.id === m.id);
  if (i < 0) return [m, ...list].sort(byNewest);
  const next = [...list];
  next[i] = { ...list[i], ...m };
  return next;
}

function patch(list: MessageSummary[], id: string, p: Partial<MessageSummary>): MessageSummary[] {
  return list.map((m) => (m.id === id ? { ...m, ...p } : m));
}

export function reduceStream(s: StreamState, ev: { type: string; data: unknown }): StreamState {
  const d = (ev.data ?? {}) as Record<string, unknown>;
  const id = typeof d.messageId === 'string' ? d.messageId : undefined;
  switch (ev.type) {
    case 'state': {
      const messages = ((d.messages as MessageSummary[]) ?? []).slice().sort(byNewest);
      return { ...s, address: (d.address as AddressInfo) ?? s.address, messages, steps: (d.steps as Record<string, string>) ?? s.steps, ready: true };
    }
    case 'message': {
      const m = d.message as MessageSummary | undefined;
      if (!id || !m) return s;
      return { ...s, messages: upsert(s.messages, { ...m, id }), arrived: id, progress: { ...s.progress, [id]: {} }, errors: omit(s.errors, id) };
    }
    case 'progress': {
      if (!id || typeof d.step !== 'string') return s;
      const step: StepState = { label: String(d.label ?? d.step), state: (d.state as StepState['state']) ?? 'start', detail: d.detail as string | undefined };
      // "parse" starting again: a new analysis of the same message (the old report stays shown)
      const restarting = d.step === 'parse' && step.state === 'start';
      const prev = restarting ? {} : (s.progress[id] ?? {});
      return {
        ...s,
        progress: { ...s.progress, [id]: { ...prev, [d.step]: step } },
        messages: patch(s.messages, id, { status: 'analyzing' }),
      };
    }
    case 'report': {
      const r = d.report as MailReport | undefined;
      if (!id || !r) return s;
      return { ...s, reports: { ...s.reports, [id]: r }, messages: patch(s.messages, id, { status: 'done', score: r.score ?? null }) };
    }
    case 'error': {
      if (!id) return s;
      return { ...s, errors: { ...s.errors, [id]: String(d.error ?? 'erreur') }, messages: patch(s.messages, id, { status: 'error' }) };
    }
    default:
      return s;
  }
}

function omit<T>(o: Record<string, T>, k: string): Record<string, T> {
  if (!(k in o)) return o;
  const { [k]: _drop, ...rest } = o;
  return rest;
}

/* ---------- preview ---------- */

/**
 * The HTML part as an iframe document: no script can run (sandbox), remote images and fonts are
 * blocked by a CSP unless the reader allows them, cid: images are replaced by their data URI.
 */
export function previewDocument(html: string, opts: { remote: boolean; inline?: { cid?: string; dataUri: string }[] }): string {
  let body = html;
  for (const i of opts.inline ?? []) {
    if (!i.cid) continue;
    const cid = i.cid.replace(/^<|>$/g, '');
    body = body.split(`cid:${cid}`).join(i.dataUri);
  }
  if (!opts.remote) body = blockRemote(body);
  const img = opts.remote ? 'data: https: http:' : 'data:';
  const csp = `default-src 'none'; img-src ${img}; style-src 'unsafe-inline'${opts.remote ? ' https: http:' : ''}; font-src data:${opts.remote ? ' https: http:' : ''}; media-src 'none'; form-action 'none'`;
  const head = `<meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="color-scheme" content="light"><base target="_blank"><style>html{background:Canvas;color:CanvasText}body{margin:12px}img[data-check-blocked]{outline:1px dashed GrayText;outline-offset:-1px}img[data-check-blocked]:not([width]):not([height]){min-width:24px;min-height:24px}</style>`;
  // CSP meta must come before anything the document loads
  if (/<head[^>]*>/i.test(body)) return body.replace(/<head[^>]*>/i, (m) => `${m}${head}`);
  if (/<html[^>]*>/i.test(body)) return body.replace(/<html[^>]*>/i, (m) => `${m}<head>${head}</head>`);
  return `<!DOCTYPE html><html><head>${head}</head><body>${body}</body></html>`;
}

const PIXEL = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

/**
 * Remote images replaced before the frame loads them (the CSP stays as a safety net, but a
 * blocked load would log an error for every image).
 */
export function blockRemote(html: string): string {
  return html
    .replace(/(<img\b[^>]*?\s)src\s*=\s*(["'])\s*(https?:[^"']*)\2/gi, (_m, pre: string, q: string, url: string) => `${pre}src=${q}${PIXEL}${q} data-check-blocked=${q}${url}${q}`)
    .replace(/(<img\b[^>]*?\s)src\s*=\s*(https?:[^\s>]+)/gi, (_m, pre: string, url: string) => `${pre}src="${PIXEL}" data-check-blocked="${url}"`)
    .replace(/\ssrcset\s*=\s*(["'])[^"']*https?:[^"']*\1/gi, '')
    .replace(/\sbackground\s*=\s*(["'])\s*https?:[^"']*\1/gi, '')
    .replace(/url\(\s*(["']?)\s*https?:[^)]*\)/gi, 'none')
    .replace(/<link\b[^>]*>/gi, '');
}

/** Remote images referenced by the HTML part (img src, background, CSS url()). */
export function countRemoteImages(html: string): number {
  const re = /(?:src|background)\s*=\s*["']?\s*https?:|url\(\s*["']?\s*https?:/gi;
  return (html.match(re) ?? []).length;
}

/* ---------- small helpers ---------- */

export const VIA_LABEL: Record<string, string> = { smtp: msg('SMTP direct'), imap: msg('boîte IMAP'), upload: msg('import') };

export function passedOf(passed: PassedCheck[], section: string): PassedCheck[] {
  return passed.filter((p) => p.section === section);
}

/** "contact@exemple.fr" from a summary or a report. */
export function fromOf(m: Pick<MessageSummary, 'from' | 'mailFrom'> | undefined, r?: MailReport | null): string {
  return r?.data.message.from ?? m?.from ?? m?.mailFrom ?? t('expéditeur inconnu');
}

/** Is a text a message source or a header block, by the shape of its first lines. */
export function looksLikeMessage(text: string): boolean {
  const lines = text.replace(/\r\n/g, '\n').trimStart().split('\n').slice(0, 80);
  const headerLines = lines.filter((l) => /^[A-Za-z][A-Za-z0-9-]{1,60}:\s?/.test(l));
  const mailHeaders = headerLines.filter((l) => /^(received|from|to|subject|message-id|dkim-signature|return-path|authentication-results|date|delivered-to|mime-version|arc-seal|x-mailer):/i.test(l));
  return /^[A-Za-z][A-Za-z0-9-]{1,60}:/.test(lines[0] ?? '') && headerLines.length >= 2 && mailHeaders.length >= 1;
}

/** RFC 2047 encoded words ("=?UTF-8?Q?C=C5=93ur?=") as text, for header values shown as measured. */
export function decodeWords(v: string | undefined): string | undefined {
  if (!v || !v.includes('=?')) return v;
  return v
    .replace(/\?=\s+=\?/g, '?==?')
    .replace(/=\?([^?]+)\?([QqBb])\?([^?]*)\?=/g, (m, charset: string, enc: string, text: string) => {
      try {
        const bytes =
          enc.toUpperCase() === 'B'
            ? Uint8Array.from(atob(text), (c) => c.charCodeAt(0))
            : Uint8Array.from(text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})|[\s\S]/g, (x, h) => (h ? String.fromCharCode(parseInt(h, 16)) : x)), (c) => c.charCodeAt(0));
        return new TextDecoder(charset).decode(bytes);
      } catch {
        return m;
      }
    });
}

/* ---------- measured and reference values of a finding ---------- */

/** Network errors in plain French; the raw text stays available as a detail. */
export function humanError(raw: string | undefined): string {
  if (!raw) return '';
  if (/ECONNREFUSED/i.test(raw)) return t('connexion refusée');
  if (/ENOTFOUND|NXDOMAIN|EAI_AGAIN/i.test(raw)) return t('domaine introuvable');
  if (/ETIMEDOUT|ETIMEOUT|timeout|délai/i.test(raw)) return t('délai dépassé');
  if (/ECONNRESET|socket hang up/i.test(raw)) return t('connexion coupée');
  if (/certificate|CERT_|SSL|TLS/i.test(raw)) return t('certificat refusé');
  if (/fetch failed|network|EHOSTUNREACH|ENETUNREACH/i.test(raw)) return t('serveur injoignable');
  if (/introuvable/i.test(raw)) return t('domaine introuvable');
  if (!/E[A-Z]{3,}|fetch|socket|errno/i.test(raw)) return raw;
  return t('pas de réponse');
}

/** Reasons sent by the server, with the technical part translated ("connect ECONNREFUSED x" …). */
export function humanReason(reason: string): string {
  return reason.replace(/\((?:connect )?(E[A-Z]+)\s*([^)]*)\)/g, (_m, code: string, rest: string) => rest.trim() ? t('({reason} sur {host})', { reason: humanError(code), host: rest.trim() }) : `(${humanError(code)})`);
}

const hostIn = (s: string | undefined) => {
  const m = /https?:\/\/([^/\s:]+)/i.exec(s ?? '');
  return m?.[1]?.replace(/^www\./, '');
};
const firstLine = (s: string | undefined) => (s ?? '').split('\n')[0].trim();

/** Protocol results kept as written (pass, fail, softfail…), except the tool's own states. */
export function authResult(r: string | undefined): string {
  if (!r) return t('non évalué');
  return ({ unavailable: t('non évalué'), skipped: t('non évalué'), temperror: t('temperror (erreur DNS passagère)'), permerror: t('permerror (enregistrement invalide)') } as Record<string, string>)[r] ?? r;
}

/** Section of a finding on screen: the server files sender reputation under the blacklists. */
export function clientSection(f: { id: string; family?: string; section?: string }): string | undefined {
  if (f.id === 'reputation.feedback_id_missing') return 'headers';
  if (f.section === 'blacklists' && (f.family === 'reputation' || f.id.startsWith('reputation.'))) return 'reputation';
  return f.section;
}

type MailF = Pick<Finding, 'id' | 'evidence' | 'title'>;

/** Measured value and reference of a finding, from its evidence and the report data. */
export function measureOf(f: MailF, d: MailReport['data']): { measured?: string; reference?: string } {
  const ev = f.evidence ?? '';
  const words = d.content?.visibleWords;
  const imgs = d.images ?? [];
  const links = d.links ?? [];
  const after = (s: string) => s.split(' : ').slice(1).join(' : ');
  switch (f.id) {
    case 'content.image_only':
      return { measured: `${plural(words ?? 0, 'mot', 'mots')}, ${plural(d.content?.images ?? imgs.length, 'image', 'images')}`, reference: t('≥ 20 mots visibles') };
    case 'images.image_heavy':
      return { measured: `${plural(words ?? 0, 'mot', 'mots')}, ${plural(d.content?.images ?? imgs.length, 'image', 'images')}`, reference: t('≥ 25 mots par image') };
    case 'content.text_too_short':
      return { measured: plural(words ?? 0, 'mot', 'mots'), reference: t('≥ 20 mots') };
    case 'content.excessive_punctuation': {
      const seq = /[!?€$]{3,}/.exec(`${d.message.subject ?? ''} ${d.preview?.text ?? ''}`)?.[0];
      return { measured: seq ? t('«\u00a0{seq}\u00a0»', { seq }) : undefined, reference: t('2 signes à la suite au plus') };
    }
    case 'content.text_html_mismatch':
      return { measured: d.content?.textHtmlSimilarity !== undefined ? t('similarité {n} %', { n: Math.round(d.content.textHtmlSimilarity * 100) }) : undefined, reference: t('similarité ≥ 40 %') };
    case 'content.no_text_part':
      return { measured: t('HTML seul'), reference: t('texte et HTML') };
    case 'headers.subject_all_caps':
      return { measured: ev || d.message.subject, reference: t('moins de 70 % de majuscules') };
    case 'headers.message_id_localhost':
    case 'headers.message_id_malformed':
      return { measured: ev, reference: t('<identifiant@domaine-public>') };
    case 'headers.precedence_bulk':
      return { measured: 'Precedence: bulk', reference: t('absent') };
    case 'html.no_doctype':
      return { measured: t('absent'), reference: '<!DOCTYPE html>' };
    case 'html.lang_missing':
      return { measured: t('absent'), reference: 'lang="fr"' };
    case 'images.http_insecure': {
      const http = imgs.filter((i) => /^http:/i.test(i.src)).length;
      return { measured: tn(http, '{n} image en http', '{n} images en http'), reference: 'https' };
    }
    case 'images.missing_alt': {
      const none = imgs.filter((i) => i.alt === undefined).length;
      return { measured: tn(imgs.length, '{none} sur {n} image sans alt', '{none} sur {n} images sans alt', { none }), reference: t('alt sur chaque image') };
    }
    case 'images.third_party_host':
      return { measured: ev.split('\n').map((h) => hostIn(h) ?? h.trim()).filter(Boolean).join(', '), reference: d.message.fromDomain ? t('site de {domain}', { domain: d.message.fromDomain }) : t('site de l’expéditeur') };
    case 'images.unreachable':
    case 'links.broken': {
      const lines = ev.split('\n').filter((l) => /^https?:/i.test(l.trim()));
      const states = (lines.length ? lines : [firstLine(ev)]).map((l) => {
        const e = after(l);
        const code = /HTTP (\d{3})/.exec(e)?.[1];
        return code ? `HTTP ${code}` : humanError(e);
      });
      return { measured: [...new Set(states)].filter(Boolean).join(', ') || undefined, reference: 'HTTP 200' };
    }
    case 'images.tracking_pixel':
      return { measured: t('image 1 × 1') };
    case 'links.empty_href':
      return { measured: plural(links.filter((l) => !l.scheme && (l.url === '#' || l.url === '')).length || 1, 'lien sans destination', 'liens sans destination'), reference: t('une adresse par lien') };
    case 'links.http_not_https':
      return { measured: tn(links.filter((l) => l.scheme === 'http').length, '{n} lien en http', '{n} liens en http'), reference: 'https' };
    case 'links.shortener':
      return { measured: hostIn(firstLine(ev)) ?? t('raccourcisseur'), reference: t('lien direct vers le site') };
    case 'links.text_url_mismatch': {
      const [shown, target] = ev.split('\n').map((l) => hostIn(l));
      return { measured: shown && target ? t('affiché {shown}, mène à {target}', { shown, target }) : undefined, reference: t('même domaine affiché et visé') };
    }
    case 'links.too_many':
      return { measured: plural(links.length, 'lien', 'liens'), reference: t('≤ 50 liens') };
    case 'links.redirect_chain':
      return { measured: plural(ev.split('\n').length - 1, 'redirection', 'redirections'), reference: t('≤ 3 redirections') };
    case 'attachments.dangerous_extension':
    case 'attachments.double_extension':
      return { measured: (d.attachments ?? []).map((a) => a.filename).filter(Boolean).join(', ') || undefined, reference: f.id === 'attachments.double_extension' ? t('une seule extension') : t('extension acceptée par Gmail') };
    case 'reputation.from_domain_not_resolvable':
      return { measured: t('{domain} introuvable', { domain: d.message.fromDomain ?? t('domaine') }), reference: t('MX ou A publié') };
    case 'reputation.feedback_id_missing':
      return { measured: t('absent'), reference: t('Feedback-ID (envois en nombre)') };
    case 'reputation.noreply_sender':
      return { measured: d.message.from, reference: t('adresse qui reçoit les réponses') };
    case 'mx.null_mx_on_sending_domain':
      return { measured: t('MX nul (0 .)'), reference: t('un MX qui reçoit') };
    case 'unsubscribe.list_id_missing':
      return { measured: t('absent'), reference: 'List-Id' };
    case 'unsubscribe.body_link_missing':
      return { measured: t('absent'), reference: t('lien dans le corps') };
  }
  const a = d.auth;
  const dom = d.message.fromDomain ?? t('votre domaine');
  if (f.id.startsWith('spf.helo')) return { measured: authResult(a?.spf?.helo?.result), reference: 'pass' };
  if (f.id.startsWith('spf.')) {
    if (/lookup/.test(f.id) && a?.spf?.lookups) return { measured: tn(a.spf.lookups.count, '{n} requête DNS', '{n} requêtes DNS'), reference: `≤ ${a.spf.lookups.limit}` };
    return { measured: authResult(a?.spf?.result), reference: 'pass' };
  }
  if (f.id.startsWith('dkim.')) {
    const sigs = a?.dkim ?? [];
    return { measured: sigs.length ? sigs.map((x) => `${x.result} (d=${x.domain})`).join(', ') : t('aucune signature'), reference: `pass, d=${dom}` };
  }
  if (f.id === 'dmarc.missing') return { measured: t('aucun enregistrement'), reference: `TXT _dmarc.${dom}` };
  if (f.id === 'dmarc.policy_none') return { measured: 'p=none', reference: t('p=quarantine ou reject') };
  if (f.id === 'dmarc.rua_missing') return { measured: t('rua absent'), reference: 'rua=mailto:…' };
  if (f.id.startsWith('dmarc.fail')) return { measured: `fail${a?.dmarc?.p ? ` (p=${a.dmarc.p})` : ''}`, reference: 'pass' };
  if (f.id.startsWith('alignment.')) return { measured: t('non aligné'), reference: t('From {domain} aligné sur SPF ou DKIM', { domain: dom }) };
  if (f.id.startsWith('helo.')) return { measured: d.envelope.helo ?? d.infrastructure?.helo, reference: t('nom public qui résout vers l’IP') };
  if (f.id.startsWith('rdns.')) return { measured: d.infrastructure?.ptr?.join(', ') || t('absent'), reference: t('PTR qui revient vers l’IP') };
  if (f.id === 'tls.inbound_plaintext') return { measured: t('en clair'), reference: t('TLS 1.2 ou plus') };
  if (f.id.startsWith('bimi.')) return { measured: authResult(a?.bimi?.result), reference: t('facultatif') };
  if (f.id.startsWith('blacklist.')) {
    const code = /→ ([\d., ]+)/.exec(ev)?.[1]?.trim();
    return { measured: code ? t('listé ({code})', { code }) : t('listé'), reference: t('absent des listes') };
  }
  if (f.id === 'unsubscribe.not_dkim_signed') return { measured: t('non couverts'), reference: t('couverts par DKIM') };
  if (f.id === 'unsubscribe.one_click_post_missing') return { measured: t('absent'), reference: 'List-Unsubscribe-Post' };
  if (f.id === 'unsubscribe.list_unsubscribe_missing') return { measured: t('absent'), reference: 'List-Unsubscribe' };
  const sa = /^SpamAssassin \S+ \(([\d.]+) point/.exec(ev);
  if (sa) return { measured: `+${sa[1].replace('.', ',')}`, reference: t('règle non déclenchée') };
  if (/_missing$/.test(f.id) && !ev) return { measured: t('absent'), reference: t('présent') };
  const line = firstLine(ev);
  if (!line) return {};
  const pretty = line.replace(/: (fetch failed|E[A-Z]{4,})\b.*$/, (_m, e: string) => `: ${humanError(e)}`);
  return { measured: pretty.length > 72 ? `${pretty.slice(0, 70)}…` : pretty };
}

/** Reference of a passed check, when the check has a known expected value. */
export const PASSED_REF: Record<string, string> = {
  'headers.message_id': msg('présent, nom de domaine public'),
  'headers.date': msg('présente, à l’heure'),
  'headers.from': msg('un seul From'),
  'content.text_html': msg('similarité ≥ 40 %'),
  'content.text_part': msg('présente'),
  'html.clean': msg('ni script, ni iframe, ni formulaire'),
  'links.ok': 'HTTP 200',
  'attachments.ok': msg('extensions acceptées'),
  'blacklist.clean': msg('0 inscription'),
  'tls.inbound': msg('TLS 1.2 ou plus'),
  'rdns.fcrdns': msg('PTR qui revient vers l’IP'),
  'helo.resolves': msg('résout vers l’IP'),
  'alignment.ok': msg('From aligné'),
  'unsubscribe.header': msg('présent'),
  'unsubscribe.one_click': 'List-Unsubscribe=One-Click',
};

/** Measured value of a passed check that carries no detail. */
export const PASSED_MEASURED: Record<string, string> = {
  'html.clean': msg('aucun'),
  'content.text_part': msg('présente'),
  'attachments.ok': msg('conformes'),
  'unsubscribe.header': msg('présent'),
};

/* ---------- "Signal" report (2026-11-11): sends, timing, the two indicators, the headline ---------- */

/** Messages of one address numbered like mail-tester's sends: the oldest is "Envoi 1". */
export function numberSends<M extends Pick<MessageSummary, 'id' | 'receivedAt'>>(messages: M[]): (M & { n: number })[] {
  return [...messages].sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt)).map((m, i) => ({ ...m, n: i + 1 }));
}

const parseTime = (v: string | undefined | null): number | undefined => {
  if (!v) return undefined;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
};

/** Longest delivery delay still shown as "acheminé en": beyond, one of the two clocks is wrong. */
const MAX_TRANSIT_SEC = 2 * 86400;

export interface Timing {
  /** the Date header: when the message was written */
  writtenAt?: number;
  /** when it reached the last server: our SMTP session, else the newest Received line */
  receivedAt?: number;
  /** when an upload was imported into check (not a reception) */
  importedAt?: number;
  /** what "envoyé il y a" counts from: the Date header, else the reception */
  sentAt?: number;
  /** reception minus Date, only when both exist and the difference is plausible */
  transitSec: number | null;
}

export function timingOf(m: Pick<MessageSummary, 'via' | 'receivedAt'>, d?: Pick<MailReportData, 'message' | 'hops' | 'receivedAt'>): Timing {
  const writtenAt = parseTime(d?.message.date);
  const lastHop = d?.hops?.length ? [...d.hops].sort((a, b) => b.index - a.index)[0] : undefined;
  const hopAt = parseTime(lastHop?.at);
  const own = parseTime(d?.receivedAt ?? m.receivedAt);
  // an upload's own time is the import, not a reception; an IMAP fetch can come long after the delivery
  const receivedAt = m.via === 'smtp' ? own : m.via === 'imap' ? (hopAt ?? own) : hopAt;
  const importedAt = m.via === 'upload' ? own : undefined;
  const sentAt = writtenAt ?? receivedAt;
  const diff = writtenAt !== undefined && receivedAt !== undefined ? Math.round((receivedAt - writtenAt) / 1000) : null;
  return { writtenAt, receivedAt, importedAt, sentAt, transitSec: diff !== null && diff >= 0 && diff <= MAX_TRANSIT_SEC ? diff : null };
}

/** "11/11 à 01:51:21", with the year when it is not the current one. */
export function fmtWhen(ts: number | undefined, now = Date.now()): string {
  if (ts === undefined) return '';
  const d = new Date(ts);
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  const day = d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit', ...(sameYear ? {} : { year: 'numeric' }) });
  const time = d.toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return t('{day} à {time}', { day, time });
}

type Imp = NonNullable<Finding['impact']>;
type AxisF = Pick<Finding, 'penalty'> & { impact?: Imp; axis?: 'sender' | 'message' };

/** Client mirror of indicatorsOf (server/src/mail/analyze/impact.ts), for a report sent without them. */
export function indicatorsFrom(findings: AxisF[]): Indicators | undefined {
  if (!findings.some((f) => f.axis && f.impact)) return undefined;
  const sum = (axis: 'sender' | 'message'): AxisSummary => {
    const fs = findings.filter((f) => f.axis === axis);
    const n = (i: Imp) => fs.filter((f) => f.impact === i).length;
    const out = { lost: Math.round(fs.reduce((t, f) => t + Math.max(0, f.penalty), 0) * 10) / 10, blocking: n('blocking'), spam: n('spam'), advice: n('advice') };
    return { ...out, status: out.blocking ? 'blocking' : out.spam ? 'spam' : out.advice ? 'advice' : 'ok' };
  };
  const sender = sum('sender');
  const message = sum('message');
  return { verdict: sender.blocking + message.blocking ? 'blocking' : sender.spam + message.spam ? 'spam' : 'ok', sender, message };
}

export const indicatorsOfReport = (r: MailReport): Indicators | undefined => r.data.indicators ?? indicatorsFrom(r.findings as AxisF[]);

export type Lit = 'ok' | 'warn' | 'out' | 'n';
export interface KeyCheck {
  key: string;
  value: string;
  lit: Lit;
}

/**
 * The six key checks of each indicator, read from the report. A check is lit red when one of its
 * findings blocks delivery, amber when one raises the spam risk, else green when the measure is
 * good and grey when there is nothing to judge (no attachment, not measured).
 */
export function keyChecks(r: MailReport): { sender: KeyCheck[]; message: KeyCheck[] } {
  const d = r.data;
  const fs = r.findings as (Finding & { impact?: Imp })[];
  const lit = (families: string[], base: Lit): Lit => {
    const mine = fs.filter((f) => families.includes(f.family) && f.penalty > 0);
    if (mine.some((f) => f.impact === 'blocking')) return 'out';
    if (mine.some((f) => f.impact === 'spam')) return 'warn';
    // a report made before the impact field: the severity says it
    if (mine.some((f) => !f.impact && (f.severity === 'critical' || f.severity === 'high'))) return 'out';
    if (mine.some((f) => !f.impact && f.severity === 'medium')) return 'warn';
    return base;
  };
  const a = d.auth;
  const sigs = a?.dkim ?? [];
  const sig = sigs.find((s) => s.result === 'pass' && s.aligned) ?? sigs.find((s) => s.result === 'pass') ?? sigs[0];
  const inf = d.infrastructure;
  const tls = inf?.tls ?? d.envelope.tls;
  const bl = d.blacklists;
  const sender: KeyCheck[] = [
    { key: 'SPF', value: authResult(a?.spf?.result), lit: lit(['spf'], a?.spf?.result === 'pass' ? 'ok' : 'n') },
    { key: 'DKIM', value: sig ? (sig.keyBits ? t('{result} · {bits} bits', { result: sig.result, bits: String(sig.keyBits) }) : sig.result) : a ? t('aucune signature') : t('non évalué'), lit: lit(['dkim'], sig?.result === 'pass' ? 'ok' : 'n') },
    { key: 'DMARC', value: a?.dmarc ? `${a.dmarc.result ?? 'none'}${a.dmarc.p ? ` · p=${a.dmarc.p}` : ''}` : t('non évalué'), lit: lit(['dmarc', 'alignment'], a?.dmarc?.result === 'pass' ? 'ok' : 'n') },
    {
      key: 'Reverse DNS',
      value: inf?.private ? t('IP locale') : inf?.fcrdns ? t('confirmé') : inf?.ptr?.length ? t('non confirmé') : inf ? t('absent') : t('non mesuré'),
      lit: lit(['rdns'], inf?.fcrdns && !inf.private ? 'ok' : 'n'),
    },
    { key: 'TLS', value: tls?.used === true ? (tlsName(tls.protocol) ?? t('oui')) : tls?.used === false ? t('en clair') : t('non indiqué'), lit: lit(['tls'], tls?.used === true ? 'ok' : 'n') },
    {
      key: msg('Listes noires'),
      value: !bl ? t('non vérifiées') : bl.listed.length ? plural(bl.listed.length, 'inscription', 'inscriptions') : t('aucune inscription'),
      lit: lit(['blacklist'], bl && !bl.listed.length && bl.checked > 0 ? 'ok' : 'n'),
    },
  ];
  const sa = d.spamassassin;
  const c = d.content;
  const links = d.links ?? [];
  const broken = links.filter((l) => l.check && (l.check.error || (l.check.status ?? 0) >= 400)).length;
  const visited = links.filter((l) => l.check).length;
  const headerF = fs.filter((f) => f.family === 'headers' && f.penalty > 0).length;
  const atts = d.attachments ?? [];
  const u = d.unsubscribe;
  const message: KeyCheck[] = [
    {
      key: 'SpamAssassin',
      value: sa?.available && sa.score !== undefined ? `${fmtNum(sa.score)} / ${fmtNum(sa.threshold ?? 5)}` : t('non mesuré'),
      lit: lit(['spamassassin'], sa?.available && sa.score !== undefined ? (sa.score < (sa.threshold ?? 5) ? 'ok' : 'out') : 'n'),
    },
    {
      key: msg('Texte et images'),
      value: c?.visibleWords !== undefined ? `${plural(c.visibleWords, 'mot', 'mots')}, ${plural(c.images ?? (d.images ?? []).length, 'image', 'images')}` : t('non mesuré'),
      lit: lit(['content', 'images', 'html'], (c?.visibleWords ?? 0) >= 20 ? 'ok' : 'n'),
    },
    {
      key: msg('Liens'),
      value: !links.length ? t('aucun') : broken ? t('{broken} en échec sur {total}', { broken, total: links.length }) : visited === links.length ? tn(links.length, '{n} qui répond', '{n} qui répondent') : t('{visited} vérifiés sur {total}', { visited, total: links.length }),
      lit: lit(['links'], links.length && !broken && visited ? 'ok' : 'n'),
    },
    { key: msg('En-têtes'), value: headerF ? plural(headerF, 'anomalie', 'anomalies') : t('conformes'), lit: lit(['headers'], headerF ? 'n' : 'ok') },
    { key: msg('Pièces jointes'), value: atts.length ? plural(atts.length, 'pièce jointe', 'pièces jointes') : t('aucune'), lit: lit(['attachments'], 'n') },
    {
      key: msg('Désinscription'),
      value: u?.listUnsubscribe ? (u.oneClick ? t('en un clic') : t('présente')) : d.isBulk ? t('absente') : t('sans objet'),
      lit: lit(['unsubscribe'], u?.listUnsubscribe ? 'ok' : 'n'),
    },
  ];
  return { sender, message };
}

const fmtNum = (x: number) => x.toLocaleString(locale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 });

const lowerFirst = (s: string) => (s.length > 1 && s[1] === s[1].toLowerCase() ? s[0].toLowerCase() + s.slice(1) : s);

export interface Headline {
  tone: 'good' | 'watch' | 'bad';
  mood: string;
  /** what blocks delivery (or that nothing does) */
  main: string;
  /** what risks the spam folder, or what only improves */
  rest?: string;
}

/** The verdict in two sentences: what blocks delivery, then what risks the spam folder. */
export function headlineOf(findings: Pick<Finding, 'title' | 'penalty' | 'impact'>[], ind: Indicators): Headline {
  const of = (i: Imp) => findings.filter((f) => f.impact === i).sort((a, b) => b.penalty - a.penalty);
  const blocking = of('blocking');
  const spam = of('spam');
  const advice = of('advice').filter((f) => f.penalty > 0);
  if (ind.verdict === 'blocking' && blocking.length) {
    const top = lowerFirst(blocking[0].title);
    return {
      tone: 'bad',
      mood: t('Livraison compromise'),
      main: tn(blocking.length, 'Un point bloque la livraison\u00a0: {top}.', '{n} points bloquent la livraison, d’abord\u00a0: {top}.', { top }),
      rest: spam.length ? tn(spam.length, 'Un autre peut le faire classer en indésirables.', '{n} autres peuvent le faire classer en indésirables.') : undefined,
    };
  }
  if (ind.verdict === 'spam' && spam.length) {
    const top = lowerFirst(spam[0].title);
    return {
      tone: 'watch',
      mood: t('Arrivera, avec un risque d’indésirables'),
      main: t('Rien ne bloque la livraison.'),
      rest: tn(spam.length, 'Un seul point peut le faire classer en indésirables\u00a0: {top}.', '{n} points peuvent le faire classer en indésirables, d’abord\u00a0: {top}.', { top }),
    };
  }
  return {
    tone: 'good',
    mood: t('Rien de bloquant ni de suspect'),
    main: t('Rien ne bloque la livraison.'),
    rest: advice.length ? tn(advice.length, '{n} amélioration possible, sans effet notable sur la livraison.', '{n} améliorations possibles, sans effet notable sur la livraison.') : t('Aucun point à reprendre.'),
  };
}

/** Status line of one indicator: its counts by effect on delivery. */
export function axisStatus(s: AxisSummary): { lit: Lit; text: string } {
  const parts: string[] = [];
  if (s.blocking) parts.push(tn(s.blocking, '{n} point bloquant', '{n} points bloquants'));
  if (s.spam) parts.push(tn(s.spam, '{n} risque d’indésirables', '{n} risques d’indésirables'));
  const lead = parts.length ? parts.join(' · ') : t('Rien de bloquant ni de suspect');
  const adv = s.advice ? ` · ${plural(s.advice, 'amélioration', 'améliorations')}` : '';
  return { lit: s.blocking ? 'out' : s.spam ? 'warn' : 'ok', text: lead + adv };
}

/* ---------- empty and invisible links in the preview ---------- */

/** A link that leads nowhere: no address, "#", or a web address without a host ("http:///"). */
export function isEmptyHref(href: string | null): boolean {
  const h = (href ?? '').trim();
  if (!h || h === '#') return true;
  if (/^https?:/i.test(h)) {
    try {
      return !new URL(h).hostname;
    } catch {
      return true;
    }
  }
  return false;
}

/**
 * Marks, in the HTML part, the links that lead nowhere and the links nobody can see (no text, no
 * image), so the preview can circle them. Returns the HTML unchanged when nothing is found or the
 * browser cannot parse it.
 */
export function markEmptyLinks(html: string): { html: string; empty: number; invisible: number } {
  if (typeof DOMParser === 'undefined') return { html, empty: 0, invisible: 0 };
  const doc = new DOMParser().parseFromString(html, 'text/html');
  let empty = 0;
  let invisible = 0;
  for (const a of Array.from(doc.querySelectorAll('a'))) {
    const blank = isEmptyHref(a.getAttribute('href'));
    const unseen = !(a.textContent ?? '').trim() && !a.querySelector('img, svg, picture, video');
    if (!blank && !unseen) continue;
    if (blank) empty++;
    if (unseen) invisible++;
    const href = (a.getAttribute('href') ?? '').trim();
    const label = blank && unseen ? t('lien vide et invisible') : blank ? t('lien vide') : t('lien invisible');
    a.setAttribute('data-check-flag', href ? `${label} ${href.length > 40 ? `${href.slice(0, 39)}…` : href}` : label);
  }
  if (!empty && !invisible) return { html, empty, invisible };
  const style = doc.createElement('style');
  style.textContent =
    'a[data-check-flag]{position:relative;outline:2px solid #e5484d;outline-offset:3px;border-radius:2px}a[data-check-flag]:empty{display:inline-block;min-width:14px;min-height:14px;vertical-align:middle}a[data-check-flag]::after{content:attr(data-check-flag);position:absolute;left:calc(100% + 10px);top:50%;transform:translateY(-50%);padding:1px 5px;border-radius:3px;font:700 11px/1.3 ui-monospace,Menlo,monospace;font-style:normal;text-decoration:none;color:#fff;background:#c62a2f;white-space:nowrap}body{padding-top:4px}';
  doc.head.appendChild(style);
  return { html: `<!DOCTYPE html>${doc.documentElement.outerHTML}`, empty, invisible };
}
