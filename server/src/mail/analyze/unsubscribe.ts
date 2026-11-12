// Unsubscribe (RFC 2369 List-Unsubscribe, RFC 8058 one-click) and the bulk-sender requirements
// of Gmail, Yahoo and Microsoft, each one stated as met or not for this message.
import { firstHeader } from '../mime.js';
import { isPublicIp } from '../../lib/net.js';
import { anchors } from './html.js';
import type { DkimSignatureInfo, AlignmentInfo } from './auth.js';
import type { StepContext } from './types.js';
import { t } from '../../i18n.js';

export function parseListUnsubscribe(v: string | undefined): { uris: string[]; valid: boolean } {
  if (!v) return { uris: [], valid: false };
  const uris = [...v.matchAll(/<([^<>]+)>/g)].map((m) => m[1].trim());
  const rest = v.replace(/<[^<>]*>/g, '').replace(/[\s,]/g, '');
  return { uris, valid: uris.length > 0 && rest === '' };
}

export function suggestUnsubscribeHeaders(domain: string, existing: string[]): string {
  const https = existing.find((u) => /^https:/i.test(u)) ?? `https://${domain}/desinscription?id=IDENTIFIANT_DU_DESTINATAIRE`;
  const mailto = existing.find((u) => /^mailto:/i.test(u)) ?? `mailto:desinscription@${domain}?subject=unsubscribe`;
  return `List-Unsubscribe: <${https}>, <${mailto}>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click`;
}

export function runUnsubscribe(sc: StepContext, sigs: DkimSignatureInfo[]) {
  const { facts, c } = sc;
  const H = facts.headers;
  const lu = firstHeader(H, 'list-unsubscribe');
  const luPost = firstHeader(H, 'list-unsubscribe-post');
  const parsed = parseListUnsubscribe(lu);
  const domain = facts.fromDomain ?? t('votre-domaine.fr');
  const https = parsed.uris.filter((u) => /^https:/i.test(u));
  const http = parsed.uris.filter((u) => /^http:/i.test(u));
  const mailto = parsed.uris.filter((u) => /^mailto:/i.test(u));
  const oneClick = !!luPost && luPost.trim() === 'List-Unsubscribe=One-Click';
  const covering = sigs.filter((s) => s.result === 'pass' && s.signedHeaders.includes('list-unsubscribe') && s.signedHeaders.includes('list-unsubscribe-post'));
  const data = {
    isBulk: facts.isBulk,
    bulkReasons: facts.bulkReasons,
    listUnsubscribe: lu,
    listUnsubscribePost: luPost,
    uris: parsed.uris,
    oneClick,
    coveredByDkim: covering.length > 0,
    coveringSignatures: covering.map((s) => `d=${s.domain} s=${s.selector}`),
    listId: firstHeader(H, 'list-id'),
  };
  sc.data.unsubscribe = data;
  const suggested = suggestUnsubscribeHeaders(domain, parsed.uris);

  if (!lu) {
    if (facts.isBulk)
      c.add('unsubscribe.list_unsubscribe_missing', {
        evidence: t('Envoi en nombre : {reasons}', { reasons: facts.bulkReasons.join(', ') }),
        suggested,
        fallback: { title: t('Pas d’en-tête List-Unsubscribe'), family: 'unsubscribe', severity: 'high', penalty: 1.5 },
      });
  } else {
    if (!parsed.valid) c.add('unsubscribe.syntax_invalid', { evidence: lu, suggested, fallback: { title: t('List-Unsubscribe mal formé'), family: 'unsubscribe', severity: 'medium', penalty: 0.7 } });
    if (parsed.uris.length && !https.length && !http.length && mailto.length)
      c.add('unsubscribe.mailto_only', { evidence: lu, suggested, fallback: { title: t('Désinscription par e-mail seulement'), family: 'unsubscribe', severity: 'medium', penalty: 0.7 } });
    if (http.length && !https.length) c.add('unsubscribe.http_not_https', { evidence: lu, suggested, fallback: { title: t('Lien de désinscription en http'), family: 'unsubscribe', severity: 'medium', penalty: 0.7 } });
    if (https.length > 1) c.add('unsubscribe.multiple_https', { evidence: lu, fallback: { title: t('Plusieurs liens https de désinscription'), family: 'unsubscribe', severity: 'low', penalty: 0.2 } });
    if (!luPost && facts.isBulk && (https.length || http.length))
      c.add('unsubscribe.one_click_post_missing', {
        evidence: lu,
        suggested: 'List-Unsubscribe-Post: List-Unsubscribe=One-Click',
        fallback: { title: t('Pas de désinscription en un clic (List-Unsubscribe-Post)'), family: 'unsubscribe', severity: 'high', penalty: 1 },
      });
    if (luPost && !oneClick)
      c.add('unsubscribe.post_value_invalid', { vars: { value: luPost }, evidence: `List-Unsubscribe-Post: ${luPost}`, suggested: 'List-Unsubscribe-Post: List-Unsubscribe=One-Click', fallback: { title: t('Valeur de List-Unsubscribe-Post incorrecte'), family: 'unsubscribe', severity: 'medium', penalty: 0.7 } });
    // Rule set by the coordinator on 2026-11-10: this finding costs points only when a DKIM
    // signature exists and does not cover List-Unsubscribe and List-Unsubscribe-Post. Without any
    // signature it is information only: the cause is already counted once by dkim.missing (and
    // DMARC failing stays counted, a distinct consequence at the recipients). Do not revert.
    const noSignature = !sigs.length;
    if (luPost && !covering.length)
      c.add('unsubscribe.not_dkim_signed', {
        ...(noSignature ? { penalty: 0, severity: 'info' as const } : {}),
        evidence: noSignature
          ? t("Aucune signature DKIM : la cause est comptée une fois, dans « le message n'est pas signé avec DKIM ».")
          : sigs.map((s) => `d=${s.domain} (${s.result}) h=${s.signedHeaders.join(':')}`).join('\n'),
        fallback: { title: t('Les en-têtes de désinscription ne sont pas couverts par DKIM'), family: 'unsubscribe', severity: 'high', penalty: 1 },
      });
    if (oneClick && covering.length && https.length) c.pass('unsubscribe.one_click', 'unsubscribe', t('Désinscription en un clic conforme (RFC 8058)'), https[0]);
    else if (parsed.valid) c.pass('unsubscribe.header', 'unsubscribe', t('En-tête List-Unsubscribe présent'), lu);
  }
  if (facts.isBulk && !facts.headersOnly) {
    const html = facts.html?.text ?? '';
    const bodyLinks = html ? anchors(html) : [];
    const words = /d[ée]sinscri|d[ée]sabonn|unsubscribe|ne plus recevoir|opt[- ]?out|se d[ée]sinscrire/i;
    const inText = words.test(facts.text?.text ?? '');
    if (!bodyLinks.some((a) => words.test(a.text) || words.test(a.href)) && !inText)
      c.add('unsubscribe.body_link_missing', { fallback: { title: t('Pas de lien de désinscription dans le message'), family: 'unsubscribe', severity: 'high', penalty: 1 } });
    if (!data.listId) c.add('unsubscribe.list_id_missing', { fallback: { title: t('Pas d’en-tête List-Id'), family: 'unsubscribe', severity: 'info', penalty: 0 } });
  }
  return { oneClick, covered: covering.length > 0, hasHttpsUnsub: https.length > 0 };
}

export interface Requirement {
  id: string;
  label: string;
  providers: ('gmail' | 'yahoo' | 'microsoft')[];
  /** all: every sender; bulk: senders of 5,000+ messages a day */
  scope: 'all' | 'bulk';
  /** true met, false not met, null not measurable on one message */
  ok: boolean | null;
  detail: string;
  sources: string[];
  /** knowledge base entry shown when the requirement is not met */
  situation?: string;
}

const SRC = {
  gmail: 'https://support.google.com/a/answer/81126',
  yahoo: 'https://senders.yahooinc.com/best-practices/',
  microsoft: 'https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/strengthening-email-ecosystem-outlook%E2%80%99s-new-requirements-for-high%E2%80%90volume-senders/4399730',
};

export function runCompliance(
  sc: StepContext,
  a: {
    spfResult: string;
    sigs: DkimSignatureInfo[];
    alignment: AlignmentInfo;
    dmarcRecord?: string;
    dmarcPolicy?: string;
    fcrdns?: string;
    oneClick: boolean;
    unsubCovered: boolean;
    hasHttpsUnsub: boolean;
  },
) {
  const { facts, c } = sc;
  const dkimPass = a.sigs.some((s) => s.result === 'pass');
  const ipKnown = !!facts.ip && isPublicIp(facts.ip) && facts.envelopeKnown;
  const reqs: Requirement[] = [
    {
      id: 'spf',
      label: t('SPF valide pour le domaine d’envoi'),
      providers: ['gmail', 'yahoo', 'microsoft'],
      scope: 'bulk',
      ok: ipKnown ? a.spfResult === 'pass' : null,
      detail: ipKnown ? t('SPF : {result}', { result: a.spfResult }) : t("IP d'envoi inconnue"),
      sources: [SRC.gmail, SRC.yahoo, SRC.microsoft],
    },
    {
      id: 'dkim',
      label: t('Signature DKIM valide'),
      providers: ['gmail', 'yahoo', 'microsoft'],
      scope: 'bulk',
      ok: dkimPass,
      detail: dkimPass ? a.sigs.filter((s) => s.result === 'pass').map((s) => `d=${s.domain}`).join(', ') : t('aucune signature valide'),
      sources: [SRC.gmail, SRC.yahoo, SRC.microsoft],
    },
    {
      id: 'spf_or_dkim',
      label: t('SPF ou DKIM valide (tous les expéditeurs)'),
      providers: ['gmail', 'yahoo'],
      scope: 'all',
      ok: dkimPass || a.spfResult === 'pass' ? true : ipKnown ? false : null,
      detail: dkimPass || a.spfResult === 'pass' ? t('au moins un des deux passe') : t('ni SPF ni DKIM ne passent'),
      sources: [SRC.gmail, SRC.yahoo],
    },
    {
      id: 'dmarc',
      label: t('Enregistrement DMARC publié (p=none au minimum)'),
      providers: ['gmail', 'yahoo', 'microsoft'],
      scope: 'bulk',
      ok: !!a.dmarcRecord && !!a.dmarcPolicy,
      detail: a.dmarcRecord ?? t('aucun enregistrement'),
      sources: [SRC.gmail, SRC.yahoo, SRC.microsoft],
    },
    {
      id: 'alignment',
      label: t('From aligné avec SPF ou DKIM'),
      providers: ['gmail', 'yahoo', 'microsoft'],
      scope: 'bulk',
      ok: a.alignment.aligned,
      detail: a.alignment.aligned ? t('aligné') : t('From {domain} non aligné', { domain: a.alignment.fromDomain ?? '?' }),
      sources: [SRC.gmail, SRC.yahoo, SRC.microsoft],
    },
    {
      id: 'ptr',
      label: t('Reverse DNS valide (PTR qui revient vers l’IP)'),
      providers: ['gmail', 'yahoo'],
      scope: 'all',
      // a private or local IP has no public reverse DNS to check: not measurable, nothing to fix
      ok: facts.ip && isPublicIp(facts.ip) ? !!a.fcrdns : null,
      detail: !facts.ip ? t("IP d'envoi inconnue") : !isPublicIp(facts.ip) ? t('{ip} est une adresse privée ou locale : non mesurable', { ip: facts.ip }) : (a.fcrdns ?? t('PTR absent ou non confirmé')),
      sources: [SRC.gmail, SRC.yahoo],
    },
    {
      id: 'tls',
      label: t('Transmission en TLS'),
      providers: ['gmail'],
      scope: 'all',
      ok: facts.tls?.used ?? null,
      detail: facts.tls?.used ? (facts.tls.protocol ?? 'TLS') : facts.tls?.used === false ? t('reçu en clair') : t('inconnu'),
      sources: [SRC.gmail],
    },
    {
      id: 'format',
      label: t('Format conforme à la RFC 5322 (From unique, Date, Message-ID)'),
      providers: ['gmail', 'yahoo'],
      scope: 'all',
      ok: !c.has('headers.from_missing') && !c.has('headers.from_multiple') && !c.has('headers.date_missing') && !c.has('headers.message_id_missing') && !c.has('headers.duplicate_single_instance'),
      detail: ['headers.from_missing', 'headers.from_multiple', 'headers.date_missing', 'headers.message_id_missing', 'headers.duplicate_single_instance'].filter((x) => c.has(x)).join(', ') || t('conforme'),
      sources: [SRC.gmail, SRC.yahoo],
    },
    {
      id: 'one_click',
      label: t('Désinscription en un clic (RFC 8058) pour les messages marketing'),
      providers: ['gmail', 'yahoo'],
      scope: 'bulk',
      ok: facts.isBulk ? a.oneClick && a.unsubCovered && a.hasHttpsUnsub : null,
      detail: facts.isBulk ? (a.oneClick ? (a.unsubCovered ? t('conforme') : t('non couverte par DKIM')) : t('absente')) : t('message non identifié comme envoi en nombre'),
      sources: [SRC.gmail, SRC.yahoo],
    },
    {
      id: 'spam_rate',
      label: t('Taux de plainte sous 0,3 %'),
      providers: ['gmail', 'yahoo'],
      scope: 'all',
      ok: null,
      detail: t('Non mesurable sur un message : consultez Google Postmaster Tools et Yahoo Sender Hub'),
      sources: [SRC.gmail, SRC.yahoo],
    },
  ];
  // Microsoft (Outlook.com, more than 5,000 a day): SPF, DKIM and DMARC aligned, all three
  const outlookOk = ipKnown ? a.spfResult === 'pass' && dkimPass && !!a.dmarcRecord && a.alignment.aligned : null;
  reqs.push({
    id: 'outlook',
    label: t('Outlook.com : SPF, DKIM et DMARC aligné réunis'),
    providers: ['microsoft'],
    scope: 'bulk',
    ok: outlookOk,
    detail: outlookOk ? t('conforme') : outlookOk === false ? t('au moins un des trois manque') : t("IP d'envoi ou MAIL FROM inconnus"),
    sources: [SRC.microsoft],
  });
  sc.data.compliance = { isBulk: facts.isBulk, bulkReasons: facts.bulkReasons, requirements: reqs };
  const failing = reqs.filter((r) => r.ok === false && (r.scope === 'all' || facts.isBulk));
  // One entry per unmet requirement. The knowledge base marks them "non cumulé" with the
  // spf, dkim, dmarc, alignment, rdns, tls, headers and unsubscribe families: those findings
  // already carry the points, so these cost nothing.
  const SITUATION: Record<string, string> = {
    spf: 'bulk-sender.spf_and_dkim_required',
    dkim: 'bulk-sender.spf_and_dkim_required',
    dmarc: 'bulk-sender.dmarc_missing',
    alignment: 'bulk-sender.dmarc_not_aligned',
    ptr: 'bulk-sender.ptr_required',
    tls: 'bulk-sender.tls_required',
    format: 'bulk-sender.rfc5322_format',
    one_click: 'bulk-sender.one_click_required',
    outlook: 'bulk-sender.outlook_high_volume',
  };
  for (const r of reqs) r.situation = SITUATION[r.id];
  for (const r of failing) {
    const id = SITUATION[r.id];
    if (!id) continue;
    if (r.id === 'alignment' && !a.dmarcRecord) continue; // covered by dmarc_missing
    c.add(id, {
      vars: { value: r.detail },
      evidence: t('{label} : {detail}', { label: r.label, detail: r.detail }),
      penalty: 0,
      severity: undefined,
      fallback: { title: r.label, family: 'bulk-sender', severity: 'high', penalty: 0 },
    });
  }
  if (!failing.length) c.pass('bulk-sender.ok', 'bulk-sender', t('Exigences Gmail, Yahoo et Microsoft remplies pour ce message'));
}
