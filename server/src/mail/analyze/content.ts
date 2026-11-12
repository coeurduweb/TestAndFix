// Body content (text part, consistency with HTML, weight, invisible characters…), HTML elements
// that filters penalise, and attachments.
import { anchors, similarity, tags, visibleText, words } from './html.js';
import { ARCHIVE_EXT, GMAIL_BLOCKED_EXT, HTML_EXT, MACRO_EXT, T } from './thresholds.js';
import type { StepContext } from './types.js';
import { t, tPlural } from '../../i18n.js';

const INVISIBLE = /[​‌‍⁠﻿­͏]/g;
const BIDI = /[‪-‮⁦-⁩]/;

function ext(name: string): string {
  const m = /\.([a-z0-9_]{1,12})$/i.exec(name.trim());
  return m ? m[1].toLowerCase() : '';
}

/** File names inside a zip archive and whether an entry is encrypted (local file headers). */
export function zipEntries(buf: Buffer): { names: string[]; encrypted: boolean } {
  const names: string[] = [];
  let encrypted = false;
  let i = buf.indexOf('PK\x03\x04', 0, 'latin1');
  let guard = 0;
  while (i !== -1 && i + 30 <= buf.length && guard++ < 5000) {
    const flags = buf.readUInt16LE(i + 6);
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    if (flags & 1) encrypted = true;
    names.push(buf.toString('utf8', i + 30, i + 30 + nameLen));
    const next = i + 30 + nameLen + extraLen + (flags & 8 ? 0 : compSize);
    i = buf.indexOf('PK\x03\x04', Math.max(next, i + 4), 'latin1');
  }
  return { names, encrypted };
}

function magicType(b: Buffer): string | undefined {
  if (b.subarray(0, 4).toString('latin1') === '%PDF') return 'pdf';
  if (b.subarray(0, 2).toString('latin1') === 'MZ') return 'exe';
  if (b.subarray(0, 4).toString('latin1') === 'PK\x03\x04') return 'zip';
  if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  if (b.subarray(0, 4).toString('latin1') === 'GIF8') return 'gif';
  if (b.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) return 'ole';
  if (b.subarray(0, 4).toString('latin1') === 'Rar!') return 'rar';
  if (b.subarray(0, 6).toString('latin1') === '7z\xbc\xaf\x27\x1c') return '7z';
  return undefined;
}

const EXT_FAMILY: Record<string, string[]> = {
  pdf: ['pdf'],
  exe: ['exe', 'dll', 'scr', 'com', 'sys', 'cpl', 'msi', 'pif'],
  zip: ['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'odt', 'ods', 'odp', 'jar', 'apk', 'epub', 'dotx', 'xltx', 'potx', 'ppsx', 'xlam', 'dotm', 'xltm', 'ppsm', 'kmz', 'appx', 'msix'],
  png: ['png'],
  jpg: ['jpg', 'jpeg', 'jpe', 'jfif'],
  gif: ['gif'],
  ole: ['doc', 'xls', 'ppt', 'msg', 'dot', 'xlt', 'pps', 'msi', 'vsd', 'pub'],
  rar: ['rar'],
  '7z': ['7z'],
};

export function runContent(sc: StepContext) {
  const { facts, c } = sc;
  const text = facts.text?.text ?? '';
  const html = facts.html?.text ?? '';
  const htmlVisible = html ? visibleText(html) : '';
  const visible = htmlVisible || text;
  const visibleWords = words(visible).length;
  const imgs = html ? tags(html, ['img']) : [];
  const contentImgs = imgs.filter((i) => !(i.attrs.width === '1' && i.attrs.height === '1'));
  const links = html ? anchors(html) : [];
  const subject = facts.subject ?? '';

  const data: Record<string, unknown> = {
    hasText: !!facts.text,
    hasHtml: !!facts.html,
    size: facts.input.raw.length,
    textBytes: facts.text?.decoded.length ?? 0,
    htmlBytes: facts.html?.decoded.length ?? 0,
    visibleWords,
    images: imgs.length,
    attachments: facts.attachments.length,
    textHtmlSimilarity: undefined as number | undefined,
  };
  sc.data.content = data;
  sc.data.preview = {
    text: text.slice(0, 200_000),
    html: html.slice(0, 1_000_000),
    htmlTruncated: html.length > 1_000_000,
    /** cid: images, as data URIs the interface can substitute when the user allows images */
    inline: facts.inline.slice(0, 20).filter((p) => p.decoded.length < 512 * 1024).map((p) => ({
      cid: p.contentId,
      type: p.contentType,
      dataUri: `data:${p.contentType};base64,${p.decoded.toString('base64')}`,
    })),
  };

  /* ---------------- content ---------------- */
  const noText = !subject.trim() && !visible.trim();
  if (noText && !facts.attachments.length)
    c.add('content.empty_message', { fallback: { title: t('Message vide'), family: 'content', severity: 'high', penalty: 2 } });
  if (facts.html && !facts.text)
    c.add('content.no_text_part', {
      fallback: {
        title: t('Le message n’a pas de version texte'),
        why: t('Un message HTML sans partie text/plain est un signal classique des filtres anti-spam.'),
        fix: [t('Activez la version texte (multipart/alternative) dans votre outil d’envoi.')],
        family: 'content',
        severity: 'medium',
        penalty: 0.7,
      },
    });
  else if (facts.html && facts.text) {
    const textClean = text.trim();
    if (textClean.length < T.minTextChars && htmlVisible.length >= T.minTextChars)
      c.add('content.text_part_empty', { fallback: { title: t('La version texte est vide'), family: 'content', severity: 'medium', penalty: 0.7 } });
    else {
      const sim = similarity(text, htmlVisible);
      data.textHtmlSimilarity = Math.round(sim * 100) / 100;
      if (sim < T.minTextHtmlSimilarity)
        c.add('content.text_html_mismatch', { vars: { value: t('{n} %', { n: Math.round(sim * 100) }) }, fallback: { title: t('Les versions texte et HTML diffèrent'), family: 'content', severity: 'medium', penalty: 0.5 } });
      else c.pass('content.text_html', 'content', t('Versions texte et HTML cohérentes'), t('similarité {n} %', { n: Math.round(sim * 100) }));
    }
  } else if (facts.text) c.pass('content.text_part', 'content', t('Version texte présente'));

  if (!noText && visibleWords < T.minBodyWords && !facts.attachments.length && !contentImgs.length)
    c.add('content.text_too_short', { vars: { value: visibleWords }, fallback: { title: t('Corps très court ({value} mots)'), family: 'content', severity: 'low', penalty: 0.3 } });
  const withoutUrls = visible.replace(/https?:\/\/\S+/g, '').replace(/\s+/g, ' ').trim();
  if (withoutUrls.length < T.minTextChars && (links.length > 0 || /https?:\/\//.test(visible)) && !contentImgs.length)
    c.add('content.url_only_body', { fallback: { title: t('Le corps se résume à un lien'), family: 'content', severity: 'medium', penalty: 0.7 } });

  const invisible = `${subject}${visible}${html}`.match(INVISIBLE)?.length ?? 0;
  data.invisibleChars = invisible;
  if (invisible > T.maxInvisibleChars)
    c.add('content.invisible_characters', { vars: { value: invisible }, fallback: { title: t('{value} caractères invisibles dans le texte'), family: 'content', severity: 'medium', penalty: 0.7 } });

  const letters = visible.replace(/[^\p{L}]/gu, '');
  const upper = visible.replace(/[^\p{Lu}]/gu, '');
  if (letters.length >= T.bodyCapsMinLetters && upper.length / letters.length >= T.bodyCapsRatio)
    c.add('content.excessive_caps', { fallback: { title: t('Texte majoritairement en majuscules'), family: 'content', severity: 'low', penalty: 0.3 } });
  if (/[!?€$]{3,}/.test(`${subject} ${visible}`))
    c.add('content.excessive_punctuation', { fallback: { title: t('Ponctuation répétée (!!!, ???, $$$)'), family: 'content', severity: 'low', penalty: 0.2 } });

  const moji = /Ã[©¨ ª«®¯´¹»¼§]|â€[™œ\x9d“”˜¦]|Â[ ©°«»]/.exec(`${subject} ${visible}`);
  if (moji) c.add('content.mojibake', { vars: { value: moji[0] }, fallback: { title: t('Caractères accentués cassés ({value})'), family: 'content', severity: 'medium', penalty: 0.7 } });
  if (`${subject}${visible}`.includes('�')) c.add('content.replacement_characters', { fallback: { title: t('Caractères de remplacement (�) dans le texte'), family: 'content', severity: 'medium', penalty: 0.5 } });
  const merge = /\*\|[A-Z_:]+\|\*|\{\{\s*[\w.]+\s*\}\}|\[\[?[A-Z_]{3,}\]\]?|%%[\w]+%%/.exec(`${subject} ${visible}`);
  if (merge) c.add('content.unreplaced_merge_tags', { vars: { value: merge[0] }, fallback: { title: t('Balise de fusion non remplacée : {value}'), family: 'content', severity: 'medium', penalty: 0.5 } });
  const placeholder = /lorem ipsum|dolor sit amet|votre texte ici|your text here|insert text/i.exec(visible);
  if (placeholder) c.add('content.placeholder_text', { vars: { value: placeholder[0] }, fallback: { title: t('Texte de remplissage oublié'), family: 'content', severity: 'low', penalty: 0.3 } });

  if (contentImgs.length && visibleWords < T.minBodyWords)
    c.add('content.image_only', {
      vars: {
        value: t('{words} pour {images} ; visez au moins {min} mots', {
          words: tPlural(visibleWords, '{n} mot visible', '{n} mots visibles'),
          images: tPlural(contentImgs.length, '{n} image', '{n} images'),
          min: T.minBodyWords,
        }),
      }, fallback: { title: t('Message composé d’images presque sans texte'), family: 'content', severity: 'high', penalty: 1.5 } });
  else if (contentImgs.length && visibleWords / contentImgs.length < T.minWordsPerImage)
    c.add('images.image_heavy', { vars: { value: t('{images} images pour {words} mots', { images: contentImgs.length, words: visibleWords }) }, fallback: { title: t('Beaucoup d’images pour peu de texte'), family: 'images', severity: 'medium', penalty: 0.5 } });

  if (facts.html && facts.html.decoded.length > T.gmailClipBytes)
    c.add('content.html_clipped_gmail', { vars: { value: t('{n} Ko', { n: Math.round(facts.html.decoded.length / 1024) }) }, fallback: { title: t('HTML de plus de 102 Ko : Gmail le coupera'), family: 'content', severity: 'medium', penalty: 0.7 } });
  if (facts.text?.cte === 'base64' && /^[\x00-\x7f]*$/.test(text))
    c.add('content.text_part_base64', { fallback: { title: t('Version texte encodée en base64 sans nécessité'), family: 'content', severity: 'low', penalty: 0.2 } });

  /* ---------------- HTML ---------------- */
  if (html) {
    const all = tags(html);
    const has = (...n: string[]) => all.filter((t) => n.includes(t.name));
    if (has('script').length) c.add('html.script_tag', { fallback: { title: t('Le HTML contient du JavaScript'), family: 'html', severity: 'high', penalty: 1.5 } });
    const handlers = all.flatMap((t) => Object.keys(t.attrs).filter((a) => /^on[a-z]+$/.test(a)));
    if (handlers.length) c.add('html.event_handlers', { vars: { value: [...new Set(handlers)].join(', ') }, fallback: { title: t('Attributs JavaScript ({value})'), family: 'html', severity: 'high', penalty: 1 } });
    if (has('iframe', 'frame', 'frameset').length) c.add('html.iframe', { fallback: { title: t('Le HTML contient une iframe'), family: 'html', severity: 'medium', penalty: 0.7 } });
    if (has('form', 'input', 'textarea', 'select').length) c.add('html.form', { fallback: { title: t('Le HTML contient un formulaire'), family: 'html', severity: 'medium', penalty: 0.7 } });
    if (has('object', 'embed', 'applet').length) c.add('html.object_embed', { fallback: { title: t('Le HTML contient un objet intégré'), family: 'html', severity: 'medium', penalty: 0.7 } });
    if (has('meta').some((m) => /refresh/i.test(m.attrs['http-equiv'] ?? ''))) c.add('html.meta_refresh', { fallback: { title: t('Redirection automatique (meta refresh)'), family: 'html', severity: 'high', penalty: 1 } });
    if (has('base').length) c.add('html.base_href', { fallback: { title: t('Balise <base> dans le HTML'), family: 'html', severity: 'low', penalty: 0.3 } });
    const css = has('link').filter((l) => /stylesheet/i.test(l.attrs.rel ?? ''));
    const imports = html.match(/@import\s+(?:url\()?['"]?([^'")\s;]+)/gi) ?? [];
    if (css.length || imports.length)
      c.add('html.external_stylesheet', { vars: { url: css[0]?.attrs.href ?? imports[0] }, evidence: [...css.map((l) => l.attrs.href), ...imports].join('\n'), fallback: { title: t('Feuille de style externe'), family: 'html', severity: 'low', penalty: 0.3 } });
    if (/@font-face/i.test(html) || has('link').some((l) => /fonts\./i.test(l.attrs.href ?? '')))
      c.add('html.external_fonts', { fallback: { title: t('Polices web externes'), family: 'html', severity: 'low', penalty: 0.1 } });
    const dataUri = (html.match(/data:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/gi) ?? []).reduce((n, s) => n + s.length, 0);
    if (dataUri > T.maxDataUriBytes)
      c.add('html.base64_inline_heavy', { vars: { value: t('{n} Ko', { n: Math.round(dataUri / 1024) }) }, fallback: { title: t('Images intégrées en base64 dans le HTML'), family: 'html', severity: 'medium', penalty: 0.5 } });
    if (!/<!doctype/i.test(html)) c.add('html.no_doctype', { fallback: { title: t('HTML sans DOCTYPE'), family: 'html', severity: 'low', penalty: 0.1 } });
    if (!/<html\b[^>]*\blang\s*=/i.test(html)) c.add('html.lang_missing', { fallback: { title: t('Langue du HTML non déclarée'), family: 'html', severity: 'info', penalty: 0 } });
    const asciiEntities = (html.match(/&#(x[0-9a-f]+|\d+);/gi) ?? []).filter((e) => {
      const n = /x/i.test(e[2]) ? parseInt(e.slice(3), 16) : parseInt(e.slice(2), 10);
      return (n >= 65 && n <= 90) || (n >= 97 && n <= 122);
    }).length;
    if (asciiEntities > 10) c.add('html.obfuscated_entities', { fallback: { title: t('Lettres écrites en entités numériques'), family: 'html', severity: 'medium', penalty: 0.5 } });
    if (!c.findings.some((f) => f.family === 'html' && f.penalty > 0.3)) c.pass('html.clean', 'html', t('Aucun élément HTML risqué (script, iframe, formulaire)'));
  }

  /* ---------------- attachments ---------------- */
  const atts = facts.attachments.map((p) => {
    const name = p.filename ?? '';
    const e = ext(name);
    const info: Record<string, unknown> = { filename: p.filename, contentType: p.contentType, size: p.decoded.length, extension: e };
    return { p, name, e, info };
  });
  sc.data.attachments = atts.map((a) => a.info);
  let total = 0;
  for (const a of atts) {
    total += a.p.decoded.length;
    const v = { value: a.name || a.p.contentType };
    if (!a.name && a.p.disposition === 'attachment')
      c.add('attachments.no_filename', { fallback: { title: t('Pièce jointe sans nom'), family: 'attachments', severity: 'low', penalty: 0.2 } });
    if (BIDI.test(a.name))
      c.add('attachments.filename_bidi_override', { evidence: JSON.stringify(a.name), fallback: { title: t('Nom de fichier avec caractère d’inversion de sens'), family: 'attachments', severity: 'high', penalty: 2 } });
    if (GMAIL_BLOCKED_EXT.has(a.e))
      c.add('attachments.dangerous_extension', { vars: v, fallback: { title: t('Pièce jointe {value} : type bloqué par Gmail'), family: 'attachments', severity: 'critical', penalty: 3 } });
    if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip)\.[a-z0-9]{2,5}$/i.test(a.name) && (GMAIL_BLOCKED_EXT.has(a.e) || HTML_EXT.has(a.e) || MACRO_EXT.has(a.e)))
      c.add('attachments.double_extension', { vars: v, fallback: { title: t('Double extension : {value}'), family: 'attachments', severity: 'high', penalty: 2 } });
    const isOle = magicType(a.p.decoded) === 'ole';
    const ooxmlMacro = a.p.decoded.includes('vbaProject.bin');
    const oleMacro = isOle && (a.p.decoded.includes(Buffer.from('_VBA_PROJECT', 'utf16le')) || a.p.decoded.includes('_VBA_PROJECT'));
    if (MACRO_EXT.has(a.e) || ooxmlMacro || oleMacro)
      c.add('attachments.office_macro', { vars: v, fallback: { title: t('Document Office avec macros : {value}'), family: 'attachments', severity: 'high', penalty: 2 } });
    if (HTML_EXT.has(a.e) || a.p.contentType === 'text/html')
      c.add('attachments.html_attachment', { vars: v, fallback: { title: t('Pièce jointe HTML : {value}'), family: 'attachments', severity: 'high', penalty: 1 } });
    if (/ms-tnef/i.test(a.p.contentType) || /^winmail\.dat$/i.test(a.name))
      c.add('attachments.winmail_dat', { fallback: { title: t('Pièce jointe winmail.dat (format Outlook)'), family: 'attachments', severity: 'low', penalty: 0.3 } });
    if (a.e === 'zip' || magicType(a.p.decoded) === 'zip') {
      const z = zipEntries(a.p.decoded);
      a.info.entries = z.names.slice(0, 50);
      if (z.encrypted)
        c.add('attachments.encrypted_archive', { vars: v, fallback: { title: t('Archive chiffrée : {value}'), family: 'attachments', severity: 'high', penalty: 1.5 } });
      const bad = z.names.filter((n) => GMAIL_BLOCKED_EXT.has(ext(n)));
      if (bad.length)
        c.add('attachments.archive_with_dangerous', { vars: { value: `${a.name} (${bad.slice(0, 3).join(', ')})` }, fallback: { title: t('Archive contenant un exécutable : {value}'), family: 'attachments', severity: 'critical', penalty: 3 } });
    } else if (ARCHIVE_EXT.has(a.e)) a.info.entries = undefined;
    if (a.e === 'pdf' || magicType(a.p.decoded) === 'pdf') {
      const s = a.p.decoded.toString('latin1');
      const active = ['/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/OpenAction'].filter((k) => new RegExp(k.replace('/', '\\/') + '\\b').test(s));
      if (active.length)
        c.add('attachments.pdf_active_content', { vars: { value: `${a.name} (${active.join(', ')})` }, fallback: { title: t('PDF avec contenu actif : {value}'), family: 'attachments', severity: 'high', penalty: 1.5 } });
    }
    const magic = magicType(a.p.decoded);
    if (magic && a.e && !(EXT_FAMILY[magic] ?? []).includes(a.e) && !(magic === 'zip' && ARCHIVE_EXT.has(a.e)))
      c.add('attachments.type_mismatch', { vars: { value: t('{name} (contenu {type})', { name: a.name, type: magic }) }, fallback: { title: t('Le contenu de {value} ne correspond pas à son extension'), family: 'attachments', severity: 'medium', penalty: 0.7 } });
  }
  if (facts.input.raw.length > T.maxMessageBytes)
    c.add('attachments.too_large', { vars: { value: t('{n} Mo', { n: (facts.input.raw.length / 1e6).toFixed(1) }) }, fallback: { title: t('Message de {value}'), family: 'attachments', severity: 'high', penalty: 1.5 } });
  else if (total > T.largeAttachmentBytes)
    c.add('attachments.large', { vars: { value: t('{n} Mo', { n: (total / 1e6).toFixed(1) }) }, fallback: { title: t('Pièces jointes lourdes ({value})'), family: 'attachments', severity: 'low', penalty: 0.3 } });
  if (atts.length && visible.trim().length < T.minTextChars)
    c.add('attachments.attachment_without_body', { fallback: { title: t('Pièce jointe sans texte d’accompagnement'), family: 'attachments', severity: 'medium', penalty: 0.5 } });
  if (atts.length && !c.findings.some((f) => f.family === 'attachments'))
    c.pass('attachments.ok', 'attachments', t('{n} pièce(s) jointe(s) sans risque détecté', { n: atts.length }));
}
