// Internal thresholds of the analyzer. The knowledge base says "seuil interne" for these
// situations: no provider publishes a figure, so these are the tool's own settings, kept here in
// one place. The figures that do come from a published rule are marked with their source.
export const T = {
  /** Date header more than this ahead of reception. */
  maxDateSkewFutureMs: 15 * 60 * 1000,
  /** Date header more than this before reception. */
  maxDateSkewPastMs: 3 * 24 * 3600 * 1000,
  subjectCapsRatio: 0.7,
  subjectCapsMinLetters: 12,
  subjectMaxEmoji: 3,
  /** Alert threshold only: RFC 5321 §6.3 asks loop detection to use at least 100. */
  maxReceivedHops: 25,
  maxHeadersBytes: 32 * 1024,
  /** RFC 5322 §2.1.1 */
  maxLineLength: 998,
  minTextChars: 20,
  minBodyWords: 20,
  /** Word-set similarity (Jaccard) between the text part and the visible HTML text. */
  minTextHtmlSimilarity: 0.4,
  maxInvisibleChars: 3,
  bodyCapsRatio: 0.5,
  bodyCapsMinLetters: 200,
  /** Gmail clips HTML bodies over 102 KB (Gmail Help Center, "message clipped"). */
  gmailClipBytes: 102 * 1024,
  maxLinks: 50,
  maxLinkRedirects: 3,
  maxLinksChecked: 40,
  linkConcurrency: 6,
  linkTimeoutMs: 5000,
  linkMaxRedirects: 10,
  maxImageBytes: 1024 * 1024,
  maxImagesChecked: 30,
  /** Fewer visible words than this per image: the message is mostly images. */
  minWordsPerImage: 25,
  maxInlineImages: 10,
  maxDataUriBytes: 100 * 1024,
  largeAttachmentBytes: 10 * 1024 * 1024,
  /** Gmail's limit on received message size. */
  maxMessageBytes: 25 * 1000 * 1000,
  /** One rule's score below this is shown but does not cost points. */
  minSaScore: 0.05,
};

/** Extensions Gmail blocks, as listed in knowledge/situations/attachments.yaml (checked 2026-11-10). */
export const GMAIL_BLOCKED_EXT = new Set(
  'ade adp apk appx appxbundle bat cab chm cmd com cpl diagcab diagcfg diagpkg dll dmg ex ex_ exe hta img ins iso isp jar jnlp js jse lib lnk mde mjs msc msi msix msixbundle msp mst nsh pif ps1 scr sct shb sys vb vbe vbs vhd vxd wsc wsf wsh xll'.split(
    ' ',
  ),
);

export const MACRO_EXT = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'ppsm']);
export const HTML_EXT = new Set(['html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml']);
export const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'bz2', 'xz', 'tar', 'cab', 'arj', 'lzh', 'ace']);

/** Public URL shorteners (list kept by the tool). */
export const SHORTENERS = new Set(
  'bit.ly bitly.com j.mp tinyurl.com t.ly is.gd v.gd cutt.ly ow.ly buff.ly rebrand.ly shorturl.at rb.gy t.co tiny.cc bl.ink s.id lnkd.in shorte.st adf.ly qr.ae soo.gd x.co trib.al goo.gl tiny.one shorturl.com u.to clck.ru'.split(
    ' ',
  ),
);

export const FREEMAIL = new Set(
  'gmail.com googlemail.com yahoo.com yahoo.fr ymail.com hotmail.com hotmail.fr outlook.com outlook.fr live.com live.fr msn.com aol.com icloud.com me.com gmx.com gmx.fr gmx.de web.de orange.fr wanadoo.fr free.fr laposte.net sfr.fr neuf.fr bbox.fr protonmail.com proton.me yandex.com yandex.ru mail.ru zoho.com'.split(
    ' ',
  ),
);

/** ESPs used for bulk and marketing mail (a message sent through them counts as bulk). */
export const BULK_ESP = new Set(['brevo', 'mailchimp', 'mailjet', 'sendgrid', 'sparkpost', 'hubspot', 'salesforce']);
