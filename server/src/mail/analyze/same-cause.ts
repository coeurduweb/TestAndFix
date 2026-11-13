// One cause, one card (2026-11-13). Reports of a WooCommerce order email listed the same empty link three
// times as raw SpamAssassin rule names, the same "no text version" twice, and a WordPress rule without
// the address that set it off. What SpamAssassin and our own checks say about one fact is merged into
// the card that carries the points, and that card names the element at fault.
import { t, tPlural } from '../../i18n.js';
import type { Collector } from './collect.js';
import type { ImageInfo, LinkInfo } from './links.js';

const MAX_SHOWN = 3;

/** An address without its query string, which can carry tokens of the recipient. */
function shown(u: string): string {
  try {
    const x = new URL(u);
    return `${x.host}${x.pathname}`;
  } catch {
    return u.split('?')[0];
  }
}

/** Paths each SpamAssassin WordPress rule looks for (URI_WP_HACKED: a page; URI_WP_HACKED_2: any file). */
const WP_PATHS: [string, RegExp][] = [
  ['sa.uri_wp_hacked', /\/(wp-content|wp-includes)\/(?:[^/?#]+\/)*[^/?#]+\.(php|html?)(?:[?#]|$)/i],
  ['sa.uri_wp_hacked_2', /\/(wp-content\/plugins|wp-content\/themes|wp-includes)\//i],
];
const WOOCOMMERCE_PLACEHOLDER = /\/wp-content\/plugins\/woocommerce\/assets\/images\/placeholder\.\w+$/i;

export function mergeSameCause(c: Collector, data: Record<string, unknown>) {
  const find = (id: string) => c.findings.find((f) => f.id === id);
  const append = (id: string, ...lines: (string | undefined)[]) => {
    const f = find(id);
    if (f) f.evidence = [f.evidence, ...lines].filter(Boolean).join('\n');
  };

  // the empty link: SpamAssassin's card carries the points, ours names the link
  const own = find('links.empty_href');
  if (find('sa.href_empty') && own) {
    const sa = find('sa.href_empty')!;
    sa.evidence = [own.evidence, sa.evidence].filter(Boolean).join('\n');
    c.remove(own.id);
  }

  // no text version: one fact, our card keeps it (SpamAssassin's MIME_HTML_ONLY weighs 0.1)
  if (find('content.no_text_part') && find('sa.mime_html_only')) {
    append('content.no_text_part', t('SpamAssassin le relève aussi (MIME_HTML_ONLY).'));
    c.remove('sa.mime_html_only');
  }

  // WordPress paths: the address that set the rule off
  const links = (data.links as LinkInfo[] | undefined) ?? [];
  const images = (data.images as ImageInfo[] | undefined) ?? [];
  const urls = [...new Set([...links.map((l) => l.url), ...images.map((i) => i.src)].filter((u) => /^https?:/i.test(u)).map(shown))];
  for (const [id, re] of WP_PATHS) {
    if (!find(id)) continue;
    const hits = urls.filter((u) => re.test(`/${u.split('/').slice(1).join('/')}`));
    if (!hits.length) continue;
    append(
      id,
      ...hits.slice(0, MAX_SHOWN).map((u) => t('Adresse en cause : {url}', { url: u })),
      hits.length > MAX_SHOWN ? tPlural(hits.length - MAX_SHOWN, 'Et {n} autre adresse du même type.', 'Et {n} autres adresses du même type.') : undefined,
      hits.every((u) => WOOCOMMERCE_PLACEHOLDER.test(u)) ? t('C’est l’image de remplacement de WooCommerce : un produit du message n’a pas d’image.') : undefined,
    );
  }
}
