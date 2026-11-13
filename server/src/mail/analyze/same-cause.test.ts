import { describe, expect, it } from 'vitest';
import { Collector } from './collect.js';
import { mergeSameCause } from './same-cause.js';

const fallback = (title: string) => ({ title, family: 'links', severity: 'low' as const, penalty: 0.1 });

describe('mergeSameCause (2026-11-13, WooCommerce order email)', () => {
  it('names the empty link in the SpamAssassin card and drops our duplicate', () => {
    const c = new Collector();
    c.add('sa.href_empty', { evidence: 'SpamAssassin HREF_EMPTY_PHPMAIL (1 point)', fallback: fallback('lien vide') });
    c.add('links.empty_href', { evidence: '<a href=""> : sur le texte « Produit téléchargeable fictif »', fallback: fallback('liens sans destination') });
    mergeSameCause(c, {});
    expect(c.findings.map((f) => f.id)).toEqual(['sa.href_empty']);
    expect(c.findings[0].evidence).toContain('Produit téléchargeable fictif');
  });

  it('keeps one "no text version" card', () => {
    const c = new Collector();
    c.add('content.no_text_part', { fallback: fallback('pas de version texte') });
    c.add('sa.mime_html_only', { fallback: fallback('HTML seul') });
    mergeSameCause(c, {});
    expect(c.findings.map((f) => f.id)).toEqual(['content.no_text_part']);
    expect(c.findings[0].evidence).toContain('MIME_HTML_ONLY');
  });

  it('gives the address behind a WordPress rule, without its query string, and recognises the WooCommerce placeholder', () => {
    const c = new Collector();
    c.add('sa.uri_wp_hacked_2', { fallback: fallback('wp') });
    const images = [
      { src: 'https://shop.example/wp-content/uploads/2026/11/logo.png' },
      { src: 'https://shop.example/wp-content/plugins/woocommerce/assets/images/placeholder.webp?ver=9' },
    ];
    mergeSameCause(c, { images, links: [{ url: 'https://shop.example/' }] });
    const ev = c.findings[0].evidence ?? '';
    expect(ev).toContain('shop.example/wp-content/plugins/woocommerce/assets/images/placeholder.webp');
    expect(ev).not.toContain('?ver=9');
    expect(ev).not.toContain('uploads');
    expect(ev).toContain('image de remplacement de WooCommerce');
  });
});
