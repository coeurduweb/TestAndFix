import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { login } from './helpers';

// WCAG 2.2 AA automatic audit of every page, light and dark. Automatic checks catch part of the
// problems only (no screen reader here): see docs/BACKLOG.md US-093.
const ROUTES = [
  '/', '/domaine/github.com', '/spf/gmail.com', '/dkim/gmail.com', '/dmarc/gmail.com', '/bimi/cnn.com',
  '/mta-sts/gmail.com', '/smtp/gmail.com', '/rdap/github.com', '/whois/github.com', '/whois?liste=github.com,afnic.fr,wikipedia.org', '/whois', '/dnssec/cloudflare.com', '/dns/gmail.com?type=MX',
  '/propagation/example.com?type=A', '/ip/8.8.8.8', '/lien?url=https://github.com', '/redirections?url=http://github.com',
  '/rapports-dmarc', '/generateurs/spf', '/generateurs/dkim', '/generateurs/dmarc', '/generateurs/mta-sts',
  '/historique', '/caches', '/carnet', '/mail/analyse', '/mail', '/sous-domaines/github.com', '/ip/github.com',
];

for (const scheme of ['light', 'dark'] as const) {
  for (const route of ROUTES) {
    test(`a11y ${scheme} ${route}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await login(page);
      await page.goto(route);
      await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 });
      await page.waitForTimeout(5000);
      const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
      const serious = r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
      const summary = serious.map((v) => `${v.id} (${v.nodes.length}) : ${v.nodes.slice(0, 2).map((n) => n.target.join(' ')).join(' ; ')}`);
      expect(summary, `violations graves sur ${route}`).toEqual([]);
    });
  }
}
