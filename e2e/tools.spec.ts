import { expect, test } from '@playwright/test';
import { login } from './helpers';

// Every tool opens with a real input, measures, and breaks nothing (no uncaught error, no horizontal scroll).
const ROUTES = [
  '/', '/domaine/github.com', '/spf/gmail.com', '/dkim/gmail.com', '/dmarc/gmail.com', '/bimi/cnn.com',
  '/mta-sts/gmail.com', '/smtp/gmail.com', '/rdap/github.com', '/whois/github.com', '/whois?liste=github.com,afnic.fr,wikipedia.org', '/whois', '/dnssec/cloudflare.com', '/dns/gmail.com?type=MX',
  '/dns/8.8.8.8', '/propagation/example.com?type=A', '/ip/8.8.8.8', '/lien?url=https://github.com',
  '/redirections?url=http://github.com', '/rapports-dmarc', '/generateurs/spf', '/generateurs/dkim',
  '/generateurs/dmarc', '/generateurs/mta-sts', '/historique', '/caches', '/carnet', '/mail/analyse', '/sous-domaines/github.com', '/ip/github.com',
];

for (const route of ROUTES) {
  test(`opens ${route} @mobile`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await login(page);
    await page.goto(route);
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(4000); // let live measurements stream in
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, 'horizontal overflow').toBeLessThanOrEqual(0);
    expect(errors, 'uncaught errors').toEqual([]);
  });
}
