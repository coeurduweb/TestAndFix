import { expect, test } from '@playwright/test';
import { login, logout, PASSWORD } from './helpers';

test.describe('access', () => {
  test('a protected tool asks for the password in place, then opens', async ({ page }) => {
    await logout(page);
    await page.goto('/spf/gmail.com');
    await expect(page.getByLabel('Mot de passe', { exact: true })).toBeVisible();
    await page.getByLabel('Mot de passe', { exact: true }).fill('mauvais');
    await page.getByRole('button', { name: 'Ouvrir', exact: true }).click();
    await expect(page.getByText(/Mot de passe incorrect/)).toBeVisible();
    await page.getByLabel('Mot de passe', { exact: true }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Ouvrir', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'gmail.com' })).toBeVisible();
  });

  test('generators stay open without password', async ({ page }) => {
    await logout(page);
    const res = await page.request.get('/api/spf/gmail.com');
    expect(res.status()).toBe(401);
    await page.goto('/generateurs/dmarc');
    await expect(page.getByLabel('Mot de passe', { exact: true })).toHaveCount(0);
  });

  test('API answers are never cacheable', async ({ page }) => {
    await login(page);
    const res = await page.request.get('/api/auth/status');
    expect(res.headers()['cache-control']).toContain('no-store');
  });
});

test.describe('universal input', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('a domain opens the domain scanner with Enter', async ({ page }) => {
    await page.goto('/');
    const box = page.getByRole('combobox', { name: /Saisie universelle/ });
    await box.fill('WWW.Example.com.');
    await expect(page.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toContainText('Scanner le domaine');
    await box.press('Enter');
    await expect(page).toHaveURL(/\/domaine\/www\.example\.com$/);
  });

  test('an IP, a URL, a DNS query and pasted headers are recognised', async ({ page }) => {
    await page.goto('/');
    const box = page.getByRole('combobox', { name: /Saisie universelle/ });
    await box.fill('8.8.8.8');
    await expect(page.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toContainText("Réputation de cette IP");
    await box.fill('https://bit.ly/abc');
    await expect(page.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toContainText('Vérifier ce lien');
    await box.fill('MX gmail.com');
    await expect(page.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toContainText('Recherche MX de gmail.com');
    await box.fill('Received: from a by b\nFrom: x@y.fr\nSubject: test');
    await expect(page.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toContainText('Analyser ces en-têtes');
  });

  test('Ctrl+K focuses the input from anywhere', async ({ page }) => {
    await page.goto('/spf');
    await page.locator('body').click();
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('combobox', { name: /Saisie universelle/ })).toBeFocused();
  });
});

test.describe('SPF page', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('measures from the URL without any click', async ({ page }) => {
    await page.goto('/spf/gmail.com');
    // the counters live in the folded technical detail (Signal, 2026-11-11): present, not shown
    await expect(page.getByText('Requêtes DNS déclenchées')).toBeAttached();
    await expect(page.locator('.verdict__number')).toContainText('/10');
    // gmail.com delegates its final rule through redirect=: it must not be reported missing
    const row = page.locator('tr', { hasText: 'Règle finale' });
    await expect(row).toContainText('via _spf.google.com');
  });

  test('tolerates a URL or an address in the form', async ({ page }) => {
    await page.goto('/spf');
    await page.getByLabel('Domaine à mesurer').fill('Contact@GMAIL.com');
    await page.getByRole('button', { name: 'Mesurer' }).click();
    await expect(page).toHaveURL(/\/spf\/gmail\.com$/);
  });

  test('no horizontal overflow on a phone @mobile', async ({ page }) => {
    await page.goto('/spf/github.com');
    await expect(page.getByText('Requêtes DNS déclenchées')).toBeAttached();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
});

test.describe('navigation inside a tool', () => {
  test.beforeEach(async ({ page }) => login(page));
  test('from the empty form to the report without reloading', async ({ page }) => {
    await page.goto('/spf');
    await page.getByLabel('Domaine à mesurer').fill('gmail.com');
    await page.getByRole('button', { name: 'Mesurer' }).click();
    await expect(page.getByText('Requêtes DNS déclenchées')).toBeAttached();
    await page.getByRole('combobox', { name: /Saisie universelle/ }).fill('github.com');
    await page.getByRole('combobox', { name: /Saisie universelle/ }).press('ArrowDown');
    await page.getByRole('option', { name: /Vérifier le SPF/ }).click();
    await expect(page.getByRole('heading', { name: 'github.com' })).toBeVisible();
  });
});
