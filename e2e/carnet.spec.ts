import { expect, test, type Browser, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { PASSWORD } from './helpers';

// One notebook per browser (2026-11-11): two browser contexts are two browsers. What one measures,
// the other does not see, until they are linked by a code; erasing and sharing by link.

const RAW = (subject: string) =>
  [
    'Received: from mail.example.com (mail.example.com [93.184.215.14]) by mx.example.net; Tue, 10 Nov 2026 14:00:00 +0100',
    'From: Test <test@example.com>',
    'To: dest@example.net',
    `Subject: ${subject}`,
    'Date: Tue, 10 Nov 2026 14:00:00 +0100',
    `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@example.com>`,
    '',
    'Corps du message.',
  ].join('\r\n');

async function browserOf(browser: Browser, baseURL: string | undefined): Promise<Page> {
  const ctx = await browser.newContext({ baseURL, locale: 'fr-FR' });
  const page = await ctx.newPage();
  const res = await page.request.post('/api/auth/login', { data: { password: PASSWORD } });
  expect(res.ok()).toBe(true);
  return page;
}

/** A measure saved in the history of this browser's notebook. */
async function measure(page: Page) {
  const res = await page.request.get('/api/dns/example.com?type=A');
  expect(res.ok()).toBe(true);
}

/** An imported message (the .eml analysis): returns its id. */
async function upload(page: Page, subject: string): Promise<string> {
  const res = await page.request.post('/api/mail/analyze', { data: { raw: RAW(subject) } });
  expect(res.ok()).toBe(true);
  return (await res.json()).messageId as string;
}

test.describe('notebook of each browser', () => {
  test('another browser sees neither the history nor the message', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    await measure(a);
    const id = await upload(a, 'Carnet de A');

    await a.goto('/historique');
    await expect(a.locator('.hist-row').first()).toBeVisible();
    await expect(a.getByText('Visible seulement depuis ce navigateur et vos appareils reliés')).toBeVisible();

    await b.goto('/historique');
    await expect(b.getByText('Aucune mesure pour l’instant')).toBeVisible();
    await b.goto(`/mail/message/${id}`);
    await expect(b.getByRole('heading', { name: 'Compte rendu introuvable' })).toBeVisible();
    expect((await b.request.get(`/api/mail/messages/${id}`)).status()).toBe(404);
  });

  test('a line of the history is deleted after a confirmation in place', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    await measure(a);
    await a.goto('/historique');
    const rows = a.locator('.hist-row');
    await expect(rows).toHaveCount(1);
    await a.getByRole('button', { name: /^Supprimer .* de l’historique$/ }).click();
    await a.getByRole('group', { name: /^Supprimer/ }).getByRole('button', { name: 'Supprimer', exact: true }).click();
    await expect(rows).toHaveCount(0);
    await a.reload();
    await expect(a.getByText('Aucune mesure pour l’instant')).toBeVisible();
  });

  test('linking by code: the preview shows the devices of the notebook first, one click for an empty browser', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    await measure(a);
    const aLabel = (await a.request.get('/api/me').then((r) => r.json())).device.label as string | null;

    await a.goto('/carnet');
    await expect(a.getByRole('heading', { level: 1 })).toContainText('Seul ce navigateur voit ce carnet');
    await a.getByRole('button', { name: 'Relier un appareil' }).click();
    const code = (await a.locator('.cn-code__value').textContent())?.trim() ?? '';
    expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    await expect(a.getByRole('img', { name: /Code QR/ }).locator('svg')).toBeVisible();

    // opened from the QR code: the devices of A's notebook, never linked without a click
    await b.goto(`/carnet?code=${code}`);
    const flow = b.locator('.cn-flow--top');
    await expect(flow.getByRole('heading', { name: /Rejoindre le carnet de ces appareils/ })).toBeVisible();
    await expect(flow.locator('.cn-dev__name')).toHaveText([aLabel || 'Appareil sans nom']);
    await expect(flow).toContainText(/Ce navigateur rejoindra ce carnet\s: cet appareil verra tout ce que vous ferez ici/);
    await expect(flow).toContainText('Ne reliez que vos propres appareils');
    await expect(flow).not.toContainText('votre carnet');
    expect((await b.request.get('/api/me').then((r) => r.json())).devices).toHaveLength(1);
    await flow.getByRole('button', { name: 'Relier ce navigateur' }).click();
    await expect(b.getByRole('status').filter({ hasText: 'Ce navigateur est relié' })).toBeVisible();
    await expect(b).toHaveURL(/\/carnet$/);
    await expect(b.getByRole('heading', { level: 1 })).toContainText('vos appareils reliés');

    await b.goto('/historique');
    await expect(b.locator('.hist-row')).toHaveCount(1);
    // A sees the new device by itself while the code is shown
    await expect(a.getByText(/est relié à ce carnet/)).toBeVisible({ timeout: 10_000 });

    // a used code does not serve twice
    const again = await b.request.post('/api/me/link', { data: { code } });
    expect(again.status()).toBe(400);
  });

  test('a browser holding data must choose before anything moves', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    await measure(a);
    await measure(b);
    const code = (await a.request.post('/api/me/link-code', { data: {} }).then((r) => r.json())).code as string;

    // typed by hand this time
    await b.goto('/carnet');
    await b.getByLabel(/Vous avez reçu un code/).fill(code.toLowerCase().replace('-', ''));
    await b.getByRole('button', { name: 'Continuer' }).click();
    const flow = b.locator('.cn-flow');
    await expect(flow).toContainText('Ce navigateur garde déjà 1 mesure');
    await expect(flow.getByRole('button', { name: 'Relier ce navigateur' })).toHaveCount(0);
    await expect(flow.getByRole('button', { name: 'Relier et y verser mes données' })).toBeVisible();
    await expect(flow.getByRole('button', { name: 'Effacer mes données puis relier' })).toBeVisible();

    // the API refuses a link without the second choice, and nothing has moved
    const refused = await b.request.post('/api/me/link', { data: { code } });
    expect(refused.status()).toBe(409);
    expect((await refused.json()).joining.results).toBe(1);
    expect((await a.request.get('/api/me').then((r) => r.json())).counts.results).toBe(1);
    expect((await b.request.get('/api/me').then((r) => r.json())).devices).toHaveLength(1);

    await flow.getByRole('button', { name: 'Relier et y verser mes données' }).click();
    await expect(b.getByRole('status').filter({ hasText: /1 mesure de ce navigateur a rejoint le carnet/ })).toBeVisible();
    expect((await a.request.get('/api/me').then((r) => r.json())).counts.results).toBe(2);
  });

  test('erase then link: the data held here goes, nothing moves', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    await measure(a);
    await measure(b);
    const code = (await a.request.post('/api/me/link-code', { data: {} }).then((r) => r.json())).code as string;
    await b.goto(`/carnet?code=${code}`);
    await b.locator('.cn-flow--top').getByRole('button', { name: 'Effacer mes données puis relier' }).click();
    await expect(b.getByRole('status').filter({ hasText: 'Ce navigateur est relié' })).toBeVisible();
    expect((await a.request.get('/api/me').then((r) => r.json())).counts.results).toBe(1);
  });

  test('a detached device loses its open mail stream', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    const code = (await a.request.post('/api/me/link-code', { data: {} }).then((r) => r.json())).code as string;
    expect((await b.request.post('/api/me/link', { data: { code } })).ok()).toBe(true);
    await b.goto('/mail');
    await expect(b).toHaveURL(/\/mail\/t-[a-z0-9]+/);
    await expect(b.getByText('Page à l’écoute')).toBeVisible();
    const me = await a.request.get('/api/me').then((r) => r.json());
    const other = (me.devices as { id: string; current: boolean }[]).find((d) => !d.current)!;
    expect((await a.request.delete(`/api/me/devices/${other.id}`)).status()).toBe(204);
    await expect(b.getByText('Page à l’écoute')).toHaveCount(0, { timeout: 15_000 });
  });

  test('erasing the data, then everything', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    await measure(a);
    await a.goto('/carnet');
    await a.evaluate(() => {
      localStorage.setItem('check:recent', '[{"value":"example.com"}]');
      sessionStorage.setItem('check:pending-message', 'x');
    });
    await a.reload();

    await a.getByRole('button', { name: 'Effacer mes données' }).click();
    const ask = a.getByRole('group', { name: /^Confirmer\s: Effacer mes données$/ });
    await expect(ask).toContainText('1 mesure disparaît');
    await ask.getByRole('button', { name: 'Effacer', exact: true }).click();
    await expect(a.getByRole('status').filter({ hasText: /Effacé\s: 1 mesure/ })).toBeVisible();
    expect(await a.evaluate(() => [localStorage.getItem('check:recent'), sessionStorage.getItem('check:pending-message')])).toEqual([null, null]);
    const meAfter = await a.request.get('/api/me').then((r) => r.json());
    expect(meAfter.counts.results).toBe(0);

    const before = meAfter.device.id as string;
    await a.getByRole('button', { name: 'Tout effacer, appareils compris' }).click();
    await a.getByRole('group', { name: /^Confirmer\s: Tout effacer/ }).getByRole('button', { name: 'Tout effacer', exact: true }).click();
    await expect(a.getByRole('status').filter({ hasText: 'carnet neuf' })).toBeVisible();
    const fresh = await a.request.get('/api/me').then((r) => r.json());
    expect(fresh.device.id).not.toBe(before);
  });

  test('sharing a report by link, then stopping', async ({ browser, baseURL }) => {
    const a = await browserOf(browser, baseURL);
    const b = await browserOf(browser, baseURL);
    const id = await upload(a, 'Rapport partagé');

    await a.goto(`/mail/message/${id}`);
    await expect(a.locator('.verdict__number')).toContainText('/10');
    await a.getByRole('button', { name: 'Partager' }).click();
    await a.getByRole('button', { name: 'Créer le lien' }).click();
    const url = (await a.locator('.mr-sharebox__url').textContent())?.trim() ?? '';
    expect(url).toMatch(/\/partage\/[^/]+$/);
    await a.keyboard.press('Escape');
    await expect(a.getByRole('button', { name: 'Partagé' })).toBeVisible();

    const path = new URL(url).pathname;
    await b.goto(path);
    await expect(b.getByText('Compte rendu partagé par lien')).toBeVisible();
    await expect(b.getByText('Rapport partagé').first()).toBeVisible();
    await expect(b.getByRole('button', { name: 'Partager' })).toHaveCount(0);
    await expect(b.getByRole('button', { name: 'Plus d’actions' })).toHaveCount(0);
    for (const scheme of ['light', 'dark'] as const) {
      await b.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      const r = await new AxeBuilder({ page: b }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
      const serious = r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id);
      expect(serious, `violations graves sur la page partagée (${scheme})`).toEqual([]);
    }
    // the shared report stays out of B's notebook
    expect((await b.request.get(`/api/mail/messages/${id}`)).status()).toBe(404);

    await a.getByRole('button', { name: 'Partagé' }).click();
    await a.getByRole('button', { name: 'Arrêter le partage' }).click();
    await expect(a.getByRole('button', { name: 'Partager' })).toBeVisible();
    await b.reload();
    await expect(b.getByRole('heading', { name: 'Lien expiré ou arrêté' })).toBeVisible();
  });

  test('the notebook fits a phone @mobile', async ({ page }) => {
    await page.request.post('/api/auth/login', { data: { password: PASSWORD } });
    await page.goto('/carnet');
    await page.getByRole('button', { name: 'Relier un appareil' }).click();
    await expect(page.locator('.cn-code__value')).toBeVisible();
    await page.getByRole('button', { name: 'Tout effacer, appareils compris' }).click();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
});
