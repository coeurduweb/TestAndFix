import { expect, test } from '@playwright/test';
import nodemailer from 'nodemailer';
import { login } from './helpers';

const SMTP_PORT = Number(process.env.CHECK_E2E_SMTP_PORT ?? 2525);

test.describe('mail test, end to end', () => {
  test.beforeEach(async ({ page }) => login(page));

  test('an address is ready without a click and the report arrives by itself', async ({ page }) => {
    await page.goto('/mail');
    await expect(page).toHaveURL(/\/mail\/t-[a-z0-9]+/);
    const id = new URL(page.url()).pathname.split('/').pop()!;
    const address = await page.request.get(`/api/mail/addresses/${id}`).then((r) => r.json()).then((a) => a.address as string);
    await expect(page.getByText(address).first()).toBeVisible();

    const transport = nodemailer.createTransport({ host: '127.0.0.1', port: SMTP_PORT, secure: false, tls: { rejectUnauthorized: false } });
    await transport.sendMail({
      from: 'Test E2E <e2e@example.com>',
      to: address,
      subject: 'Votre devis de refonte',
      text: 'Bonjour, voici le devis demandé.',
      html: '<p>Bonjour, voici le <a href="https://example.com/devis">devis</a> demandé.</p>',
    });

    // no click: the page switches to the report and the score settles
    await expect(page.locator('.verdict__number')).toContainText('/10', { timeout: 60_000 });
    await expect(page.getByText('Votre devis de refonte').first()).toBeVisible();
    // example.com publishes no SPF authorising 127.0.0.1: authentication must be reported as failing
    await expect(page.getByText(/SPF/).first()).toBeVisible();
  });

  test('pasted headers are analysed from the dedicated page', async ({ page }) => {
    await page.goto('/mail/analyse');
    const raw = [
      'Received: from mail.example.com (mail.example.com [93.184.215.14]) by mx.example.net; Tue, 10 Nov 2026 14:00:00 +0100',
      'From: Test <test@example.com>',
      'To: dest@example.net',
      'Subject: Bonjour',
      'Date: Tue, 10 Nov 2026 14:00:00 +0100',
      'Message-ID: <abc@example.com>',
      '',
      'Corps du message.',
    ].join('\n');
    await page.locator('main textarea').first().fill(raw);
    const analyse = page.getByRole('button', { name: /Analyser/ });
    if (await analyse.isVisible()) await analyse.click();
    await expect(page.locator('.verdict__number')).toContainText('/10', { timeout: 60_000 });
  });
});
