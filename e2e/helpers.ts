import type { Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
// The local password is read from .env (never written in the repository: it is also the production one).
// CHECK_E2E_PASSWORD overrides it.
function localPassword(): string {
  try {
    return readFileSync(new URL('../.env', import.meta.url), 'utf8').match(/^CHECK_PASSWORD=(.*)$/m)?.[1]?.trim() ?? '';
  } catch {
    return '';
  }
}
export const PASSWORD = process.env.CHECK_E2E_PASSWORD ?? process.env.CHECK_PASSWORD ?? localPassword();
export async function login(page: Page) {
  await page.request.post('/api/auth/login', { data: { password: PASSWORD } });
}
export async function logout(page: Page) {
  await page.request.post('/api/auth/logout');
}
