import { defineConfig, devices } from '@playwright/test';

// Runs against the dev servers (npm run dev -w server, npm run dev -w web) with the password of .env (CHECK_PASSWORD).
export default defineConfig({
  testDir: 'e2e',
  timeout: 90_000,
  expect: { timeout: 30_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.CHECK_E2E_URL ?? 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
    locale: 'fr-FR',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] }, grep: /@mobile/ },
  ],
});
