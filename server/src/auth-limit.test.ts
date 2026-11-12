import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MAX_FAILED_LOGINS_GLOBAL, resetLoginAttempts } from './auth.js';
import { startTestApp, type TestApp } from './test-helpers.js';

let T: TestApp;
beforeAll(async () => {
  T = await startTestApp();
  resetLoginAttempts();
});
afterAll(() => T.app.close());

const login = (ip: string, password = 'wrong') =>
  T.app.inject({ method: 'POST', url: '/api/auth/login', payload: { password }, headers: { 'x-forwarded-for': ip, 'sec-fetch-site': 'same-origin' } });

describe('login attempts', () => {
  it('caps failures per IP, then for the whole server when the guesses come from many IPs', async () => {
    for (let i = 0; i < 5; i++) expect((await login('198.51.100.1')).statusCode).toBe(401);
    expect((await login('198.51.100.1')).statusCode).toBe(429);
    for (let i = 0; i < MAX_FAILED_LOGINS_GLOBAL - 5; i++) expect((await login(`198.51.100.${10 + (i % 200)}`)).statusCode).toBe(401);
    // a fresh IP is now refused too, even with the right password
    const r = await login('203.0.113.7', 'mot-de-passe-de-test');
    expect(r.statusCode).toBe(429);
    expect(JSON.parse(r.body).retryAfter).toBeGreaterThan(0);
  });
});
