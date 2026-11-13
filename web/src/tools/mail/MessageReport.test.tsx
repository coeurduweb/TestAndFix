// Order of the report ("Signal", 2026-11-11): the sends, the verdict, the two indicators, the work
// list with the path beside it, the message as it arrives, then the technical data in tabs.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { MessageReport } from './MessageReport';
import type { MailReport, MessageSummary } from './types';
import bad from './__fixtures__/bad-report.json';

afterEach(cleanup);
vi.stubGlobal('fetch', () => Promise.reject(new TypeError('offline')));

const r = bad as unknown as MailReport;
const message: MessageSummary = {
  id: 'm-1', addressId: 't-1', receivedAt: r.data.receivedAt, via: 'smtp', status: 'done', score: r.score ?? 0, clientIp: '127.0.0.1', clientPtr: null,
  helo: 'localhost', mailFrom: r.data.message.from ?? null, rcptTo: ['t-1@check.localhost'], tls: null, from: r.data.message.from ?? null,
  fromDomain: r.data.message.fromDomain ?? null, subject: r.data.message.subject ?? null, size: 100,
};

/** The fixture as the server writes it since 2026-11-11: each finding with its axis and its impact. */
const SENDER = new Set(['spf', 'dkim', 'dmarc', 'alignment', 'rdns', 'helo', 'blacklist', 'tls', 'reputation']);
const withImpact = {
  ...r,
  findings: r.findings.map((f) => ({
    ...f,
    axis: SENDER.has(f.family) ? 'sender' : 'message',
    impact: f.severity === 'critical' ? 'blocking' : f.penalty > 0 && (f.severity === 'high' || f.severity === 'medium') ? 'spam' : 'advice',
  })),
} as MailReport;

const follows = (a: Element, b: Element) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);

describe('MessageReport', () => {
  it('opens on the sends and the verdict, then the list with its first row open, then the tabs', () => {
    render(
      <MemoryRouter>
        <MessageReport message={message} report={r} />
      </MemoryRouter>,
    );
    const order = ['.mr-sends', '.verdict', '.todo', '.mr-side', '#s-tech'].map((sel) => document.querySelector(sel));
    expect(order.every(Boolean)).toBe(true);
    for (let i = 1; i < order.length; i++) expect(follows(order[i - 1]!, order[i]!)).toBe(true);
    // the only send of the address is "Envoi 1", marked as the current one
    expect(screen.getByRole('link', { name: /Envoi 1/ }).getAttribute('aria-current')).toBe('true');
    // the first row shows its fix without any click, with the measured value
    const first = document.querySelector('.todo .todo__item')!;
    expect(first.querySelector('.steps')).not.toBeNull();
    expect(first.querySelector('.mail-measure')!.textContent).toContain('Mesuré');
    // no indicators without impact on the findings (report made before 2026-11-11)
    expect(document.querySelector('.mr-axes')).toBeNull();
    // technical data: one tab open, no lab table before it
    const tabs = screen.getAllByRole('tab');
    expect(tabs[0].getAttribute('aria-selected')).toBe('true');
    expect(tabs.map((t) => t.textContent)).toContain('Source');
    const tech = document.querySelector('#s-tech')!;
    for (const t of document.querySelectorAll('.lab-table')) expect(tech.contains(t)).toBe(true);
    // the arrow keys move between tabs
    fireEvent.keyDown(tabs[0], { key: 'ArrowRight' });
    expect(screen.getAllByRole('tab')[1].getAttribute('aria-selected')).toBe('true');
  });

  it('says what blocks delivery and filters the list by indicator', () => {
    render(
      <MemoryRouter>
        <MessageReport message={message} report={withImpact} />
      </MemoryRouter>,
    );
    expect(document.querySelector('.verdict')!.className).toContain('verdict--bad');
    expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/^\d+ éléments bloquent la livraison, d’abord\u00a0: /);
    const sender = screen.getByRole('button', { name: /^Expéditeur/ });
    const all = document.querySelectorAll('.todo__item').length;
    fireEvent.click(sender);
    expect(sender.getAttribute('aria-pressed')).toBe('true');
    const rows = document.querySelectorAll('.todo__item');
    expect(rows.length).toBeLessThan(all);
    for (const row of rows) expect(within(row as HTMLElement).getByText('Expéditeur')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Tout afficher' }));
    expect(document.querySelectorAll('.todo__item').length).toBe(all);
  });
});
