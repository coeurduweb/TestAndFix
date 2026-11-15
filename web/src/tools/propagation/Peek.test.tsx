// Full records of an answer (user, 2026-11-15: several TXT showed « +3 » without their values, a DKIM key
// was cut): the card opens on hover, focus and click, and marks each record against the expected value.
import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { Records } from './Peek';
import { ResolverGroup } from './ResolverList';
import type { AuthorityEvent, ResolverEvent, Row } from './model';

afterEach(cleanup);

const TXT = ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc', 'H5v5f6gh5v64'];
const DKIM = 'v=DKIM1; k=rsa; p=' + 'A'.repeat(380);

const authority = (values: string[]): AuthorityEvent => ({
  zone: 'exemple.fr', servers: [], serials: [1], divergent: false,
  divergence: { answers: false, serials: false, dynamic: false, sameAnswerDifferentSerials: false }, serialGroups: [],
  reference: { source: 'authority', exists: true, kind: 'records', values, cname: null, ttl: 300, serial: 1, finalValues: values, chain: [] },
  authority: { exists: true, cname: null, values }, expectedMatchesAuthority: null, ms: 10,
});

const row = (ip: string, status: ResolverEvent['status'], values: string[]): Row => {
  const info = { ip, name: ip, provider: 'Op ' + ip, asn: 1, country_code: 'FR', continent: 'EU', city: 'Paris', lat: 48.8, lon: 2.3, anycast: false, group: 'local' as const, filtering: 'none' as const, dnssec: true, latencyMs: 20 };
  return { info, remeasuring: false, ev: { ...info, status, rcode: 'NOERROR', cname: null, values, ttl: 300, refreshAt: null, geo: null, uncertain: false, at: '2026-11-15T00:00:00.000Z' } };
};

const list = (rows: Row[], ref: string[]) =>
  render(<ResolverGroup title="Europe" rows={rows} authority={authority(ref)} highlight={null} isGood={() => true} />);

describe('records of an answer', () => {
  it('says when the answer is the expected one', () => {
    render(<Records values={[...TXT].reverse()} reference={TXT} />);
    expect(screen.getByText('Identique à la valeur attendue')).toBeTruthy();
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(screen.queryByText('en plus')).toBeNull();
  });

  it('marks what is served in plus and what is missing', () => {
    render(<Records values={['H5v5f6gh5v64', 'v=spf1 -all']} reference={TXT} />);
    expect(screen.getByText('1 valeur en plus, 2 valeurs attendues manquent')).toBeTruthy();
    const extra = screen.getByText('v=spf1 -all').closest('li')!;
    expect(within(extra).getByText('en plus')).toBeTruthy();
    const missing = screen.getByText('google-site-verification=abc').closest('li')!;
    expect(within(missing).getByText('manque')).toBeTruthy();
    // what is not served cannot be copied
    expect(within(missing).queryByRole('button')).toBeNull();
  });

  it('accepts more records when the expected value only has to be contained', () => {
    render(<Records values={[...TXT, 'autre=1']} reference={['H5v5f6gh5v64']} subset />);
    expect(screen.getByText('Contient la valeur attendue')).toBeTruthy();
    expect(screen.queryByText('en plus')).toBeNull();
  });

  it('shows a long value whole', () => {
    render(<Records values={[DKIM]} />);
    expect(screen.getByText(DKIM)).toBeTruthy();
  });
});

describe('a resolver row', () => {
  it('opens every record on a click on its value, and closes on Escape', () => {
    list([row('192.0.2.1', 'fresh', TXT)], TXT);
    const btn = screen.getByRole('button', { name: /Voir les 3 valeurs servies par Op 192\.0\.2\.1/ });
    expect(btn.textContent).toContain('+2');
    fireEvent.click(btn);
    const card = screen.getByRole('dialog', { name: 'Valeurs servies par Op 192.0.2.1' });
    for (const v of TXT) expect(within(card).getByText(v)).toBeTruthy();
    expect(btn.getAttribute('aria-expanded')).toBe('true');
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('opens on keyboard focus', async () => {
    list([row('192.0.2.2', 'fresh', [DKIM])], [DKIM]);
    await act(async () => {
      screen.getByRole('button', { name: /Voir la valeur servie/ }).focus();
      await new Promise((r) => setTimeout(r, 10));
    });
    expect(within(screen.getByRole('dialog')).getByText(DKIM)).toBeTruthy();
  });

  it('compares an old answer with the expected one', () => {
    list([row('192.0.2.3', 'stale', ['H5v5f6gh5v64', 'v=spf1 -all'])], TXT);
    fireEvent.click(screen.getByRole('button', { name: /Voir les 2 valeurs/ }));
    expect(within(screen.getByRole('dialog')).getByText('1 valeur en plus, 2 valeurs attendues manquent')).toBeTruthy();
  });

  it('keeps a short single value in the row, with no card', () => {
    list([row('192.0.2.4', 'fresh', ['1.2.3.4'])], ['1.2.3.4']);
    expect(screen.getByText('1.2.3.4')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Voir/ })).toBeNull();
  });
});
