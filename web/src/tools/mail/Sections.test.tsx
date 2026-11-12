// The explicit rows (SPF, DKIM, DMARC…) take their findings once, even under StrictMode's double render.
import { StrictMode } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ReportSections } from './Sections';
import { ComplianceMatrix } from './Panels';
import type { MailReport } from './types';
import bad from './__fixtures__/bad-report.json';

const r = bad as unknown as MailReport;
afterEach(cleanup);

function rowOf(label: string, section: string) {
  const sec = document.getElementById(section)!;
  const cell = within(sec).getAllByText(label, { exact: true })[0];
  return cell.closest('tr')!;
}

describe('ReportSections', () => {
  it('writes SPF, DKIM, DMARC as explicit rows carrying their points', () => {
    render(
      <StrictMode>
        <MemoryRouter>
          <ReportSections r={r} />
        </MemoryRouter>
      </StrictMode>,
    );
    expect(rowOf('SPF', 's-auth').textContent).toContain('none');
    expect(rowOf('SPF', 's-auth').textContent).toContain('1,5');
    expect(rowOf('DKIM', 's-auth').textContent).toContain('aucune signature');
    expect(rowOf('DMARC', 's-auth').textContent).toContain('1,5');
    // the same finding is not listed a second time under the explicit row
    expect(within(document.getElementById('s-auth')!).queryByText("Le message n'est pas signé avec DKIM")).toBeNull();
    // SpamAssassin: one row per rule
    expect(rowOf('DKIM_ADSP_NXDOMAIN', 's-spamassassin').textContent).toContain('+0,8');
    expect(screen.queryByText('Exigences Gmail, Yahoo, Microsoft')).toBeNull();
  });
});

describe('ComplianceMatrix', () => {
  it('one row per requirement, one cell per provider', () => {
    render(
      <MemoryRouter>
        <ComplianceMatrix r={r} />
      </MemoryRouter>,
    );
    const rows = document.querySelectorAll('.mail-matrix tr.lab-row');
    expect(rows.length).toBe(r.data.compliance!.requirements.length);
    expect(rows[0].querySelectorAll('.mail-matrix__cell').length).toBe(3);
  });
});

describe('section status', () => {
  it('a section whose source is down says "non mesuré", reputation has its own section', () => {
    const down = { ...r, data: { ...r.data, spamassassin: { available: false, error: 'connect ECONNREFUSED 127.0.0.1:7830' } } } as MailReport;
    render(
      <MemoryRouter>
        <ReportSections r={down} />
      </MemoryRouter>,
    );
    const sa = document.getElementById('s-spamassassin')!;
    expect(sa.querySelector('.mr-sec__status')!.textContent).toBe('non mesuré');
    expect(sa.textContent).toContain('connexion refusée');
    expect(document.getElementById('s-reputation')!.textContent).toContain('introuvable');
    expect(document.getElementById('s-blacklists')!.textContent).not.toContain('Feedback-ID');
  });
});
