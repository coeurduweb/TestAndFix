import { describe, expect, it } from 'vitest';
import type { SvgCheck } from '../domain/model';
import { certName, leftoverMetrics, otherSvgIssues, svgMetrics } from './svg';

// cloudflare.com, measured 2026-11-10
const cloudflare: SvgCheck = {
  url: 'https://www.cloudflare.com/cloudflare_1171114652.svg', status: 200, contentType: 'image/svg+xml', bytes: 44212, version: '1.1', viewBox: '0 0 199.98 90.58', square: false,
  problems: ['attribut baseProfile="tiny-ps" absent', 'version="1.1" au lieu de "1.2"', 'élément <title> absent ou vide'],
  warnings: ['élément <desc> absent (Google recommande de l’ajouter)', 'logo non carré (viewBox 0 0 199.98 90.58) : Google et le BIMI Group recommandent un carré', 'fichier de 43 Ko décompressé, au-delà des 32 Ko recommandés'],
  // the server flags the size and format advice (2026-11-12, language-neutral: the texts are translated)
  sizeWarnings: ['logo non carré (viewBox 0 0 199.98 90.58) : Google et le BIMI Group recommandent un carré', 'fichier de 43 Ko décompressé, au-delà des 32 Ko recommandés'],
};

describe('svgMetrics', () => {
  it('measures each requirement once and keeps only the problems no row shows', () => {
    const rows = svgMetrics(cloudflare);
    expect(rows.find((r) => r.key === 'profile')?.dev.kind).toBe('out');
    expect(rows.find((r) => r.key === 'version')?.measured).toBe('1.1');
    expect(rows.find((r) => r.key === 'square')?.dev.kind).toBe('warn');
    expect(rows.find((r) => r.key === 'size')).toMatchObject({ measured: '43,2 Ko', dev: { kind: 'warn', text: '11 Ko' } });
    expect(otherSvgIssues(cloudflare)).toEqual([{ text: 'élément <desc> absent (Google recommande de l’ajouter)', must: false }]);
    expect(leftoverMetrics(cloudflare)[0].ids).toEqual(['bimi.svg_recommendation']);
  });
  it('stops at the HTTP row when the file cannot be read', () => {
    expect(svgMetrics({ url: 'https://x/l.svg', error: 'HTTP 404', problems: [], warnings: [] })).toHaveLength(1);
  });
});

describe('certName', () => {
  it('reads the CN with escaped commas', () => {
    expect(certName('C=US, O=DigiCert\\, Inc., CN=DigiCert Verified Mark RSA4096 SHA256 2021 CA1')).toBe('DigiCert Verified Mark RSA4096 SHA256 2021 CA1');
    expect(certName('C=US, O=Exemple\\, SA')).toBe('Exemple, SA');
  });
});
