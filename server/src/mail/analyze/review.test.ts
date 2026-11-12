// Defects found by the independent review of the reports (2026-11-10): each test reproduces one.
import { describe, expect, it } from 'vitest';
import { analyzeMessage } from './index.js';
import { describeFetchError } from './links.js';
import { deps, fakeResolver, fixture, goodZone, SENDER_IP } from '../test-helpers.js';
import type { Fetcher } from './types.js';
import type { MailReport } from './index.js';

const html = (body: string) =>
  Buffer.from(
    [
      'From: Boutique <news@atelier-exemple.fr>',
      'To: t-abcd2345@check.localhost',
      'Subject: Nouveautés',
      'Date: Tue, 10 Nov 2026 15:58:00 +0100',
      'Message-ID: <r1@atelier-exemple.fr>',
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      '',
      body,
      '',
    ].join('\r\n'),
  );
const smtp = (raw: Buffer, extra = {}) => ({ raw, via: 'smtp' as const, clientIp: SENDER_IP, helo: 'mail.atelier-exemple.fr', mailFrom: 'bounce@atelier-exemple.fr', tls: { protocol: 'TLSv1.3' }, ...extra });
const allText = (r: MailReport) => JSON.stringify(r.findings.map((f) => [f.title, f.why, f.fix, f.evidence, f.providerFix]));
const NINE = '<p>Découvrez notre nouvelle collection de chaises en chêne massif</p>';

describe('review defects', () => {
  it('1. unreachable image: the HTTP status, not the number of images', async () => {
    const fetcher: Fetcher = async () => ({ status: 404, headers: {} });
    const raw = html(`<html><body>${NINE} et bien plus encore pour votre maison cet hiver, venez nous voir en boutique.<img src="https://www.atelier-exemple.fr/a.jpg" alt="a"><img src="https://www.atelier-exemple.fr/b.jpg" alt="b"></body></html>`);
    const r = await analyzeMessage(smtp(raw), deps(fakeResolver(goodZone()), { fetcher }));
    const f = r.findings.find((x) => x.id === 'images.unreachable')!;
    expect(f.why).toContain('erreur HTTP 404');
    expect(f.why).not.toMatch(/erreur 2\b/);
    expect(f.evidence).toContain('2 images');
  });

  it('2. missing alt: number agrees', async () => {
    const raw = html(`<html><body>${NINE} et bien plus encore pour votre maison cet hiver, venez nous voir en boutique.<img src="https://www.atelier-exemple.fr/a.jpg"></body></html>`);
    const r = await analyzeMessage(smtp(raw), deps(fakeResolver(goodZone())));
    const f = r.findings.find((x) => x.id === 'images.missing_alt')!;
    expect(allText(r)).not.toMatch(/1 images/);
    expect(f.evidence).toMatch(/^1 image sans attribut alt/);
  });

  it('3. import without MAIL FROM: no "undefined", no generic wording', async () => {
    const raw = fixture('via-mailbox.eml').toString('latin1').replace(/^Return-Path:.*\r\n/, '');
    const zone = goodZone();
    delete zone['_dmarc.atelier-exemple.fr'];
    const r = await analyzeMessage({ raw: Buffer.from(raw, 'latin1'), via: 'upload' }, deps(fakeResolver(zone)));
    const text = allText(r);
    expect(text).not.toContain('undefined');
    expect(text).not.toContain("le domaine d'enveloppe");
    expect(r.findings.find((f) => f.id === 'alignment.none_aligned')?.evidence).toContain('aucun MAIL FROM (message importé)');
    expect(JSON.stringify(r.data)).not.toContain('"undefined"');
    // pasted without any Received: no IP either
    const bare = raw.replace(/^(Delivered-To|Received|\t).*\r\n/gm, '');
    const r2 = await analyzeMessage({ raw: Buffer.from(bare, 'latin1'), via: 'upload' }, deps(fakeResolver(zone)));
    expect(allText(r2)).not.toContain('undefined');
    expect(JSON.stringify(r2.data)).not.toContain('"undefined"');
    expect(r2.findings.find((f) => f.id === 'alignment.none_aligned')?.evidence).toContain('SPF non évalué');
  });

  it('4. private sending IP: PTR requirement not measurable, no fix', async () => {
    const r = await analyzeMessage(smtp(fixture('newsletter-no-post.eml'), { clientIp: '127.0.0.1' }), deps(fakeResolver(goodZone())));
    const req = (r.data.compliance as { requirements: { id: string; ok: boolean | null; detail: string }[] }).requirements.find((x) => x.id === 'ptr')!;
    expect(req.ok).toBeNull();
    expect(req.detail).toMatch(/privée ou locale/);
    expect(r.findings.map((f) => f.id)).not.toContain('bulk-sender.ptr_required');
    expect(allText(r)).not.toContain("l'IP 127.0.0.1");
  });

  it('5. image with a few words: "presque sans texte", with the figures', async () => {
    const raw = html(`<html><body>${NINE}<img src="https://www.atelier-exemple.fr/a.jpg" alt="Collection"></body></html>`);
    const r = await analyzeMessage(smtp(raw), deps(fakeResolver(goodZone())));
    const f = r.findings.find((x) => x.id === 'content.image_only')!;
    const t = `${f.title} ${f.why}`;
    expect(t).toMatch(/presque sans texte/);
    expect(t).not.toMatch(/sans texte"|entièrement dans les images/);
    expect(t).toContain('9 mots visibles pour 1 image');
    expect(t).toContain('au moins 20 mots');
  });

  it('6. readable French reason next to the technical detail', async () => {
    const fetcher: Fetcher = async () => {
      throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED 203.0.113.9:443'), { code: 'ECONNREFUSED' }) });
    };
    const r = await analyzeMessage(smtp(fixture('clean.eml')), deps(fakeResolver(goodZone()), { fetcher, spamd: { host: '127.0.0.1', port: 1, timeoutMs: 500 } }));
    const link = (r.data.links as { check?: { error?: string; reason?: string } }[])[0];
    expect(link.check?.reason).toBe('connexion refusée par le serveur');
    expect(link.check?.error).toContain('ECONNREFUSED');
    const broken = r.findings.find((f) => f.id === 'links.broken')!;
    expect(broken.evidence).toContain('connexion refusée');
    expect(broken.evidence).not.toContain('fetch failed');
    const sa = r.unavailable!.find((u) => u.source === 'SpamAssassin') as { reason: string; detail?: string };
    expect(sa.reason).not.toMatch(/ECONNREFUSED|connect /);
    expect(sa.detail).toMatch(/ECONNREFUSED/);
    expect(describeFetchError(new Error('délai de 5 s dépassé')).reason).toBe('pas de réponse en 5 s');
    expect(describeFetchError(Object.assign(new Error('x'), { code: 'UNSAFE_TARGET' })).reason).toMatch(/adresse privée/);
  });
});

describe('review 2 (2026-11-10)', () => {
  const auth = (r: MailReport) => r.data.auth as { spf: { result: string }; alignment: { spf: { evaluated: boolean; result: string; label: string } }; authenticationResults?: string };

  it('1. import without IP nor MAIL FROM: no SPF evaluation, spf=none in the headers we write', async () => {
    const raw = fixture('via-mailbox.eml').toString('latin1').replace(/^(Return-Path|Delivered-To|Received|\t).*\r\n/gm, '');
    const r = await analyzeMessage({ raw: Buffer.from(raw, 'latin1'), via: 'upload' }, deps(fakeResolver(goodZone())));
    const ar = auth(r).authenticationResults!;
    expect(ar).not.toContain('undefined');
    expect(ar).not.toContain('temperror');
    expect(ar).toContain("spf=none (message importé, pas d'IP)");
    expect(ar).toMatch(/Received-SPF: none/);
  });

  it('2. local IP: alignment says SPF not evaluated, Received-SPF is none with « IP locale »', async () => {
    const r = await analyzeMessage(smtp(fixture('clean.eml'), { clientIp: '127.0.0.1' }), deps(fakeResolver(goodZone())));
    const a = auth(r);
    expect(a.alignment.spf).toMatchObject({ evaluated: false, result: 'not_evaluated' });
    expect(a.alignment.spf.label).toContain('SPF non évalué');
    expect(a.authenticationResults).toMatch(/Received-SPF: none \([^)]*IP locale/);
    expect(a.authenticationResults).toContain('spf=none (IP locale)');
    expect(a.authenticationResults).not.toMatch(/softfail|spf=fail/);
  });

  it('3. no DKIM at all: the unsubscribe headers finding costs nothing, DMARC failure still counts', async () => {
    const base = fixture('newsletter-no-post.eml').toString('latin1').replace('Precedence: bulk\r\n', 'Precedence: bulk\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n');
    const zone = goodZone();
    zone['atelier-exemple.fr'].TXT = [['v=spf1 -all']];
    const r = await analyzeMessage(smtp(Buffer.from(base, 'latin1')), deps(fakeResolver(zone)));
    const ns = r.findings.find((f) => f.id === 'unsubscribe.not_dkim_signed')!;
    expect(ns).toMatchObject({ penalty: 0, severity: 'info' });
    expect(r.findings.find((f) => f.id === 'dkim.missing')!.penalty).toBeGreaterThan(0);
    expect(r.findings.find((f) => f.id.startsWith('dmarc.fail'))!.penalty).toBeGreaterThan(0);
  });
});
