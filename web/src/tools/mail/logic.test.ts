import { describe, expect, it } from 'vitest';
import {
  blockRemote, buildPath, complianceCell, complianceOrder, countRemoteImages, findPrevious, fmtDelay, initialStream,
  clientSection, decodeWords, humanError, humanReason, looksLikeMessage, lostPoints, measureOf, previewDocument, reduceStream, sectionOrder, takeByPrefix, tlsName, groupDeviation,
  headlineOf, indicatorsFrom, isEmptyHref, keyChecks, markEmptyLinks, numberSends, timingOf,
} from './logic';
import type { Hop, MailReport, MessageSummary, Requirement } from './types';

const f = (id: string, penalty: number, severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'medium') => ({ id, penalty, severity, title: id });

describe('lostPoints', () => {
  it('keeps only what costs points, most expensive first, then the most severe, then the server order', () => {
    const out = lostPoints([f('a', 0.3), f('free', 0, 'critical'), f('b', 1.5, 'medium'), f('c', 1.5, 'high'), f('d', 3), f('e', 0.3)]);
    expect(out.map((x) => x.id)).toEqual(['d', 'c', 'b', 'a', 'e']);
  });
  it('sectionOrder puts the free notes after the costly findings', () => {
    expect(sectionOrder([f('note', 0, 'info'), f('x', 0.2), f('y', 1)]).map((x) => x.id)).toEqual(['y', 'x', 'note']);
  });
});

describe('groupDeviation and takeByPrefix', () => {
  it('sums the points of a group, red when one of them is severe', () => {
    expect(groupDeviation([f('a', 1, 'high'), f('b', 0.3, 'low')])).toMatchObject({ kind: 'out', text: '1,3', direction: 'down' });
    expect(groupDeviation([f('a', 0.2, 'low')])).toMatchObject({ kind: 'warn', text: '0,2' });
    expect(groupDeviation([f('a', 0, 'info')])).toMatchObject({ kind: 'info' });
    expect(groupDeviation([])).toMatchObject({ kind: 'ok' });
  });
  it('gives each finding to one row only', () => {
    const used = new Set<string>();
    const items = [{ id: 'spf.softfail' }, { id: 'spf.helo_none' }, { id: 'dkim.missing' }];
    expect(takeByPrefix(items, ['spf.'], used).map((x) => x.id)).toEqual(['spf.softfail', 'spf.helo_none']);
    expect(takeByPrefix(items, ['spf.', 'dkim.'], used).map((x) => x.id)).toEqual(['dkim.missing']);
  });
});

const hop = (index: number, p: Partial<Hop>): Hop => ({ index, tls: null, raw: '', ...p });

describe('buildPath', () => {
  const hops: Hop[] = [
    hop(2, { from: 'mail.atelier-exemple.fr', ip: '93.184.215.14', by: 'mx1.mailhost.net', with: 'ESMTPS', tls: true, tlsDetail: 'TLSv1.3 TLS_AES_256_GCM_SHA384', at: '2026-11-10T15:00:02.000Z', delaySec: 4 }),
    hop(1, { from: '[192.168.1.20]', ip: '192.168.1.20', by: 'mail.atelier-exemple.fr', with: 'ESMTPSA', tls: true, at: '2026-11-10T14:59:58.000Z' }),
    hop(3, { from: 'mx1.mailhost.net', ip: '10.0.0.5', by: 'imap.mailhost.net', with: 'ESMTP', tls: false, at: '2026-11-10T15:00:05.000Z', delaySec: 3 }),
  ];
  const p = buildPath(hops, 'Tue, 10 Nov 2026 15:59:57 +0100');

  it('chains the relays oldest first, the "by" of a hop being the sender of the next', () => {
    expect(p.nodes.map((n) => n.name)).toEqual(['[192.168.1.20]', 'mail.atelier-exemple.fr', 'mx1.mailhost.net', 'imap.mailhost.net']);
    expect(p.nodes[1].ip).toBe('93.184.215.14');
    expect(p.nodes[2].ip).toBe('10.0.0.5');
    expect(p.nodes.every((n) => n.aliases.length === 0)).toBe(true);
  });
  it('describes each hand-off: encryption, protocol, delay', () => {
    expect(p.legs.map((l) => l.tls)).toEqual([true, true, false]);
    expect(p.legs[1]).toMatchObject({ protocol: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', delaySec: 4 });
    expect(p.legs[0].delaySec).toBeNull();
    expect(p.plaintextLegs).toBe(1);
    expect(p.totalSec).toBe(7);
    expect(p.sinceDate).toBe(1);
  });
  it('keeps a different name for the same relay as an alias instead of an unmeasured hop', () => {
    const q = buildPath([hop(1, { from: 'a.example', by: 'b.example' }), hop(2, { from: 'b-out.example', ip: '203.0.113.9', by: 'c.example' })]);
    expect(q.nodes.map((n) => n.name)).toEqual(['a.example', 'b.example', 'c.example']);
    expect(q.nodes[1]).toMatchObject({ ip: '203.0.113.9', aliases: ['b-out.example'] });
    expect(q.totalSec).toBeNull();
  });
  it('handles an empty chain', () => {
    expect(buildPath([])).toMatchObject({ nodes: [], legs: [], totalSec: null, sinceDate: null });
  });
});

describe('formatting', () => {
  it('fmtDelay', () => {
    expect(fmtDelay(0)).toBe('< 1 s');
    expect(fmtDelay(4)).toBe('4 s');
    expect(fmtDelay(75)).toBe('1 min 15 s');
    expect(fmtDelay(120)).toBe('2 min');
    expect(fmtDelay(7320)).toBe('2 h 2 min');
    expect(fmtDelay(-5)).toBe('5 s en arrière');
    expect(fmtDelay(null)).toBe('');
  });
  it('tlsName', () => {
    expect(tlsName('TLSv1.3')).toBe('TLS 1.3');
    expect(tlsName('TLSv1')).toBe('TLS 1');
    expect(tlsName(undefined)).toBeUndefined();
  });
});

describe('compliance', () => {
  const req = (id: string, ok: boolean | null, scope: 'all' | 'bulk', providers: Requirement['providers'] = ['gmail', 'yahoo']): Requirement => ({ id, label: id, ok, scope, providers, sources: [] });
  it('cell per provider', () => {
    const r = req('ptr', false, 'all');
    expect(complianceCell(r, 'gmail')).toBe('fail');
    expect(complianceCell(r, 'microsoft')).toBe('not-required');
    expect(complianceCell(req('rate', null, 'all'), 'yahoo')).toBe('unknown');
  });
  it('failures that apply come first, unmeasurable last', () => {
    const list = [req('met', true, 'all'), req('rate', null, 'all'), req('bulkfail', false, 'bulk'), req('allfail', false, 'all')];
    expect(complianceOrder(list, false).map((r) => r.id)).toEqual(['allfail', 'bulkfail', 'met', 'rate']);
    expect(complianceOrder(list, true).map((r) => r.id)).toEqual(['bulkfail', 'allfail', 'met', 'rate']);
  });
});

const msg = (id: string, receivedAt: string, p: Partial<MessageSummary> = {}): MessageSummary => ({
  id, addressId: 't-1', receivedAt, via: 'smtp', status: 'done', score: 5, clientIp: null, clientPtr: null, helo: null, mailFrom: null,
  rcptTo: [], tls: null, from: null, fromDomain: 'exemple.fr', subject: null, size: null, ...p,
});

describe('findPrevious', () => {
  it('takes the newest analysed message received before the current one', () => {
    const cur = msg('c', '2026-11-10T12:00:00Z');
    const list = [msg('later', '2026-11-10T13:00:00Z'), msg('old', '2026-11-09T12:00:00Z'), msg('prev', '2026-11-10T11:00:00Z'), msg('failed', '2026-11-10T11:30:00Z', { status: 'error' }), cur];
    expect(findPrevious(cur, list)?.id).toBe('prev');
    expect(findPrevious(cur, [cur])).toBeUndefined();
  });
});

describe('reduceStream', () => {
  const m1 = msg('m1', '2026-11-10T12:00:00Z', { status: 'received' });
  it('state, then a message, its progress, its report', () => {
    let s = reduceStream(initialStream, { type: 'state', data: { address: { id: 't-1' }, messages: [], steps: { parse: 'Lecture' } } });
    expect(s.ready).toBe(true);
    s = reduceStream(s, { type: 'message', data: { messageId: 'm1', message: m1 } });
    expect(s.arrived).toBe('m1');
    expect(s.messages.map((m) => m.id)).toEqual(['m1']);
    s = reduceStream(s, { type: 'progress', data: { messageId: 'm1', step: 'parse', label: 'Lecture', state: 'done' } });
    expect(s.progress.m1.parse.state).toBe('done');
    expect(s.messages[0].status).toBe('analyzing');
    s = reduceStream(s, { type: 'report', data: { messageId: 'm1', report: { score: 7.5, findings: [], passed: [], measuredAt: '' } } });
    expect(s.messages[0]).toMatchObject({ status: 'done', score: 7.5 });
    expect(s.reports.m1).toBeDefined();
  });
  it('keeps the newest message first and does not duplicate a known one', () => {
    let s = reduceStream(initialStream, { type: 'state', data: { messages: [m1], steps: {} } });
    s = reduceStream(s, { type: 'message', data: { messageId: 'm2', message: msg('m2', '2026-11-10T12:05:00Z') } });
    s = reduceStream(s, { type: 'message', data: { messageId: 'm1', message: { ...m1, subject: 'x' } } });
    expect(s.messages.map((m) => m.id)).toEqual(['m2', 'm1']);
    expect(s.messages[1].subject).toBe('x');
  });
  it('a new analysis of the same message restarts its steps but keeps the old report on screen', () => {
    let s = reduceStream(initialStream, { type: 'state', data: { messages: [m1], steps: {} } });
    s = reduceStream(s, { type: 'report', data: { messageId: 'm1', report: { score: 3, findings: [], passed: [], measuredAt: '' } } });
    s = reduceStream(s, { type: 'progress', data: { messageId: 'm1', step: 'auth', label: 'Auth', state: 'done' } });
    s = reduceStream(s, { type: 'progress', data: { messageId: 'm1', step: 'parse', label: 'Lecture', state: 'start' } });
    expect(Object.keys(s.progress.m1)).toEqual(['parse']);
    expect(s.reports.m1).toBeDefined();
  });
  it('records an analysis error', () => {
    let s = reduceStream(initialStream, { type: 'state', data: { messages: [m1], steps: {} } });
    s = reduceStream(s, { type: 'error', data: { messageId: 'm1', error: 'boom' } });
    expect(s.errors.m1).toBe('boom');
    expect(s.messages[0].status).toBe('error');
  });
});

describe('preview', () => {
  const html = '<html><body><img src="https://t.example/p.gif" width="1" height="1"><img src=\'cid:logo@x\'><div style="background:url(https://x.example/bg.png)">Bonjour</div><link rel="stylesheet" href="https://x.example/a.css"></body></html>';
  it('blocks remote images before the frame loads them', () => {
    const out = blockRemote(html);
    expect(out).not.toMatch(/src="https:/);
    expect(out).toContain('data-check-blocked="https://t.example/p.gif"');
    expect(out).not.toContain('url(https:');
    expect(out).not.toContain('<link');
    expect(countRemoteImages(html)).toBe(2);
  });
  it('puts the CSP first, swaps cid: images, lets remote images through on request', () => {
    const blocked = previewDocument(html, { remote: false, inline: [{ cid: '<logo@x>', dataUri: 'data:image/png;base64,AAA' }] });
    expect(blocked.indexOf('Content-Security-Policy')).toBeLessThan(blocked.indexOf('<img'));
    expect(blocked).toContain("img-src data:;");
    expect(blocked).toContain("src='data:image/png;base64,AAA'");
    const open = previewDocument(html, { remote: true });
    expect(open).toContain('src="https://t.example/p.gif"');
    expect(open).toContain('img-src data: https: http:');
    expect(previewDocument('<p>x</p>', { remote: false })).toMatch(/^<!DOCTYPE html><html><head><meta http-equiv/);
    // a <header> is not the <head>: the CSP must still be in a real head, before the content
    const withHeader = previewDocument('<html><body><header class="top"><style>@import "https://t.example/x.css"</style></header></body></html>', { remote: false });
    expect(withHeader).toMatch(/^<html><head><meta http-equiv="Content-Security-Policy"/);
    expect(withHeader.indexOf('Content-Security-Policy')).toBeLessThan(withHeader.indexOf('<header'));
  });
});

describe('looksLikeMessage', () => {
  it('recognises a header block or a full message', () => {
    expect(looksLikeMessage('Received: from a by b\nFrom: x@y.fr\nSubject: test\n\nBonjour')).toBe(true);
    expect(looksLikeMessage('Delivered-To: t@x\r\nReturn-Path: <a@b>\r\n')).toBe(true);
  });
  it('ignores ordinary text', () => {
    expect(looksLikeMessage('Bonjour, voici mon message')).toBe(false);
    expect(looksLikeMessage('Note: une seule ligne')).toBe(false);
    expect(looksLikeMessage('texte\nFrom: x@y.fr\nSubject: a')).toBe(false);
  });
});

describe('decodeWords', () => {
  it('decodes Q and B encoded words, leaves plain text alone', () => {
    expect(decodeWords('=?UTF-8?Q?Camille=2C_C=C5=93ur_d=27atelier?= <contact@exemple-agence.com>')).toBe('Camille, Cœur d\'atelier <contact@exemple-agence.com>');
    expect(decodeWords('=?utf-8?B?w6l0w6k=?=')).toBe('été');
    expect(decodeWords('Paul <paul@x.fr>')).toBe('Paul <paul@x.fr>');
  });
});

describe('measureOf and clientSection', () => {
  const data = {
    message: { fromDomain: 'exemple.fr', subject: 'GAGNEZ !!!', size: 1 },
    content: { visibleWords: 9, images: 1 },
    links: [{ url: 'https://login.exemple.net/x', scheme: 'https', shortener: false, source: 'html', text: 'https://www.paypal.com', mismatch: 'www.paypal.com' }],
    images: [],
  } as never;
  it('writes the measured value and the reference of common findings', () => {
    expect(measureOf({ id: 'content.image_only', title: '', evidence: undefined }, data)).toEqual({ measured: '9 mots, 1 image', reference: '≥ 20 mots visibles' });
    expect(measureOf({ id: 'links.text_url_mismatch', title: '', evidence: 'Texte affiché : https://www.paypal.com\nCible : https://login.exemple.net/confirm' }, data).measured).toBe('affiché paypal.com, mène à login.exemple.net');
    expect(measureOf({ id: 'links.broken', title: '', evidence: 'https://x.fr/a : HTTP 404' }, data)).toEqual({ measured: 'HTTP 404', reference: 'HTTP 200' });
    expect(measureOf({ id: 'links.broken', title: '', evidence: 'https://x.fr/a : fetch failed' }, data).measured).toBe('serveur injoignable');
    expect(measureOf({ id: 'reputation.feedback_id_missing', title: '' }, data).measured).toBe('absent');
  });
  it('translates network errors', () => {
    expect(humanError('connect ECONNREFUSED 127.0.0.1:7830')).toBe('connexion refusée');
    expect(humanError('getaddrinfo ENOTFOUND x')).toBe('domaine introuvable');
    expect(humanError('délai de 5 s dépassé')).toBe('délai dépassé');
    expect(humanReason('spamd injoignable (connect ECONNREFUSED 127.0.0.1:7830) : la note')).toBe('spamd injoignable (connexion refusée sur 127.0.0.1:7830) : la note');
  });
  it('files sender reputation apart from the blacklists, Feedback-ID with the headers', () => {
    expect(clientSection({ id: 'reputation.from_domain_not_resolvable', family: 'reputation', section: 'blacklists' })).toBe('reputation');
    expect(clientSection({ id: 'reputation.feedback_id_missing', family: 'reputation', section: 'blacklists' })).toBe('headers');
    expect(clientSection({ id: 'blacklist.ip_listed', family: 'blacklist', section: 'blacklists' })).toBe('blacklists');
  });
});

describe('Signal report helpers', () => {
  const summary = (id: string, receivedAt: string, via: MessageSummary['via'] = 'smtp') => ({ id, receivedAt, via });

  it('numbers the sends from the oldest', () => {
    const out = numberSends([summary('b', '2026-11-11T01:00:00Z'), summary('a', '2026-11-11T00:00:00Z')]);
    expect(out.map((m) => `${m.id}${m.n}`)).toEqual(['a1', 'b2']);
  });

  it('times a send from its Date header to its reception, never from an import', () => {
    const data = (date: string | undefined, hopAt?: string) => ({ message: { date, size: 1 }, hops: hopAt ? [{ index: 1, at: hopAt, tls: null, raw: '' }] : [], receivedAt: '2026-11-11T01:02:17Z' });
    const smtp = timingOf(summary('a', '2026-11-11T00:51:48Z'), { ...data('Wed, 11 Nov 2026 01:51:21 +0100'), receivedAt: '2026-11-11T00:51:48Z' });
    expect(smtp.transitSec).toBe(27);
    expect(smtp.sentAt).toBe(Date.parse('2026-11-11T00:51:21Z'));
    const up = timingOf(summary('a', '2026-11-11T01:02:17Z', 'upload'), data('Wed, 11 Nov 2026 01:51:21 +0100', '2026-11-11T00:51:48Z'));
    expect(up.transitSec).toBe(27);
    expect(up.importedAt).toBe(Date.parse('2026-11-11T01:02:17Z'));
    // no Received time on an upload: no reception, no delay
    expect(timingOf(summary('a', '2026-11-11T01:02:17Z', 'upload'), data('Wed, 11 Nov 2026 01:51:21 +0100')).transitSec).toBeNull();
    // a Date after the reception, or days before it: a wrong clock, not a delay
    expect(timingOf(summary('a', '2026-11-11T00:00:00Z'), { ...data('Wed, 11 Nov 2026 02:00:00 +0100'), receivedAt: '2026-11-11T00:00:00Z' }).transitSec).toBeNull();
    expect(timingOf(summary('a', '2026-11-11T00:00:00Z'), { ...data('Wed, 4 Nov 2026 01:00:00 +0100'), receivedAt: '2026-11-11T00:00:00Z' }).transitSec).toBeNull();
    // without a Date header, "envoyé il y a" counts from the reception
    expect(timingOf(summary('a', '2026-11-11T00:00:00Z'), { ...data(undefined), receivedAt: '2026-11-11T00:00:00Z' }).sentAt).toBe(Date.parse('2026-11-11T00:00:00Z'));
  });

  it('computes the two indicators like the server when the report has none', () => {
    const ind = indicatorsFrom([
      { penalty: 1.5, impact: 'blocking', axis: 'sender' },
      { penalty: 0.5, impact: 'spam', axis: 'message' },
      { penalty: 0.25, impact: 'advice', axis: 'message' },
    ])!;
    expect(ind.verdict).toBe('blocking');
    expect(ind.sender).toMatchObject({ lost: 1.5, blocking: 1, status: 'blocking' });
    expect(ind.message).toMatchObject({ lost: 0.8, spam: 1, advice: 1, status: 'spam' });
    expect(indicatorsFrom([{ penalty: 1 }])).toBeUndefined();
  });

  it('writes the headline from what blocks, then what risks the spam folder', () => {
    const g = (title: string, penalty: number, impact: 'blocking' | 'spam' | 'advice') => ({ title, penalty, impact });
    const ind = (verdict: 'blocking' | 'spam' | 'ok') => ({ verdict, sender: { lost: 0, blocking: 0, spam: 0, advice: 0, status: 'ok' as const }, message: { lost: 0, blocking: 0, spam: 0, advice: 0, status: 'ok' as const } });
    expect(headlineOf([g('Trop d’image', 1, 'spam')], ind('spam'))).toMatchObject({ tone: 'watch', main: 'Rien ne bloque la livraison.', rest: 'Un seul point peut le faire classer en indésirables\u00a0: trop d’image.' });
    const b = headlineOf([g('DKIM absent', 1.5, 'blocking'), g('SPF absent', 1.5, 'blocking'), g('Lien cassé', 0.5, 'spam')], ind('blocking'));
    // the first letter is lowered only when the second is lowercase: an acronym stays as written
    expect(b).toMatchObject({ tone: 'bad', main: '2 points bloquent la livraison, d’abord\u00a0: DKIM absent.' });
    expect(b.rest).toBe('Un autre peut le faire classer en indésirables.');
    // the verdict names the most useful thing the sender can do; what only the service can do is left out
    const adv = (title: string, worth: number, outOfReach?: string) => ({ title, penalty: 0, impact: 'advice' as const, advicePenalty: worth, outOfReach });
    expect(headlineOf([adv('Doctype absent', 0.1, 'Gmail'), adv('DKIM de 1024 bits', 0.3), adv('Rapports DMARC absents', 0.3)], ind('ok'))).toMatchObject({ tone: 'good', rest: '2 améliorations possibles, d’abord\u00a0: DKIM de 1024 bits.' });
    expect(headlineOf([adv('Doctype absent', 0.1, 'Gmail')], ind('ok')).rest).toBe('Aucun point à reprendre de votre côté.');
    for (const h of [b, headlineOf([], ind('ok'))]) expect(`${h.mood}${h.main}${h.rest}`).not.toMatch(/[\u2014\u2013]/);
  });

  it('marks the links that lead nowhere or that nobody sees', () => {
    const m = markEmptyLinks('<p><a href="https://ok.fr">ok</a><a href="http:///"></a><a href="#">vide</a><a href="https://x.fr"><img src="a.png"></a></p>');
    expect(m).toMatchObject({ empty: 2, invisible: 1 });
    expect(m.html).toContain('data-check-flag="lien vide et invisible http:///"');
    expect(m.html).toContain('data-check-flag="lien vide #"');
    expect(markEmptyLinks('<a href="https://ok.fr">ok</a>').html).toBe('<a href="https://ok.fr">ok</a>');
    expect(isEmptyHref('mailto:a@b.fr')).toBe(false);
  });

  it('reads the key checks from the report, lit by the impact of their findings', () => {
    const report = {
      findings: [{ id: 'images.image_heavy', family: 'images', severity: 'medium', penalty: 0.5, impact: 'spam' }, { id: 'dkim.key_1024', family: 'dkim', severity: 'low', penalty: 0.3, impact: 'advice' }],
      passed: [],
      data: {
        envelope: { tls: { used: true, protocol: 'TLSv1.3', source: 'received' }, ipSource: 'received', rcptTo: [] },
        message: { size: 1 },
        hops: [],
        isBulk: false,
        auth: { spf: { result: 'pass' }, dkim: [{ domain: 'a.fr', selector: 's', result: 'pass', keyBits: 1024, signedHeaders: [], testing: false, aligned: 'strict' }], dmarc: { result: 'pass', p: 'none' } },
        infrastructure: { fcrdns: true, ptr: ['x'] },
        blacklists: { checked: 40, listed: [], refused: [], errors: [], clean: [] },
        content: { visibleWords: 21, images: 1 },
        links: [{ url: 'https://a.fr', scheme: 'https', source: 'html', shortener: false, check: { status: 200, redirects: [], ms: 1 } }],
        spamassassin: { available: false },
      },
    } as unknown as MailReport;
    const k = keyChecks(report);
    expect(k.sender.map((c) => `${c.key}=${c.value}:${c.lit}`)).toEqual([
      'SPF=pass:ok', 'DKIM=pass · 1024 bits:ok', 'DMARC=pass · p=none:ok', 'Reverse DNS=confirmé:ok', 'TLS=TLS 1.3:ok', 'Listes noires=aucune inscription:ok',
    ]);
    expect(k.message.map((c) => `${c.key}=${c.value}:${c.lit}`)).toEqual([
      'SpamAssassin=non mesuré:n', 'Texte et images=21 mots, 1 image:warn', 'Liens=1 qui répond:ok', 'En-têtes=conformes:ok', 'Pièces jointes=aucune:n', 'Désinscription=sans objet:n',
    ]);
  });
});
