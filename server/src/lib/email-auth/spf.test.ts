import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from './common.js';
import { FakeDns, type FakeZone } from './fake-dns.js';
import { analyzeSpf, checkDomainSpec, evaluateSpf, expandMacros, parsePastedRecord, parseTerm } from './spf.js';

const ids = (a: { issues: { id: string }[] }) => a.issues.map((i) => i.id);
const spf = (zone: FakeZone, domain = 'example.fr', record?: string) => analyzeSpf(new FakeDns(zone), domain, { record });
const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('SPF parsing', () => {
  it('parses mechanisms, qualifiers and cidr', () => {
    expect(parseTerm('-ip4:192.0.2.0/24')).toMatchObject({ kind: 'mechanism', qualifier: '-', name: 'ip4', value: '192.0.2.0', cidr4: 24 });
    expect(parseTerm('a:mail.example.fr/28//64')).toMatchObject({ name: 'a', value: 'mail.example.fr', cidr4: 28, cidr6: 64 });
    expect(parseTerm('redirect=_spf.example.fr')).toMatchObject({ kind: 'modifier', name: 'redirect' });
    expect(parseTerm('ip4:300.1.1.1').error).toMatch(/invalide/);
    expect(parseTerm('ipv4:1.2.3.4')).toMatchObject({ kind: 'invalid', error: 'mécanisme inconnu' });
    expect(parseTerm('include').error).toMatch(/exige un domaine/);
    expect(checkDomainSpec('1.2.3.4')).toMatch(/adresse IP/);
    expect(checkDomainSpec('localhost')).toMatch(/complet/);
    expect(checkDomainSpec('%{i}._spf.example.fr')).toBeUndefined();
  });
  it('expands macros (RFC 7208 §7.4 examples)', () => {
    const mc = { ip: '192.0.2.3', sender: 'strong-bad@email.example.com', domain: 'email.example.com' };
    expect(expandMacros('%{s}', mc)).toBe('strong-bad@email.example.com');
    expect(expandMacros('%{d4}', mc)).toBe('email.example.com');
    expect(expandMacros('%{d2}', mc)).toBe('example.com');
    expect(expandMacros('%{dr}', mc)).toBe('com.example.email');
    expect(expandMacros('%{l-}', mc)).toBe('strong.bad');
    expect(expandMacros('%{ir}.%{v}._spf.%{d2}', mc)).toBe('3.2.0.192.in-addr._spf.example.com');
    expect(expandMacros('%{ir}.%{v}._spf.%{d2}', { ...mc, ip: '2001:db8::cb01' })).toBe(
      '1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com',
    );
  });
  it('reads a record pasted as quoted strings', () => {
    expect(parsePastedRecord('"v=spf1 ip4:192.0.2.1" " -all"')).toEqual({ value: 'v=spf1 ip4:192.0.2.1 -all', strings: ['v=spf1 ip4:192.0.2.1', ' -all'] });
  });
});

describe('SPF analysis (simulated DNS)', () => {
  it('expands the tree, counts lookups and flattens networks', async () => {
    const a = await spf({
      'example.fr': { TXT: ['v=spf1 mx include:_spf.esp.test ip4:198.51.100.7 -all'], MX: [{ preference: 10, exchange: 'mx.example.fr' }] },
      'mx.example.fr': { A: ['203.0.113.25'] },
      '_spf.esp.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all'] },
    });
    expect(a.data.lookupCount).toBe(2);
    expect(a.data.voidCount).toBe(0);
    expect(a.data.ipv4.sort()).toEqual(['192.0.2.0/24', '198.51.100.7', '203.0.113.25']);
    expect(a.data.ipv6).toEqual(['2001:db8::/32']);
    expect(a.issues).toEqual([]);
    expect(a.data.suggested).toBeUndefined();
    expect(a.passed.map((p) => p.id)).toContain('spf.lookup_limit');
  });
  it('reports a missing record', async () => {
    expect(ids(await spf({ 'example.fr': { TXT: ['google-site-verification=x'] } }))).toEqual(['spf.missing']);
  });
  it('reports a record that is almost SPF', async () => {
    expect(ids(await spf({ 'example.fr': { TXT: ['v=spf2 -all'] } }))).toContain('spf.version_invalid');
  });
  it('reports several records and merges them in the suggestion', async () => {
    const a = await spf({ 'example.fr': { TXT: ['v=spf1 ip4:192.0.2.1 -all', 'v=spf1 include:_spf.google.com ~all'] }, '_spf.google.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 ~all'] } });
    expect(ids(a)).toContain('spf.multiple_records');
    expect(a.data.suggested).toBe('v=spf1 ip4:192.0.2.1 include:_spf.google.com -all');
  });
  it('flags +all, ?all and a missing all', async () => {
    expect(ids(await spf({ 'example.fr': { TXT: ['v=spf1 +all'] } }))).toContain('spf.plus_all');
    const n = await spf({ 'example.fr': { TXT: ['v=spf1 ip4:192.0.2.1 ?all'] } });
    expect(ids(n)).toContain('spf.neutral_all');
    expect(n.data.suggested).toBe('v=spf1 ip4:192.0.2.1 ~all');
    const none = await spf({ 'example.fr': { TXT: ['v=spf1 ip4:192.0.2.1'] } });
    expect(ids(none)).toContain('spf.no_all');
    expect(none.data.suggested).toBe('v=spf1 ip4:192.0.2.1 ~all');
  });
  it('flags syntax errors, unknown mechanisms, ptr and terms after all', async () => {
    const a = await spf({ 'example.fr': { TXT: ['v=spf1 ip4:300.0.0.1 ipv4:192.0.2.1 ptr -all a'] } });
    expect(ids(a)).toEqual(expect.arrayContaining(['spf.syntax_error', 'spf.unknown_mechanism', 'spf.ptr_mechanism', 'spf.terms_after_all']));
    expect(a.data.suggested).toBe('v=spf1 a -all');
  });
  it('flags include targets without SPF, redirect targets without SPF and void lookups', async () => {
    const a = await spf({
      'example.fr': { TXT: ['v=spf1 include:gone.test include:nospf.test a:none1.example.fr mx:none2.example.fr -all'] },
      'nospf.test': { TXT: ['hello'] },
      'none1.example.fr': {},
    });
    expect(ids(a)).toEqual(expect.arrayContaining(['spf.include_no_spf', 'spf.void_lookup_limit']));
    expect(a.data.voidCount).toBe(4);
    expect(a.data.suggested).toBe('v=spf1 a:none1.example.fr mx:none2.example.fr -all');
    const r = await spf({ 'example.fr': { TXT: ['v=spf1 redirect=_spf.nowhere.test'] } });
    expect(ids(r)).toContain('spf.redirect_target_invalid');
  });
  it('counts more than 10 lookups and points at the term that crosses the limit', async () => {
    const zone: FakeZone = { 'example.fr': { TXT: ['v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:s${i}.test`).join(' ') + ' -all'] } };
    for (let i = 0; i < 11; i++) zone[`s${i}.test`] = { TXT: [`v=spf1 ip4:192.0.2.${i + 1} -all`] };
    const a = await spf(zone);
    expect(a.data.lookupCount).toBe(11);
    expect(ids(a)).toContain('spf.lookup_limit');
    expect(a.data.tree.terms.find((t) => t.overLimit)?.term).toBe('include:s10.test');
  });
  it('flattens own a/mx when the budget is exceeded', async () => {
    const zone: FakeZone = {
      'example.fr': { TXT: ['v=spf1 a mx ' + Array.from({ length: 9 }, (_, i) => `include:s${i}.test`).join(' ') + ' -all'], A: ['192.0.2.10'], MX: [{ preference: 10, exchange: 'mx.example.fr' }] },
      'mx.example.fr': { A: ['192.0.2.20'] },
    };
    for (let i = 0; i < 9; i++) zone[`s${i}.test`] = { TXT: [`v=spf1 ip4:198.51.100.${i + 1} -all`] };
    const a = await spf(zone);
    expect(a.data.lookupCount).toBe(11);
    expect(a.data.suggested).toMatch(/^v=spf1 ip4:192\.0\.2\.10 ip4:192\.0\.2\.20 include:s0\.test/);
    expect(a.data.suggestedLookupCount).toBe(9);
  });
  it('detects include loops and duplicates', async () => {
    const a = await spf({
      'example.fr': { TXT: ['v=spf1 include:a.test include:a.test -all'] },
      'a.test': { TXT: ['v=spf1 include:example.fr -all'] },
    });
    expect(ids(a)).toEqual(expect.arrayContaining(['spf.include_loop', 'spf.duplicate_terms']));
  });
  it('flags an MX mechanism with more than 10 MX', async () => {
    const mx = Array.from({ length: 11 }, (_, i) => ({ preference: i, exchange: `mx${i}.example.fr` }));
    expect(ids(await spf({ 'example.fr': { TXT: ['v=spf1 mx -all'], MX: mx } }))).toContain('spf.mx_too_many_addresses');
  });
  it('flags a pasted string over 255 octets and gives it split', async () => {
    const long = 'v=spf1 ' + Array.from({ length: 30 }, (_, i) => `ip4:192.0.2.${i + 1}`).join(' ') + ' -all';
    const a = await spf({}, 'example.fr', long);
    const f = a.issues.find((i) => i.id === 'spf.string_too_long');
    expect(f?.suggested).toMatch(/^"v=spf1 .*" ".*-all"$/);
  });
  it('flags a TXT answer over 512 octets', async () => {
    const big = Array.from({ length: 6 }, (_, i) => `verification-${i}=` + 'x'.repeat(80));
    expect(ids(await spf({ 'example.fr': { TXT: ['v=spf1 -all', ...big] } }))).toContain('spf.dns_response_too_large');
  });
  it('turns DNS failures into temperror', async () => {
    expect(ids(await spf({ 'example.fr': 'SERVFAIL' }))).toEqual(['spf.temperror']);
    expect(ids(await spf({}))).toEqual(['spf.domain_nxdomain']);
  });
  it('flags broad ranges, macros, exp and an open SPF on a domain that sends nothing', async () => {
    const a = await spf({ 'example.fr': { TXT: ['v=spf1 ip4:10.0.0.0/8 exists:%{i}._spf.example.fr exp=explain.example.fr ~all'], MX: [{ preference: 0, exchange: '' }] } });
    expect(ids(a)).toEqual(expect.arrayContaining(['spf.range_too_broad', 'spf.macros', 'spf.exp_modifier', 'spf.non_sending_domain_open']));
    expect(a.data.dynamic).toContain('exists:%{i}._spf.example.fr');
  });
});

describe('SPF evaluation of an IP (simulated DNS)', () => {
  const zone: FakeZone = {
    'example.fr': { TXT: ['v=spf1 -ip4:192.0.2.66 include:_spf.esp.test a mx ~all'], A: ['198.51.100.1'], MX: [{ preference: 10, exchange: 'mx.example.fr' }] },
    'mx.example.fr': { A: ['198.51.100.2'] },
    '_spf.esp.test': { TXT: ['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all'] },
    'red.fr': { TXT: ['v=spf1 redirect=example.fr'] },
  };
  it('finds the deciding mechanism', async () => {
    const dns = new FakeDns(zone);
    const r = await evaluateSpf(dns, { ip: '192.0.2.10', domain: 'example.fr' });
    expect(r).toMatchObject({ result: 'pass', mechanism: { term: 'include:_spf.esp.test', domain: 'example.fr' } });
    expect(r.chain).toEqual([{ term: 'include:_spf.esp.test', domain: 'example.fr' }, { term: 'ip4:192.0.2.0/24', domain: '_spf.esp.test' }]);
    expect(await evaluateSpf(dns, { ip: '192.0.2.66', domain: 'example.fr' })).toMatchObject({ result: 'fail', mechanism: { term: '-ip4:192.0.2.66' } });
    expect(await evaluateSpf(dns, { ip: '198.51.100.2', domain: 'example.fr' })).toMatchObject({ result: 'pass', mechanism: { term: 'mx' } });
    expect(await evaluateSpf(dns, { ip: '203.0.113.9', domain: 'example.fr' })).toMatchObject({ result: 'softfail', mechanism: { term: '~all' } });
    expect(await evaluateSpf(dns, { ip: '2001:db8::1', domain: 'example.fr' })).toMatchObject({ result: 'pass' });
    const red = await evaluateSpf(dns, { ip: '192.0.2.10', domain: 'red.fr' });
    expect(red.result).toBe('pass');
    expect(red.chain.map((c) => c.term)).toEqual(['redirect=example.fr', 'include:_spf.esp.test', 'ip4:192.0.2.0/24']);
    expect(await evaluateSpf(dns, { ip: '192.0.2.10', domain: 'nothing.fr' })).toMatchObject({ result: 'none' });
  });
  it('returns permerror past 10 lookups and on syntax errors', async () => {
    const z: FakeZone = { 'x.fr': { TXT: ['v=spf1 ' + Array.from({ length: 11 }, (_, i) => `a:h${i}.x.fr`).join(' ') + ' -all'] } };
    for (let i = 0; i < 11; i++) z[`h${i}.x.fr`] = { A: [`192.0.2.${i + 1}`] };
    expect((await evaluateSpf(new FakeDns(z), { ip: '203.0.113.1', domain: 'x.fr' })).result).toBe('permerror');
    expect((await evaluateSpf(new FakeDns({ 'y.fr': { TXT: ['v=spf1 ipv4:1.2.3.4 -all'] } }), { ip: '1.2.3.4', domain: 'y.fr' })).result).toBe('permerror');
    expect((await evaluateSpf(new FakeDns({ 'z.fr': { TXT: ['v=spf1 include:gone.test -all'] } }), { ip: '1.2.3.4', domain: 'z.fr' })).result).toBe('permerror');
  });
  it('expands exists:%{i} macros', async () => {
    const dns = new FakeDns({ 'm.fr': { TXT: ['v=spf1 exists:%{i}._spf.m.fr -all'] }, '192.0.2.5._spf.m.fr': { A: ['127.0.0.2'] } });
    expect((await evaluateSpf(dns, { ip: '192.0.2.5', domain: 'm.fr' })).result).toBe('pass');
    expect((await evaluateSpf(dns, { ip: '192.0.2.6', domain: 'm.fr' })).result).toBe('fail');
  });
});

describe('SPF live (real DNS from the root)', () => {
  it('expands gmail.com through its redirect', async () => {
    const a = await analyzeSpf(live(), 'gmail.com');
    expect(a.data.record).toMatch(/^v=spf1 /);
    expect(a.data.lookupCount).toBeGreaterThan(0);
    expect(a.data.lookupCount).toBeLessThanOrEqual(10);
    expect(a.data.ipv4.length + a.data.ipv6.length).toBeGreaterThan(0);
    expect(a.issues.filter((i) => ['spf.missing', 'spf.lookup_limit', 'spf.plus_all'].includes(i.id))).toEqual([]);
  });
  it('evaluates a Google IP against gmail.com', async () => {
    const r = await evaluateSpf(live(), { ip: '209.85.220.41', domain: 'gmail.com' });
    expect(r.result).toBe('pass');
    expect(r.chain.at(-1)?.term).toMatch(/^ip4:/);
    const bad = await evaluateSpf(live(), { ip: '192.0.2.1', domain: 'gmail.com' });
    expect(['softfail', 'fail']).toContain(bad.result);
  });
});
