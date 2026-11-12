// Live: github.com is routed by location at its authoritative servers (NS1 and Route 53).
import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { ecsQuery } from './ecs.js';

describe('ECS query to an authoritative server', () => {
  it('returns a subnet-dependent answer with a non-zero scope', async () => {
    const { servers } = await new ResolveSession().findAuthorities('github.com');
    const ip = servers.flatMap((s) => s.ips).find((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x))!;
    const r = await ecsQuery(ip, 'github.com', 'A', '87.98.254.10');
    expect(r.rcode).toBe('NOERROR');
    expect(r.flags.aa).toBe(true);
    expect(r.answers.some((a) => a.type === 'A')).toBe(true);
    expect(r.scope).toBeGreaterThan(0);
  });
  it('refuses IPv6 clients (not supported)', async () => {
    await expect(ecsQuery('192.0.2.1', 'example.com', 'A', '2001:db8::1')).rejects.toThrow(/IPv4/);
  });
});
