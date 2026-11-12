// Propagation DNS tool: routes, SSE stream and the daily qualification job.
import { t, msg } from '../../i18n.js';
import type { FastifyInstance } from 'fastify';
import { saveResult } from '../../db.js';
import { openSse } from '../../lib/sse.js';
import type { ServerTool, ToolContext } from '../types.js';
import { AsnLookup } from './asn.js';
import { query } from '../../dns/client.js';
import { CheckError, checkAuthority, checkResolvers, normalizeName, revalidateNxLies, summarize, type ResolverEvent } from './check.js';
import { currentServerLocation, detectIpv6, ipv6State, runningState, schedule, settings, startQualification, stopJob } from './job.js';
import { isPropType, SUPPORTED_TYPES, type PropType } from './normalize.js';
import { defaultSelection, filterCounts, parseFilters, selectResolvers, type Filters } from './selection.js';
import { familyOf, regionOf, regionTable } from './store.js';
import { candidates, continentNames, continentOf, lastRun, loadSeed, qualifiedResolvers, quarantineRewriters, readSeed, type Candidate } from './store.js';

export const GLOBAL_NOTE = msg(
  'Ces résolveurs sont anycast : la même adresse est servie par des nœuds dans le monde entier, et notre requête arrive au nœud le plus proche de notre serveur. Leur réponse montre ce que voient les utilisateurs proches de notre serveur, pas ceux du pays de l’opérateur.');

export function resolverView(r: Candidate) {
  return {
    ip: r.ip,
    name: r.name,
    provider: r.provider,
    asn: r.asn,
    country_code: r.country_code,
    continent: continentOf(r.country_code),
    region: r.anycast ? null : regionOf(r.country_code),
    family: familyOf(r.ip),
    city: r.anycast ? null : r.city,
    lat: r.anycast ? null : r.lat,
    lon: r.anycast ? null : r.lon,
    geoPrecision: r.anycast ? null : r.geo_precision,
    anycast: !!r.anycast,
    group: r.anycast ? 'global' : 'local',
    filtering: r.filtering,
    dnssec: r.dnssec == null ? null : !!r.dnssec,
    latencyMs: r.latency_ms,
    qualifiedAt: r.qualified_at ? new Date(r.qualified_at).toISOString() : null,
    source: r.source,
  };
}

function resolversPayload(ctx: ToolContext) {
  const q = qualifiedResolvers(ctx.db);
  const all = candidates(ctx.db);
  const byCountry = new Map<string, ReturnType<typeof resolverView>[]>();
  for (const r of q.filter((r) => !r.anycast)) {
    const k = r.country_code ?? '??';
    byCountry.set(k, [...(byCountry.get(k) ?? []), resolverView(r)]);
  }
  const run = lastRun(ctx.db);
  const st = runningState();
  return {
    qualification: run
      ? {
          status: run.status,
          startedAt: run.startedAt,
          finishedAt: run.finishedAt,
          durationMs: run.durationMs,
          tested: run.tested,
          skippedQuarantine: run.skippedQuarantine,
          passed: run.passed,
          qualified: run.qualified,
          qualifiedGlobal: run.qualifiedGlobal,
          qualifiedLocal: run.qualifiedLocal,
          countries: run.countries,
          dnssecValidating: run.dnssecValidating,
          failures: run.failures,
          checkNames: run.checkNames,
          note: run.note ?? null,
          lastAttempt: run.lastAttempt
            ? { status: run.lastAttempt.status, finishedAt: run.lastAttempt.finishedAt, note: run.lastAttempt.note ?? null }
            : null,
        }
      : null,
    running: st ? { startedAt: st.startedAt, manual: st.manual, progress: st.progress } : null,
    candidates: all.length,
    perCountry: settings().perCountry,
    serverLocation: currentServerLocation() ?? run?.serverLocation ?? null,
    continents: continentNames(),
    global: { note: t(GLOBAL_NOTE), resolvers: q.filter((r) => r.anycast).map(resolverView) },
    countries: [...byCountry.entries()]
      .map(([country_code, resolvers]) => ({ country_code, continent: continentOf(country_code), resolvers }))
      .sort((a, b) => a.country_code.localeCompare(b.country_code)),
    total: q.length,
    ipv6Available: ipv6State()?.available ?? null,
    defaultSelection: defaultSelection(ctx.db),
    regions: regionTable().regions,
    counts: filterCounts(q),
  };
}

interface StreamQuery {
  name?: string;
  type?: string;
  expected?: string;
  onlyPending?: string;
  ips?: string;
  scope?: string;
  continents?: string;
  regions?: string;
  countries?: string;
  family?: string;
}

export const tool: ServerTool = {
  id: 'propagation',

  register(app: FastifyInstance, ctx: ToolContext) {
    app.get('/api/propagation/resolvers', async () => resolversPayload(ctx));

    app.post('/api/propagation/qualify', async (_req, reply) => {
      const p = startQualification(ctx, { manual: true });
      if (!p) {
        const st = runningState();
        return reply.code(409).send({ error: 'already_running', startedAt: st?.startedAt, progress: st?.progress ?? null });
      }
      p.catch(() => {});
      return reply.code(202).send({ started: true, startedAt: runningState()?.startedAt });
    });

    app.get<{ Querystring: StreamQuery }>('/api/propagation/stream', async (req, reply) => {
      const q = req.query;
      const type = String(q.type ?? 'A').toUpperCase();
      if (!isPropType(type)) return reply.code(400).send({ error: 'bad_type', supported: SUPPORTED_TYPES });
      let name: string;
      try {
        name = normalizeName(String(q.name ?? ''), type);
      } catch (e) {
        return reply.code(400).send({ error: (e as CheckError).code ?? 'bad_name', message: (e as Error).message });
      }
      let filters: Filters;
      try {
        filters = parseFilters(q as Record<string, unknown>);
      } catch (e) {
        return reply.code(400).send({ error: 'bad_filter', message: (e as Error).message });
      }
      if (filters.family === '6' && ipv6State()?.available !== true) {
        return reply.code(503).send({ error: 'ipv6_unavailable', message: t('IPv6 non disponible depuis ce serveur') });
      }
      const onlyPending = q.onlyPending === '1' || q.onlyPending === 'true';
      let resolvers = qualifiedResolvers(ctx.db);
      if (!onlyPending) resolvers = selectResolvers(resolvers, filters, defaultSelection(ctx.db));
      if (onlyPending) {
        const wanted = new Set(String(q.ips ?? '').split(/[\s,]+/).filter(Boolean));
        if (!wanted.size) return reply.code(400).send({ error: 'ips_required', message: t('onlyPending=1 demande la liste ips') });
        // only resolvers that are still qualified: the endpoint never queries arbitrary IPs
        resolvers = resolvers.filter((r) => wanted.has(r.ip));
      }
      const expected = q.expected?.trim() ? q.expected : undefined;
      const input = { name, type: type as PropType, expected };

      const sse = openSse(req, reply);
      const startedAt = new Date().toISOString();
      const run = lastRun(ctx.db);
      sse.send('start', {
        name,
        type,
        expected: expected ?? null,
        onlyPending,
        scope: filters.scope,
        filters: { continents: filters.continents, regions: filters.regions, countries: filters.countries, family: filters.family },
        resolverCount: resolvers.length,
        qualifiedAt: run?.finishedAt ?? null,
        startedAt,
      });
      try {
        const session = ctx.dns();
        const authority = await checkAuthority(session, input, sse.signal);
        sse.send('authority', authority);
        const events: ResolverEvent[] = await checkResolvers(input, authority.reference, resolvers, (e) => sse.send('resolver', e), {
          signal: sse.signal,
          authorityIps: authority.servers.filter((s) => !s.error).map((s) => s.ip),
          asn: new AsnLookup(session),
          referenceTtl: authority.reference.ttl,
          authority,
        });
        if (sse.closed) return;
        // serial changed while we measured: a creation may be in progress, NXDOMAIN is not a lie
        const ok = authority.servers.find((s) => !s.error && s.serial != null);
        if (ok && authority.serials.length) {
          const now = await query(ok.ip, authority.zone, 'SOA', { rd: false, timeoutMs: 3000 }).catch(() => null);
          const serial = now?.answers.find((a) => a.type === 'SOA');
          const changed = serial != null && Number((serial.data as { serial: number }).serial) !== ok.serial;
          for (const e of revalidateNxLies(events, changed)) sse.send('resolver', e);
        }
        // a resolver that rewrites answers is hidden now and skipped by the next qualification
        quarantineRewriters(ctx.db, events.filter((e) => e.status === 'rewritten').map((e) => e.ip));
        const summary = summarize(events, authority.reference);
        const resultId = saveResult(
          'propagation',
          `${name} ${type}`,
          { input: { ...input, onlyPending }, startedAt, finishedAt: new Date().toISOString(), authority, resolvers: events, summary },
          {
            score: null,
            summary: {
              name,
              type,
              onlyPending,
              percentFresh: summary.percentFresh,
              fresh: summary.fresh,
              total: summary.total,
              divergent: authority.divergent,
            },
          },
          ctx.db,
        );
        sse.send('done', { ...summary, resultId, startedAt, finishedAt: new Date().toISOString(), onlyPending });
      } catch (e) {
        if (!sse.closed) sse.send('error', { code: (e as CheckError).code ?? 'error', message: (e as Error).message });
      } finally {
        sse.close();
      }
    });
  },

  async start(ctx: ToolContext) {
    loadSeed(ctx.db, readSeed());
    const v6 = await detectIpv6();
    console.log(`propagation: outgoing IPv6 ${v6.available ? 'available' : 'NOT available, IPv6 resolvers are skipped'}`);
    schedule(ctx, (m) => console.log(m));
  },

  async stop() {
    await stopJob();
  },
};
