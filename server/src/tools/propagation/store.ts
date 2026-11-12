// Persistence of candidates and qualification results.
// The shared `resolvers` table (db.ts) holds what the rest of the app may read: identity,
// location, qualified flag, date, latency, reasons. What only this tool needs (consecutive
// failures, quarantine, DNSSEC, ASN, minimum RTT) lives in its own table, created here so
// that db.ts does not change. A request to move these columns into db.ts is in the report.
import fs from 'node:fs';
import { currentLang, locale } from '../../i18n.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { DB } from '../../db.js';
import { getSetting, setSetting } from '../../db.js';
import type { CheckId, ResolverRow, SeedResolver } from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));
// src/tools/propagation -> server/data-seed (also valid from dist/tools/propagation)
export const SEED_DIR = path.resolve(here, '..', '..', '..', 'data-seed');

export interface ResolverState {
  ip: string;
  asn: number | null;
  geo_precision: 'city' | 'country' | null;
  dnssec: number | null;
  passed: number;
  fails: number;
  quarantined_until: number | null;
  min_rtt_ms: number | null;
  checked_at: number | null;
}

export interface Candidate extends ResolverRow {
  asn: number | null;
  geo_precision: 'city' | 'country' | null;
  dnssec: number | null;
  passed: number;
  fails: number;
  quarantined_until: number | null;
  min_rtt_ms: number | null;
  group: 'global' | 'local';
}

const STATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS propagation_resolver_state (
  ip TEXT PRIMARY KEY,
  asn INTEGER,
  geo_precision TEXT,
  dnssec INTEGER,             -- 1: SERVFAIL on dnssec-failed.org, 0: answered it, NULL: unknown
  passed INTEGER NOT NULL DEFAULT 0,   -- passed every test at the last run (before country caps)
  fails INTEGER NOT NULL DEFAULT 0,    -- consecutive failed runs
  quarantined_until INTEGER,  -- not tested again before this time (ms epoch)
  min_rtt_ms INTEGER,
  checked_at INTEGER,
  filtering_detected TEXT     -- 'malware' when the filter test name was blocked at the last run
);`;

export function ensureSchema(db: DB) {
  db.exec(STATE_SCHEMA);
  // databases created before 2026-11-10 evening lack this column
  const cols = (db.prepare('PRAGMA table_info(propagation_resolver_state)').all() as { name: string }[]).map((c) => c.name);
  if (!cols.includes('filtering_detected')) db.exec('ALTER TABLE propagation_resolver_state ADD COLUMN filtering_detected TEXT');
}

export function readSeed(dir = SEED_DIR): SeedResolver[] {
  const doc = JSON.parse(fs.readFileSync(path.join(dir, 'resolvers.json'), 'utf8')) as { resolvers: SeedResolver[] };
  return doc.resolvers;
}

let continents: { countries: Record<string, string>; continents: Record<string, string> } | undefined;
export function continentOf(cc: string | null | undefined): string | null {
  continents ??= JSON.parse(fs.readFileSync(path.join(SEED_DIR, 'resolvers-continents.json'), 'utf8'));
  return (cc && continents!.countries[cc.toUpperCase()]) || null;
}
/** UN M49 code of each continent of the table, so that Intl names it in the reader's language. */
const CONTINENT_M49: Record<string, string> = { AF: '002', AN: 'AQ', AS: '142', EU: '150', NA: '003', OC: '009', SA: '005' };
/** A UN M49 area or ISO country code named in the current language; the French name of the data otherwise. */
function areaName(code: string | undefined, french: string): string {
  if (!code || currentLang() === 'fr') return french;
  try {
    const n = new Intl.DisplayNames(locale(), { type: 'region' }).of(code);
    return n && n !== code ? n : french;
  } catch {
    return french;
  }
}
export function continentNames(): Record<string, string> {
  continentOf(null);
  return Object.fromEntries(Object.entries(continents!.continents).map(([k, v]) => [k, areaName(CONTINENT_M49[k], v)]));
}

/** UN M49 sub-regions (intermediate regions in Africa and the Americas), French names. */
let regions: { countries: Record<string, string>; regions: Record<string, { name: string; continent: string }> } | undefined;
export function regionTable() {
  regions ??= JSON.parse(fs.readFileSync(path.join(SEED_DIR, 'resolvers-regions.json'), 'utf8'));
  return regions!;
}
export function regionOf(cc: string | null | undefined): { code: string; name: string } | null {
  const code = cc ? regionTable().countries[cc.toUpperCase()] : undefined;
  return code ? { code, name: areaName(code, regionTable().regions[code].name) } : null;
}
export const familyOf = (ip: string): 4 | 6 => (ip.includes(':') ? 6 : 4);

/** Upsert the seed into `resolvers`. Locations found at runtime are kept when the seed has none. */
export function loadSeed(db: DB, seed: SeedResolver[], at = Date.now()): number {
  ensureSchema(db);
  const up = db.prepare(`
    INSERT INTO resolvers(ip, name, provider, country_code, city, lat, lon, anycast, filtering, source, created_at)
    VALUES(@ip, @name, @provider, @country_code, @city, @lat, @lon, @anycast, @filtering, @source, @at)
    ON CONFLICT(ip) DO UPDATE SET
      name = excluded.name, provider = excluded.provider, anycast = excluded.anycast,
      filtering = excluded.filtering, source = excluded.source,
      country_code = COALESCE(excluded.country_code, resolvers.country_code),
      city = CASE WHEN excluded.lat IS NOT NULL THEN excluded.city ELSE resolvers.city END,
      lat = COALESCE(excluded.lat, resolvers.lat),
      lon = COALESCE(excluded.lon, resolvers.lon)`);
  const st = db.prepare(`
    INSERT INTO propagation_resolver_state(ip, asn, geo_precision) VALUES(?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET asn = COALESCE(excluded.asn, asn), geo_precision = COALESCE(excluded.geo_precision, geo_precision)`);
  const tx = db.transaction(() => {
    for (const r of seed) {
      up.run({
        ip: r.ip,
        name: r.name,
        provider: r.provider,
        country_code: r.country_code || null,
        city: r.city,
        lat: r.lat,
        lon: r.lon,
        anycast: r.anycast ? 1 : 0,
        filtering: r.filtering,
        source: r.source,
        at,
      });
      st.run(r.ip, r.asn, r.geo_precision);
    }
  });
  tx();
  return seed.length;
}

export function candidates(db: DB, ips?: string[]): Candidate[] {
  ensureSchema(db);
  const rows = db
    .prepare(
      `SELECT r.*, s.asn, s.geo_precision, s.dnssec, COALESCE(s.passed,0) AS passed, COALESCE(s.fails,0) AS fails,
              s.quarantined_until, s.min_rtt_ms, s.filtering_detected
       FROM resolvers r LEFT JOIN propagation_resolver_state s ON s.ip = r.ip`,
    )
    .all() as Candidate[];
  const want = ips ? new Set(ips) : null;
  return rows
    .filter((r) => !want || want.has(r.ip))
    .map((r) => {
      const { filtering_detected, ...rest } = r as Candidate & { filtering_detected: string | null };
      // a block seen by our test overrides an "unfiltered" seed entry, never the reverse
      const filtering = filtering_detected && (!rest.filtering || rest.filtering === 'none') ? filtering_detected : rest.filtering;
      return { ...rest, filtering, group: rest.anycast ? 'global' : 'local' } as Candidate;
    });
}

export function qualifiedResolvers(db: DB): Candidate[] {
  return candidates(db).filter((r) => r.qualified === 1);
}

export interface Outcome {
  ip: string;
  /** Tested this run (false: skipped because quarantined). */
  tested: boolean;
  passed: boolean;
  qualified: boolean;
  reasons: CheckId[];
  latencyMs: number | null;
  minRttMs: number | null;
  dnssec: boolean | null;
  /** 'malware' when the filter test name was blocked; null otherwise (proves nothing). */
  filteringDetected?: string | null;
  location?: { country_code: string; city: string | null; lat: number; lon: number; geo_precision: 'city' | 'country' };
}

const QUARANTINE_MS = 7 * 24 * 3600 * 1000;

export function saveOutcomes(db: DB, outcomes: Outcome[], at = Date.now()) {
  ensureSchema(db);
  const upR = db.prepare(
    'UPDATE resolvers SET qualified = ?, qualified_at = ?, latency_ms = ?, reasons = ? WHERE ip = ?',
  );
  const upUntested = db.prepare('UPDATE resolvers SET qualified = 0, reasons = ? WHERE ip = ?');
  const upLoc = db.prepare('UPDATE resolvers SET country_code = ?, city = ?, lat = ?, lon = ? WHERE ip = ?');
  const getS = db.prepare('SELECT fails FROM propagation_resolver_state WHERE ip = ?');
  const upS = db.prepare(`
    INSERT INTO propagation_resolver_state(ip, dnssec, passed, fails, quarantined_until, min_rtt_ms, checked_at, geo_precision, filtering_detected)
    VALUES(@ip, @dnssec, @passed, @fails, @q, @rtt, @at, @gp, @fd)
    ON CONFLICT(ip) DO UPDATE SET dnssec = COALESCE(excluded.dnssec, dnssec), passed = excluded.passed,
      fails = excluded.fails, quarantined_until = excluded.quarantined_until,
      min_rtt_ms = COALESCE(excluded.min_rtt_ms, min_rtt_ms), checked_at = excluded.checked_at,
      geo_precision = COALESCE(excluded.geo_precision, geo_precision), filtering_detected = excluded.filtering_detected`);
  const tx = db.transaction(() => {
    for (const o of outcomes) {
      if (o.location) upLoc.run(o.location.country_code, o.location.city, o.location.lat, o.location.lon, o.ip);
      if (!o.tested) {
        upUntested.run(JSON.stringify(o.reasons), o.ip);
        continue;
      }
      upR.run(o.qualified ? 1 : 0, at, o.latencyMs, JSON.stringify(o.reasons), o.ip);
      const prev = (getS.get(o.ip) as { fails: number } | undefined)?.fails ?? 0;
      const fails = o.passed ? 0 : prev + 1;
      upS.run({
        ip: o.ip,
        dnssec: o.dnssec == null ? null : o.dnssec ? 1 : 0,
        passed: o.passed ? 1 : 0,
        fails,
        q: fails >= 2 ? at + QUARANTINE_MS : null,
        rtt: o.minRttMs,
        at,
        gp: o.location?.geo_precision ?? null,
        fd: o.filteringDetected ?? null,
      });
    }
  });
  tx();
}

/**
 * A resolver caught rewriting an answer during a live check: hidden at once and not tested again
 * for 7 days (quarantine), whatever its qualification said.
 */
export function quarantineRewriters(db: DB, ips: string[], at = Date.now()) {
  if (!ips.length) return;
  ensureSchema(db);
  const upR = db.prepare(`UPDATE resolvers SET qualified = 0, reasons = '["rewrites_answers"]' WHERE ip = ?`);
  const upS = db.prepare(`
    INSERT INTO propagation_resolver_state(ip, passed, fails, quarantined_until) VALUES(?, 0, 2, ?)
    ON CONFLICT(ip) DO UPDATE SET passed = 0, fails = MAX(fails, 2), quarantined_until = excluded.quarantined_until`);
  db.transaction(() => {
    for (const ip of ips) {
      upR.run(ip);
      upS.run(ip, at + QUARANTINE_MS);
    }
  })();
}

export interface QualificationRun {
  status: 'ok' | 'suspect' | 'aborted' | 'error';
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  candidates: number;
  tested: number;
  skippedQuarantine: number;
  passed: number;
  qualified: number;
  qualifiedGlobal: number;
  qualifiedLocal: number;
  countries: number;
  dnssecValidating: number;
  failures: Record<string, number>;
  checkNames: string[];
  serverLocation: ServerLocation | null;
  note?: string;
  /** Latest failed or suspect attempt, when the stored run is an older successful one. */
  lastAttempt?: QualificationRun;
}

export interface ServerLocation {
  ip: string | null;
  country_code: string | null;
  city: string | null;
  lat: number;
  lon: number;
  source: string;
}

const RUN_KEY = 'propagation.qualification';
export const lastRun = (db: DB) => getSetting<QualificationRun | null>(RUN_KEY, null, db);
export const saveRun = (db: DB, run: QualificationRun) => setSetting(RUN_KEY, run, db);
