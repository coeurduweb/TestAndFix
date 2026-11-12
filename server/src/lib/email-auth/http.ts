// HTTP GET for user-supplied URLs (BIMI logo and certificate, MTA-STS policy, RDAP).
// History: from 2026-11-10 this file held a copy of safeGet because lib/net.ts failed on every host
// name (lookup called with { all: true }). net.ts is fixed since; this is now a plain pass-through,
// kept so the analyzers have one import point and accept any Resolver as session.
import type { ResolveSession } from '../../dns/iterative.js';
import { safeGet, type SafeFetchResult } from '../net.js';
import type { Resolver } from './common.js';

export function httpGet(
  url: string,
  opts: { maxBytes?: number; session?: Resolver; headers?: Record<string, string> } = {},
): Promise<SafeFetchResult> {
  // safeGet only calls session.resolve(): a GuardedResolver works as well as a ResolveSession
  return safeGet(url, { ...opts, session: opts.session as ResolveSession | undefined });
}
