// The three CT sources, in relay. crt.name (names and first-seen date, fast) and crt.sh (every
// certificate with issuer, serial and dates, slow) are asked together; Cert Spotter (unexpired
// certificates only, small keyless quota) is asked only when crt.sh gave nothing, so that the
// certificate details still come from somewhere without spending the quota on every measurement.
// Each source that fails is reported, never blocking; results are merged by the caller.
// No cache anywhere: each call asks the services again.
import { orgDomain } from '../email-auth/common.js';
import { searchCertSpotter } from './certspotter.js';
import { searchCrtName } from './crtname.js';
import { searchCrtSh } from './crtsh.js';
import type { CtFetch, CtSourceId, CtSourceResult } from './types.js';
import { t } from '../../i18n.js';

export * from './types.js';
export { ctFetcher } from './http.js';

export const SOURCE_ORDER: CtSourceId[] = ['crt.name', 'crt.sh', 'certspotter'];

export async function collectCt(
  domain: string,
  fetch: CtFetch,
  opts: { onSource?: (r: CtSourceResult) => void; signal?: AbortSignal } = {},
): Promise<CtSourceResult[]> {
  const out = new Map<CtSourceId, CtSourceResult>();
  const done = (r: CtSourceResult) => {
    out.set(r.source, r);
    opts.onSource?.(r);
    return r;
  };
  const apex = orgDomain(domain);
  const [, crtsh] = await Promise.all([
    searchCrtName(fetch, apex, domain, opts.signal).then(done),
    searchCrtSh(fetch, domain, opts.signal).then(done),
  ]);
  if (crtsh.status !== 'ok') done(await searchCertSpotter(fetch, domain, opts.signal));
  else done({ source: 'certspotter', status: 'skipped', certs: [], names: [], error: t('non interrogé : crt.sh a répondu'), ms: 0 });
  return SOURCE_ORDER.map((s) => out.get(s)!).filter(Boolean);
}
