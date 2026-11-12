// OpenPhish community feed (https://openphish.com/phishing_feeds.html): a plain list of URLs,
// refreshed every 12 hours upstream.
//
// EXCEPTION TO THE "NO CACHE" RULE, on purpose: this is a list to download, not a measurement.
// The file is fetched at most once per hour and kept in memory between checks; checking a URL
// against it never triggers a download more often than that. Every other source of this tool
// is queried live for each check.
import { apiFetch, httpProblem, SourceUnavailable, type ApiFetch } from './source.js';
import { t } from '../../i18n.js';

export const OPENPHISH_FEED = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const REFRESH_MS = 60 * 60 * 1000;
/** A stale copy is still used when the download fails, up to the upstream refresh period. */
const STALE_MAX_MS = 12 * 60 * 60 * 1000;

interface Feed {
  fetchedAt: number;
  urls: Set<string>;
  hosts: Map<string, string[]>;
}

let feed: Feed | undefined;
let loading: Promise<Feed> | undefined;

export function normalizeFeedUrl(u: string): string {
  try {
    const x = new URL(u.trim());
    x.hash = '';
    let s = `${x.protocol}//${x.hostname.toLowerCase()}${x.port ? ':' + x.port : ''}${x.pathname}${x.search}`;
    if (s.endsWith('/')) s = s.slice(0, -1);
    return s;
  } catch {
    return u.trim().replace(/\/$/, '');
  }
}

function hostOf(u: string): string | undefined {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export function parseFeed(text: string, fetchedAt: number): Feed {
  const urls = new Set<string>();
  const hosts = new Map<string, string[]>();
  for (const line of text.split(/\r?\n/)) {
    const u = line.trim();
    if (!/^https?:\/\//i.test(u)) continue;
    urls.add(normalizeFeedUrl(u));
    const h = hostOf(u);
    if (h) hosts.set(h, [...(hosts.get(h) ?? []), u]);
  }
  return { fetchedAt, urls, hosts };
}

export interface OpenPhishOptions {
  fetch?: ApiFetch;
  feedUrl?: string;
  now?: () => number;
}

async function getFeed(opts: OpenPhishOptions): Promise<{ feed: Feed; stale?: string }> {
  const now = (opts.now ?? Date.now)();
  if (feed && now - feed.fetchedAt < REFRESH_MS) return { feed };
  loading ??= (async () => {
    const res = await (opts.fetch ?? apiFetch)(opts.feedUrl ?? OPENPHISH_FEED, { headers: { accept: 'text/plain' }, timeoutMs: 15000 });
    const problem = httpProblem(res.status, 'OpenPhish', res.text);
    if (problem) throw problem;
    const f = parseFeed(res.text, now);
    if (!f.urls.size) throw new SourceUnavailable('error', 'flux OpenPhish vide');
    feed = f;
    return f;
  })().finally(() => (loading = undefined));
  try {
    return { feed: await loading };
  } catch (e) {
    if (feed && now - feed.fetchedAt < STALE_MAX_MS)
      return { feed, stale: t('téléchargement impossible ({error}), copie de {time} UTC utilisée', { error: (e as Error).message, time: new Date(feed.fetchedAt).toISOString().slice(11, 16) }) };
    throw e;
  }
}

export interface OpenPhishData {
  feedSize: number;
  fetchedAt: string;
  stale?: string;
  /** URLs checked that are in the feed, exactly. */
  exact: string[];
  /** URLs checked whose host appears in the feed with another path. */
  sameHost: { url: string; feedUrls: string[] }[];
}

export async function openPhishCheck(urls: string[], opts: OpenPhishOptions = {}): Promise<OpenPhishData> {
  const { feed: f, stale } = await getFeed(opts);
  const exact: string[] = [];
  const sameHost: OpenPhishData['sameHost'] = [];
  for (const u of [...new Set(urls)]) {
    if (f.urls.has(normalizeFeedUrl(u))) {
      exact.push(u);
      continue;
    }
    const h = hostOf(u);
    const list = h ? f.hosts.get(h) : undefined;
    if (list?.length) sameHost.push({ url: u, feedUrls: list.slice(0, 5) });
  }
  return { feedSize: f.urls.size, fetchedAt: new Date(f.fetchedAt).toISOString().replace(/\.\d{3}Z$/, 'Z'), stale, exact, sameHost };
}

/** Tests only. */
export function resetOpenPhishFeed() {
  feed = undefined;
  loading = undefined;
}
