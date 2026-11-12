// The notebook ("carnet") of this browser: the server keeps each browser's history, mail tests and
// DMARC reports apart (httpOnly cookie), visible only from this browser and the devices linked to it.
// Shapes of GET /api/me and its actions, and what the browser keeps by itself under "check:" keys.
import { api, get, post } from './api';
import { plural } from './format';
import { t } from './i18n';

export interface Device {
  id: string;
  /** "Firefox sur Android"; null when the browser said nothing usable */
  label: string | null;
  createdAt: string;
  lastSeenAt: string;
  current?: boolean;
}
export interface Counts {
  results: number;
  mailMessages: number;
  mailAddresses: number;
  dmarcReports: number;
}
export interface Me {
  device: Device;
  devices: Device[];
  counts: Counts;
  oldest: string | null;
  retentionDays: number;
}
export interface LinkCode {
  code: string;
  expiresAt: string;
}
export interface Share {
  token: string;
  path: string;
}

export const getMe = () => get<Me>('/api/me');
export const makeLinkCode = () => post<LinkCode>('/api/me/link-code');
/** What linking with this code would do, without using it: the devices of the notebook to join, and what this browser holds now. */
export interface LinkPreview {
  devices: { label: string | null; lastSeenAt: string }[];
  joining: Counts;
}
export const previewLink = (code: string) => post<LinkPreview>('/api/me/link/preview', { code });
/** 409 confirm_merge (body.joining) when this browser holds data and confirmMerge is not true. */
export const linkWithCode = (code: string, confirmMerge?: boolean) =>
  post<{ linked: true; moved: Counts }>('/api/me/link', confirmMerge ? { code, confirmMerge: true } : { code });
export const detachDevice = (id: string) => api<null>(`/api/me/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const eraseNotebook = (scope: 'data' | 'all') => post<{ erased: Counts }>('/api/me/erase', { scope });

/** "ABCD-EFGH": letters and digits typed or pasted in any case, with or without the dash. */
export function normalizeCode(raw: string): string {
  const s = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  return s.length > 4 ? `${s.slice(0, 4)}-${s.slice(4)}` : s;
}
export const isCode = (s: string) => /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(s);

export const total = (c: Counts) => c.results + c.mailMessages + c.mailAddresses + c.dmarcReports;

/** "12 mesures, 3 messages et 1 adresse de test"; empty kinds are left out. */
export function countsText(c: Counts, empty = t('rien')): string {
  const parts = [
    c.results && plural(c.results, 'mesure', 'mesures'),
    c.mailMessages && plural(c.mailMessages, 'message reçu', 'messages reçus'),
    c.mailAddresses && plural(c.mailAddresses, 'adresse de test', 'adresses de test'),
    c.dmarcReports && plural(c.dmarcReports, 'rapport DMARC', 'rapports DMARC'),
  ].filter(Boolean) as string[];
  if (!parts.length) return empty;
  return parts.length === 1 ? parts[0] : t('{list} et {last}', { list: parts.slice(0, -1).join(', '), last: parts[parts.length - 1] });
}

/** Display preference, not a trace: kept when the traces are erased. */
const KEPT = new Set(['check:theme']);

/**
 * Removes what this browser keeps by itself (recent searches, remembered DKIM selectors, the cache
 * agent token and address, pending pastes): every "check:" key of localStorage and sessionStorage
 * except the theme. Returns how many keys were removed.
 */
export function clearLocalTraces(): number {
  let n = 0;
  for (const store of [safe(() => localStorage), safe(() => sessionStorage)]) {
    if (!store) continue;
    try {
      const keys: string[] = [];
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        if (k && k.startsWith('check:') && !KEPT.has(k)) keys.push(k);
      }
      for (const k of keys) store.removeItem(k);
      n += keys.length;
    } catch {
      /* storage unavailable */
    }
  }
  return n;
}

function safe<T>(f: () => T): T | null {
  try {
    return f();
  } catch {
    return null;
  }
}
