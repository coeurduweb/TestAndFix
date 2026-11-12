// SSE subscription to /api/redirects/trace: `hop` events arrive one by one, `done` carries the
// complete result. (lib/useEventStream listens to a fixed list of event names without `hop`.)
import { useEffect, useState } from 'react';
import { t } from '../../lib/i18n';
import type { Hop, TraceResult } from './model';

export interface TraceState {
  hops: Hop[];
  result: TraceResult | null;
  error: string | null;
  status: 'idle' | 'running' | 'done' | 'error';
}

const INITIAL: TraceState = { hops: [], result: null, error: null, status: 'idle' };

export function useTrace(query: string | null): TraceState & { rerun: () => void } {
  const [state, setState] = useState<TraceState>(INITIAL);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!query) {
      setState(INITIAL);
      return;
    }
    setState({ ...INITIAL, status: 'running' });
    const es = new EventSource(`/api/redirects/trace?${query}`, { withCredentials: true });
    let finished = false;
    es.addEventListener('hop', (ev) => {
      const hop = JSON.parse((ev as MessageEvent).data) as Hop;
      setState((s) => ({ ...s, hops: [...s.hops.filter((h) => h.index !== hop.index), hop] }));
    });
    es.addEventListener('done', (ev) => {
      finished = true;
      const result = JSON.parse((ev as MessageEvent).data) as TraceResult;
      setState({ hops: result.data.hops, result, error: null, status: 'done' });
      es.close();
    });
    es.addEventListener('error', (ev) => {
      const data = (ev as MessageEvent).data;
      if (finished) return;
      finished = true;
      let message = t('Le serveur de TestAndFix ne répond pas, ou la session a expiré. Rechargez la page.');
      if (typeof data === 'string' && data) {
        try {
          message = (JSON.parse(data) as { message?: string }).message ?? message;
        } catch {
          /* raw */
        }
      } else {
        // the stream was refused before opening (invalid input answers 400, expired session 401).
        // Ask the JSON route why with max=0: it validates the URL first, then refuses max=0
        // before any request is made, so nothing is fetched nor stored.
        fetch(`/api/redirects/trace?${query}&max=0`, { headers: { accept: 'application/json' }, credentials: 'same-origin' })
          .then(async (r) => {
            if (r.status === 401) return t('Session expirée : reconnectez-vous.');
            const b = (await r.json().catch(() => null)) as { message?: string } | null;
            return b?.message && !b.message.startsWith('max') ? b.message : null;
          })
          .then((m) => m && setState((s) => ({ ...s, error: m })))
          .catch(() => {});
      }
      setState((s) => ({ ...s, error: message, status: 'error' }));
      es.close();
    });
    return () => es.close();
  }, [query, nonce]);

  // before the effect has run, a page with an URL is already measuring (no flash of "arrêtée")
  const status = query && state.status === 'idle' ? 'running' : state.status;
  return { ...state, status, rerun: () => setNonce((n) => n + 1) };
}
