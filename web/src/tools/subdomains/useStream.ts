// SSE of /api/subdomains/:domain/stream. Local to the tool because the shared useEventStream only
// listens to the event names of STREAM_EVENTS, which lacks `inventory` and `subdomain` (addition
// requested; this hook can then become a call to useEventStream). Subdomain events arrive by
// hundreds: they are batched into one state update per animation frame.
import { useEffect, useRef, useState } from 'react';
import { initialStream, reduce, type StreamState } from './model';

const EVENTS = ['start', 'source', 'inventory', 'subdomain', 'done', 'error'];

export function useSubdomainStream(domain: string | null): { state: StreamState; status: 'idle' | 'open' | 'done' | 'error'; restart: () => void } {
  const [state, setState] = useState<StreamState>(initialStream);
  const [status, setStatus] = useState<'idle' | 'open' | 'done' | 'error'>('idle');
  const [nonce, setNonce] = useState(0);
  const queue = useRef<{ type: string; data: unknown }[]>([]);

  useEffect(() => {
    if (!domain) return;
    setState(initialStream);
    setStatus('open');
    queue.current = [];
    let frame = 0;
    const flush = () => {
      frame = 0;
      const batch = queue.current;
      queue.current = [];
      if (batch.length) setState((s) => batch.reduce(reduce, s));
    };
    const es = new EventSource(`/api/subdomains/${encodeURIComponent(domain)}/stream`, { withCredentials: true });
    for (const type of EVENTS) {
      es.addEventListener(type, ((ev: MessageEvent) => {
        let data: unknown = ev.data;
        try {
          data = JSON.parse(ev.data);
        } catch {
          /* raw text */
        }
        queue.current.push({ type, data });
        if (type === 'done' || type === 'error') {
          if (frame) cancelAnimationFrame(frame);
          flush();
          setStatus(type === 'done' ? 'done' : 'error');
          es.close();
        } else if (!frame) frame = requestAnimationFrame(flush);
      }) as EventListener);
    }
    es.onerror = () => {
      setStatus((s) => (s === 'done' ? s : 'error'));
      es.close();
    };
    return () => {
      if (frame) cancelAnimationFrame(frame);
      es.close();
    };
  }, [domain, nonce]);

  return { state, status, restart: () => setNonce((n) => n + 1) };
}
