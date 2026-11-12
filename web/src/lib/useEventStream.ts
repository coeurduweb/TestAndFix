// Subscribe to a Server-Sent Events endpoint and fold its events into state.
import { useEffect, useRef, useState } from 'react';

export type StreamStatus = 'idle' | 'connecting' | 'open' | 'done' | 'error';

export function useEventStream<S>(
  url: string | null,
  reducer: (state: S, event: { type: string; data: unknown }) => S,
  initial: S,
  opts: { doneEvent?: string } = {},
): { state: S; status: StreamStatus; restart: () => void } {
  const [state, setState] = useState<S>(initial);
  const [status, setStatus] = useState<StreamStatus>('idle');
  const [nonce, setNonce] = useState(0);
  const reducerRef = useRef(reducer);
  reducerRef.current = reducer;

  useEffect(() => {
    if (!url) return;
    setState(initial);
    setStatus('connecting');
    const es = new EventSource(url, { withCredentials: true });
    const done = opts.doneEvent ?? 'done';
    const handler = (type: string) => (ev: MessageEvent) => {
      let data: unknown = ev.data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        /* raw */
      }
      setState((s) => reducerRef.current(s, { type, data }));
      if (type === done) {
        setStatus('done');
        es.close();
      }
    };
    const known = new Set<string>();
    // EventSource needs explicit listeners per event name: intercept them through a Proxy-free list
    const listen = (type: string) => {
      if (known.has(type)) return;
      known.add(type);
      es.addEventListener(type, handler(type) as EventListener);
    };
    for (const t of STREAM_EVENTS) listen(t);
    es.onopen = () => setStatus('open');
    es.onerror = () => {
      setStatus((s) => (s === 'done' ? s : 'error'));
      es.close();
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, nonce]);

  return { state, status, restart: () => setNonce((n) => n + 1) };
}

/** Every event name emitted by the server streams. */
export const STREAM_EVENTS = [
  'start', 'state', 'message', 'progress', 'report', 'section', 'authority', 'resolver', 'done', 'error', 'step',
  'result', 'hop', 'row', 'source', 'inventory', 'subdomain',
];
