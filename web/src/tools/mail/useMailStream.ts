// Live events of a test address. The browser reconnects by itself after a drop; the server
// answers every (re)connection with a full `state`, so nothing is missed.
// Not lib/useEventStream: that hook closes the stream on the first error and does not listen
// to `state`, and a test address waits for minutes.
import { useEffect, useReducer, useState } from 'react';
import { initialStream, reduceStream, type StreamState } from './logic';

export type Conn = 'connecting' | 'open' | 'reconnecting' | 'closed';

const EVENTS = ['state', 'message', 'progress', 'report'] as const;

type Action = { type: string; data: unknown } | { type: '__reset' };

function reducer(s: StreamState, a: Action): StreamState {
  if (a.type === '__reset') return initialStream;
  return reduceStream(s, a as { type: string; data: unknown });
}

export function useMailStream(addressId: string | null | undefined): { state: StreamState; conn: Conn } {
  const [state, dispatch] = useReducer(reducer, initialStream);
  const [conn, setConn] = useState<Conn>('connecting');

  useEffect(() => {
    dispatch({ type: '__reset' });
    if (!addressId) return;
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    let stopped = false;

    const parse = (raw: string) => {
      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    };
    const connect = () => {
      setConn(attempts ? 'reconnecting' : 'connecting');
      es = new EventSource(`/api/mail/addresses/${encodeURIComponent(addressId)}/events`, { withCredentials: true });
      es.onopen = () => {
        attempts = 0;
        setConn('open');
      };
      for (const t of EVENTS) es.addEventListener(t, (ev) => dispatch({ type: t, data: parse((ev as MessageEvent).data) }));
      // "error" is both the analysis-error event of the server and the connection error of the browser
      es.addEventListener('error', (ev) => {
        const data = (ev as MessageEvent).data;
        if (typeof data === 'string' && data) {
          dispatch({ type: 'error', data: parse(data) });
          return;
        }
        if (stopped) return;
        if (es?.readyState === EventSource.CLOSED) {
          // the browser gave up (HTTP error): try again, more slowly each time
          es.close();
          attempts++;
          setConn(attempts > 6 ? 'closed' : 'reconnecting');
          if (attempts <= 6) retry = setTimeout(connect, Math.min(30000, 1000 * 2 ** attempts));
        } else setConn('reconnecting');
      });
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      es?.close();
    };
  }, [addressId]);

  return { state, conn };
}
