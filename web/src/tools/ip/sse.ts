// Server-Sent Events read through fetch + ReadableStream, for GET and POST alike.
// EventSource cannot send a POST body (POST /api/ip/batch/stream), cannot read the JSON body of a
// 400 (invalid input), and only hears the event names it was told about (useEventStream's list
// has neither `start`, `source` nor `row`). This reader parses the stream itself, per the WHATWG
// event-stream format: `event:`, `data:` (several lines joined), comments, CR, LF or CRLF.
import { useEffect, useRef, useState } from 'react';
import { ApiError } from '../../lib/api';
import { t } from '../../lib/i18n';

export interface SseEvent {
  type: string;
  data: unknown;
}

/** Incremental parser: feed it text chunks as they come, it calls back once per complete event. */
export class SseParser {
  private buf = '';
  private type = '';
  private data: string[] = [];
  private pendingCr = false;

  constructor(private readonly onEvent: (e: SseEvent) => void) {}

  push(chunk: string): void {
    let s = chunk;
    // a CR that ended the previous chunk may be the first half of a CRLF
    if (this.pendingCr && s.startsWith('\n')) s = s.slice(1);
    this.pendingCr = false;
    this.buf += s;
    let start = 0;
    for (let i = 0; i < this.buf.length; i++) {
      const c = this.buf[i];
      if (c !== '\n' && c !== '\r') continue;
      if (c === '\r') {
        if (i === this.buf.length - 1) this.pendingCr = true;
        else if (this.buf[i + 1] === '\n') {
          this.line(this.buf.slice(start, i));
          i++;
          start = i + 1;
          continue;
        }
      }
      this.line(this.buf.slice(start, i));
      start = i + 1;
    }
    this.buf = this.buf.slice(start);
  }

  /** End of stream: a last event without its blank line is dropped, as the format says. */
  end(): void {
    this.buf = '';
    this.type = '';
    this.data = [];
  }

  private line(l: string) {
    if (l === '') {
      this.dispatch();
      return;
    }
    if (l.startsWith(':')) return;
    const i = l.indexOf(':');
    const field = i < 0 ? l : l.slice(0, i);
    let value = i < 0 ? '' : l.slice(i + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.type = value;
    else if (field === 'data') this.data.push(value);
    // id and retry are not used by check's streams
  }

  private dispatch() {
    if (!this.data.length) {
      this.type = '';
      return;
    }
    const raw = this.data.join('\n');
    let data: unknown = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* raw text */
    }
    const type = this.type || 'message';
    this.type = '';
    this.data = [];
    this.onEvent({ type, data });
  }
}

export interface SseRequest {
  url: string;
  method?: 'GET' | 'POST';
  json?: unknown;
}

/** Open the stream, call onEvent per event; resolves at the end of the stream. Throws ApiError on a non-2xx answer. */
export async function readSse(req: SseRequest, onEvent: (e: SseEvent) => void, signal?: AbortSignal): Promise<void> {
  const res = await fetch(req.url, {
    method: req.method ?? 'GET',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { accept: 'text/event-stream', ...(req.json !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: req.json !== undefined ? JSON.stringify(req.json) : undefined,
    signal,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      /* not JSON */
    }
    if (res.status === 401) window.dispatchEvent(new CustomEvent('check:auth-required'));
    throw new ApiError(res.status, (body as { error?: string } | null)?.error ?? `http_${res.status}`, body);
  }
  if (!res.body) throw new Error(t('Le navigateur ne sait pas lire la réponse en continu.'));
  const parser = new SseParser(onEvent);
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parser.push(value);
  }
  parser.end();
}

export type SseStatus = 'idle' | 'open' | 'done' | 'error';

/**
 * Fold a stream into state. `key` identifies the request (a new key restarts); `restart` measures
 * again. The stream is aborted on unmount or when the key changes.
 */
export function useSse<S>(
  req: SseRequest | null,
  key: string,
  reducer: (s: S, e: SseEvent) => S,
  initial: () => S,
): { state: S; status: SseStatus; error: Error | null; restart: () => void } {
  const [state, setState] = useState<S>(initial);
  const [status, setStatus] = useState<SseStatus>('idle');
  const [error, setError] = useState<Error | null>(null);
  const [nonce, setNonce] = useState(0);
  const reqRef = useRef(req);
  reqRef.current = req;
  const reducerRef = useRef(reducer);
  reducerRef.current = reducer;

  useEffect(() => {
    const r = reqRef.current;
    setState(initial());
    setError(null);
    if (!r) {
      setStatus('idle');
      return;
    }
    const ac = new AbortController();
    let sawDone = false;
    setStatus('open');
    readSse(
      r,
      (e) => {
        if (ac.signal.aborted) return;
        if (e.type === 'done') sawDone = true;
        if (e.type === 'error') setError(new Error((e.data as { message?: string } | null)?.message ?? t('La mesure a échoué.')));
        setState((s) => reducerRef.current(s, e));
      },
      ac.signal,
    )
      .then(() => {
        if (ac.signal.aborted) return;
        if (sawDone) setStatus('done');
        else {
          setStatus('error');
          setError((x) => x ?? new Error(t('La mesure s’est interrompue avant la fin. Relancez-la.')));
        }
      })
      .catch((e: unknown) => {
        if (ac.signal.aborted) return;
        setStatus('error');
        setError(e instanceof Error ? e : new Error(String(e)));
      });
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, nonce]);

  return { state, status, error, restart: () => setNonce((n) => n + 1) };
}
