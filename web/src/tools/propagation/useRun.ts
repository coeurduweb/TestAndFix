// SSE run of the propagation check. Own hook rather than lib/useEventStream because the page needs
// the rounds of the watch mode (answers kept between rounds), the reason of a refused request
// (EventSource hides the HTTP status) and batched updates.
// Resolver events are batched (every 80 ms) so 400 answers in a second do not mean 400 renders.
import { useCallback, useEffect, useReducer, useRef } from 'react';
import { msg, t } from '../../lib/i18n';
import {
  initialRun, runReducer, streamUrl, type AuthorityEvent, type DoneEvent, type ResolverEvent, type RunState, type StartEvent,
} from './model';

const MESSAGES: Record<string, string> = {
  bad_name: msg('Ce nom n’est pas un nom DNS valide. Vérifiez l’orthographe ; les tirets bas des noms de service sont acceptés.'),
  bad_type: msg('Ce type d’enregistrement n’est pas suivi par la propagation.'),
  ips_required: msg('La relance des résolveurs en attente demande leur liste.'),
  resolution_failed: msg('La résolution depuis les serveurs racine a échoué.'),
  no_zone: msg('Aucune zone DNS ne contient ce nom.'),
  no_authority: msg('Aucun serveur autoritaire n’a répondu.'),
};

async function probe(url: string): Promise<{ code: string; message: string }> {
  const ac = new AbortController();
  try {
    const res = await fetch(url, { credentials: 'same-origin', cache: 'no-store', signal: ac.signal });
    if (res.ok) {
      ac.abort();
      return { code: 'interrupted', message: t('Le flux de mesure s’est interrompu. Relancez la mesure.') };
    }
    if (res.status === 401) window.dispatchEvent(new CustomEvent('check:auth-required'));
    const body = (await res.json().catch(() => null)) as { error?: string; message?: string } | null;
    const code = body?.error ?? `http_${res.status}`;
    return {
      code,
      message: res.status === 401 ? t('Session expirée : reconnectez-vous.') : body?.message ?? (MESSAGES[code] ? t(MESSAGES[code]) : t('Le serveur a refusé la mesure (HTTP {status}).', { status: res.status })),
    };
  } catch {
    return { code: 'unreachable', message: t('Le serveur de TestAndFix ne répond pas. Vérifiez qu’il tourne, puis relancez.') };
  }
}

export function usePropagationRun(name: string | null, type: string, expected: string | null, where = '') {
  const [state, dispatch] = useReducer(runReducer, initialRun);
  const esRef = useRef<EventSource | null>(null);
  const stateRef = useRef<RunState>(state);
  stateRef.current = state;

  const close = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
  }, []);

  const run = useCallback(
    (scope: string[] | null) => {
      if (!name) return;
      close();
      dispatch({ type: 'begin', scope });
      const url = streamUrl(name, type, expected, scope, where);
      const es = new EventSource(url, { withCredentials: true });
      esRef.current = es;
      let started = false;
      let finished = false;
      let buffer: ResolverEvent[] = [];
      let timer: ReturnType<typeof setTimeout> | null = null;
      const flush = () => {
        timer = null;
        if (!buffer.length) return;
        const b = buffer;
        buffer = [];
        dispatch({ type: 'resolvers', data: b });
      };
      const parse = (ev: Event) => {
        try {
          return JSON.parse((ev as MessageEvent).data);
        } catch {
          return null;
        }
      };
      const alive = () => esRef.current === es;
      es.addEventListener('start', (ev) => {
        if (!alive()) return;
        started = true;
        dispatch({ type: 'start', data: parse(ev) as StartEvent });
      });
      es.addEventListener('authority', (ev) => {
        if (!alive()) return;
        started = true;
        dispatch({ type: 'authority', data: parse(ev) as AuthorityEvent });
      });
      es.addEventListener('resolver', (ev) => {
        if (!alive()) return;
        const d = parse(ev) as ResolverEvent | null;
        if (d) buffer.push(d);
        timer ??= setTimeout(flush, 80);
      });
      es.addEventListener('done', (ev) => {
        if (!alive()) return;
        finished = true;
        if (timer) clearTimeout(timer);
        flush();
        dispatch({ type: 'done', data: parse(ev) as DoneEvent });
        close();
      });
      // the server's own `error` event carries data; a connection failure does not
      es.addEventListener('error', (ev) => {
        if (!alive() || finished) return;
        const data = ev instanceof MessageEvent && ev.data ? (parse(ev) as { code?: string; message?: string } | null) : null;
        if (timer) clearTimeout(timer);
        flush();
        close();
        finished = true;
        if (data) {
          dispatch({ type: 'error', data: { code: data.code ?? 'error', message: data.message ?? (MESSAGES[data.code ?? ''] ? t(MESSAGES[data.code ?? '']) : t('La mesure a échoué.')) } });
          return;
        }
        if (!started) void probe(url).then((e) => dispatch({ type: 'error', data: e }));
        else dispatch({ type: 'error', data: { code: 'interrupted', message: t('Le flux de mesure s’est interrompu avant la fin : les réponses reçues restent affichées. Relancez la mesure.') } });
      });
    },
    [name, type, expected, where, close],
  );

  useEffect(() => {
    if (name) run(null);
    return close;
  }, [name, run, close]);

  return { state, run, stop: close, stateRef };
}
