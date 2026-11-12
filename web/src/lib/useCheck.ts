// Fetch a check result for the current input; re-measure on demand. Never cached.
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from './api';
import { t } from './i18n';

export interface CheckState<T> {
  data: T | null;
  error: ApiError | Error | null;
  loading: boolean;
  rerun: () => void;
}

export function useCheck<T>(url: string | null, init?: RequestInit & { json?: Record<string, unknown> }): CheckState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const initRef = useRef(init);
  initRef.current = init;

  useEffect(() => {
    if (!url) {
      setData(null);
      setError(null);
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    api<T>(url, initRef.current)
      .then((d) => alive && setData(d))
      .catch((e) => alive && (setError(e), setData(null)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [url, nonce]);

  const rerun = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading, rerun };
}

/** Human message for an API error. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    const serverMsg = (e.body as { message?: string } | null)?.message;
    if (serverMsg) return serverMsg;
    if (e.status === 504 || e.code === 'timeout') return t('La mesure a pris trop de temps. Relancez-la : les serveurs interrogés étaient peut-être lents.');
    if (e.status === 400) return t('Cette saisie ne ressemble pas à ce que cet outil attend.');
    if (e.status === 401) return t('Session expirée : reconnectez-vous.');
    if (e.status >= 500) return t('Le serveur de TestAndFix a rencontré une erreur. Relancez la mesure ; si elle se répète, consultez ses journaux.');
  }
  if (e instanceof TypeError) return t('Le serveur de TestAndFix ne répond pas. Vérifiez qu’il tourne.');
  return (e as Error)?.message ?? t('Erreur inconnue.');
}
