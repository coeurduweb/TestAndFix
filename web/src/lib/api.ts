// Fetch wrapper: JSON in/out, never cached, auth errors surfaced as a typed error.
export class ApiError extends Error {
  constructor(public status: number, public code: string, public body: unknown) {
    super(code);
  }
}

type Json = Record<string, unknown> | unknown[];

export async function api<T = unknown>(path: string, init: RequestInit & { json?: Json } = {}): Promise<T> {
  const { json, headers, ...rest } = init;
  const res = await fetch(path, {
    cache: 'no-store',
    credentials: 'same-origin',
    ...rest,
    headers: { ...(json ? { 'content-type': 'application/json' } : {}), ...headers },
    body: json ? JSON.stringify(json) : rest.body,
  });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON */
  }
  if (!res.ok) {
    const code = (body as { error?: string } | null)?.error ?? `http_${res.status}`;
    if (res.status === 401) window.dispatchEvent(new CustomEvent('check:auth-required'));
    throw new ApiError(res.status, code, body);
  }
  return body as T;
}

export const get = <T>(path: string) => api<T>(path);
export const post = <T>(path: string, json?: Json) => api<T>(path, { method: 'POST', json });
