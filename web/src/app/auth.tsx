import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { get, post } from '../lib/api';

interface AuthState {
  authenticated: boolean;
  configured: boolean;
  loading: boolean;
  login(password: string): Promise<void>;
  logout(): Promise<void>;
  refresh(): Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);
export const useAuth = () => useContext(Ctx)!;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState({ authenticated: false, configured: true, loading: true });
  const refresh = useCallback(async () => {
    try {
      const s = await get<{ authenticated: boolean; configured: boolean }>('/api/auth/status');
      setState({ ...s, loading: false });
    } catch {
      setState((x) => ({ ...x, loading: false }));
    }
  }, []);
  useEffect(() => {
    refresh();
    const onRequired = () => setState((x) => ({ ...x, authenticated: false }));
    window.addEventListener('check:auth-required', onRequired);
    return () => window.removeEventListener('check:auth-required', onRequired);
  }, [refresh]);
  const login = useCallback(async (password: string) => {
    await post('/api/auth/login', { password });
    setState((x) => ({ ...x, authenticated: true }));
  }, []);
  const logout = useCallback(async () => {
    await post('/api/auth/logout');
    setState((x) => ({ ...x, authenticated: false }));
  }, []);
  return <Ctx.Provider value={{ ...state, login, logout, refresh }}>{children}</Ctx.Provider>;
}
