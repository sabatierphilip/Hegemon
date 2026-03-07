'use client';

import { createContext, ReactNode, useContext, useMemo, useState } from 'react';

type AuthContextType = {
  token: string | null;
  setToken: (token: string | null) => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const defaultToken = process.env.NEXT_PUBLIC_AUTO_AUTH_TOKEN ?? 'autonomous-session';
  const [token, setToken] = useState<string | null>(defaultToken);
  const value = useMemo(() => ({ token, setToken }), [token]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
