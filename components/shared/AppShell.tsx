'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ReactNode, useState } from 'react';
import { useAuth } from '@/lib/auth';

const routes = ['/', '/drones', '/graph', '/control-plane', '/peers', '/settings'];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { token } = useAuth();
  const router = useRouter();
  const [disconnected, setDisconnected] = useState(false);

  if (!token && pathname !== '/login') {
    router.push('/login');
    return null;
  }

  return (
    <div className="min-h-screen bg-bg text-text">
      {disconnected && <div className="border-b border-critical bg-critical/20 px-3 py-2 text-xs text-critical">Backend disconnected</div>}
      {pathname !== '/login' && (
        <nav className="sticky top-0 z-20 flex items-center gap-2 border-b border-border bg-card/95 px-3 py-2 text-xs">
          {routes.map((route) => (
            <Link
              key={route}
              href={route}
              className={`rounded px-2 py-1 ${pathname === route ? 'bg-accent text-white' : 'text-textSecondary hover:bg-border'}`}
            >
              {route === '/' ? 'dashboard' : route.replace('/', '')}
            </Link>
          ))}
          <button className="ml-auto rounded px-2 py-1 text-textSecondary hover:bg-border" onClick={() => setDisconnected(false)}>
            clear banner
          </button>
        </nav>
      )}
      <main className="p-3">{children}</main>
    </div>
  );
}
