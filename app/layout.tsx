import './globals.css';
import { ReactNode } from 'react';
import { AuthProvider } from '@/lib/auth';
import { AppShell } from '@/components/shared/AppShell';

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <AuthProvider>
          <AppShell>{children}</AppShell>
        </AuthProvider>
      </body>
    </html>
  );
}
