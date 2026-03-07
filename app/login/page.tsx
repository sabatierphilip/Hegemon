'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export default function LoginPage() {
  const { setToken } = useAuth();
  const router = useRouter();
  const [value, setValue] = useState('');

  return (
    <div className="mx-auto mt-24 max-w-sm">
      <Card className="space-y-2 p-4">
        <h1 className="text-lg">Hegemon Login</h1>
        <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="Bearer token" className="mono" />
        <Button onClick={() => { setToken(value); router.push('/'); }}>Authenticate</Button>
      </Card>
    </div>
  );
}
