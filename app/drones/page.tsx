'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Drone, Endpoint } from '@/types/hegemon';
import { apiRequest, ApiError } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { DroneList } from '@/components/drone/DroneList';
import { ComposerShell } from '@/components/drone/composer/ComposerShell';
import { DroneDetail } from '@/components/drone/DroneDetail';

type DroneTab = 'construction' | 'fleet';

export default function DronesPage() {
  const { token } = useAuth();
  const router = useRouter();
  const [drones, setDrones] = useState<Drone[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [selectedId, setSelectedId] = useState<string>();
  const [droneTab, setDroneTab] = useState<DroneTab>('construction');

  useEffect(() => {
    const load = async () => {
      try {
        const [d, o] = await Promise.all([
          apiRequest<Drone[]>('/api/drones', token),
          apiRequest<{ endpoints: Endpoint[] }>('/api/control-plane/overview', token),
        ]);
        setDrones(d);
        setEndpoints(o.endpoints ?? []);
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) router.push('/login');
      }
    };
    load();
  }, [token, router]);

  const selected = useMemo(() => drones.find((d) => d.id === selectedId), [drones, selectedId]);

  return (
    <div>
      <div className="flex gap-2 border-b border-border pb-2 mb-3">
        {(['construction', 'fleet'] as DroneTab[]).map((t) => (
          <button key={t} onClick={() => setDroneTab(t)} className={`rounded px-3 py-1 text-xs ${droneTab === t ? 'bg-accent text-white' : 'text-textSecondary hover:bg-border'}`}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>
      {droneTab === 'construction' && <ComposerShell drones={drones} endpoints={endpoints} />}
      {droneTab === 'fleet' && (
        <div className="grid grid-cols-12 gap-2">
          <div className="col-span-4">
            <DroneList drones={drones} selectedId={selectedId} onSelect={setSelectedId} onCreate={() => setSelectedId(undefined)} />
          </div>
          <div className="col-span-8">
            <DroneDetail drone={selected} />
          </div>
        </div>
      )}
    </div>
  );
}
