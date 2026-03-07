import { Drone } from '@/types/hegemon';
import { TierBadge } from '@/components/shared/TierBadge';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

export function DroneList({ drones, selectedId, onSelect, onCreate }: { drones: Drone[]; selectedId?: string; onSelect: (id: string) => void; onCreate: () => void; }) {
  return (
    <Card className="h-[calc(100vh-7rem)] overflow-auto p-2">
      <div className="mb-2 flex items-center justify-between"><h3 className="text-sm">Drones</h3><Button size="sm" onClick={onCreate}>New Drone</Button></div>
      <div className="space-y-2 text-xs">
        {drones.map((d) => (
          <button key={d.id} onClick={() => onSelect(d.id)} className={`w-full rounded border p-2 text-left ${selectedId === d.id ? 'border-accent bg-border' : 'border-border'}`}>
            <div className="flex items-center justify-between"><span>{d.name}</span><StatusIndicator status={d.status} /></div>
            <div className="mt-1 flex gap-1"><TierBadge tier={d.tier} /><span className="rounded bg-border px-2 py-0.5">{d.autonomy_level}</span></div>
            <div className="mono mt-1 text-textSecondary">TTL: {d.ttl_seconds}s</div>
          </button>
        ))}
      </div>
    </Card>
  );
}
