import { Drone } from '@/types/hegemon';
import { Card } from '@/components/ui/card';
import { TerminalLog } from '@/components/shared/TerminalLog';

export function DroneDetail({ drone }: { drone?: Drone }) {
  if (!drone) return <Card className="p-3 text-xs text-textSecondary">Select a drone</Card>;
  return (
    <Card className="h-[calc(100vh-7rem)] space-y-3 overflow-auto p-3 text-xs">
      <h3 className="text-sm">Drone Detail</h3>
      <div className="mono">ID: {drone.id}</div>
      <div>Name: {drone.name}</div>
      <div>Phase: {drone.phase || 'n/a'}</div>
      <div>Confidence: {(drone.confidence ?? 0).toFixed(2)}</div>
      <TerminalLog lines={[`telemetry ${drone.name}`, 'finding: none', 'deadrop: synced']} />
      <div className="rounded border border-border p-2">Actions: terminate | contain | export source</div>
    </Card>
  );
}
