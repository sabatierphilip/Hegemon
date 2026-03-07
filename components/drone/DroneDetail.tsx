'use client';

import { useEffect, useMemo, useState } from 'react';
import { Drone } from '@/types/hegemon';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { TerminalLog } from '@/components/shared/TerminalLog';
import { TierBadge } from '@/components/shared/TierBadge';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { apiRequest } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export function DroneDetail({ drone }: { drone?: Drone }) {
  const { token } = useAuth();
  const [telemetry, setTelemetry] = useState<string[]>([]);
  const [countdown, setCountdown] = useState<number>(drone?.ttl_seconds ?? 0);

  useEffect(() => {
    setCountdown(drone?.ttl_seconds ?? 0);
  }, [drone?.id, drone?.ttl_seconds]);

  useEffect(() => {
    if (!drone || drone.status !== 'active') return;
    const timer = setInterval(() => {
      setCountdown((t) => Math.max(0, t - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [drone]);

  useEffect(() => {
    if (!drone || drone.status !== 'active') return;
    const interval = setInterval(async () => {
      try {
        const data = await apiRequest<{ telemetry: string[] }>(`/api/drones/${drone.id}/telemetry`, token);
        setTelemetry(data.telemetry ?? []);
      } catch {
        // best effort polling
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [drone, token]);

  const stats = useMemo(
    () => [
      ['Hosts', drone?.stats.hosts_pinged ?? 0],
      ['Ports', drone?.stats.ports_scanned ?? 0],
      ['Findings', drone?.stats.findings_count ?? 0],
      ['Nodes', drone?.stats.nodes_executed ?? 0],
    ],
    [drone]
  );

  const callAction = async (action: 'launch' | 'terminate' | 'recall') => {
    if (!drone) return;
    try {
      await apiRequest(`/api/drones/${drone.id}/${action}`, token, { method: 'POST' });
    } catch {
      // no-op
    }
  };

  if (!drone) return <Card className="p-3 text-xs text-textSecondary">Select a drone</Card>;

  return (
    <Card className="h-[calc(100vh-7rem)] space-y-3 overflow-auto p-3 text-xs">
      <h3 className="text-sm">Drone Detail</h3>

      <div className="space-y-1">
        <div className="font-mono">ID: {drone.id}</div>
        <div>Name: {drone.name}</div>
        <div className="flex items-center gap-1">
          <TierBadge tier={drone.tier} />
          <span className="rounded bg-border px-2 py-0.5">{drone.autonomy_level}</span>
          <StatusIndicator status={drone.status} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 rounded border border-border p-2">
        <div>TTL: {countdown}s</div>
        <div>PID: {drone.pid ?? 'n/a'}</div>
        <div className="col-span-2 break-all font-mono">Blob Hash: {drone.blob_hash}</div>
        <div>Blob Size: {drone.blob_size_bytes} bytes</div>
        <div>Node: {drone.current_node_id ?? 'n/a'}</div>
      </div>

      <div className="grid grid-cols-4 gap-1">
        {stats.map(([label, value]) => (
          <div key={String(label)} className="rounded border border-border p-1 text-center">
            <div className="text-[11px] text-textSecondary">{label}</div>
            <div className="font-mono">{value}</div>
          </div>
        ))}
      </div>

      <div>
        <div className="mb-1 text-textSecondary">Live Telemetry</div>
        <TerminalLog lines={telemetry.length ? telemetry : drone.live_output ?? []} />
      </div>

      <div>
        <div className="mb-1 text-textSecondary">Findings</div>
        <ul className="list-disc space-y-1 pl-4">
          {(drone.findings ?? []).map((finding) => (
            <li key={finding}>{finding}</li>
          ))}
          {!drone.findings?.length && <li className="list-none text-textSecondary">No findings.</li>}
        </ul>
      </div>

      <div className="flex flex-wrap gap-1">
        <Button size="sm" onClick={() => callAction('launch')}>
          Launch
        </Button>
        <Button size="sm" variant="outline" onClick={() => callAction('terminate')}>
          Terminate
        </Button>
        <Button size="sm" variant="outline" onClick={() => callAction('recall')}>
          Recall
        </Button>
        <Button size="sm" variant="ghost" onClick={() => navigator.clipboard.writeText(telemetry.join('\n'))}>
          View Source
        </Button>
      </div>
    </Card>
  );
}
