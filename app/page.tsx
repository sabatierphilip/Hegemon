'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiRequest, ApiError } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { DashboardState } from '@/types/hegemon';
import { SeverityBar } from '@/components/dashboard/SeverityBar';
import { AlertsTable } from '@/components/dashboard/AlertsTable';
import { ContainmentPanel } from '@/components/dashboard/ContainmentPanel';
import { HorizonSummary } from '@/components/dashboard/HorizonSummary';
import { Card } from '@/components/ui/card';
import { TerminalLog } from '@/components/shared/TerminalLog';

const fallback: DashboardState = { events_processed: 0, candidate_severity: 0, risk_confidence: 0, baseline_ready: false, distributed_attack_active: false, alerts: [], soar_actions: [], contained_hosts: [] };

export default function DashboardPage() {
  const { token } = useAuth();
  const router = useRouter();
  const [state, setState] = useState<DashboardState>(fallback);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    const run = async () => {
      try {
        const data = await apiRequest<DashboardState>('/api/state', token);
        setState(data);
        setOffline(false);
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) router.push('/login');
        if (e instanceof ApiError && e.status === 0) setOffline(true);
      }
    };
    run();
    const interval = setInterval(run, 2000);
    return () => clearInterval(interval);
  }, [token, router]);

  return (
    <div className="space-y-3">
      {offline && <div className="rounded border border-critical bg-critical/20 p-2 text-xs text-critical">Backend disconnected</div>}
      <SeverityBar events={state.events_processed} score={state.candidate_severity} confidence={state.risk_confidence} baselineReady={state.baseline_ready} distributed={state.distributed_attack_active} />
      <div className="grid gap-3 lg:grid-cols-2">
        <AlertsTable alerts={state.alerts} />
        <ContainmentPanel hosts={state.contained_hosts} action={state.last_containment_action} simulation={state.simulation_mode} />
        <HorizonSummary persistent={state.persistent_horizon_activity} />
        <Card className="p-2"><h3 className="mb-1 text-sm">SOAR actions</h3><TerminalLog lines={state.soar_actions} /></Card>
        <Card className="p-2 text-xs">Mirror clone activity: deployment, confidence, phase, counter-clone status</Card>
        <Card className="p-2 text-xs">Distributor risk gauge</Card>
      </div>
    </div>
  );
}
