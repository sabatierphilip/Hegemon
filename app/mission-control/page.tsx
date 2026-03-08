'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AgentCard } from '@/components/mission-control/AgentCard';
import { CampaignObjectivePanel } from '@/components/mission-control/CampaignObjectivePanel';
import { CampaignTimeline } from '@/components/mission-control/CampaignTimeline';
import { DirectiveSimulator } from '@/components/mission-control/DirectiveSimulator';
import { DroneOrderLog } from '@/components/mission-control/DroneOrderLog';
import { IntelAggregator } from '@/components/mission-control/IntelAggregator';
import { MissionDirectiveInput } from '@/components/mission-control/MissionDirectiveInput';
import { MissionOperationsBoard } from '@/components/mission-control/MissionOperationsBoard';
import { QTableViewer } from '@/components/mission-control/QTableViewer';
import { StrategicBriefing } from '@/components/mission-control/StrategicBriefing';
import { apiRequest } from '@/lib/api';
import { useAuth } from '@/lib/auth';

type Tab = 'agents' | 'campaign' | 'intel' | 'strategy' | 'operations';

export default function MissionControlPage() {
  const { token } = useAuth();
  const [tab, setTab] = useState<Tab>('agents');
  const [status, setStatus] = useState<any>(null);
  const [campaign, setCampaign] = useState<any>(null);
  const [log, setLog] = useState<any[]>([]);
  const [qtable, setQtable] = useState<any>(null);
  const [briefing, setBriefing] = useState<any>(null);
  const [board, setBoard] = useState<any>(null);
  const [simulation, setSimulation] = useState<any>(null);
  const [parsePreview, setParsePreview] = useState('');
  const pollRef = useRef<NodeJS.Timeout>();

  const poll = useCallback(async () => {
    try {
      const [s, c, l, q, b, boardResp] = await Promise.all([
        apiRequest<any>('/api/agents/hannibal/status', token),
        apiRequest<any>('/api/agents/hannibal/campaign', token),
        apiRequest<any>('/api/agents/hannibal/log', token),
        apiRequest<any>('/api/agents/hannibal/qtable', token),
        apiRequest<any>('/api/agents/hannibal/briefing', token),
        apiRequest<any>('/api/agents/hannibal/mission-control/state', token),
      ]);
      setStatus(s);
      setCampaign(c.campaign);
      setLog(l.log ?? []);
      setQtable(q);
      setBriefing(b);
      setBoard(boardResp);
    } catch {
      // noop
    }
  }, [token]);

  useEffect(() => {
    void poll();
    pollRef.current = setInterval(() => void poll(), 5000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [poll]);

  const handleInstruct = async (text: string) => {
    const result = await apiRequest<any>('/api/agents/hannibal/instruct', token, { method: 'POST', body: JSON.stringify({ text }) });
    setParsePreview(result.explanation ?? '');
    await poll();
    return result;
  };

  const handleSimulate = async (directive: string) => {
    const result = await apiRequest<any>('/api/agents/hannibal/simulate', token, { method: 'POST', body: JSON.stringify({ directive }) });
    setSimulation(result);
  };

  const handleAbort = async () => {
    await apiRequest('/api/agents/hannibal/abort', token, { method: 'POST', body: '{}' });
    await poll();
  };

  const handlePause = async () => {
    await apiRequest('/api/agents/hannibal/pause', token, { method: 'POST', body: '{}' });
    await poll();
  };

  const handleResume = async () => {
    await apiRequest('/api/agents/hannibal/resume', token, { method: 'POST', body: '{}' });
    await poll();
  };

  const handleCreateTask = async (payload: any) => {
    await apiRequest('/api/agents/hannibal/mission-control/task', token, { method: 'POST', body: JSON.stringify(payload) });
    await poll();
  };

  const handleUpdateTask = async (taskId: string, payload: any) => {
    await apiRequest(`/api/agents/hannibal/mission-control/task/${taskId}`, token, { method: 'PATCH', body: JSON.stringify(payload) });
    await poll();
  };

  const handleIssueOrder = async (payload: any) => {
    await apiRequest('/api/agents/hannibal/mission-control/order', token, { method: 'POST', body: JSON.stringify(payload) });
    await poll();
  };

  const handleCloseOrder = async (orderId: string, payload: any) => {
    await apiRequest(`/api/agents/hannibal/mission-control/order/${orderId}/close`, token, { method: 'POST', body: JSON.stringify(payload) });
    await poll();
  };

  const handleRegisterDirective = async (payload: any) => {
    await apiRequest('/api/agents/hannibal/mission-control/directive', token, { method: 'POST', body: JSON.stringify(payload) });
    await poll();
  };

  const handleRefreshPlaybooks = async () => {
    await apiRequest('/api/agents/hannibal/mission-control/playbooks/refresh', token, { method: 'POST', body: '{}' });
    await poll();
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2 border-b border-border pb-2">
        {(['agents', 'campaign', 'intel', 'strategy', 'operations'] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`rounded px-3 py-1 text-xs ${tab === t ? 'bg-accent text-white' : 'text-textSecondary hover:bg-border'}`}>
            {t.toUpperCase()}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          {status?.state === 'running' && <span className="rounded bg-low/20 px-2 py-0.5 text-[10px] text-low">HANNIBAL ACTIVE</span>}
          {status?.state === 'paused' && <span className="rounded bg-medium/20 px-2 py-0.5 text-[10px] text-medium">PAUSED</span>}
          {status?.risk_band && <span className="rounded border border-border px-2 py-0.5 text-[10px] text-textSecondary uppercase">Risk {status.risk_band}</span>}
          {board?.tasking && <span className="rounded border border-border px-2 py-0.5 text-[10px] text-textSecondary">Tasks {board.tasking.open}</span>}
        </div>
      </div>

      {tab === 'agents' && (
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-5 space-y-3">
            <AgentCard status={status} onAbort={handleAbort} onPause={handlePause} onResume={handleResume} />
            <QTableViewer qtable={qtable} />
            <StrategicBriefing briefing={briefing} />
          </div>
          <div className="col-span-7 space-y-3">
            <MissionDirectiveInput onSubmit={handleInstruct} parsePreview={parsePreview} />
            <DirectiveSimulator onSimulate={handleSimulate} simulation={simulation} />
          </div>
        </div>
      )}

      {tab === 'campaign' && (
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-4">
            <CampaignObjectivePanel campaign={campaign} />
          </div>
          <div className="col-span-5">
            <CampaignTimeline campaign={campaign} />
          </div>
          <div className="col-span-3">
            <DroneOrderLog log={log} />
          </div>
        </div>
      )}

      {tab === 'intel' && <IntelAggregator campaign={campaign} />}
      {tab === 'strategy' && (
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-7">
            <StrategicBriefing briefing={briefing} />
          </div>
          <div className="col-span-5">
            <DirectiveSimulator onSimulate={handleSimulate} simulation={simulation} />
          </div>
        </div>
      )}

      {tab === 'operations' && (
        <MissionOperationsBoard
          board={board}
          onCreateTask={handleCreateTask}
          onUpdateTask={handleUpdateTask}
          onIssueOrder={handleIssueOrder}
          onCloseOrder={handleCloseOrder}
          onRegisterDirective={handleRegisterDirective}
          onRefreshPlaybooks={handleRefreshPlaybooks}
        />
      )}
    </div>
  );
}
