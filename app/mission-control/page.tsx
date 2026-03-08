'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AgentCard } from '@/components/mission-control/AgentCard';
import { CampaignObjectivePanel } from '@/components/mission-control/CampaignObjectivePanel';
import { CampaignTimeline } from '@/components/mission-control/CampaignTimeline';
import { DroneOrderLog } from '@/components/mission-control/DroneOrderLog';
import { IntelAggregator } from '@/components/mission-control/IntelAggregator';
import { MissionDirectiveInput } from '@/components/mission-control/MissionDirectiveInput';
import { QTableViewer } from '@/components/mission-control/QTableViewer';
import { apiRequest } from '@/lib/api';
import { useAuth } from '@/lib/auth';

type Tab = 'agents' | 'campaign' | 'intel';

export default function MissionControlPage() {
  const { token } = useAuth();
  const [tab, setTab] = useState<Tab>('agents');
  const [status, setStatus] = useState<any>(null);
  const [campaign, setCampaign] = useState<any>(null);
  const [log, setLog] = useState<any[]>([]);
  const [qtable, setQtable] = useState<any>(null);
  const [parsePreview, setParsePreview] = useState('');
  const pollRef = useRef<NodeJS.Timeout>();

  const poll = useCallback(async () => {
    try {
      const [s, c, l, q] = await Promise.all([
        apiRequest<any>('/api/agents/hannibal/status', token),
        apiRequest<any>('/api/agents/hannibal/campaign', token),
        apiRequest<any>('/api/agents/hannibal/log', token),
        apiRequest<any>('/api/agents/hannibal/qtable', token),
      ]);
      setStatus(s);
      setCampaign(c.campaign);
      setLog(l.log ?? []);
      setQtable(q);
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

  return (
    <div className="space-y-3">
      <div className="flex gap-2 border-b border-border pb-2">
        {(['agents', 'campaign', 'intel'] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`rounded px-3 py-1 text-xs ${tab === t ? 'bg-accent text-white' : 'text-textSecondary hover:bg-border'}`}>
            {t.toUpperCase()}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          {status?.state === 'running' && <span className="rounded bg-low/20 px-2 py-0.5 text-[10px] text-low">HANNIBAL ACTIVE</span>}
          {status?.state === 'paused' && <span className="rounded bg-medium/20 px-2 py-0.5 text-[10px] text-medium">PAUSED</span>}
        </div>
      </div>

      {tab === 'agents' && (
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-5 space-y-3">
            <AgentCard status={status} onAbort={handleAbort} onPause={handlePause} onResume={handleResume} />
            <QTableViewer qtable={qtable} />
          </div>
          <div className="col-span-7">
            <MissionDirectiveInput onSubmit={handleInstruct} parsePreview={parsePreview} />
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
    </div>
  );
}
