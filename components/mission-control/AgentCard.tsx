'use client';

const PHASE_COLORS: Record<string, string> = {
  dormant: 'text-textSecondary',
  reconnaissance: 'text-info',
  mapping: 'text-info',
  flanking: 'text-medium',
  encirclement: 'text-high',
  exploitation: 'text-critical',
  withdrawal: 'text-medium',
};

export function AgentCard({ status, onAbort, onPause, onResume }: { status: any; onAbort: () => void; onPause: () => void; onResume: () => void }) {
  const phase = status?.phase ?? 'dormant';
  const phaseColor = PHASE_COLORS[phase] ?? 'text-text';
  return (
    <div className="rounded border border-border bg-card p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={`h-2 w-2 rounded-full ${status?.state === 'running' ? 'bg-low animate-pulse' : status?.state === 'paused' ? 'bg-medium' : 'bg-border'}`} />
          <span className="text-sm font-semibold text-text">HANNIBAL</span>
          <span className="text-[10px] text-textSecondary">Encirclement Doctrine</span>
        </div>
        <span className={`text-xs font-mono font-bold uppercase ${phaseColor}`}>{phase}</span>
      </div>

      {status?.campaign_id && <div className="text-[10px] text-textSecondary font-mono">{status.campaign_id}</div>}

      <div className="grid grid-cols-3 gap-1 text-center">
        {[{ label: 'Hosts', value: status?.alive_hosts ?? 0 }, { label: 'Drones', value: status?.active_drones ?? 0 }, { label: 'Creds', value: status?.credentials_harvested ?? 0 }].map((m) => (
          <div key={m.label} className="rounded bg-bg p-1.5">
            <div className="text-sm font-bold text-text">{m.value}</div>
            <div className="text-[9px] text-textSecondary">{m.label}</div>
          </div>
        ))}
      </div>

      <div>
        <div className="flex justify-between text-[10px] text-textSecondary mb-0.5">
          <span>Exposure</span>
          <span>{((status?.exposure_score ?? 0) * 100).toFixed(0)}%</span>
        </div>
        <div className="h-1.5 rounded bg-bg overflow-hidden">
          <div
            className={`h-full rounded transition-all ${(status?.exposure_score ?? 0) > 0.75 ? 'bg-critical' : (status?.exposure_score ?? 0) > 0.4 ? 'bg-medium' : 'bg-low'}`}
            style={{ width: `${((status?.exposure_score ?? 0) * 100).toFixed(0)}%` }}
          />
        </div>
      </div>

      <div className="flex gap-1.5">
        {status?.state === 'running' && <button onClick={onPause} className="rounded border border-border px-2 py-1 text-[10px] text-textSecondary hover:bg-border">Pause</button>}
        {status?.state === 'paused' && <button onClick={onResume} className="rounded border border-low/50 px-2 py-1 text-[10px] text-low hover:bg-low/10">Resume</button>}
        {status?.state !== 'dormant' && <button onClick={onAbort} className="rounded border border-critical/50 px-2 py-1 text-[10px] text-critical hover:bg-critical/10 ml-auto">Abort & Withdraw</button>}
      </div>

      <div className="border-t border-border pt-2 text-[9px] text-textSecondary space-y-0.5">
        <div className="font-medium text-text text-[10px]">Doctrine — Cannae Encirclement</div>
        <div>Scout → Map → Flank → Encircle → Strike</div>
        <div>Withdrawal triggered at &gt;75% exposure</div>
        <div>Q-learning episode: {status?.q_episode ?? '—'}</div>
      </div>
    </div>
  );
}
