'use client';

const EVENT_COLORS: Record<string, string> = {
  drone_deployed: 'text-low',
  drone_completed: 'text-info',
  action_selected: 'text-accent',
  campaign_started: 'text-low',
  campaign_aborted: 'text-critical',
  deliberation_error: 'text-critical',
  fleet_cap_reached: 'text-medium',
  deploy_failed: 'text-high',
};

export function DroneOrderLog({ log }: { log: any[] }) {
  return (
    <div className="rounded border border-border bg-card p-3 space-y-1">
      <div className="text-xs font-medium text-text">Agent Log</div>
      <div className="space-y-0.5 max-h-80 overflow-y-auto font-mono">
        {log.length === 0 && <div className="text-[10px] text-textSecondary">Awaiting events…</div>}
        {log
          .slice()
          .reverse()
          .map((entry, i) => (
            <div key={i} className={`text-[9px] ${EVENT_COLORS[entry.event] ?? 'text-textSecondary'}`}>
              <span className="text-textSecondary">{new Date(entry.ts * 1000).toLocaleTimeString()} </span>
              <span className="uppercase">{entry.event}</span>
              {entry.action && <span className="text-textSecondary"> — {entry.action}</span>}
              {entry.drone_name && <span className="text-textSecondary"> {entry.drone_name}</span>}
              {entry.error && <span className="text-critical"> {entry.error.slice(0, 60)}</span>}
              {entry.rationale && <div className="ml-3 text-textSecondary italic text-[8px]">{entry.rationale.slice(0, 80)}</div>}
            </div>
          ))}
      </div>
    </div>
  );
}
