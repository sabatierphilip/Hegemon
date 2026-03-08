'use client';

const BAND_CLASS: Record<string, string> = {
  low: 'text-low border-low/40 bg-low/10',
  elevated: 'text-medium border-medium/40 bg-medium/10',
  critical: 'text-critical border-critical/40 bg-critical/10',
};

export function StrategicBriefing({ briefing }: { briefing: any }) {
  if (!briefing) {
    return <div className="rounded border border-border bg-card p-3 text-[10px] text-textSecondary">Briefing unavailable.</div>;
  }

  const riskPct = Math.round((briefing.risk_score ?? 0) * 100);
  const band = String(briefing.risk_band ?? 'low');
  const className = BAND_CLASS[band] ?? BAND_CLASS.low;

  return (
    <div className="rounded border border-border bg-card p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs font-medium text-text">Strategic Briefing</div>
        <span className={`rounded border px-2 py-0.5 text-[10px] uppercase ${className}`}>{band}</span>
      </div>

      <div>
        <div className="flex justify-between text-[10px] text-textSecondary mb-0.5">
          <span>Risk score</span>
          <span>{riskPct}%</span>
        </div>
        <div className="h-1.5 rounded bg-bg overflow-hidden">
          <div className={`h-full rounded ${band === 'critical' ? 'bg-critical' : band === 'elevated' ? 'bg-medium' : 'bg-low'}`} style={{ width: `${riskPct}%` }} />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-1 text-center">
        {[
          { label: 'Fleet', value: briefing.fleet_snapshot?.active ?? 0 },
          { label: 'Total', value: briefing.fleet_snapshot?.total ?? 0 },
          { label: 'Errors', value: briefing.fleet_snapshot?.error ?? 0 },
          { label: 'Velocity', value: briefing.phase_velocity ?? '—' },
        ].map((m) => (
          <div key={m.label} className="rounded bg-bg p-1.5">
            <div className="text-[11px] font-semibold text-text">{m.value}</div>
            <div className="text-[9px] text-textSecondary">{m.label}</div>
          </div>
        ))}
      </div>

      <div>
        <div className="text-[10px] font-medium text-text mb-1">Top Risks</div>
        <div className="space-y-1">
          {(briefing.top_risks ?? []).map((risk: string, idx: number) => (
            <div key={idx} className="rounded border border-border px-2 py-1 text-[10px] text-textSecondary">• {risk}</div>
          ))}
        </div>
      </div>

      <div>
        <div className="text-[10px] font-medium text-text mb-1">Recommended Actions</div>
        <div className="space-y-1">
          {(briefing.recommended_actions ?? []).map((rec: any, idx: number) => (
            <div key={idx} className="rounded border border-border px-2 py-1">
              <div className="text-[10px] text-text font-semibold font-mono">{rec.action}</div>
              <div className="text-[9px] text-textSecondary uppercase">Priority: {rec.priority}</div>
              <div className="text-[9px] text-textSecondary mt-0.5">{rec.reason}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
