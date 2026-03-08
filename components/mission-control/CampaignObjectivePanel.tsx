'use client';

const PHASES = ['dormant', 'reconnaissance', 'mapping', 'flanking', 'encirclement', 'exploitation', 'withdrawal'];

export function CampaignObjectivePanel({ campaign }: { campaign: any }) {
  if (!campaign) return null;
  const phaseIdx = PHASES.indexOf(campaign.phase ?? 'dormant');

  return (
    <div className="rounded border border-border bg-card p-3 space-y-3">
      <div className="text-xs font-medium text-text">Objective</div>
      <div className="text-[10px] text-textSecondary">{campaign.mission_objective}</div>

      <div className="space-y-0.5">
        {PHASES.filter((p) => p !== 'dormant').map((p, i) => {
          const idx = i + 1;
          const done = phaseIdx > idx;
          const active = phaseIdx === idx;
          return (
            <div key={p} className={`flex items-center gap-2 text-[10px] ${active ? 'text-accent' : done ? 'text-low' : 'text-textSecondary'}`}>
              <div className={`h-1.5 w-1.5 rounded-full ${active ? 'bg-accent animate-pulse' : done ? 'bg-low' : 'bg-border'}`} />
              <span className="uppercase">{p}</span>
              {done && <span className="text-[8px]">✓</span>}
            </div>
          );
        })}
      </div>

      {(campaign.objectives_completed ?? []).length > 0 && (
        <div>
          <div className="text-[10px] font-medium text-text mb-1">Completed</div>
          {campaign.objectives_completed.map((o: string, i: number) => (
            <div key={i} className="text-[9px] text-low">
              ✓ {o}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
