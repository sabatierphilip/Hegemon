'use client';

export function IntelAggregator({ campaign }: { campaign: any }) {
  if (!campaign) return <div className="rounded border border-border bg-card p-3 text-[10px] text-textSecondary">No campaign active.</div>;

  return (
    <div className="grid grid-cols-3 gap-3">
      <div className="rounded border border-border bg-card p-3">
        <div className="text-xs font-medium text-text mb-2">Live Hosts</div>
        <div className="space-y-0.5 max-h-60 overflow-y-auto">
          {(campaign.alive_hosts ?? []).map((h: string, i: number) => (
            <div key={i} className="flex items-center gap-1.5 text-[10px]">
              <div className="h-1.5 w-1.5 rounded-full bg-low" />
              <span className="font-mono text-text">{h}</span>
              {campaign.high_value_targets?.includes(h) && <span className="rounded border border-critical/40 px-1 text-[8px] text-critical">HVT</span>}
            </div>
          ))}
          {!campaign.alive_hosts?.length && <div className="text-[10px] text-textSecondary">None discovered yet.</div>}
        </div>
      </div>

      <div className="rounded border border-border bg-card p-3">
        <div className="text-xs font-medium text-text mb-2">Pivot Chains</div>
        <div className="space-y-1 max-h-60 overflow-y-auto">
          {(campaign.pivot_chains ?? []).map((chain: any, i: number) => (
            <div key={i} className="text-[9px] font-mono text-textSecondary border-b border-border pb-0.5">
              <span className="text-medium">{chain.source}</span>
              <span className="text-textSecondary"> → </span>
              <span className="text-high">{chain.target}</span>
              <span className="ml-1 text-[8px]">(method={chain.method} conf={((chain.confidence ?? 0) * 100).toFixed(0)}%)</span>
            </div>
          ))}
          {!campaign.pivot_chains?.length && <div className="text-[10px] text-textSecondary">No chains mapped yet.</div>}
        </div>
      </div>

      <div className="rounded border border-border bg-card p-3">
        <div className="text-xs font-medium text-text mb-2">Credential Findings</div>
        <div className="space-y-0.5 max-h-60 overflow-y-auto">
          {(campaign.credential_findings ?? []).slice(0, 20).map((c: any, i: number) => (
            <div key={i} className="text-[9px] text-textSecondary border-b border-border pb-0.5">
              <span className="text-high font-mono">{c.key ?? c.path ?? c.raw ?? 'unknown'}</span>
              <span className="ml-1 text-[8px]">({c.source ?? 'finding'})</span>
            </div>
          ))}
          {!campaign.credential_findings?.length && <div className="text-[10px] text-textSecondary">No credentials harvested yet.</div>}
        </div>
      </div>
    </div>
  );
}
