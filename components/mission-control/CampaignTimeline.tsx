'use client';

const DRONE_TYPE_COLORS: Record<string, string> = {
  scout: 'text-info border-info/40',
  mapper: 'text-info border-info/60',
  flanker: 'text-medium border-medium/40',
  harvester: 'text-high border-high/40',
  encircler: 'text-high border-high/60',
  striker: 'text-critical border-critical/50',
  watchdog: 'text-textSecondary border-border',
};

export function CampaignTimeline({ campaign }: { campaign: any }) {
  if (!campaign) return <div className="rounded border border-border bg-card p-3 text-[10px] text-textSecondary">No active campaign.</div>;
  const orders: any[] = campaign.drone_orders ?? [];

  return (
    <div className="rounded border border-border bg-card p-3 space-y-2">
      <div className="text-xs font-medium text-text">Campaign Timeline</div>
      <div className="text-[10px] text-textSecondary font-mono">Phase: {campaign.phase}</div>
      <div className="space-y-1.5 max-h-80 overflow-y-auto">
        {orders.length === 0 && <div className="text-[10px] text-textSecondary">Awaiting first order…</div>}
        {orders
          .slice()
          .reverse()
          .map((order, i) => {
            const droneType = order.action?.toLowerCase().replace('deploy_', '') ?? 'scout';
            const colorClass = DRONE_TYPE_COLORS[droneType] ?? 'text-text border-border';
            const ts = new Date(order.ts * 1000).toLocaleTimeString();
            return (
              <div key={i} className={`rounded border px-2 py-1.5 text-[10px] ${colorClass}`}>
                <div className="flex justify-between">
                  <span className="font-mono font-semibold uppercase">{droneType}</span>
                  <span className="text-textSecondary">{ts}</span>
                </div>
                <div className="text-textSecondary mt-0.5">{order.drone_name}</div>
                <div className="text-textSecondary">
                  → {order.target} ({order.phase})
                </div>
              </div>
            );
          })}
      </div>
    </div>
  );
}
