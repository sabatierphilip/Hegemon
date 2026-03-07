export function TierBadge({ tier }: { tier: 'controlled' | 'tethered' | 'autonomous' }) {
  const style = tier === 'autonomous' ? 'bg-info/20 text-info' : tier === 'tethered' ? 'bg-medium/20 text-medium' : 'bg-low/20 text-low';
  return <span className={`rounded px-2 py-0.5 text-[11px] ${style}`}>{tier}</span>;
}
