import { Card } from '@/components/ui/card';

export function HorizonSummary({ persistent }: { persistent?: boolean }) {
  const items = [{ label: '5m', events: 14, peak: 62 }, { label: '30m', events: 44, peak: 73 }, { label: '180m', events: 120, peak: 88 }];
  return <Card className="p-3 text-xs"><div className="mb-2 flex items-center justify-between"><h3>Horizon</h3>{persistent && <span className="rounded bg-medium/20 px-2 py-1 text-medium">persistent</span>}</div><div className="grid grid-cols-3 gap-2">{items.map(i => <div key={i.label} className="rounded border border-border p-2"><div className="text-textSecondary">{i.label}</div><div className="mono">{i.events} evt</div><div className="mono">peak {i.peak}</div></div>)}</div></Card>;
}
