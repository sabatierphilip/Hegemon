import { Card } from '@/components/ui/card';

export function ContainmentPanel({ hosts, action, simulation }: { hosts: string[]; action?: string; simulation?: boolean }) {
  return <Card className="p-3 text-xs"><div className="mb-2 flex items-center justify-between"><h3>Containment</h3><span className={`rounded px-2 py-1 ${simulation ? 'bg-info/20 text-info' : 'bg-critical/20 text-critical'}`}>{simulation ? 'simulation' : 'live'}</span></div><div className="mono">{hosts.join(', ') || 'none'}</div><div className="mt-2 text-textSecondary">Last action: {action || 'n/a'}</div></Card>;
}
