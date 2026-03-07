import { Severity } from '@/types/hegemon';

const map: Record<Severity, string> = {
  critical: 'bg-critical/20 text-critical',
  high: 'bg-high/20 text-high',
  medium: 'bg-medium/20 text-medium',
  low: 'bg-low/20 text-low',
  info: 'bg-info/20 text-info'
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`rounded px-2 py-0.5 text-[11px] uppercase ${map[severity]}`}>{severity}</span>;
}
