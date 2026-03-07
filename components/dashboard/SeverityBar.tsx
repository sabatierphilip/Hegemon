import { Card } from '@/components/ui/card';

export function SeverityBar({ events, score, confidence, baselineReady, distributed }: { events: number; score: number; confidence: number; baselineReady: boolean; distributed: boolean; }) {
  const color = score > 70 ? 'text-critical' : score >= 40 ? 'text-medium' : 'text-low';
  return (
    <Card className="grid grid-cols-2 gap-3 p-3 lg:grid-cols-5">
      <div><div className="text-xs text-textSecondary">Events Processed</div><div className="mono text-lg">{events}</div></div>
      <div><div className="text-xs text-textSecondary">Candidate Severity</div><div className={`mono text-lg ${color}`}>{score}</div></div>
      <div><div className="text-xs text-textSecondary">Risk Confidence</div><div className="mono text-lg">{confidence.toFixed(2)}</div></div>
      <div><div className="text-xs text-textSecondary">Baseline Ready</div><div className="text-sm">{baselineReady ? 'yes' : 'no'}</div></div>
      <div><div className="text-xs text-textSecondary">Distributed Attack</div><span className={`rounded px-2 py-1 text-xs ${distributed ? 'bg-critical/20 text-critical' : 'bg-low/20 text-low'}`}>{distributed ? 'active' : 'inactive'}</span></div>
    </Card>
  );
}
