'use client';

import { useState } from 'react';

export function DirectiveSimulator({ onSimulate, simulation }: { onSimulate: (directive: string) => Promise<void>; simulation: any }) {
  const [directive, setDirective] = useState('Shift to aggressive encirclement and enforce mode');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!directive.trim()) return;
    setLoading(true);
    try {
      await onSimulate(directive);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded border border-border bg-card p-3 space-y-2">
      <div className="text-xs font-medium text-text">Directive Simulator</div>
      <div className="text-[10px] text-textSecondary">Run a what-if projection before issuing a live order.</div>
      <textarea
        rows={2}
        value={directive}
        onChange={(e) => setDirective(e.target.value)}
        className="w-full rounded border border-border bg-bg px-2 py-1.5 text-xs text-text placeholder:text-textSecondary focus:border-accent focus:outline-none"
      />
      <button onClick={run} disabled={loading} className="rounded bg-accent px-3 py-1 text-xs text-white disabled:opacity-50">
        {loading ? 'Simulating…' : 'Simulate Directive'}
      </button>

      {simulation && (
        <div className="rounded border border-border bg-bg p-2 text-[10px] text-textSecondary space-y-1">
          <div className="text-text font-semibold">Outcome: {simulation.predicted_outcome}</div>
          <div>Exposure Δ: {(Number(simulation.exposure_delta ?? 0) * 100).toFixed(0)}%</div>
          <div>Host gain: {simulation.host_gain ?? 0}</div>
          <div>Credential gain: {simulation.credential_gain ?? 0}</div>
          {(simulation.notes ?? []).map((note: string, i: number) => (
            <div key={i}>• {note}</div>
          ))}
        </div>
      )}
    </div>
  );
}
