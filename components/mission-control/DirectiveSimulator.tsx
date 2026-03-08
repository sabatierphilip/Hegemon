'use client';

import { useState } from 'react';

type SimulationNode = {
  id: string;
  title: string;
  status: string;
  progress: number;
  info: string;
};

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

  const nodes: SimulationNode[] = simulation?.task_graph?.nodes ?? [];

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
        <div className="rounded border border-border bg-bg p-2 text-[10px] text-textSecondary space-y-2">
          <div className="text-text font-semibold">Outcome: {simulation.predicted_outcome}</div>
          <div>Exposure Δ: {(Number(simulation.exposure_delta ?? 0) * 100).toFixed(0)}%</div>
          <div>Host gain: {simulation.host_gain ?? 0}</div>
          <div>Credential gain: {simulation.credential_gain ?? 0}</div>
          <div>Pivot gain: {simulation.pivot_gain ?? 0}</div>
          <div>Detection Δ: {simulation.detection_delta ?? 0}</div>
          <div>Projected phase: {simulation.projected_phase ?? 'unknown'}</div>
          <div>Confidence: {Math.round(Number(simulation.confidence ?? 0) * 100)}%</div>

          <div className="rounded border border-border p-2 space-y-1">
            <div className="text-text font-semibold">Task Decomposition Graph</div>
            {(nodes ?? []).map((node) => (
              <div key={node.id} className="rounded border border-border bg-card p-1">
                <div className="flex items-center gap-2">
                  <span className="text-text">{node.title}</span>
                  <span className="uppercase text-[9px]">{node.status}</span>
                  <span className="ml-auto">{node.progress}%</span>
                  <details>
                    <summary className="cursor-pointer text-accent">i</summary>
                    <div className="mt-1 text-[9px] text-textSecondary">{node.info}</div>
                  </details>
                </div>
              </div>
            ))}
          </div>

          {simulation.binary_codegen?.enabled && (
            <div className="rounded border border-border p-2 space-y-1">
              <div className="text-text font-semibold">Binary Codegen</div>
              <div>
                Tool calls: {simulation.binary_codegen.tool_calls_used}/{simulation.binary_codegen.tool_calls_budget}
              </div>
              <div>Architecture: {simulation.binary_codegen.machine_code?.arch}</div>
              <div>Bytes: {simulation.binary_codegen.machine_code?.byte_length ?? 0}</div>
              <details>
                <summary className="cursor-pointer text-accent">View machine code hex</summary>
                <div className="mt-1 break-all text-[9px]">{simulation.binary_codegen.machine_code?.hex ?? ''}</div>
              </details>
            </div>
          )}

          {(simulation.notes ?? []).map((note: string, i: number) => (
            <div key={i}>• {note}</div>
          ))}
        </div>
      )}
    </div>
  );
}
