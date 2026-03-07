'use client';

import { Info } from 'lucide-react';
import { useState } from 'react';

export function SamplePayloadCard({
  name,
  category,
  size,
  nodes,
  onClick,
  onConfigure,
  info,
}: {
  name: string;
  category: string;
  size: string;
  nodes: string[];
  onClick: () => void;
  onConfigure: () => void;
  info: string;
}) {
  const [showInfo, setShowInfo] = useState(false);

  return (
    <div className="w-full rounded border border-border p-2 text-left text-xs hover:bg-border">
      <div className="flex items-center justify-between gap-1">
        <b>{name}</b>
        <div className="flex items-center gap-1">
          <span className="rounded bg-border px-1">{category}</span>
          <button type="button" className="rounded bg-border px-1" onClick={() => setShowInfo((s) => !s)} title="Info">
            <Info size={12} />
          </button>
          <button type="button" className="rounded bg-low/20 px-1 text-low" onClick={onConfigure} title="Configure">
            d
          </button>
        </div>
      </div>
      <button type="button" className="mt-1 block w-full text-left text-textSecondary" onClick={onClick}>
        {size} · {nodes.join(', ')}
      </button>
      {showInfo && (
        <div className="mt-1 space-y-0.5 text-[11px] text-textSecondary">
          <div>{info}</div>
          <div>Input: telemetry/object payload</div>
          <div>Output: action execution result</div>
        </div>
      )}
    </div>
  );
}
