'use client';

import { Handle, Position, NodeProps } from 'reactflow';
import { Clock } from 'lucide-react';

export function TimerNode({ data, selected }: NodeProps) {
  const isAdaptive = data.params?.adaptive;
  const display = isAdaptive ? 'adaptive' : `${data.params?.seconds ?? data.params?.base_seconds ?? 60}s`;

  return (
    <div
      className={`min-w-[100px] rounded border bg-card px-3 py-2 text-xs ${selected ? 'border-info' : 'border-info/40'}`}
      style={{ borderLeft: '3px solid #3b82f6' }}
    >
      <Handle type="target" position={Position.Top} className="!bg-info" />
      <div className="flex items-center gap-1">
        <Clock size={10} className="text-info" />
        <span className="font-mono text-info">{data.kind}</span>
      </div>
      <div className="mt-1 text-text">{display}</div>
      <Handle type="source" position={Position.Bottom} className="!bg-info" />
    </div>
  );
}
