'use client';

import { Handle, Position, NodeProps } from 'reactflow';
import { Package } from 'lucide-react';

export function PayloadNode({ data, selected }: NodeProps) {
  return (
    <div
      className={`min-w-[120px] rounded border bg-card px-3 py-2 text-xs ${selected ? 'border-low' : 'border-low/40'}`}
      style={{ borderLeft: '3px solid #22c55e' }}
    >
      <Handle type="target" position={Position.Top} className="!bg-low" />
      <div className="flex items-center gap-1">
        <Package size={10} className="text-low" />
        <span className="font-mono text-low">{data.kind}</span>
      </div>
      <div className="mt-1 text-textSecondary">{data.params?.action ?? 'payload'}</div>
      <span className="mt-1 inline-block rounded bg-low/20 px-1 text-low">{data.params?.category ?? ''}</span>
      <Handle type="source" position={Position.Bottom} className="!bg-low" />
    </div>
  );
}
