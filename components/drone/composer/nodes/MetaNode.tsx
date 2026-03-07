import { Handle, Position, NodeProps } from 'reactflow';

export function MetaNode({ data, selected }: NodeProps) {
  return (
    <div
      className={`min-w-[130px] rounded bg-card px-3 py-2 text-xs ${selected ? 'border-medium' : 'border-medium/40'}`}
      style={{ border: '1.5px dashed #eab308' }}
    >
      <Handle type="target" position={Position.Left} className="!bg-medium" />
      <div className="font-mono text-medium">{data.kind}</div>
      <div className="mt-1 text-textSecondary">{data.params?.label ?? ''}</div>
      <Handle type="source" position={Position.Right} className="!bg-medium" />
    </div>
  );
}
