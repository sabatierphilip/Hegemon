import { Handle, Position, NodeProps } from 'reactflow';

export function BrainNode({ data, selected }: NodeProps) {
  return (
    <div
      className={`min-w-[120px] rounded border bg-card px-3 py-2 text-xs ${selected ? 'border-accent' : 'border-accent/40'}`}
      style={{ borderLeft: '3px solid #6366f1' }}
    >
      <Handle type="target" position={Position.Top} className="!bg-accent" />
      <div className="font-mono font-medium text-text">{data.kind}</div>
      {data.params && Object.keys(data.params).length > 0 && (
        <div className="mt-1 text-textSecondary">
          {Object.entries(data.params)
            .slice(0, 2)
            .map(([k, v]) => (
              <div key={k}>
                {k}: <span className="text-text">{String(v).slice(0, 20)}</span>
              </div>
            ))}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-accent" />
    </div>
  );
}
