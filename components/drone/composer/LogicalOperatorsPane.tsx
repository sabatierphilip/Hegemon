'use client';

import { Info } from 'lucide-react';
import { useState } from 'react';

const LOGICAL_NODES = [
  { kind: 'logical_and', label: 'AND', params: { op: 'and', conditions: 2 }, info: 'All inbound conditions must evaluate true.', inputType: 'boolean[]', outputType: 'boolean' },
  { kind: 'logical_or', label: 'OR', params: { op: 'or', conditions: 2 }, info: 'Any inbound condition can evaluate true.', inputType: 'boolean[]', outputType: 'boolean' },
  { kind: 'logical_not', label: 'NOT', params: { op: 'not' }, info: 'Inverts the result of a condition.', inputType: 'boolean', outputType: 'boolean' },
  { kind: 'logical_xor', label: 'XOR', params: { op: 'xor', conditions: 2 }, info: 'True only when exactly one condition is true.', inputType: 'boolean[]', outputType: 'boolean' },
  { kind: 'expr_check', label: 'Value Check', params: { field: 'telemetry.findings', operator: '>=', value: 1 }, info: 'Compares a field against a threshold or value.', inputType: 'number|string', outputType: 'boolean' },
];

function DraggableLogicItem({ node }: { node: (typeof LOGICAL_NODES)[number] }) {
  const [showInfo, setShowInfo] = useState(false);

  return (
    <div className="rounded border border-border p-2 text-xs">
      <div className="flex items-center justify-between gap-2">
        <div
          draggable
          onDragStart={(e) => {
            e.dataTransfer.setData(
              'application/hegemon-node',
              JSON.stringify({ kind: node.kind, nodeType: 'brain', defaultParams: node.params })
            );
            e.dataTransfer.effectAllowed = 'move';
          }}
          className="cursor-grab rounded bg-border px-2 py-1 font-mono hover:bg-accent/20 active:cursor-grabbing"
        >
          {node.label}
        </div>
        <button type="button" className="rounded bg-border px-1 py-0.5" onClick={() => setShowInfo((s) => !s)} title="Info">
          <Info size={12} />
        </button>
      </div>
      {showInfo && (
        <div className="mt-2 space-y-1 text-[11px] text-textSecondary">
          <p>{node.info}</p>
          <p>Input: {node.inputType}</p>
          <p>Output: {node.outputType}</p>
        </div>
      )}
      <div className="mt-2 grid grid-cols-2 gap-1 text-[11px]">
        {Object.entries(node.params).map(([k, v]) => (
          <div key={k} className="rounded bg-bg px-1 py-0.5">
            {k}: {String(v)}
          </div>
        ))}
      </div>
    </div>
  );
}

export function LogicalOperatorsPane() {
  return (
    <div className="space-y-2">
      <div className="text-xs text-textSecondary">Use these for expression checks. All nodes accept unlimited inbound connections.</div>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
        {LOGICAL_NODES.map((node) => (
          <DraggableLogicItem key={node.kind} node={node} />
        ))}
      </div>
    </div>
  );
}
