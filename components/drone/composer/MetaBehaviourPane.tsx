'use client';

import { Info } from 'lucide-react';
import { useState } from 'react';

const META_NODES = [
  { kind: 'self_destruct_on_findings', params: { threshold: 5, wipe_memory: true, wipe_disk: true, revoke_tokens: true, label: 'Destruct if findings > N' }, inputType: 'findings_count:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_anomaly', params: { threshold: 0.8, wipe_memory: true, label: 'Destruct if anomaly > 0.8' }, inputType: 'anomaly_score:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_hmac_fail', params: { max_failures: 3, revoke_tokens: true, label: 'Destruct on HMAC fail' }, inputType: 'hmac_failures:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_duplicate', params: { kill_duplicates: true, label: 'Destruct if self already running' }, inputType: 'instance_count:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_kill_signal', params: { wipe_deadrops: true, label: 'Destruct on kill signal' }, inputType: 'signal:kill', outputType: 'action:destruct' },
  { kind: 'tighten_checkin', params: { threshold: 3, min_seconds: 10, label: 'Tighten checkin on findings' }, inputType: 'findings_count:number', outputType: 'checkin_seconds:number' },
  { kind: 'widen_checkin', params: { idle_cycles: 5, max_seconds: 300, label: 'Widen checkin when idle' }, inputType: 'idle_cycles:number', outputType: 'checkin_seconds:number' },
  { kind: 'update_payload_from_deadrop', params: { label: 'Update payload from deadrop' }, inputType: 'deadrop_payload:object', outputType: 'payload_patch:object' },
  { kind: 'spawn_replacement', params: { label: 'Spawn replacement before destruct' }, inputType: 'destruct_signal', outputType: 'replacement_id:string' },
  { kind: 'escalate_autonomy', params: { threshold: 0.8, label: 'Escalate autonomy on anomaly' }, inputType: 'anomaly_score:number', outputType: 'autonomy_level:string' },
  { kind: 'health_report', params: { every_n: 5, label: 'Health report every N checkins' }, inputType: 'checkin_counter:number', outputType: 'health_report:object' },
  { kind: 'instance_guard', params: { max: 1, label: 'Max N instances' }, inputType: 'instance_count:number', outputType: 'allow_run:boolean' },
] as const;

export function MetaBehaviourPane() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1 text-xs text-medium">
        <span>↔</span> Meta nodes are draggable, inspectable, and support unlimited incoming links.
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Self-Destruct Conditions</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => n.kind.startsWith('self_destruct')).map((n) => (
            <MetaDraggable key={n.kind} node={n} info="Hard cleanup path with memory wipe, token revoke, and deadrop purge support." />
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Self-Referential Actions</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => !n.kind.startsWith('self_destruct') && n.kind !== 'instance_guard').map((n) => (
            <MetaDraggable key={n.kind} node={n} info="Runtime adaptation control node." />
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Instance Management</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => n.kind === 'instance_guard').map((n) => (
            <MetaDraggable key={n.kind} node={n} info="Limit/coordinate active drone instances." />
          ))}
        </div>
      </div>
    </div>
  );
}

function MetaDraggable({
  node,
  info,
}: {
  node: (typeof META_NODES)[number];
  info: string;
}) {
  const [showInfo, setShowInfo] = useState(false);

  return (
    <div className="flex items-center gap-1 rounded border border-dashed border-medium/60 px-2 py-1 text-xs text-medium hover:bg-medium/10">
      <div
        draggable
        onDragStart={(e) => {
          e.dataTransfer.setData(
            'application/hegemon-node',
            JSON.stringify({
              kind: node.kind,
              nodeType: 'meta',
              defaultParams: node.params,
            })
          );
        }}
        className="cursor-grab active:cursor-grabbing"
      >
        ↔ {node.params.label}
      </div>
      <button type="button" onClick={() => setShowInfo((s) => !s)} className="rounded bg-medium/10 px-1 py-0.5" title="Info">
        <Info size={12} />
      </button>
      {showInfo && (
        <div className="max-w-56 text-[10px] text-textSecondary">
          <div>{info}</div>
          <div>Input: {node.inputType}</div>
          <div>Output: {node.outputType}</div>
        </div>
      )}
    </div>
  );
}
