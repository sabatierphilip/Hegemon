'use client';

const META_NODES = [
  { kind: 'self_destruct_on_findings', params: { threshold: 5, label: 'Destruct if findings > N' } },
  { kind: 'self_destruct_on_anomaly', params: { threshold: 0.8, label: 'Destruct if anomaly > 0.8' } },
  { kind: 'self_destruct_on_hmac_fail', params: { max_failures: 3, label: 'Destruct on HMAC fail' } },
  { kind: 'self_destruct_on_duplicate', params: { label: 'Destruct if self already running' } },
  { kind: 'self_destruct_on_kill_signal', params: { label: 'Destruct on kill signal' } },
  { kind: 'tighten_checkin', params: { threshold: 3, min_seconds: 10, label: 'Tighten checkin on findings' } },
  { kind: 'widen_checkin', params: { idle_cycles: 5, max_seconds: 300, label: 'Widen checkin when idle' } },
  { kind: 'update_payload_from_deadrop', params: { label: 'Update payload from deadrop' } },
  { kind: 'spawn_replacement', params: { label: 'Spawn replacement before destruct' } },
  { kind: 'escalate_autonomy', params: { threshold: 0.8, label: 'Escalate autonomy on anomaly' } },
  { kind: 'health_report', params: { every_n: 5, label: 'Health report every N checkins' } },
  { kind: 'instance_guard', params: { max: 1, label: 'Max N instances' } },
] as const;

export function MetaBehaviourPane() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1 text-xs text-medium">
        <span>↔</span> Meta nodes attach bidirectionally to any brain or payload node. Drag onto canvas, connect with double arrows.
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Self-Destruct Conditions</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => n.kind.startsWith('self_destruct')).map((n) => (
            <MetaDraggable key={n.kind} node={n} />
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Self-Referential Actions</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => !n.kind.startsWith('self_destruct') && n.kind !== 'instance_guard').map((n) => (
            <MetaDraggable key={n.kind} node={n} />
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1 text-xs text-textSecondary">Instance Management</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.filter((n) => n.kind === 'instance_guard').map((n) => (
            <MetaDraggable key={n.kind} node={n} />
          ))}
        </div>
      </div>
    </div>
  );
}

function MetaDraggable({ node }: { node: (typeof META_NODES)[number] }) {
  return (
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
      className="cursor-grab rounded border border-dashed border-medium/60 px-2 py-1 text-xs text-medium hover:bg-medium/10 active:cursor-grabbing"
    >
      ↔ {node.params.label}
    </div>
  );
}
