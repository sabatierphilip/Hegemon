'use client';

import { Clock } from 'lucide-react';

const BRAIN_NODES = {
  Lifecycle: [
    { kind: 'on_launch', params: {} },
    { kind: 'self_terminate', params: {} },
    { kind: 'self_destruct', params: { secure_wipe: true } },
    { kind: 'on_error', params: { action: 'report' } },
    { kind: 'on_ttl_expiry', params: {} },
  ],
  Probe: [
    { kind: 'ping_host', params: { host: '', fallback_port: 443 } },
    { kind: 'port_scan', params: { host: '', port_range: '1-1024' } },
    { kind: 'banner_grab', params: { host: '' } },
    { kind: 'subnet_scan', params: { cidr: '10.0.0.0/24' } },
    { kind: 'http_probe', params: { url: '', method: 'GET', expect_status: 200 } },
    { kind: 'tls_check', params: { host: '', port: 443 } },
    { kind: 'dns_resolve', params: { hostname: '', record_type: 'A' } },
    { kind: 'icmp_sweep', params: { cidr: '' } },
  ],
  Detect: [
    { kind: 'deploy_honeypot', params: { port: 2222, service: 'ssh' } },
    { kind: 'peer_sync', params: {} },
    { kind: 'ingest_telemetry', params: {} },
    { kind: 'local_intel_match', params: {} },
    { kind: 'file_integrity_check', params: { path: '', hash_algo: 'sha256' } },
    { kind: 'process_watch', params: { name_pattern: '' } },
    { kind: 'network_baseline_diff', params: { interface: 'eth0' } },
    { kind: 'log_tail', params: { path: '/var/log/syslog', lines: 100 } },
    { kind: 'registry_watch', params: { hive: 'HKLM', key: '' } },
    { kind: 'env_snapshot', params: {} },
  ],
  Respond: [
    { kind: 'isolate_source_ip', params: { method: 'iptables' } },
    { kind: 'send_report', params: { severity: 'info' } },
    { kind: 'write_deadrop', params: {} },
    { kind: 'spawn_child_drone', params: { max_children: 3 } },
    { kind: 'kill_process', params: { name: '' } },
    { kind: 'block_ip', params: { ip: '', direction: 'both' } },
    { kind: 'quarantine_file', params: { path: '', dest: '/tmp/quarantine' } },
    { kind: 'rotate_credentials', params: { service: '' } },
    { kind: 'emit_alert', params: { level: 'critical', message: '' } },
    { kind: 'exec_remediation', params: { script: '', timeout: 30 } },
  ],
  Control: [
    { kind: 'wait', params: { seconds: 60 } },
    { kind: 'adaptive_wait', params: { base_seconds: 60 } },
    { kind: 'repeat', params: { max_iterations: 10, target_node_id: '' } },
    { kind: 'conditional_retask', params: { condition_key: 'findings_count', threshold: 1 } },
    { kind: 'loop_until', params: { condition_key: 'findings_count', operator: '<', threshold: 1 } },
    { kind: 'parallel', params: {} },
    { kind: 'if_severity', params: { operator: '>=', value: 1 } },
    { kind: 'if_ttl_expired', params: {} },
    { kind: 'checkpoint', params: { label: '' } },
    { kind: 'rate_limit', params: { max_per_minute: 10 } },
  ],
};

const TIMER_NODES = [
  { kind: 'wait', params: { seconds: 30 }, label: 'Wait 30s' },
  { kind: 'wait', params: { seconds: 60 }, label: 'Wait 60s' },
  { kind: 'wait', params: { seconds: 300 }, label: 'Wait 5m' },
  { kind: 'wait', params: { seconds: 600 }, label: 'Wait 10m' },
  { kind: 'adaptive_wait', params: { base_seconds: 60, adaptive: true }, label: 'Adaptive Wait' },
  { kind: 'checkin_interval', params: { use_checkin: true }, label: 'Checkin Interval' },
];

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
];

function DraggableNode({ kind, defaultParams, nodeType, className, label }: { kind: string; defaultParams: Record<string, unknown>; nodeType: 'brain' | 'timer' | 'meta'; className: string; label?: string }) {
  return (
    <div
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(
          'application/hegemon-node',
          JSON.stringify({ kind, nodeType, defaultParams })
        );
        e.dataTransfer.effectAllowed = 'move';
      }}
      className={className}
    >
      {label ?? kind}
    </div>
  );
}

export function ActionPalette() {
  return (
    <div className="space-y-3 text-xs">
      <div>
        <div className="mb-1 font-medium text-text">Brain Nodes</div>
        <div className="space-y-2">
          {Object.entries(BRAIN_NODES).map(([group, nodes]) => (
            <div key={group}>
              <div className="mb-1 text-textSecondary">{group}</div>
              <div className="flex flex-wrap gap-1">
                {nodes.map((node) => (
                  <DraggableNode
                    key={node.kind}
                    kind={node.kind}
                    defaultParams={node.params}
                    nodeType="brain"
                    className="cursor-grab rounded bg-border px-2 py-1 font-mono text-xs hover:bg-accent/20 active:cursor-grabbing"
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center gap-1 text-info"><Clock size={10} /> Timer Nodes</div>
        <div className="flex flex-wrap gap-1">
          {TIMER_NODES.map((node) => (
            <DraggableNode
              key={node.label}
              kind={node.kind}
              defaultParams={node.params}
              nodeType="timer"
              label={node.label}
              className="cursor-grab rounded border border-info/40 px-2 py-1 font-mono text-xs text-info hover:bg-info/10 active:cursor-grabbing"
            />
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center gap-1 text-medium"><span>↔</span> Meta Nodes</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.map((node) => (
            <DraggableNode
              key={node.kind}
              kind={node.kind}
              defaultParams={node.params}
              nodeType="meta"
              label={`↔ ${node.params.label}`}
              className="cursor-grab rounded border border-dashed border-medium/60 px-2 py-1 font-mono text-xs text-medium hover:bg-medium/10 active:cursor-grabbing"
            />
          ))}
        </div>
      </div>
    </div>
  );
}
