'use client';

import { useState } from 'react';
import { Clock, Info } from 'lucide-react';

type PaletteNode = {
  kind: string;
  params: Record<string, unknown>;
  description?: string;
  label?: string;
  inputType?: string;
  outputType?: string;
  action?: string;
};

const BRAIN_NODES: Record<string, PaletteNode[]> = {
  Lifecycle: [
    { kind: 'on_launch', params: {}, description: 'Entry node for drone behavior graph.', inputType: 'none', outputType: 'control_signal' },
    { kind: 'self_terminate', params: {}, description: 'Graceful process exit when mission is complete.', inputType: 'control_signal', outputType: 'none', action: 'terminate_process' },
    { kind: 'self_destruct', params: { secure_wipe: true, wipe_deadrops: true, revoke_tokens: true }, description: 'Aggressive teardown with cleanup and credential invalidation.', inputType: 'threat_score|kill_signal', outputType: 'none', action: 'wipe_and_revoke' },
    { kind: 'on_error', params: { action: 'report' }, description: 'Fallback path invoked when runtime actions fail.', inputType: 'error_event', outputType: 'report_event' },
    { kind: 'on_ttl_expiry', params: {}, description: 'Invoked automatically when drone TTL expires.', inputType: 'ttl_timeout', outputType: 'control_signal' },
  ],
  Probe: [
    { kind: 'ping_host', params: { host: '', fallback_port: 443 }, inputType: 'host:string', outputType: 'latency_ms:number' },
    { kind: 'port_scan', params: { host: '', port_range: '1-1024' }, inputType: 'host:string', outputType: 'open_ports:number[]' },
    { kind: 'banner_grab', params: { host: '' }, inputType: 'host:string', outputType: 'service_banner:string' },
    { kind: 'subnet_scan', params: { cidr: '10.0.0.0/24' }, inputType: 'cidr:string', outputType: 'alive_hosts:string[]' },
    { kind: 'http_probe', params: { url: '', method: 'GET', expect_status: 200 }, inputType: 'url:string', outputType: 'http_status:number' },
    { kind: 'tls_check', params: { host: '', port: 443 }, inputType: 'host:string', outputType: 'tls_valid:boolean' },
    { kind: 'dns_resolve', params: { hostname: '', record_type: 'A' }, inputType: 'hostname:string', outputType: 'records:string[]' },
    { kind: 'icmp_sweep', params: { cidr: '' }, inputType: 'cidr:string', outputType: 'responders:string[]' },
    { kind: 'lateral_move', params: { host: '', port: 445, method: 'smb_pivot' }, description: 'TCP probe lateral movement to target host. Records reachable hosts.', inputType: 'host:string', outputType: 'moved:boolean' },
    { kind: 'credential_probe', params: { host: 'local', scope: 'env' }, description: 'Sweeps env vars and credential files for secrets.', inputType: 'scope:string', outputType: 'findings:object[]' },
  ],
  Detect: [
    { kind: 'deploy_honeypot', params: { port: 2222, service: 'ssh' }, inputType: 'port:number', outputType: 'trap_events:object[]' },
    { kind: 'peer_sync', params: {}, inputType: 'none', outputType: 'peer_state:object' },
    { kind: 'ingest_telemetry', params: {}, inputType: 'telemetry_stream', outputType: 'normalized_event:object' },
    { kind: 'local_intel_match', params: {}, inputType: 'ioc_set:object', outputType: 'match_result:boolean' },
    { kind: 'file_integrity_check', params: { path: '', hash_algo: 'sha256' }, inputType: 'path:string', outputType: 'integrity_ok:boolean' },
    { kind: 'process_watch', params: { name_pattern: '' }, inputType: 'process_list:object[]', outputType: 'process_match:object[]' },
    { kind: 'network_baseline_diff', params: { interface: 'eth0' }, inputType: 'netflow:object[]', outputType: 'delta:object' },
    { kind: 'log_tail', params: { path: '/var/log/syslog', lines: 100 }, inputType: 'log_path:string', outputType: 'log_lines:string[]' },
    { kind: 'registry_watch', params: { hive: 'HKLM', key: '' }, inputType: 'registry_key:string', outputType: 'registry_delta:object' },
    { kind: 'env_snapshot', params: {}, inputType: 'none', outputType: 'env_map:Record<string,string>' },
  ],
  Respond: [
    { kind: 'isolate_source_ip', params: { method: 'iptables' }, inputType: 'ip:string', outputType: 'isolation_result:boolean' },
    { kind: 'send_report', params: { severity: 'info' }, inputType: 'finding:object', outputType: 'report_id:string' },
    { kind: 'write_deadrop', params: {}, inputType: 'payload:object', outputType: 'deadrop_path:string' },
    { kind: 'spawn_child_drone', params: { max_children: 3 }, inputType: 'spawn_policy:object', outputType: 'child_drone_id:string' },
    { kind: 'kill_process', params: { name: '' }, inputType: 'process_name:string', outputType: 'kill_success:boolean' },
    { kind: 'block_ip', params: { ip: '', direction: 'both' }, inputType: 'ip:string', outputType: 'firewall_rule_id:string' },
    { kind: 'quarantine_file', params: { path: '', dest: '/tmp/quarantine' }, inputType: 'path:string', outputType: 'quarantine_path:string' },
    { kind: 'rotate_credentials', params: { service: '' }, inputType: 'service:string', outputType: 'rotation_status:boolean' },
    { kind: 'emit_alert', params: { level: 'critical', message: '' }, inputType: 'finding:object', outputType: 'alert_id:string' },
    { kind: 'exec_remediation', params: { script: '', timeout: 30 }, inputType: 'script:string', outputType: 'exit_code:number' },
    { kind: 'confront_intruder', params: { strategy: 'bidirectional_block' }, description: 'Engages active countermeasure against detected intrusion.', inputType: 'target:string', outputType: 'action_result:boolean' },
  ],
  Control: [
    { kind: 'wait', params: { seconds: 60 }, inputType: 'control_signal', outputType: 'control_signal' },
    { kind: 'adaptive_wait', params: { base_seconds: 60 }, inputType: 'feedback_score:number', outputType: 'delay_seconds:number' },
    { kind: 'repeat', params: { max_iterations: 10, target_node_id: '' }, inputType: 'control_signal', outputType: 'loop_signal' },
    { kind: 'conditional_retask', params: { condition_key: 'findings_count', threshold: 1 }, inputType: 'metric:number', outputType: 'retask:boolean' },
    { kind: 'loop_until', params: { condition_key: 'findings_count', operator: '<', threshold: 1 }, inputType: 'metric:number', outputType: 'loop_continue:boolean' },
    { kind: 'parallel', params: {}, inputType: 'control_signal', outputType: 'fanout_signal[]' },
    { kind: 'if_severity', params: { operator: '>=', value: 1 }, inputType: 'severity:number', outputType: 'branch:boolean' },
    { kind: 'if_ttl_expired', params: {}, inputType: 'ttl_seconds:number', outputType: 'expired:boolean' },
    { kind: 'checkpoint', params: { label: '' }, inputType: 'state_snapshot:object', outputType: 'checkpoint_id:string' },
    { kind: 'rate_limit', params: { max_per_minute: 10 }, inputType: 'event_rate:number', outputType: 'throttle:boolean' },
  ],
};

const RING2_NODES: PaletteNode[] = [
  { kind: 'manage_service', params: { service_name: '', action: 'status' }, description: 'Start/stop/create/delete system service.', inputType: 'service_name:string', outputType: 'result:boolean' },
  { kind: 'manage_systemd_unit', params: { unit: '', action: 'status' }, description: 'Manage systemd units (Linux).', inputType: 'unit:string', outputType: 'active:boolean' },
  { kind: 'ptrace_inspect', params: { pid: 0 }, description: 'Attach ptrace to process, dump memory maps.', inputType: 'pid:number', outputType: 'maps:string' },
  { kind: 'inotify_watch', params: { path: '/etc', flags: 'CLOSE_WRITE' }, description: 'Kernel-level file watch via inotify.', inputType: 'path:string', outputType: 'events:object[]' },
  { kind: 'read_proc_mem', params: { pid: 0 }, description: 'Read /proc/{pid}/mem directly.', inputType: 'pid:number', outputType: 'data:bytes' },
  { kind: 'inspect_namespaces', params: {}, description: 'Enumerate process namespace memberships.', inputType: 'none', outputType: 'namespaces:object[]' },
  { kind: 'snapshot_vss', params: { volume: 'C:\\' }, description: 'VSS snapshot for forensic capture (Windows).', inputType: 'volume:string', outputType: 'snapshot_path:string' },
  { kind: 'load_driver', params: { driver_path: '', driver_name: '' }, description: 'Load kernel driver via insmod/sc.', inputType: 'driver_path:string', outputType: 'loaded:boolean' },
];

const TIMER_NODES: PaletteNode[] = [
  { kind: 'wait', params: { seconds: 30 }, label: 'Wait 30s', description: 'Fixed wait interval.', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 60 }, label: 'Wait 60s', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 300 }, label: 'Wait 5m', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 600 }, label: 'Wait 10m', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'adaptive_wait', params: { base_seconds: 60, adaptive: true }, label: 'Adaptive Wait', inputType: 'feedback_score:number', outputType: 'dynamic_delay:number' },
  { kind: 'checkin_interval', params: { use_checkin: true }, label: 'Checkin Interval', inputType: 'checkin_seconds:number', outputType: 'delay_seconds:number' },
];

const META_NODES: PaletteNode[] = [
  { kind: 'self_destruct_on_findings', params: { threshold: 5, label: 'Destruct if findings > N' }, inputType: 'findings_count:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_anomaly', params: { threshold: 0.8, label: 'Destruct if anomaly > 0.8' }, inputType: 'anomaly_score:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_hmac_fail', params: { max_failures: 3, label: 'Destruct on HMAC fail' }, inputType: 'hmac_failures:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_duplicate', params: { label: 'Destruct if self already running' }, inputType: 'instance_count:number', outputType: 'action:destruct' },
  { kind: 'self_destruct_on_kill_signal', params: { label: 'Destruct on kill signal' }, inputType: 'signal:kill', outputType: 'action:destruct' },
  { kind: 'tighten_checkin', params: { threshold: 3, min_seconds: 10, label: 'Tighten checkin on findings' }, inputType: 'findings_count:number', outputType: 'checkin_seconds:number' },
  { kind: 'widen_checkin', params: { idle_cycles: 5, max_seconds: 300, label: 'Widen checkin when idle' }, inputType: 'idle_cycles:number', outputType: 'checkin_seconds:number' },
  { kind: 'update_payload_from_deadrop', params: { label: 'Update payload from deadrop' }, inputType: 'deadrop_payload:object', outputType: 'payload_patch:object' },
  { kind: 'spawn_replacement', params: { label: 'Spawn replacement before destruct' }, inputType: 'destruct_signal', outputType: 'replacement_id:string' },
  { kind: 'escalate_autonomy', params: { threshold: 0.8, label: 'Escalate autonomy on anomaly' }, inputType: 'anomaly_score:number', outputType: 'autonomy_level:string' },
  { kind: 'health_report', params: { every_n: 5, label: 'Health report every N checkins' }, inputType: 'checkin_counter:number', outputType: 'health_report:object' },
  { kind: 'instance_guard', params: { max: 1, label: 'Max N instances' }, inputType: 'instance_count:number', outputType: 'allow_run:boolean' },
];

function DraggableNode({
  kind,
  defaultParams,
  nodeType,
  className,
  label,
  description,
  inputType,
  outputType,
  action,
}: {
  kind: string;
  defaultParams: Record<string, unknown>;
  nodeType: 'brain' | 'timer' | 'meta' | 'payload';
  className: string;
  label?: string;
  description?: string;
  inputType?: string;
  outputType?: string;
  action?: string;
}) {
  const [showInfo, setShowInfo] = useState(false);

  return (
    <div className={`relative rounded ${className}`}>
      <div className="flex items-center gap-1">
        <div
          draggable
          onDragStart={(e) => {
            e.dataTransfer.setData('application/hegemon-node', JSON.stringify({ kind, nodeType, defaultParams }));
            e.dataTransfer.effectAllowed = 'move';
          }}
          className="cursor-grab px-2 py-1 font-mono text-xs active:cursor-grabbing"
        >
          {label ?? kind}
        </div>
        <button type="button" onClick={() => setShowInfo((s) => !s)} className="rounded bg-border px-1 py-0.5 text-[10px]" title="Info">
          <Info size={12} />
        </button>
      </div>
      {showInfo && (
        <div className="absolute left-0 top-6 z-50 w-56 rounded border border-border bg-card p-2 shadow-lg space-y-0.5 text-[10px] text-textSecondary">
          <div>{description ?? `${kind} node used in graph orchestration and can accept multiple incoming links.`}</div>
          <div>In: <span className="text-text">{inputType ?? 'n/a'}</span></div>
          <div>Out: <span className="text-text">{outputType ?? 'n/a'}</span></div>
          {action && <div>Action: <span className="text-text">{action}</span></div>}
        </div>
      )}
    </div>
  );
}

export function ActionPalette({ executionRing = 3 }: { executionRing?: 1 | 2 | 3 }) {
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
                  <DraggableNode key={node.kind} kind={node.kind} defaultParams={node.params} nodeType="brain" description={node.description} inputType={node.inputType} outputType={node.outputType} action={node.action} className="bg-border hover:bg-accent/20" />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {executionRing <= 2 && (
        <div>
          <div className="mb-1 flex items-center gap-2 font-medium text-amber-300">Ring 2 Nodes <span className="rounded border border-amber-500/50 px-1 py-0.5 text-[10px] text-amber-200">Requires elevated privileges</span></div>
          <div className="flex flex-wrap gap-1">
            {RING2_NODES.map((node) => (
              <DraggableNode key={node.kind} kind={node.kind} defaultParams={node.params} nodeType="brain" description={node.description} inputType={node.inputType} outputType={node.outputType} className="border border-amber-500/40 bg-amber-500/10 text-amber-200 hover:bg-amber-500/20" />
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="mb-1 flex items-center gap-1 font-medium text-text">
          <Clock size={12} /> Timer Nodes
        </div>
        <div className="flex flex-wrap gap-1">
          {TIMER_NODES.map((node) => (
            <DraggableNode key={`${node.kind}-${node.label ?? node.kind}`} kind={node.kind} defaultParams={node.params} nodeType="timer" label={node.label} description={node.description} inputType={node.inputType} outputType={node.outputType} action={node.action} className="bg-info/10 text-info hover:bg-info/20" />
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 font-medium text-medium">Meta Nodes (Bidirectional)</div>
        <div className="flex flex-wrap gap-1">
          {META_NODES.map((node) => (
            <DraggableNode key={node.kind} kind={node.kind} defaultParams={node.params} nodeType="meta" label={String(node.params.label ?? node.kind)} inputType={node.inputType} outputType={node.outputType} action={node.action} className="border border-dashed border-medium/60 text-medium hover:bg-medium/10" />
          ))}
        </div>
      </div>
    </div>
  );
}
