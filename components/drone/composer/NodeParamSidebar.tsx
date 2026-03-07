'use client';

import { Node } from 'reactflow';

type FieldType = 'text' | 'number' | 'boolean' | 'select';

type ParamField = {
  key: string;
  label: string;
  type: FieldType;
  placeholder?: string;
  min?: number;
  max?: number;
  step?: number;
  options?: string[];
};

const PARAM_SCHEMAS: Record<string, ParamField[]> = {
  ping_host: [
    { key: 'host', label: 'Host', type: 'text', placeholder: '10.0.0.1' },
    { key: 'message', label: 'Message', type: 'text', placeholder: 'optional payload' },
    { key: 'fallback_port', label: 'Fallback Port', type: 'number', min: 1, max: 65535 },
  ],
  port_scan: [
    { key: 'host', label: 'Host', type: 'text' },
    { key: 'port_range', label: 'Port Range', type: 'text', placeholder: '1-1024' },
  ],
  wait: [{ key: 'seconds', label: 'Seconds', type: 'number', min: 1, max: 86400 }],
  adaptive_wait: [
    { key: 'base_seconds', label: 'Base Seconds', type: 'number' },
    { key: 'adaptive', label: 'Adaptive Mode', type: 'boolean' },
  ],
  repeat: [
    { key: 'max_iterations', label: 'Max Iterations', type: 'number', min: 1 },
    { key: 'target_node_id', label: 'Target Node ID', type: 'text' },
  ],
  conditional_retask: [
    {
      key: 'condition_key',
      label: 'Condition',
      type: 'select',
      options: ['findings_count', 'anomaly_score', 'hosts_pinged', 'ports_scanned'],
    },
    { key: 'threshold', label: 'Threshold', type: 'number' },
    { key: 'target_node_id', label: 'Target Node ID', type: 'text' },
  ],
  deploy_honeypot: [
    { key: 'port', label: 'Port', type: 'number', min: 1, max: 65535 },
    { key: 'service', label: 'Service', type: 'select', options: ['ssh', 'http', 'ftp', 'smtp', 'rdp'] },
  ],
  send_report: [
    { key: 'severity', label: 'Severity', type: 'select', options: ['info', 'low', 'medium', 'high', 'critical'] },
    { key: 'include_findings', label: 'Include Findings', type: 'boolean' },
  ],
  subnet_scan: [{ key: 'cidr', label: 'CIDR', type: 'text', placeholder: '10.0.0.0/24' }],
  http_probe: [
    { key: 'url', label: 'URL', type: 'text' },
    { key: 'method', label: 'Method', type: 'select', options: ['GET', 'POST', 'HEAD'] },
    { key: 'expect_status', label: 'Expected Status', type: 'number' },
  ],
  spawn_child_drone: [{ key: 'max_children', label: 'Max Children', type: 'number', min: 1, max: 10 }],
  lateral_move: [
    { key: 'host', label: 'Target Host', type: 'text', placeholder: '10.0.0.1' },
    { key: 'port', label: 'Port', type: 'number', min: 1, max: 65535 },
    { key: 'method', label: 'Method', type: 'select', options: ['tcp_probe', 'smb_pivot', 'rdp_trace', 'ssh_hop', 'winrm'] },
  ],
  pivot_host: [
    { key: 'target_host', label: 'Pivot Target Host', type: 'text', placeholder: '10.0.10.24' },
    { key: 'port', label: 'Seed Port', type: 'number', min: 1, max: 65535 },
    { key: 'method', label: 'Pivot Method', type: 'select', options: ['winrm', 'ssh_hop', 'rdp_trace', 'smb_pivot', 'tcp_probe'] },
  ],
  credential_probe: [
    { key: 'host', label: 'Host Context', type: 'text', placeholder: 'local' },
    { key: 'scope', label: 'Scope', type: 'select', options: ['env', 'files', 'both'] },
  ],
  confront_intruder: [
    { key: 'ip', label: 'Target IP', type: 'text' },
    { key: 'strategy', label: 'Strategy', type: 'select', options: ['bidirectional_block', 'counter-lateral-quarantine', 'active-containment', 'sinkhole'] },
  ],
  countermeasure: [
    { key: 'target', label: 'Intruder Target', type: 'text', placeholder: '10.0.0.66' },
    { key: 'strategy', label: 'Countermeasure Strategy', type: 'select', options: ['counter-lateral-quarantine', 'active-containment', 'sinkhole', 'bidirectional_block'] },
  ],
  manage_service: [
    { key: 'service_name', label: 'Service Name', type: 'text' },
    { key: 'action', label: 'Action', type: 'select', options: ['start', 'stop', 'restart', 'status', 'create', 'delete'] },
  ],
  manage_systemd_unit: [
    { key: 'unit', label: 'Unit', type: 'text', placeholder: 'nginx.service' },
    { key: 'action', label: 'Action', type: 'select', options: ['start', 'stop', 'restart', 'enable', 'disable', 'status'] },
  ],
  ptrace_inspect: [{ key: 'pid', label: 'PID', type: 'number', min: 1 }],
  inotify_watch: [
    { key: 'path', label: 'Watch Path', type: 'text', placeholder: '/etc' },
    { key: 'flags', label: 'Flags', type: 'select', options: ['CLOSE_WRITE', 'ATTRIB', 'CREATE', 'DELETE', 'MODIFY', 'ALL'] },
  ],
  snapshot_vss: [{ key: 'volume', label: 'Volume', type: 'text', placeholder: 'C:\\' }],
  load_driver: [
    { key: 'driver_path', label: 'Driver Path', type: 'text' },
    { key: 'driver_name', label: 'Driver Name', type: 'text' },
  ],
  self_destruct: [
    { key: 'secure_wipe', label: 'Secure Wipe', type: 'boolean' },
    { key: 'wipe_memory', label: 'Wipe Memory', type: 'boolean' },
    { key: 'wipe_deadrops', label: 'Purge Deadrops', type: 'boolean' },
    { key: 'revoke_tokens', label: 'Revoke Tokens', type: 'boolean' },
    { key: 'seconds', label: 'Delay Before Destruct (s)', type: 'number', min: 1 },
  ],
  logical_and: [{ key: 'conditions', label: 'Condition Count', type: 'number', min: 2 }],
  logical_or: [{ key: 'conditions', label: 'Condition Count', type: 'number', min: 2 }],
  logical_xor: [{ key: 'conditions', label: 'Condition Count', type: 'number', min: 2 }],
  logical_not: [{ key: 'op', label: 'Operator', type: 'select', options: ['not'] }],
  expr_check: [
    { key: 'field', label: 'Field Path', type: 'text', placeholder: 'telemetry.findings' },
    { key: 'operator', label: 'Operator', type: 'select', options: ['==', '!=', '>=', '<=', '>', '<'] },
    { key: 'value', label: 'Expected Value', type: 'text' },
  ],
  self_destruct_on_findings: [{ key: 'threshold', label: 'Findings Threshold', type: 'number', min: 1 }],
  tighten_checkin: [
    { key: 'threshold', label: 'Trigger at findings >', type: 'number', min: 1 },
    { key: 'min_seconds', label: 'Min Interval (s)', type: 'number', min: 5 },
  ],
  widen_checkin: [
    { key: 'idle_cycles', label: 'Idle Cycles Before Widen', type: 'number', min: 1 },
    { key: 'max_seconds', label: 'Max Interval (s)', type: 'number', max: 300 },
  ],
  escalate_autonomy: [{ key: 'threshold', label: 'Anomaly Threshold', type: 'number', min: 0, max: 1, step: 0.05 }],
  health_report: [{ key: 'every_n', label: 'Every N Checkins', type: 'number', min: 1 }],
  instance_guard: [{ key: 'max', label: 'Max Instances', type: 'number', min: 1, max: 10 }],
  checkin_interval: [{ key: 'use_checkin', label: 'Use Drone Checkin Interval', type: 'boolean' }],
};

export function NodeParamSidebar({
  selectedNodeId,
  nodes,
  onUpdateNode,
  onDeleteNode,
}: {
  selectedNodeId: string | null;
  nodes: Node[];
  onUpdateNode: (id: string, params: Record<string, unknown>) => void;
  onDeleteNode: (id: string) => void;
}) {
  const node = nodes.find((n) => n.id === selectedNodeId);

  if (!node) {
    return (
      <div className="rounded border border-border p-2 text-xs">
        <h4 className="mb-2 text-sm">Node Params</h4>
        <div className="text-textSecondary">Select node to edit parameters.</div>
      </div>
    );
  }

  const params = (node.data?.params ?? {}) as Record<string, unknown>;
  const fields = PARAM_SCHEMAS[node.data?.kind as string] ?? [];

  const onFieldChange = (field: ParamField, value: string | number | boolean) => {
    onUpdateNode(node.id, { ...params, [field.key]: value });
  };

  return (
    <div className="space-y-2 rounded border border-border p-2 text-xs">
      <h4 className="text-sm">Node Params</h4>
      <div className="font-mono text-textSecondary">{node.id}</div>
      <span className="inline-block rounded bg-border px-2 py-0.5 text-[11px] uppercase">{node.type}</span>

      <div className="space-y-2">
        {fields.length === 0 ? (
          <div className="text-textSecondary">No dedicated schema for this node kind.</div>
        ) : (
          fields.map((field) => {
            const value = params[field.key];

            if (field.type === 'boolean') {
              return (
                <label key={field.key} className="flex items-center justify-between gap-2">
                  <span>{field.label}</span>
                  <input
                    type="checkbox"
                    checked={Boolean(value)}
                    onChange={(e) => onFieldChange(field, e.target.checked)}
                  />
                </label>
              );
            }

            if (field.type === 'select') {
              return (
                <label key={field.key} className="block">
                  <span>{field.label}</span>
                  <select
                    className="mt-1 w-full rounded border border-border bg-bg px-2 py-1"
                    value={String(value ?? field.options?.[0] ?? '')}
                    onChange={(e) => onFieldChange(field, e.target.value)}
                  >
                    {(field.options ?? []).map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </label>
              );
            }

            return (
              <label key={field.key} className="block">
                <span>{field.label}</span>
                <input
                  className="mt-1 w-full rounded border border-border bg-bg px-2 py-1"
                  type={field.type}
                  placeholder={field.placeholder}
                  min={field.min}
                  max={field.max}
                  step={field.step}
                  value={field.type === 'number' ? Number(value ?? 0) : String(value ?? '')}
                  onChange={(e) => {
                    const next = field.type === 'number' ? Number(e.target.value) : e.target.value;
                    onFieldChange(field, next);
                  }}
                />
              </label>
            );
          })
        )}
      </div>

      <button
        type="button"
        onClick={() => onDeleteNode(node.id)}
        className="w-full rounded border border-critical/60 px-2 py-1 text-critical hover:bg-critical/10"
      >
        Delete Node
      </button>
    </div>
  );
}
