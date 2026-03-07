const groups = {
  Lifecycle: ['on_launch', 'self_terminate', 'self_destruct'],
  Probe: ['ping_host', 'port_scan', 'banner_grab', 'subnet_scan'],
  Detect: ['deploy_honeypot', 'peer_sync', 'ingest_telemetry', 'local_intel_match'],
  Respond: ['isolate_source_ip', 'send_report', 'write_deadrop', 'spawn_child_drone'],
  Control: ['wait', 'adaptive_wait', 'repeat', 'conditional_retask', 'loop_until', 'parallel']
};

export function ActionPalette() {
  return <div className="space-y-2 text-xs">{Object.entries(groups).map(([k, v]) => <div key={k}><div className="mb-1 text-textSecondary">{k}</div><div className="flex flex-wrap gap-1">{v.map(n => <span key={n} className="rounded bg-border px-2 py-1 mono">{n}</span>)}</div></div>)}</div>;
}
