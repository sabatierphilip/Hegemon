export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AlertItem {
  id: string;
  source: string;
  severity: Severity;
  title: string;
  host: string;
  summary: string;
}

export interface DashboardState {
  events_processed: number;
  candidate_severity: number;
  risk_confidence: number;
  baseline_ready: boolean;
  distributed_attack_active: boolean;
  persistent_horizon_activity?: boolean;
  alerts: AlertItem[];
  soar_actions: string[];
  contained_hosts: string[];
  last_containment_action?: string;
  simulation_mode?: boolean;
}

export interface Drone {
  id: string;
  name: string;
  tier: 'controlled' | 'tethered' | 'autonomous';
  autonomy_level: 'observe' | 'contain' | 'enforce';
  status: 'ready' | 'active' | 'terminated' | 'error';
  ttl_seconds: number;
  checkin_interval_seconds: number;
  launched_at: string | null;
  return_at: string | null;
  pid: number | null;
  blob_hash: string;
  blob_size_bytes: number;
  deadrop_path: string;
  findings: string[];
  stats: {
    hosts_pinged: number;
    ports_scanned: number;
    findings_count: number;
    nodes_executed: number;
  };
  live_output: string[];
  current_node_id: string | null;
  compiler_ring: 1 | 2 | 3;
  artifact_format: string;
  child_drone_ids: number[];
}

export interface Endpoint {
  id: string;
  hostname: string;
  ip?: string;
}
