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
  autonomy: 'observe' | 'contain' | 'enforce';
  status: 'active' | 'idle' | 'error' | 'offline';
  ttl_seconds: number;
  phase?: string;
  confidence?: number;
}

export interface Endpoint {
  id: string;
  hostname: string;
  ip?: string;
}
