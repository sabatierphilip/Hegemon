export interface HannibalStatus {
  state: 'dormant' | 'running' | 'paused';
  campaign_id?: string;
  phase?: string;
  alive_hosts?: number;
  active_drones?: number;
  credentials_harvested?: number;
  exposure_score?: number;
  objectives_completed?: string[];
  log_tail?: AgentLogEntry[];
  q_episode?: number;
}

export interface AgentLogEntry {
  ts: number;
  event: string;
  action?: string;
  drone_id?: string;
  drone_name?: string;
  rationale?: string;
  error?: string;
  outcome?: string;
  reward?: number;
}

export interface Campaign {
  campaign_id: string;
  agent_id: string;
  mission_objective: string;
  phase: string;
  alive_hosts: string[];
  mapped_hosts: Record<string, any>;
  credential_findings: any[];
  pivot_chains: any[];
  high_value_targets: string[];
  active_drone_ids: string[];
  terminated_drone_ids: string[];
  drone_orders: DroneOrder[];
  hosts_reached: number;
  credentials_harvested: number;
  pivot_paths_confirmed: number;
  exposure_score: number;
  objectives_completed: string[];
  started_at: number;
  last_updated: number;
}

export interface DroneOrder {
  action: string;
  drone_id: string;
  drone_name: string;
  target: string;
  ts: number;
  phase: string;
}

export interface MissionDirective {
  raw_text: string;
  intent: string;
  target_host?: string;
  target_network?: string;
  objective?: string;
  autonomy_override?: string;
  confidence: number;
  parse_notes: string[];
}
