import { Edge, Node } from 'reactflow';

export interface ComposerState {
  droneName: string;
  tier: 'controlled' | 'tethered' | 'autonomous';
  autonomy: 'observe' | 'contain' | 'enforce';
  executionRing: 1 | 2 | 3;
  endpointId?: string;
  host?: string;
  cidr?: string;
  targetDroneId?: string;
  ttlSeconds?: number;
  unlimitedTTL?: boolean;
  checkinSeconds: number;
  nodes: Node[];
  edges: Edge[];
  childGraph?: { nodes: Node[]; edges: Edge[] };
  payload: Record<string, unknown>;
  meta: {
    selfDestruct: Record<string, unknown>;
    selfReferential: Record<string, unknown>;
    instanceManagement: Record<string, unknown>;
  };
}
