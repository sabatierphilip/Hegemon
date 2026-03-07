'use client';

import { useMemo, useState } from 'react';
import { Position } from 'reactflow';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ComposerState } from '@/types/composer';
import { Drone, Endpoint } from '@/types/hegemon';
import { EntityPane } from './EntityPane';
import { TimeControlPane } from './TimeControlPane';
import { BrainGraphPane } from './BrainGraphPane';
import { PayloadPane } from './PayloadPane';
import { MetaBehaviourPane } from './MetaBehaviourPane';
import { metaBehaviourDefaults } from '@/lib/metaBehaviourDefaults';
import { apiRequest } from '@/lib/api';
import { useAuth } from '@/lib/auth';

export function ComposerShell({ drones, endpoints }: { drones: Drone[]; endpoints: Endpoint[] }) {
  const { token } = useAuth();
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [previewSource, setPreviewSource] = useState('');
  const [previewOpen, setPreviewOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [state, setState] = useState<ComposerState>({
    droneName: 'new-drone',
    tier: 'controlled',
    autonomy: 'observe',
    ttlSeconds: 3600,
    checkinSeconds: 30,
    nodes: [
      {
        id: 'on_launch',
        position: { x: 100, y: 100 },
        sourcePosition: Position.Bottom,
        targetPosition: Position.Top,
        data: { label: 'on_launch', kind: 'on_launch', params: {} },
        type: 'brain',
      },
    ],
    edges: [],
    payload: { action: 'noop' },
    meta: metaBehaviourDefaults,
  });

  const buildPayload = (composer: ComposerState) => ({
    name: composer.droneName,
    tier: composer.tier,
    autonomy_level: composer.autonomy,
    ttl_seconds: composer.ttlSeconds,
    checkin_interval_seconds: composer.checkinSeconds,
    endpoint_id: composer.endpointId,
    host: composer.host,
    cidr: composer.cidr,
    target_drone_id: composer.targetDroneId,
    nodes: composer.nodes,
    edges: composer.edges,
    payload: composer.payload,
    meta: composer.meta,
  });

  const handlePreviewBuild = async () => {
    setError(null);
    setMessage(null);
    try {
      const result = await apiRequest<{ source: string }>('/api/drones/preview-build', token, {
        method: 'POST',
        body: JSON.stringify(buildPayload(state)),
      });
      setPreviewSource(result.source ?? 'No source returned.');
      setPreviewOpen(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Preview build failed');
    }
  };

  const handleSaveBrain = async () => {
    setError(null);
    setMessage(null);
    try {
      await apiRequest('/api/drones/brains', token, {
        method: 'POST',
        body: JSON.stringify({ nodes: state.nodes, edges: state.edges, name: state.droneName }),
      });
      setMessage('Brain saved.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save brain failed');
    }
  };

  const handleAssemble = async () => {
    setError(null);
    setMessage(null);
    if (!state.nodes.some((n) => n.data?.kind === 'on_launch')) {
      setError('Missing mandatory on_launch start node.');
      return;
    }

    try {
      await apiRequest('/api/drones/assemble', token, {
        method: 'POST',
        body: JSON.stringify(buildPayload(state)),
      });
      setMessage('Drone assembled.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Assemble failed');
    }
  };

  const panes = useMemo(
    () => [
      {
        id: 'entities',
        title: 'Pane 1 — Entities',
        content: <EntityPane state={state} setState={setState} endpoints={endpoints} drones={drones} />,
      },
      { id: 'time', title: 'Pane 2 — Time Control', content: <TimeControlPane state={state} setState={setState} /> },
      {
        id: 'graph',
        title: 'Pane 3 — Brain Graph',
        content: (
          <BrainGraphPane
            state={state}
            setState={setState}
            selectedNodeId={selectedNodeId}
            onSelectNode={setSelectedNodeId}
          />
        ),
      },
      { id: 'payload', title: 'Pane 4 — Payload', content: <PayloadPane state={state} setState={setState} /> },
      { id: 'meta', title: 'Pane 5 — Meta-Behaviour', content: <MetaBehaviourPane /> },
    ],
    [state, selectedNodeId, drones, endpoints]
  );

  const toggle = (id: string) => {
    const next = { ...collapsed, [id]: !collapsed[id] };
    setCollapsed(next);
    sessionStorage.setItem('composer-panels', JSON.stringify(next));
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={handlePreviewBuild}>
          Preview Build
        </Button>
        <Button size="sm" variant="outline" onClick={handleSaveBrain}>
          Save Brain
        </Button>
        <Button size="sm" onClick={handleAssemble}>
          Assemble Drone
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => navigator.clipboard.writeText(JSON.stringify(state, null, 2))}
        >
          Export JSON
        </Button>
      </div>

      {error && <Card className="border-critical/50 p-2 text-xs text-critical">{error}</Card>}
      {message && <Card className="border-low/50 p-2 text-xs text-low">{message}</Card>}

      {panes.map((pane) => (
        <Card key={pane.id} className="p-2">
          <button className="mb-2 w-full text-left text-sm" onClick={() => toggle(pane.id)}>
            {pane.title}
          </button>
          {!collapsed[pane.id] && pane.content}
        </Card>
      ))}

      {previewOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <Card className="w-full max-w-4xl space-y-2 p-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm">Preview Build Source</h4>
              <Button size="sm" variant="outline" onClick={() => setPreviewOpen(false)}>
                Close
              </Button>
            </div>
            <pre className="h-96 overflow-auto font-mono text-xs">{previewSource}</pre>
          </Card>
        </div>
      )}
    </div>
  );
}
