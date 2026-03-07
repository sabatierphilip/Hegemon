'use client';

import { useMemo, useState } from 'react';
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

const panelKeys = ['entities', 'time', 'graph', 'payload', 'meta'];

export function ComposerShell({ drones, endpoints }: { drones: Drone[]; endpoints: Endpoint[] }) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    if (typeof window === 'undefined') return {};
    return JSON.parse(sessionStorage.getItem('composer-panels') ?? '{}');
  });

  const [state, setState] = useState<ComposerState>({
    droneName: 'new-drone',
    tier: 'controlled',
    autonomy: 'observe',
    ttlSeconds: 3600,
    checkinSeconds: 30,
    nodes: [{ id: 'on_launch', position: { x: 100, y: 100 }, data: { label: 'on_launch' }, type: 'default' }],
    edges: [],
    payload: { action: 'noop' },
    meta: metaBehaviourDefaults
  });

  const panes = useMemo(
    () => [
      { id: 'entities', title: 'Pane 1 — Entities', content: <EntityPane state={state} setState={setState} endpoints={endpoints} drones={drones} /> },
      { id: 'time', title: 'Pane 2 — Time Control', content: <TimeControlPane state={state} setState={setState} /> },
      { id: 'graph', title: 'Pane 3 — Brain Graph', content: <BrainGraphPane state={state} /> },
      { id: 'payload', title: 'Pane 4 — Payload', content: <PayloadPane state={state} setState={setState} /> },
      { id: 'meta', title: 'Pane 5 — Meta-Behaviour', content: <MetaBehaviourPane /> }
    ],
    [state, drones, endpoints]
  );

  const toggle = (id: string) => {
    const next = { ...collapsed, [id]: !collapsed[id] };
    setCollapsed(next);
    sessionStorage.setItem('composer-panels', JSON.stringify(next));
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-2"><Button size="sm">Preview Build</Button><Button size="sm" variant="outline">Save Brain</Button><Button size="sm" variant="ghost">Load Sample</Button><Button size="sm" variant="ghost" onClick={() => navigator.clipboard.writeText(JSON.stringify(state, null, 2))}>Export JSON</Button></div>
      {panes.map((pane) => (
        <Card key={pane.id} className="p-2">
          <button className="mb-2 w-full text-left text-sm" onClick={() => toggle(pane.id)}>{pane.title}</button>
          {!collapsed[pane.id] && pane.content}
        </Card>
      ))}
      <Card className="p-2 text-xs">Sample Templates: Registry Patcher / Persistent Watcher / Honeypot Sentinel / Terminator / Cert Monitor</Card>
    </div>
  );
}
