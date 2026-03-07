'use client';

import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';
import { ComposerState } from '@/types/composer';
import { ActionPalette } from './ActionPalette';
import { NodeParamSidebar } from './NodeParamSidebar';

export function BrainGraphPane({ state }: { state: ComposerState }) {
  return (
    <div className="grid grid-cols-12 gap-2">
      <div className="col-span-3 rounded border border-border p-2"><ActionPalette /></div>
      <div className="col-span-6 h-72 rounded border border-border">
        <ReactFlow nodes={state.nodes} edges={state.edges} fitView>
          <Background />
          <Controls />
          <MiniMap />
        </ReactFlow>
      </div>
      <div className="col-span-3"><NodeParamSidebar selectedNode={state.nodes[0]?.id} /></div>
    </div>
  );
}
