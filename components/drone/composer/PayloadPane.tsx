'use client';

import { useMemo, useState } from 'react';
import { Plus } from 'lucide-react';
import { ComposerState } from '@/types/composer';
import { payloadSamples } from '@/lib/payloadSamples';
import { SamplePayloadCard } from './payload/SamplePayloadCard';
import { AtomicFunctionPicker } from './payload/AtomicFunctionPicker';
import { PayloadEditor } from './payload/PayloadEditor';

type CustomPayload = {
  id: string;
  name: string;
  payload: Record<string, unknown>;
};

export function PayloadPane({ state, setState }: { state: ComposerState; setState: (fn: (s: ComposerState) => ComposerState) => void }) {
  const [customPayloads, setCustomPayloads] = useState<CustomPayload[]>([]);

  const addCustomPayload = () => {
    const id = `custom-${Date.now()}`;
    setCustomPayloads((items) => [...items, { id, name: `Custom Payload ${items.length + 1}`, payload: { action: 'custom', output_format: 'binary_blob' } }]);
  };

  const allDraggables = useMemo(
    () => [
      ...payloadSamples.map((sample) => ({
        id: sample.name,
        name: sample.name,
        category: sample.category,
        size: sample.size,
        nodes: sample.nodes,
        payload: sample.payload,
      })),
      ...customPayloads.map((sample) => ({
        id: sample.id,
        name: sample.name,
        category: 'Custom',
        size: 'dynamic',
        nodes: ['payload'],
        payload: sample.payload,
      })),
    ],
    [customPayloads]
  );

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs text-textSecondary">Payload draggables include info and per-item configurator controls.</div>
        <button type="button" className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs" onClick={addCustomPayload}>
          <Plus size={12} /> Add Custom Payload
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {allDraggables.map((s) => (
          <div
            key={s.id}
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData(
                'application/hegemon-node',
                JSON.stringify({
                  kind: `payload_${s.name.toLowerCase().replace(/ /g, '_')}`,
                  nodeType: 'payload',
                  defaultParams: { ...s.payload, category: s.category, displayName: s.name, config_id: s.id },
                })
              );
            }}
          >
            <SamplePayloadCard
              name={s.name}
              category={s.category}
              size={s.size}
              nodes={s.nodes}
              onClick={() => setState((st) => ({ ...st, payload: s.payload }))}
              onConfigure={() => setState((st) => ({ ...st, payload: { ...s.payload, configured_at: new Date().toISOString(), config_id: s.id } }))}
              info={`Payload ${s.name} can be dropped repeatedly, each drop supports unique params in Node Params.`}
            />
          </div>
        ))}
      </div>

      <AtomicFunctionPicker onAdd={(fn) => setState((st) => ({ ...st, payload: { ...st.payload, [fn]: true } }))} />
      <PayloadEditor value={state.payload} onChange={(payload) => setState((st) => ({ ...st, payload }))} />
    </div>
  );
}
