import { ComposerState } from '@/types/composer';
import { payloadSamples } from '@/lib/payloadSamples';
import { SamplePayloadCard } from './payload/SamplePayloadCard';
import { AtomicFunctionPicker } from './payload/AtomicFunctionPicker';
import { PayloadEditor } from './payload/PayloadEditor';

export function PayloadPane({ state, setState }: { state: ComposerState; setState: (fn: (s: ComposerState) => ComposerState) => void; }) {
  return <div className="space-y-2"><div className="grid grid-cols-2 gap-2">{payloadSamples.map(s => <SamplePayloadCard key={s.name} name={s.name} category={s.category} size={s.size} nodes={s.nodes} onClick={() => setState(st => ({ ...st, payload: s.payload }))} />)}</div><AtomicFunctionPicker onAdd={(fn) => setState(st => ({ ...st, payload: { ...st.payload, [fn]: true } }))} /><PayloadEditor value={state.payload} onChange={(payload) => setState(st => ({ ...st, payload }))} /></div>;
}
