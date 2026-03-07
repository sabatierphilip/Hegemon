import { Endpoint, Drone } from '@/types/hegemon';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { ComposerState } from '@/types/composer';

export function EntityPane({ state, setState, endpoints, drones }: { state: ComposerState; setState: (fn: (s: ComposerState) => ComposerState) => void; endpoints: Endpoint[]; drones: Drone[]; }) {
  return <div className="grid grid-cols-2 gap-2 text-xs">
    <div><label>Endpoint</label><Select value={state.endpointId ?? ''} onChange={e => setState(s => ({ ...s, endpointId: e.target.value || undefined }))}><option value="">select</option>{endpoints.map(ep => <option key={ep.id} value={ep.id}>{ep.hostname}</option>)}</Select></div>
    <div><label>Host/CIDR</label><Input value={state.host ?? ''} onChange={e => setState(s => ({ ...s, host: e.target.value }))} placeholder="host" /></div>
    <div><label>Target Drone</label><Select value={state.targetDroneId ?? ''} onChange={e => setState(s => ({ ...s, targetDroneId: e.target.value || undefined }))}><option value="">none</option>{drones.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</Select></div>
    <div><label>Tier</label><Select value={state.tier} onChange={e => setState(s => ({ ...s, tier: e.target.value as ComposerState['tier'] }))}><option value="controlled">controlled</option><option value="tethered">tethered</option><option value="autonomous">autonomous</option></Select></div>
    <div><label>Autonomy</label><Select value={state.autonomy} onChange={e => setState(s => ({ ...s, autonomy: e.target.value as ComposerState['autonomy'] }))}><option value="observe">observe</option><option value="contain">contain</option><option value="enforce">enforce</option></Select></div>
    <div>
      <label className="block text-xs mb-1">Execution Ring</label>
      <Select
        value={String(state.executionRing ?? 3)}
        onChange={(e) => setState((s) => ({
          ...s,
          executionRing: Number(e.target.value) as 1 | 2 | 3,
        }))}
      >
        <option value="3">Ring 3 — Userland (Python)</option>
        <option value="2">Ring 2 — OS/Elevated (requires root/admin)</option>
        <option value="1">Ring 1 — Kernel/eBPF (requires human approval)</option>
      </Select>
      {state.executionRing === 1 && (
        <div className="mt-1 rounded border border-critical/50 p-1 text-[10px] text-critical">
          Ring 1 requires human approval before launch. eBPF compiler must be available on target.
        </div>
      )}
      {state.executionRing === 2 && (
        <div className="mt-1 rounded border border-medium/50 p-1 text-[10px] text-medium">
          Ring 2 requires elevated privileges on target host.
        </div>
      )}
    </div>
    <div><label>Drone Name</label><Input value={state.droneName} onChange={e => setState(s => ({ ...s, droneName: e.target.value }))} /></div>
  </div>;
}
