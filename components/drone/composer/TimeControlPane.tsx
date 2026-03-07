import { ComposerState } from '@/types/composer';

export function TimeControlPane({ state, setState }: { state: ComposerState; setState: (fn: (s: ComposerState) => ComposerState) => void; }) {
  const ttl = state.unlimitedTTL ? 'Unlimited' : `${Math.floor((state.ttlSeconds ?? 300) / 60)}m`;
  return <div className="space-y-2 text-xs">
    <label className="block">TTL: {ttl}</label>
    <input type="range" min={300} max={86400} step={60} value={state.ttlSeconds ?? 3600} onChange={e => setState(s => ({ ...s, ttlSeconds: Number(e.target.value), unlimitedTTL: false }))} className="w-full" />
    <button className="rounded bg-border px-2 py-1" onClick={() => setState(s => ({ ...s, unlimitedTTL: !s.unlimitedTTL }))}>toggle unlimited</button>
    <label className="block">Checkin: {state.checkinSeconds}s</label>
    <input type="range" min={10} max={300} step={10} value={state.checkinSeconds} onChange={e => setState(s => ({ ...s, checkinSeconds: Number(e.target.value) }))} className="w-full" />
    <div className="rounded border border-border p-2">Presets: Single pass / Patrol / Persistent / Terminator / Burst</div>
  </div>;
}
