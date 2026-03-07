import { atomicFunctions } from '@/lib/atomicFunctions';

export function AtomicFunctionPicker({ onAdd }: { onAdd: (fn: string) => void }) {
  return <div className="grid grid-cols-2 gap-2 text-xs">{Object.entries(atomicFunctions).map(([group, items]) => <div key={group} className="rounded border border-border p-2"><div className="mb-1 text-textSecondary">{group}</div><div className="flex flex-wrap gap-1">{items.map((fn) => <button key={fn} className="mono rounded bg-border px-1 py-0.5" onClick={() => onAdd(fn)}>{fn}</button>)}</div></div>)}</div>;
}
