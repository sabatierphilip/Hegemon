'use client';

import { Info } from 'lucide-react';
import { useState } from 'react';
import { atomicFunctions } from '@/lib/atomicFunctions';

export function AtomicFunctionPicker({ onAdd }: { onAdd: (fn: string) => void }) {
  const [info, setInfo] = useState<string | null>(null);

  return (
    <div className="space-y-1 text-xs">
      {info && <div className="rounded border border-border p-2 text-[11px] text-textSecondary">{info}</div>}
      <div className="grid grid-cols-2 gap-2">
        {Object.entries(atomicFunctions).map(([group, items]) => (
          <div key={group} className="rounded border border-border p-2">
            <div className="mb-1 text-textSecondary">{group}</div>
            <div className="flex flex-wrap gap-1">
              {items.map((fn) => (
                <div key={fn} className="flex items-center gap-1">
                  <button className="mono rounded bg-border px-1 py-0.5" onClick={() => onAdd(fn)}>
                    {fn}
                  </button>
                  <button type="button" className="rounded bg-border px-1 py-0.5" onClick={() => setInfo(`${fn}: atomic operation for payload behavior composition.`)}>
                    <Info size={11} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
