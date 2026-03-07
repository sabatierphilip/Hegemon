'use client';

import { Clock, Info } from 'lucide-react';
import { useState } from 'react';
import { ComposerState } from '@/types/composer';

const PRESETS = {
  'Single pass': { ttlSeconds: 1200, checkinSeconds: 60, timerNodes: [{ kind: 'wait', params: { seconds: 10 }, label: 'Wait 10s' }] },
  Patrol: {
    ttlSeconds: 7200,
    checkinSeconds: 45,
    timerNodes: [{ kind: 'adaptive_wait', params: { base_seconds: 60, adaptive: true }, label: 'Adaptive Wait' }],
  },
  Persistent: { ttlSeconds: 43200, checkinSeconds: 120, timerNodes: [{ kind: 'wait', params: { seconds: 300 }, label: 'Wait 5m' }] },
  Terminator: { ttlSeconds: 7200, checkinSeconds: 10, timerNodes: [{ kind: 'wait', params: { seconds: 10 }, label: 'Wait 10s' }] },
  Burst: { ttlSeconds: 600, checkinSeconds: 10, timerNodes: [{ kind: 'wait', params: { seconds: 5 }, label: 'Wait 5s' }] },
};

const TIMER_NODES = [
  { kind: 'wait', params: { seconds: 30 }, label: 'Wait 30s', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 60 }, label: 'Wait 60s', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 300 }, label: 'Wait 5m', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'wait', params: { seconds: 600 }, label: 'Wait 10m', inputType: 'control_signal', outputType: 'delayed_control_signal' },
  { kind: 'adaptive_wait', params: { base_seconds: 60, adaptive: true }, label: 'Adaptive Wait', inputType: 'feedback_score:number', outputType: 'dynamic_delay:number' },
  { kind: 'checkin_interval', params: { use_checkin: true }, label: 'Checkin Interval', inputType: 'checkin_seconds:number', outputType: 'delay_seconds:number' },
];

export function TimeControlPane({ state, setState }: { state: ComposerState; setState: (fn: (s: ComposerState) => ComposerState) => void }) {
  const [openInfo, setOpenInfo] = useState<string | null>(null);
  const ttl = state.unlimitedTTL ? 'Unlimited' : `${Math.floor((state.ttlSeconds ?? 300) / 60)}m`;
  const ttlSeconds = state.ttlSeconds ?? 3600;
  const checkinSeconds = Math.max(state.checkinSeconds, 1);
  const ticks = Math.floor(ttlSeconds / checkinSeconds);

  return (
    <div className="space-y-3 text-xs">
      <label className="block">TTL: {ttl}</label>
      <input
        type="range"
        min={300}
        max={86400}
        step={60}
        value={ttlSeconds}
        onChange={(e) => setState((s) => ({ ...s, ttlSeconds: Number(e.target.value), unlimitedTTL: false }))}
        className="w-full"
      />

      <button className="rounded bg-border px-2 py-1" onClick={() => setState((s) => ({ ...s, unlimitedTTL: !s.unlimitedTTL }))}>
        Toggle Unlimited TTL
      </button>

      <label className="block">Checkin: {state.checkinSeconds}s</label>
      <input
        type="range"
        min={10}
        max={300}
        step={5}
        value={state.checkinSeconds}
        onChange={(e) => setState((s) => ({ ...s, checkinSeconds: Number(e.target.value) }))}
        className="w-full"
      />

      <div>
        <div className="mb-1 text-textSecondary">Presets</div>
        <div className="flex flex-wrap gap-1">
          {Object.entries(PRESETS).map(([name, preset]) => (
            <button
              key={name}
              className="rounded border border-border px-2 py-1 hover:bg-border"
              onClick={() => {
                setState((s) => ({
                  ...s,
                  ttlSeconds: preset.ttlSeconds,
                  unlimitedTTL: false,
                  checkinSeconds: preset.checkinSeconds,
                }));
              }}
            >
              {name}
            </button>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center gap-1 text-xs text-info">
          <Clock size={10} /> Timer Nodes — drag to canvas
        </div>
        <div className="flex flex-wrap gap-1">
          {TIMER_NODES.map((t) => (
            <div key={t.label} className="flex items-center gap-1 rounded border border-info/40 px-1 py-1 text-xs text-info hover:bg-info/10">
              <div
                draggable
                onDragStart={(e) => {
                  e.dataTransfer.setData('application/hegemon-node', JSON.stringify({ kind: t.kind, nodeType: 'timer', defaultParams: t.params }));
                }}
                className="cursor-grab"
              >
                <Clock size={8} className="mr-1 inline" />
                {t.label}
              </div>
              <button type="button" className="rounded bg-info/10 px-1 py-0.5" onClick={() => setOpenInfo((v) => (v === t.label ? null : t.label))} title="Info">
                <Info size={10} />
              </button>
              {openInfo === t.label && (
                <div className="max-w-44 text-[10px] text-textSecondary">
                  Input: {t.inputType}<br />Output: {t.outputType}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="rounded border border-border p-2">
        <div className="mb-1 text-textSecondary">TTL Timeline</div>
        <svg viewBox="0 0 320 32" className="h-10 w-full">
          <defs>
            <linearGradient id="ttlGradient" x1="0%" x2="100%" y1="0%" y2="0%">
              <stop offset="0%" stopColor="#22c55e" />
              <stop offset="60%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>
          <rect x="8" y="12" width="304" height="8" rx="4" fill="url(#ttlGradient)" />
          {Array.from({ length: Math.min(ticks, 50) }).map((_, index) => {
            const x = 8 + (index * 304) / Math.max(ticks, 1);
            return <line key={index} x1={x} y1={8} x2={x} y2={24} stroke="#94a3b8" strokeWidth="1" />;
          })}
        </svg>
      </div>
    </div>
  );
}
