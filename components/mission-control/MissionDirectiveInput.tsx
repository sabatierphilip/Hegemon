'use client';

import { useState } from 'react';

const HINTS = [
  'Deploy Hannibal against 10.0.0.1 — full recon',
  'Target 192.168.1.0/24, find credentials, enforce mode',
  'Pause the campaign',
  'What is the current status?',
  'Abort and withdraw all drones',
  'Resume, observe only',
];

export function MissionDirectiveInput({ onSubmit, parsePreview }: { onSubmit: (text: string) => Promise<any>; parsePreview: string }) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);

  const submit = async () => {
    if (!text.trim()) return;
    setLoading(true);
    try {
      const result = await onSubmit(text);
      setLastResult(result);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded border border-border bg-card p-3 space-y-2">
      <div className="text-xs font-medium text-text">Hannibal — Command Input</div>
      <div className="text-[10px] text-textSecondary">Issue orders in plain English. Hannibal will parse intent and execute.</div>
      <div className="flex flex-wrap gap-1">
        {HINTS.map((h) => (
          <button key={h} onClick={() => setText(h)} className="rounded border border-border px-1.5 py-0.5 text-[9px] text-textSecondary hover:bg-border hover:text-text">
            {h.slice(0, 40)}
            {h.length > 40 ? '…' : ''}
          </button>
        ))}
      </div>

      <textarea
        className="w-full rounded border border-border bg-bg px-2 py-1.5 text-xs text-text placeholder:text-textSecondary focus:border-accent focus:outline-none"
        rows={3}
        placeholder="e.g. Deploy Hannibal against 10.0.1.0/24 — map network and harvest credentials, enforce mode"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && e.ctrlKey) submit();
        }}
      />

      <div className="flex items-center gap-2">
        <button onClick={submit} disabled={loading || !text.trim()} className="rounded bg-accent px-3 py-1 text-xs text-white disabled:opacity-50">
          {loading ? 'Parsing…' : 'Issue Order ↵'}
        </button>
        <span className="text-[10px] text-textSecondary">Ctrl+Enter to submit</span>
      </div>

      {parsePreview && <pre className="rounded border border-border bg-bg p-2 text-[10px] text-textSecondary whitespace-pre-wrap">{parsePreview}</pre>}

      {lastResult && lastResult.acted && (
        <div className="rounded border border-low/40 bg-low/10 p-1.5 text-[10px] text-low">
          ✓ Order accepted{lastResult.campaign_id ? ` — Campaign ${lastResult.campaign_id}` : ''}
        </div>
      )}
      {lastResult && !lastResult.acted && <div className="rounded border border-medium/40 bg-medium/10 p-1.5 text-[10px] text-medium">⚠ Order parsed but no action taken. Confidence may be low.</div>}
    </div>
  );
}
