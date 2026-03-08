'use client';

export function QTableViewer({ qtable }: { qtable: any }) {
  if (!qtable) return null;
  return (
    <div className="rounded border border-border bg-card p-3 text-[10px] text-textSecondary">
      <div className="text-xs font-medium text-text mb-2">Q-Table</div>
      <div>Episode: {qtable.episode}</div>
      <div>Epsilon: {qtable.epsilon}</div>
      <div>Entries: {qtable.entries}</div>
    </div>
  );
}
