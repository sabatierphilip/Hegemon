export function SamplePayloadCard({ name, category, size, nodes, onClick }: { name: string; category: string; size: string; nodes: string[]; onClick: () => void; }) {
  return <button onClick={onClick} className="w-full rounded border border-border p-2 text-left text-xs hover:bg-border"><div className="flex items-center justify-between"><b>{name}</b><span className="rounded bg-border px-1">{category}</span></div><div className="text-textSecondary">{size} · {nodes.join(', ')}</div></button>;
}
