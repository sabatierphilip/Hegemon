export function StatusIndicator({ status }: { status: string }) {
  const c = status === 'active' ? 'bg-low' : status === 'error' ? 'bg-critical' : 'bg-muted';
  return <span className="inline-flex items-center gap-1 text-xs text-textSecondary"><span className={`h-2 w-2 rounded-full ${c}`} />{status}</span>;
}
