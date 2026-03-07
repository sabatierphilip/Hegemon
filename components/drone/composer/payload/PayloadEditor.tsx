export function PayloadEditor({ value, onChange }: { value: Record<string, unknown>; onChange: (value: Record<string, unknown>) => void; }) {
  return (
    <div className="space-y-2">
      <textarea className="mono h-40 w-full rounded border border-border bg-bg p-2 text-xs" value={JSON.stringify(value, null, 2)} onChange={(e) => {
        try { onChange(JSON.parse(e.target.value)); } catch { }
      }} />
      <div className="text-xs text-textSecondary">Compiled size estimate: {JSON.stringify(value).length} bytes</div>
    </div>
  );
}
