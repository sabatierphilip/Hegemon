export function TerminalLog({ lines }: { lines: string[] }) {
  return <pre className="mono h-40 overflow-auto rounded border border-border bg-bg p-2 text-xs text-textSecondary">{lines.join('\n')}</pre>;
}
