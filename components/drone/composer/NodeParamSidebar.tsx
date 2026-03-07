export function NodeParamSidebar({ selectedNode }: { selectedNode?: string }) {
  return <div className="rounded border border-border p-2 text-xs"><h4 className="mb-2">Node Params</h4><div className="text-textSecondary">{selectedNode ? `Editing ${selectedNode}` : 'Select node to edit parameters.'}</div></div>;
}
