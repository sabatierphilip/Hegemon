'use client';

import { useMemo, useState } from 'react';
import { AlertItem } from '@/types/hegemon';
import { Card } from '@/components/ui/card';
import { SeverityBadge } from '@/components/shared/SeverityBadge';

export function AlertsTable({ alerts }: { alerts: AlertItem[] }) {
  const [sortKey, setSortKey] = useState<keyof AlertItem>('severity');
  const sorted = useMemo(() => [...alerts].sort((a, b) => String(a[sortKey]).localeCompare(String(b[sortKey]))), [alerts, sortKey]);
  return (
    <Card className="p-2">
      <div className="mb-2 flex gap-2 text-xs">
        {(['source', 'severity', 'title', 'host'] as (keyof AlertItem)[]).map((k) => (
          <button key={k} onClick={() => setSortKey(k)} className="rounded bg-border px-2 py-1">sort {k}</button>
        ))}
      </div>
      <div className="overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-textSecondary"><tr><th>Source</th><th>Severity</th><th>Title</th><th>Host</th><th>Summary</th></tr></thead>
          <tbody>{sorted.map((a) => <tr key={a.id} className="border-t border-border"><td>{a.source}</td><td><SeverityBadge severity={a.severity} /></td><td>{a.title}</td><td>{a.host}</td><td>{a.summary}</td></tr>)}</tbody>
        </table>
      </div>
    </Card>
  );
}
