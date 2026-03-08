'use client';

import { useMemo, useState } from 'react';

type Props = {
  board: any;
  onCreateTask: (payload: any) => Promise<void>;
  onUpdateTask: (taskId: string, payload: any) => Promise<void>;
  onIssueOrder: (payload: any) => Promise<void>;
  onCloseOrder: (orderId: string, payload: any) => Promise<void>;
  onRegisterDirective: (payload: any) => Promise<void>;
  onRefreshPlaybooks: () => Promise<void>;
};

export function MissionOperationsBoard({ board, onCreateTask, onUpdateTask, onIssueOrder, onCloseOrder, onRegisterDirective, onRefreshPlaybooks }: Props) {
  const [taskTitle, setTaskTitle] = useState('');
  const [taskOwner, setTaskOwner] = useState('mission-control');
  const [taskPriority, setTaskPriority] = useState('normal');
  const [taskNote, setTaskNote] = useState('');

  const [orderAction, setOrderAction] = useState('DEPLOY_SCOUT');
  const [orderRationale, setOrderRationale] = useState('Expand reconnaissance envelope to validate host map gaps.');

  const [directiveTitle, setDirectiveTitle] = useState('Adaptive encirclement push');
  const [directiveObjective, setDirectiveObjective] = useState('Constrain high-value hosts while minimizing telemetry footprint');
  const [directiveMode, setDirectiveMode] = useState('balanced');

  const tasks = board?.tasks ?? [];
  const orders = board?.orders ?? [];
  const directives = board?.directives ?? [];
  const playbooks = board?.playbooks ?? [];

  const groupedTasks = useMemo(() => {
    const buckets: Record<string, any[]> = { open: [], in_progress: [], closed: [] };
    for (const t of tasks) {
      if (t.status === 'closed' || t.status === 'complete') buckets.closed.push(t);
      else if (t.status === 'in_progress') buckets.in_progress.push(t);
      else buckets.open.push(t);
    }
    return buckets;
  }, [tasks]);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-12 gap-3">
        <div className="col-span-4 rounded border border-border bg-card p-3 space-y-2">
          <div className="text-xs font-medium text-text">Create Task</div>
          <input value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} placeholder="Task title" className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <input value={taskOwner} onChange={(e) => setTaskOwner(e.target.value)} placeholder="Owner" className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <select value={taskPriority} onChange={(e) => setTaskPriority(e.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text">
            {['low', 'normal', 'high', 'urgent'].map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <textarea value={taskNote} onChange={(e) => setTaskNote(e.target.value)} rows={2} placeholder="Initial note" className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <button
            className="rounded bg-accent px-3 py-1 text-xs text-white"
            onClick={() => {
              void onCreateTask({ title: taskTitle, owner: taskOwner, priority: taskPriority, notes: taskNote ? [taskNote] : [] });
              setTaskTitle('');
              setTaskNote('');
            }}
          >
            Create Task
          </button>
        </div>

        <div className="col-span-4 rounded border border-border bg-card p-3 space-y-2">
          <div className="text-xs font-medium text-text">Issue Order</div>
          <select value={orderAction} onChange={(e) => setOrderAction(e.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text">
            {[
              'DEPLOY_SCOUT',
              'DEPLOY_MAPPER',
              'DEPLOY_FLANKER',
              'DEPLOY_HARVESTER',
              'DEPLOY_ENCIRCLER',
              'DEPLOY_STRIKER',
              'RECALL_ALL_DRONES',
              'TERMINATE_HIGHEST_RISK_DRONE',
            ].map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
          <textarea value={orderRationale} onChange={(e) => setOrderRationale(e.target.value)} rows={3} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <button className="rounded bg-accent px-3 py-1 text-xs text-white" onClick={() => void onIssueOrder({ action: orderAction, rationale: orderRationale })}>
            Issue Order
          </button>
        </div>

        <div className="col-span-4 rounded border border-border bg-card p-3 space-y-2">
          <div className="text-xs font-medium text-text">Register Directive</div>
          <input value={directiveTitle} onChange={(e) => setDirectiveTitle(e.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <textarea value={directiveObjective} onChange={(e) => setDirectiveObjective(e.target.value)} rows={2} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text" />
          <select value={directiveMode} onChange={(e) => setDirectiveMode(e.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-text">
            {['observe', 'balanced', 'enforce'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <button
            className="rounded bg-accent px-3 py-1 text-xs text-white"
            onClick={() => void onRegisterDirective({ title: directiveTitle, objective: directiveObjective, mode: directiveMode, ttl_seconds: 900 })}
          >
            Register Directive
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-3">
        <div className="col-span-7 rounded border border-border bg-card p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs font-medium text-text">Task Board</div>
            <div className="text-[10px] text-textSecondary">Open {groupedTasks.open.length} • In Progress {groupedTasks.in_progress.length} • Closed {groupedTasks.closed.length}</div>
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[
              { key: 'open', label: 'Open' },
              { key: 'in_progress', label: 'In Progress' },
              { key: 'closed', label: 'Closed' },
            ].map((bucket) => (
              <div key={bucket.key} className="rounded border border-border bg-bg p-2 space-y-1 max-h-[440px] overflow-y-auto">
                <div className="text-[10px] font-semibold text-text mb-1">{bucket.label}</div>
                {(groupedTasks[bucket.key] ?? []).map((task: any) => (
                  <div key={task.task_id} className="rounded border border-border bg-card p-1.5">
                    <div className="text-[10px] text-text font-medium">{task.title}</div>
                    <div className="text-[9px] text-textSecondary">{task.owner} • {task.priority}</div>
                    <div className="text-[9px] text-textSecondary mt-0.5">{task.notes?.slice(-1)?.[0] ?? 'No notes'}</div>
                    {bucket.key !== 'closed' && (
                      <div className="mt-1 flex gap-1">
                        <button className="rounded border border-border px-1 py-0.5 text-[9px] text-textSecondary" onClick={() => void onUpdateTask(task.task_id, { status: 'in_progress' })}>Start</button>
                        <button className="rounded border border-border px-1 py-0.5 text-[9px] text-textSecondary" onClick={() => void onUpdateTask(task.task_id, { status: 'closed' })}>Close</button>
                      </div>
                    )}
                  </div>
                ))}
                {(groupedTasks[bucket.key] ?? []).length === 0 && <div className="text-[9px] text-textSecondary">No tasks</div>}
              </div>
            ))}
          </div>
        </div>

        <div className="col-span-5 space-y-3">
          <div className="rounded border border-border bg-card p-3">
            <div className="text-xs font-medium text-text mb-2">Orders</div>
            <div className="space-y-1 max-h-60 overflow-y-auto">
              {orders.slice().reverse().map((order: any) => (
                <div key={order.order_id} className="rounded border border-border p-1.5 text-[9px]">
                  <div className="text-text font-semibold">{order.action}</div>
                  <div className="text-textSecondary">{order.rationale}</div>
                  <div className="text-textSecondary">state: {order.state}</div>
                  {order.state !== 'closed' && <button className="mt-1 rounded border border-border px-1 py-0.5 text-[9px] text-textSecondary" onClick={() => void onCloseOrder(order.order_id, { outcome: 'executed' })}>Mark Closed</button>}
                </div>
              ))}
              {orders.length === 0 && <div className="text-[9px] text-textSecondary">No orders yet.</div>}
            </div>
          </div>

          <div className="rounded border border-border bg-card p-3">
            <div className="text-xs font-medium text-text mb-2">Directives</div>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {directives.slice().reverse().map((d: any) => (
                <div key={d.directive_id} className="rounded border border-border p-1.5 text-[9px]">
                  <div className="text-text font-semibold">{d.title}</div>
                  <div className="text-textSecondary">{d.objective}</div>
                  <div className="text-textSecondary">mode {d.mode}</div>
                </div>
              ))}
              {directives.length === 0 && <div className="text-[9px] text-textSecondary">No directives yet.</div>}
            </div>
          </div>

          <div className="rounded border border-border bg-card p-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-text">Playbook Catalog</div>
              <button className="rounded border border-border px-2 py-0.5 text-[9px] text-textSecondary" onClick={() => void onRefreshPlaybooks()}>Refresh</button>
            </div>
            <div className="text-[9px] text-textSecondary mt-1">Loaded {playbooks.length} playbooks (display capped).</div>
            <div className="space-y-1 max-h-44 overflow-y-auto mt-2">
              {playbooks.slice(0, 40).map((pb: any) => (
                <div key={pb.playbook_id} className="rounded border border-border p-1 text-[9px]">
                  <div className="text-text">{pb.name}</div>
                  <div className="text-textSecondary">{pb.phase} • {pb.risk_profile}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
