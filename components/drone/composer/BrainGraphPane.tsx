'use client';

import { useCallback, useEffect, useMemo, useRef } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  Connection,
  Edge,
  Node,
  ReactFlowInstance,
  MarkerType,
  Position,
  applyNodeChanges,
  applyEdgeChanges,
  NodeChange,
  EdgeChange,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { ComposerState } from '@/types/composer';
import { ActionPalette } from './ActionPalette';
import { NodeParamSidebar } from './NodeParamSidebar';
import { BrainNode, TimerNode, PayloadNode, MetaNode } from './nodes';

const nodeTypes = { brain: BrainNode, timer: TimerNode, payload: PayloadNode, meta: MetaNode };

const STANDARD_EDGE = {
  type: 'smoothstep',
  markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' },
  style: { stroke: '#6366f1', strokeWidth: 1.5 },
};

const META_EDGE = {
  type: 'smoothstep',
  markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' },
  markerStart: { type: MarkerType.ArrowClosed, color: '#eab308' },
  style: { stroke: '#eab308', strokeWidth: 1.5, strokeDasharray: '4 2' },
};

export function BrainGraphPane({
  state,
  setState,
  selectedNodeId,
  onSelectNode,
}: {
  state: ComposerState;
  setState: (fn: (s: ComposerState) => ComposerState) => void;
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
}) {
  const [nodes, setNodes] = useNodesState(state.nodes);
  const [edges, setEdges] = useEdgesState(state.edges);
  const rfInstance = useRef<ReactFlowInstance | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const edgesRef = useRef(edges);

  const graphDimensions = useMemo(() => {
    const minWidth = 700;
    const minHeight = 384;
    if (!nodes.length) return { width: minWidth, height: minHeight };

    const padding = 220;
    const rightMostX = nodes.reduce((acc, node) => Math.max(acc, node.position.x), 0);
    const bottomMostY = nodes.reduce((acc, node) => Math.max(acc, node.position.y), 0);

    return {
      width: Math.max(minWidth, rightMostX + padding),
      height: Math.max(minHeight, bottomMostY + padding),
    };
  }, [nodes]);

  useEffect(() => {
    edgesRef.current = edges;
  }, [edges]);

  const syncUp = useCallback(
    (newNodes: Node[], newEdges: Edge[]) => {
      setState((s) => ({ ...s, nodes: newNodes, edges: newEdges }));
    },
    [setState]
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      const sourceNode = nodes.find((n) => n.id === connection.source);
      const targetNode = nodes.find((n) => n.id === connection.target);
      const isMeta = sourceNode?.type === 'meta' || targetNode?.type === 'meta';
      const edge = { ...connection, ...(isMeta ? META_EDGE : STANDARD_EDGE), id: `e-${Date.now()}` };
      setEdges((eds) => {
        const next = addEdge(edge, eds);
        syncUp(nodes, next);
        return next;
      });
    },
    [nodes, setEdges, syncUp]
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const raw = e.dataTransfer.getData('application/hegemon-node');
      if (!raw || !rfInstance.current || !containerRef.current) return;
      const { kind, nodeType, defaultParams } = JSON.parse(raw) as {
        kind: string;
        nodeType: 'brain' | 'timer' | 'payload' | 'meta';
        defaultParams?: Record<string, unknown>;
      };

      const bounds = containerRef.current.getBoundingClientRect();
      const position = rfInstance.current.screenToFlowPosition({
        x: e.clientX - bounds.left,
        y: e.clientY - bounds.top,
      });

      const newNode: Node = {
        id: `${kind}-${Date.now()}`,
        type: nodeType,
        position,
        sourcePosition: nodeType === 'meta' ? Position.Right : Position.Bottom,
        targetPosition: nodeType === 'meta' ? Position.Left : Position.Top,
        data: { kind, params: defaultParams ?? {}, label: kind },
      };

      setNodes((ns) => {
        const next = [...ns, newNode];
        syncUp(next, edgesRef.current);
        return next;
      });
      onSelectNode(newNode.id);
    },
    [onSelectNode, setNodes, syncUp]
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => onSelectNode(node.id), [onSelectNode]);

  const onPaneClick = useCallback(() => onSelectNode(null), [onSelectNode]);

  const handleNodesChange = useCallback(
    (changes: NodeChange[]) => {
      const next = applyNodeChanges(changes, nodes);
      setNodes(next);
      syncUp(next, edges);
      if (selectedNodeId && !next.find((node) => node.id === selectedNodeId)) {
        onSelectNode(null);
      }
    },
    [edges, nodes, onSelectNode, selectedNodeId, setNodes, syncUp]
  );

  const handleEdgesChange = useCallback(
    (changes: EdgeChange[]) => {
      const next = applyEdgeChanges(changes, edges);
      setEdges(next);
      syncUp(nodes, next);
    },
    [edges, nodes, setEdges, syncUp]
  );

  return (
    <div className="grid grid-cols-12 gap-2">
      <div className="col-span-3 overflow-auto rounded border border-border p-2">
        <ActionPalette />
      </div>

      <div ref={containerRef} className="col-span-6 overflow-auto rounded border border-border bg-slate-950/80">
        <div style={{ width: graphDimensions.width, height: graphDimensions.height }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={handleNodesChange}
            onEdgesChange={handleEdgesChange}
            onConnect={onConnect}
            onDragOver={onDragOver}
            onDrop={onDrop}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onInit={(instance) => {
              rfInstance.current = instance;
            }}
            fitView
            deleteKeyCode="Delete"
          >
            <Background color="#334155" gap={18} />
            <Controls />
            <MiniMap
              bgColor="#020617"
              nodeColor={(n) =>
                n.type === 'meta'
                  ? '#eab308'
                  : n.type === 'timer'
                    ? '#3b82f6'
                    : n.type === 'payload'
                      ? '#22c55e'
                      : '#6366f1'
              }
            />
          </ReactFlow>
        </div>
      </div>

      <div className="col-span-3">
        <NodeParamSidebar
          selectedNodeId={selectedNodeId}
          nodes={nodes}
          onUpdateNode={(id, params) => {
            setNodes((ns) => {
              const next = ns.map((n) => (n.id === id ? { ...n, data: { ...n.data, params } } : n));
              syncUp(next, edges);
              return next;
            });
          }}
          onDeleteNode={(id) => {
            const nextNodes = nodes.filter((n) => n.id !== id);
            const nextEdges = edges.filter((e) => e.source !== id && e.target !== id);
            setNodes(nextNodes);
            setEdges(nextEdges);
            syncUp(nextNodes, nextEdges);
            onSelectNode(null);
          }}
        />
      </div>
    </div>
  );
}
