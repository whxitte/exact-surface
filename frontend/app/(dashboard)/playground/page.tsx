"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
// after the library's sheet, so these overrides win — see canvas.css
import "./canvas.css";
import { Play, Save, Search, Trash2, Loader2, AlertTriangle } from "lucide-react";
import {
  api,
  type NodeSpec,
  type Program,
  type WorkflowGraph,
  type WorkflowRun,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { NodeCard, type CanvasNodeData } from "./node-card";

const NODE_TYPES = { card: NodeCard };

let seq = 0;
const nextId = () => `n${++seq}`;

/** Canvas state -> the shape the API validates and runs. Positions ride along so a
 *  saved workflow reopens exactly as it was drawn. */
function toGraph(nodes: Node[], edges: Edge[]): WorkflowGraph {
  return {
    nodes: Object.fromEntries(
      nodes.map((n) => {
        const d = n.data as CanvasNodeData;
        return [n.id, { type: d.spec.key, params: d.params, x: n.position.x, y: n.position.y }];
      }),
    ),
    edges: edges.map((e) => ({
      source: e.source,
      sourceHandle: e.sourceHandle ?? "",
      target: e.target,
      targetHandle: e.targetHandle ?? "",
    })),
  };
}

export default function PlaygroundPage() {
  return (
    <ReactFlowProvider>
      <Playground />
    </ReactFlowProvider>
  );
}

function Playground() {
  const [specs, setSpecs] = useState<NodeSpec[]>([]);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [programId, setProgramId] = useState("");
  const [query, setQuery] = useState("");
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [run, setRun] = useState<WorkflowRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [name, setName] = useState("Untitled workflow");
  const wrapper = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.playgroundNodes().then((r) => setSpecs(r.nodes)).catch(() => {});
    api
      .listPrograms()
      .then((p) => {
        setPrograms(p);
        if (p.length) setProgramId(p[0].program_id);
      })
      .catch(() => {});
  }, []);

  const specByKey = useMemo(
    () => Object.fromEntries(specs.map((s) => [s.key, s])) as Record<string, NodeSpec>,
    [specs],
  );

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const hit = specs.filter(
      (s) => !q || s.label.toLowerCase().includes(q) || s.summary.toLowerCase().includes(q),
    );
    const out = new Map<string, NodeSpec[]>();
    for (const s of hit) out.set(s.group, [...(out.get(s.group) ?? []), s]);
    return [...out.entries()];
  }, [specs, query]);

  const addNode = useCallback(
    (spec: NodeSpec, at?: { x: number; y: number }) => {
      const params: Record<string, unknown> = {};
      for (const p of spec.params) if (p.default !== null) params[p.name] = p.default;
      const id = nextId();
      setNodes((ns) => [
        ...ns,
        {
          id,
          type: "card",
          // stagger, so clicking several palette items in a row does not stack them
          position: at ?? { x: 60 + (ns.length % 3) * 280, y: 60 + Math.floor(ns.length / 3) * 190 },
          data: { spec, params } satisfies CanvasNodeData,
        },
      ]);
      setSelected(id);
    },
    [setNodes],
  );

  /** Refuse an illegal wire at drag time rather than at run time — the user finds out
   *  while their hand is still on the mouse, which is the whole point of a canvas. */
  const isValidConnection = useCallback(
    (c: Connection | Edge) => {
      const src = nodes.find((n) => n.id === c.source);
      const dst = nodes.find((n) => n.id === c.target);
      if (!src || !dst) return false;
      const out = (src.data as CanvasNodeData).spec.outputs.find((p) => p.name === c.sourceHandle);
      const inp = (dst.data as CanvasNodeData).spec.inputs.find((p) => p.name === c.targetHandle);
      if (!out || !inp) return false;
      if (out.type !== inp.type && out.type !== "any" && inp.type !== "any") return false;
      // one wire per input socket, matching the server-side validator
      return !edges.some((e) => e.target === c.target && e.targetHandle === c.targetHandle);
    },
    [nodes, edges],
  );

  const onConnect = useCallback(
    (c: Connection) => setEdges((es) => addEdge({ ...c, animated: true }, es)),
    [setEdges],
  );

  const doRun = async () => {
    if (!programId) {
      setError("Pick a program first — findings and assets from this run are stored there.");
      return;
    }
    setBusy(true);
    setError("");
    setRun(null);
    try {
      // The worker runs the canvas (the scanning tools only exist in its image), so
      // this queues and then polls. Node status arrives incrementally, which is why
      // each poll result is set rather than only the final one.
      const { run_id } = await api.runWorkflow(programId, toGraph(nodes, edges));
      const TERMINAL = ["success", "failed", "cancelled"];
      // Bounded so a stuck worker cannot leave the UI spinning forever.
      for (let i = 0; i < 600; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        let snapshot;
        try {
          snapshot = await api.workflowRun(run_id);
        } catch {
          continue; // a blip while the worker starts is not a failed run
        }
        setRun(snapshot);
        if (TERMINAL.includes(snapshot.status)) {
          if (snapshot.status === "failed" && snapshot.error) setError(snapshot.error);
          return;
        }
      }
      setError("This run is taking longer than expected — check the Activity page.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "run failed";
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  const doSave = async () => {
    setBusy(true);
    setError("");
    try {
      await api.saveWorkflow(`wf_${Date.now().toString(36)}`, {
        name,
        graph: toGraph(nodes, edges),
        program_id: programId,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "save failed");
    } finally {
      setBusy(false);
    }
  };

  // Paint run status onto the nodes themselves, so progress reads on the canvas
  // rather than only in a side panel.
  const painted = useMemo(
    () =>
      nodes.map((n) => ({
        ...n,
        data: { ...(n.data as CanvasNodeData), report: run?.nodes[n.id] },
      })),
    [nodes, run],
  );

  const selectedNode = painted.find((n) => n.id === selected);
  const selectedSpec = selectedNode ? (selectedNode.data as CanvasNodeData).spec : null;

  const setParam = (key: string, value: unknown) => {
    setNodes((ns) =>
      ns.map((n) =>
        n.id === selected
          ? { ...n, data: { ...(n.data as CanvasNodeData), params: { ...(n.data as CanvasNodeData).params, [key]: value } } }
          : n,
      ),
    );
  };

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col">
      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="h-8 w-48 text-sm"
          aria-label="Workflow name"
        />
        <select
          value={programId}
          onChange={(e) => setProgramId(e.target.value)}
          className="h-8 rounded-md border border-border bg-background px-2 text-sm"
          aria-label="Program"
        >
          <option value="">Select a program…</option>
          {programs.map((p) => (
            <option key={p.program_id} value={p.program_id}>
              {p.apex_domain}
            </option>
          ))}
        </select>
        <div className="flex-1" />
        <Button variant="ghost" onClick={doSave} disabled={busy || !nodes.length} className="h-8">
          <Save className="mr-1.5 h-3.5 w-3.5" /> Save
        </Button>
        <Button onClick={doRun} disabled={busy || !nodes.length} className="h-8">
          {busy ? (
            <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="mr-1.5 h-3.5 w-3.5" />
          )}
          Run
        </Button>
      </div>

      {error && (
        <div className="flex items-start gap-2 border-b border-border bg-severity-critical/10 px-4 py-2 text-xs text-severity-critical">
          <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        {/* palette */}
        <aside className="hidden w-64 shrink-0 flex-col border-r border-border md:flex">
          <div className="border-b border-border p-2">
            <div className="relative">
              <Search className="absolute left-2 top-2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search nodes…"
                className="h-8 pl-7 text-xs"
              />
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {groups.map(([group, items]) => (
              <div key={group} className="mb-3">
                <div className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {group}
                </div>
                <div className="space-y-1">
                  {items.map((s) => (
                    <button
                      key={s.key}
                      onClick={() => addNode(s)}
                      draggable
                      onDragStart={(e) => e.dataTransfer.setData("application/node-key", s.key)}
                      className="w-full rounded-md border border-border bg-card px-2 py-1.5 text-left transition-colors hover:border-primary"
                    >
                      <div className="text-[12px] font-medium">{s.label}</div>
                      <div className="line-clamp-2 text-[10px] leading-snug text-muted-foreground">
                        {s.summary}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
            {!groups.length && (
              <p className="px-1 py-4 text-xs text-muted-foreground">No nodes match “{query}”.</p>
            )}
          </div>
        </aside>

        {/* canvas */}
        <div className="min-w-0 flex-1" ref={wrapper}>
          <ReactFlow
            nodes={painted}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            isValidConnection={isValidConnection}
            nodeTypes={NODE_TYPES}
            onNodeClick={(_e, n) => setSelected(n.id)}
            onPaneClick={() => setSelected(null)}
            onDrop={(e) => {
              e.preventDefault();
              const key = e.dataTransfer.getData("application/node-key");
              const spec = specByKey[key];
              const box = wrapper.current?.getBoundingClientRect();
              if (spec && box) {
                addNode(spec, { x: e.clientX - box.left - 120, y: e.clientY - box.top - 30 });
              }
            }}
            onDragOver={(e) => {
              e.preventDefault();
              e.dataTransfer.dropEffect = "move";
            }}
            fitView
            proOptions={{ hideAttribution: false }}
          >
            <Background gap={16} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        {/* inspector */}
        <aside className="hidden w-72 shrink-0 flex-col overflow-y-auto border-l border-border lg:flex">
          {!selectedSpec && (
            <div className="p-4 text-xs leading-relaxed text-muted-foreground">
              <p className="mb-2 font-medium text-foreground">How this works</p>
              <p className="mb-2">
                Drag a node from the left. Wire a node&apos;s output socket into another
                node&apos;s input to pass data along — discovered hosts feed the next scan.
              </p>
              <p>
                Select a node to set its parameters. Run results are painted onto the nodes
                themselves.
              </p>
            </div>
          )}
          {selectedSpec && selectedNode && (
            <div className="space-y-3 p-3">
              <div>
                <div className="text-sm font-semibold">{selectedSpec.label}</div>
                <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                  {selectedSpec.summary}
                </p>
              </div>

              {selectedSpec.params.map((p) => {
                const value = (selectedNode.data as CanvasNodeData).params[p.name];
                return (
                  <div key={p.name} className="space-y-1">
                    <Label className="text-[11px]">
                      {p.label}
                      {p.required && <span className="text-primary">*</span>}
                    </Label>
                    {p.kind === "bool" ? (
                      <input
                        type="checkbox"
                        checked={Boolean(value)}
                        onChange={(e) => setParam(p.name, e.target.checked)}
                        className="h-4 w-4 accent-current"
                      />
                    ) : p.name === "hosts" ? (
                      <textarea
                        value={String(value ?? "")}
                        onChange={(e) => setParam(p.name, e.target.value)}
                        rows={4}
                        placeholder={"example.com\napi.example.com"}
                        className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-[11px]"
                      />
                    ) : (
                      <Input
                        value={String(value ?? "")}
                        type={p.kind === "int" ? "number" : "text"}
                        onChange={(e) =>
                          setParam(p.name, p.kind === "int" ? e.target.value : e.target.value)
                        }
                        className="h-8 text-xs"
                      />
                    )}
                    {p.help && (
                      <p className="text-[10px] leading-snug text-muted-foreground">{p.help}</p>
                    )}
                  </div>
                );
              })}

              {run?.nodes[selectedNode.id]?.outputs && (
                <div className="space-y-1">
                  <Label className="text-[11px]">Output</Label>
                  <pre className="max-h-64 overflow-auto rounded-md border border-border bg-background p-2 font-mono text-[10px] leading-relaxed">
                    {JSON.stringify(run.nodes[selectedNode.id].outputs, null, 2)}
                  </pre>
                </div>
              )}

              <Button
                variant="ghost"
                className={cn("h-8 w-full text-severity-critical")}
                onClick={() => {
                  setNodes((ns) => ns.filter((n) => n.id !== selected));
                  setEdges((es) => es.filter((e) => e.source !== selected && e.target !== selected));
                  setSelected(null);
                }}
              >
                <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Remove node
              </Button>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
