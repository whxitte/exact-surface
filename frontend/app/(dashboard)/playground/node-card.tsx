"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { AlertTriangle, CheckCircle2, Loader2, MinusCircle, XCircle } from "lucide-react";
import type { NodeRunReport, NodeSpec } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Colour per port type, so a wire's meaning is readable without hovering. */
const PORT_COLOUR: Record<string, string> = {
  hosts: "!bg-primary",
  urls: "!bg-sky-400",
  records: "!bg-violet-400",
  text: "!bg-amber-400",
  json: "!bg-muted-foreground",
  any: "!bg-foreground",
};

const TIER_ACCENT: Record<string, string> = {
  pipeline: "border-l-primary",
  utility: "border-l-sky-400",
  source: "border-l-amber-400",
  output: "border-l-violet-400",
};

const STATUS_ICON = {
  running: Loader2,
  success: CheckCircle2,
  failed: XCircle,
  skipped: MinusCircle,
} as const;

const STATUS_COLOUR = {
  running: "text-severity-medium",
  success: "text-primary",
  failed: "text-severity-critical",
  skipped: "text-muted-foreground",
} as const;

export type CanvasNodeData = {
  spec: NodeSpec;
  params: Record<string, unknown>;
  report?: NodeRunReport;
  invalid?: string;
};

/** One node on the canvas: its ports as handles, plus live run status. */
export function NodeCard({ data, selected }: NodeProps) {
  const { spec, report, invalid } = data as CanvasNodeData;
  const Icon = report ? STATUS_ICON[report.status] : null;

  return (
    <div
      className={cn(
        "w-60 rounded-lg border border-l-4 bg-card shadow-sm transition-colors",
        TIER_ACCENT[spec.tier] ?? "border-l-border",
        selected ? "border-primary ring-1 ring-primary" : "border-border",
        invalid && "border-severity-critical ring-1 ring-severity-critical",
      )}
    >
      {/* Inputs on the left, evenly spaced down the card's edge. */}
      {spec.inputs.map((port, i) => (
        <Handle
          key={port.name}
          id={port.name}
          type="target"
          position={Position.Left}
          style={{ top: 44 + i * 20 }}
          className={cn("!h-2.5 !w-2.5 !border-2 !border-card", PORT_COLOUR[port.type])}
          title={`${port.label} (${port.type})${port.required ? " — required" : ""}`}
        />
      ))}
      {spec.outputs.map((port, i) => (
        <Handle
          key={port.name}
          id={port.name}
          type="source"
          position={Position.Right}
          style={{ top: 44 + i * 20 }}
          className={cn("!h-2.5 !w-2.5 !border-2 !border-card", PORT_COLOUR[port.type])}
          title={`${port.label} (${port.type})`}
        />
      ))}

      <div className="flex items-start gap-2 px-3 py-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-[13px] font-semibold">{spec.label}</span>
            {Icon && (
              <Icon
                className={cn(
                  "h-3.5 w-3.5 shrink-0",
                  STATUS_COLOUR[report!.status],
                  report!.status === "running" && "animate-spin",
                )}
              />
            )}
          </div>
          <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-muted-foreground">
            {spec.summary}
          </p>
        </div>
      </div>

      {/* Port labels, so a user knows what each socket carries without guessing. */}
      <div className="flex justify-between px-3 pb-2 text-[10px] text-muted-foreground">
        <div className="space-y-0.5">
          {spec.inputs.map((p) => (
            <div key={p.name}>{p.label}{p.required && <span className="text-primary">*</span>}</div>
          ))}
        </div>
        <div className="space-y-0.5 text-right">
          {spec.outputs.map((p) => (
            <div key={p.name}>{p.label}</div>
          ))}
        </div>
      </div>

      {spec.caution && (
        <div className="flex items-start gap-1.5 border-t border-border px-3 py-1.5 text-[10px] text-severity-medium">
          <AlertTriangle className="mt-px h-3 w-3 shrink-0" />
          <span className="leading-snug">{spec.caution}</span>
        </div>
      )}

      {report?.error && (
        <div className="border-t border-border px-3 py-1.5 text-[10px] leading-snug text-severity-critical">
          {report.error}
        </div>
      )}
      {report?.note && !report.error && (
        <div className="border-t border-border px-3 py-1.5 text-[10px] text-muted-foreground">
          {report.note}
        </div>
      )}
      {invalid && (
        <div className="border-t border-border px-3 py-1.5 text-[10px] leading-snug text-severity-critical">
          {invalid}
        </div>
      )}
    </div>
  );
}
