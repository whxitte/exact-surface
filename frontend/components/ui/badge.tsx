import * as React from "react";
import { cn } from "@/lib/utils";
import { severityClasses } from "@/lib/severity";

export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        className,
      )}
      {...props}
    />
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={cn("uppercase tracking-wide", severityClasses[severity] || severityClasses.info)}>
      {severity}
    </Badge>
  );
}
