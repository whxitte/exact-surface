"use client";

import { useEffect, useState } from "react";
import { Eye } from "lucide-react";
import { api } from "@/lib/api";

/**
 * Tells a visitor they are on the public read-only demo.
 *
 * Presentation only. The API refuses every state-changing request in middleware
 * (`api/demo.py`), which is what actually holds — anyone can re-enable a disabled
 * button in devtools, so this banner is a courtesy rather than a control. It exists so
 * a visitor understands why a save does nothing, not to prevent the save.
 */
export function DemoBanner() {
  const [message, setMessage] = useState("");

  useEffect(() => {
    api
      .publicConfig()
      .then((c) => setMessage(c.demo_mode ? c.demo_message : ""))
      .catch(() => setMessage("")); // a customer deployment simply has no demo mode
  }, []);

  if (!message) return null;

  return (
    <div className="border-b border-primary/30 bg-primary/10 px-4 py-2.5 text-center text-xs text-primary sm:px-6">
      <span className="inline-flex flex-wrap items-center justify-center gap-2">
        <Eye className="h-3.5 w-3.5 shrink-0" />
        <span className="font-semibold">Read-only demo</span>
        <span className="text-primary/85">{message}</span>
      </span>
    </div>
  );
}
