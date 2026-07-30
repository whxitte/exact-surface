"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export interface SwitchProps
  extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "onChange" | "type" | "value"> {
  checked: boolean;
  onChange: (checked: boolean) => void;
}

/**
 * A toggle switch.
 *
 * Implemented as a real `<button role="switch">` rather than a visually-hidden
 * checkbox. The hidden-input version only responded to clicks when the caller happened
 * to wrap the whole switch in a `<label>`, so a switch dropped into a plain `<div>`
 * rendered perfectly and did nothing — which is how the scan-module and alert-policy
 * toggles ended up dead. A button owns its own click handling, is keyboard-operable for
 * free (Space/Enter), and cannot be broken by its surroundings.
 */
export const Switch = React.forwardRef<HTMLButtonElement, SwitchProps>(
  ({ className, checked, onChange, disabled, ...props }, ref) => (
    <button
      ref={ref}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-10 shrink-0 items-center rounded-full outline-none",
        "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer",
        className,
      )}
      {...props}
    >
      {/* Track */}
      <span
        aria-hidden
        className={cn(
          "absolute left-[3px] right-[3px] h-2.5 rounded-full transition-colors duration-200 ease-in-out",
          checked ? "bg-primary/40" : "bg-zinc-700",
        )}
      />
      {/* Thumb */}
      <span
        aria-hidden
        className={cn(
          "absolute left-[2px] top-[3.5px] h-[17px] w-[17px] rounded-full shadow-sm",
          "transition-all duration-200 ease-in-out",
          checked ? "translate-x-[19px] bg-primary" : "translate-x-0 bg-zinc-400",
        )}
      />
    </button>
  ),
);
Switch.displayName = "Switch";
