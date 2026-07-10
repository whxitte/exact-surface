import * as React from "react";
import { cn } from "@/lib/utils";

export interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type" | "onChange"> {
  checked: boolean;
  onChange: (checked: boolean) => void;
}

export const Switch = React.forwardRef<HTMLInputElement, SwitchProps>(
  ({ className, checked, onChange, ...props }, ref) => (
    <div className={cn("relative inline-flex items-center h-6 w-10 cursor-pointer select-none", className)}>
      <input
        ref={ref}
        type="checkbox"
        className="sr-only peer"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        {...props}
      />
      {/* Track */}
      <div
        className={cn(
          "absolute left-[3px] right-[3px] h-2.5 rounded-full transition-colors duration-200 ease-in-out",
          "bg-zinc-700 peer-checked:bg-primary/40"
        )}
      />
      {/* Thumb */}
      <div
        className={cn(
          "absolute left-[2px] top-[3.5px] h-[17px] w-[17px] rounded-full transition-all duration-200 ease-in-out shadow-sm",
          "bg-zinc-400 peer-checked:bg-primary peer-checked:translate-x-[19px]",
          "peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background",
          "peer-disabled:opacity-50"
        )}
      />
    </div>
  ),
);
Switch.displayName = "Switch";
