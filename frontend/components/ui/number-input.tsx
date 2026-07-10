import * as React from "react";
import { cn } from "@/lib/utils";

export interface NumberInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "onChange"> {
  value: number;
  onChange: (val: number) => void;
  min?: number;
  max?: number;
}

export const NumberInput = React.forwardRef<HTMLInputElement, NumberInputProps>(
  ({ className, value, onChange, min, max, disabled, ...props }, ref) => {
    const handleDecrement = () => {
      if (disabled) return;
      if (min !== undefined && value <= min) return;
      onChange(value - 1);
    };

    const handleIncrement = () => {
      if (disabled) return;
      if (max !== undefined && value >= max) return;
      onChange(value + 1);
    };

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = Number(e.target.value);
      if (!isNaN(val)) {
        onChange(val);
      }
    };

    const isMinDisabled = disabled || (min !== undefined && value <= min);
    const isMaxDisabled = disabled || (max !== undefined && value >= max);

    return (
      <div
        className={cn(
          "inline-flex items-center h-8 rounded-md border border-input bg-background overflow-hidden select-none",
          disabled && "opacity-50 cursor-not-allowed",
          className
        )}
      >
        <button
          type="button"
          onClick={handleDecrement}
          disabled={isMinDisabled}
          className={cn(
            "h-full w-8 flex items-center justify-center font-bold text-sm transition-colors",
            "bg-primary text-primary-foreground hover:bg-primary/90",
            "disabled:bg-muted disabled:text-muted-foreground disabled:cursor-not-allowed"
          )}
        >
          -
        </button>
        <input
          ref={ref}
          type="number"
          value={value}
          onChange={handleInputChange}
          min={min}
          max={max}
          disabled={disabled}
          className={cn(
            "h-full w-12 text-center bg-transparent border-0 px-1 py-0 text-sm font-medium focus:outline-none focus:ring-0",
            "[appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
          )}
          {...props}
        />
        <button
          type="button"
          onClick={handleIncrement}
          disabled={isMaxDisabled}
          className={cn(
            "h-full w-8 flex items-center justify-center font-bold text-sm transition-colors",
            "bg-primary text-primary-foreground hover:bg-primary/90",
            "disabled:bg-muted disabled:text-muted-foreground disabled:cursor-not-allowed"
          )}
        >
          +
        </button>
      </div>
    );
  }
);
NumberInput.displayName = "NumberInput";
