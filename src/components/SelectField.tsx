import type { ComponentPropsWithoutRef } from "react";
import { cx } from "../lib/styles";

type SelectFieldProps = ComponentPropsWithoutRef<"select"> & {
  variant?: "default" | "sort";
  wrapperClassName?: string;
};

export function SelectField({
  variant = "default",
  className,
  wrapperClassName,
  children,
  ...props
}: SelectFieldProps) {
  const isSort = variant === "sort";

  return (
    <div className={cx("relative", wrapperClassName)}>
      <select
        {...props}
        className={cx(
          "peer w-full appearance-none rounded-md border border-app-border bg-app-raised outline-none transition [color-scheme:dark] disabled:cursor-not-allowed disabled:opacity-50",
          isSort
            ? "min-h-8 py-[6px] pl-2.5 pr-8 text-[11px] font-semibold text-app-muted hover:border-app-muted/50 hover:text-app-text focus:border-app-blue focus:ring-2 focus:ring-app-blue/15"
            : "min-h-8 py-[6px] pl-2.5 pr-8 text-xs font-medium text-app-text hover:border-app-muted/50 focus:border-app-blue focus:ring-2 focus:ring-app-blue/15",
          className,
        )}
      >
        {children}
      </select>
      <svg
        aria-hidden="true"
        viewBox="0 0 20 20"
        className={cx(
          "pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 transition-colors",
          "text-app-subtle peer-focus:text-app-blue",
        )}
      >
        <path
          d="M5.5 7.5 10 12l4.5-4.5"
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="1.8"
        />
      </svg>
    </div>
  );
}
