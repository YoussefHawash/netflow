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
          "peer w-full appearance-none rounded-md outline-none transition [color-scheme:dark] disabled:cursor-not-allowed disabled:opacity-50",
          "shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]",
          isSort
            ? "min-h-7 border border-app-blueStrong/70 bg-app-blueStrong/90 py-1 pl-2.5 pr-8 text-[11px] font-semibold text-white hover:border-app-blue hover:bg-app-blue focus:border-app-blue focus:ring-2 focus:ring-app-blue/25"
            : "min-h-8 border border-app-border bg-[#1b222b] py-[6px] pl-2.5 pr-8 text-xs font-medium text-app-text hover:border-app-blue/50 hover:bg-[#202832] focus:border-app-blue focus:ring-2 focus:ring-app-blueStrong/25",
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
          isSort
            ? "text-white/80 peer-focus:text-white"
            : "text-app-muted peer-focus:text-app-blue",
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
