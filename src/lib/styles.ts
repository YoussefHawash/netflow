export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export const panel =
  "min-w-0 rounded-md border border-app-line bg-app-surface p-4 shadow-[0_1px_0_rgba(255,255,255,0.03)]";

export const panelHeader =
  "mb-3 flex min-h-8 items-center justify-between gap-3";

export const panelTitle = "text-[13px] font-semibold text-app-text";

export const panelSubtitle = "mt-0.5 text-[11px] text-app-subtle";

export const control =
  "min-h-8 w-full rounded-md border border-app-border bg-app-raised px-2.5 py-[6px] text-xs font-medium text-app-text outline-none transition placeholder:text-app-subtle hover:border-app-muted/40 focus-visible:border-app-blue focus-visible:ring-2 focus-visible:ring-app-blue/15";

export const tableShell =
  "min-h-0 flex-1 overflow-auto rounded-md border border-app-line";

export const th =
  "sticky top-0 z-10 whitespace-nowrap border-b border-app-line bg-app-surface/95 px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-[0.5px] text-app-subtle backdrop-blur";

export function td(compact: boolean, extra?: string) {
  return cx(
    "overflow-hidden border-b border-app-line/50 px-3 align-middle text-app-text text-ellipsis whitespace-nowrap transition-colors group-hover/row:bg-app-raised/35",
    compact ? "py-1.5 text-[11px]" : "py-2.5 text-xs",
    extra,
  );
}

export const mutedCell = "text-app-muted";

export const numeric = "tabular-nums";

export const badge =
  "inline-flex min-h-5 items-center rounded-md border border-app-border bg-app-raised px-1.5 py-px text-[10px] font-semibold text-app-muted";

export const button =
  "inline-flex min-h-8 items-center justify-center rounded-md border border-app-border bg-app-raised px-3 text-xs font-semibold text-app-muted transition hover:border-app-muted/50 hover:text-app-text disabled:cursor-not-allowed disabled:opacity-60";

export const primaryButton =
  "inline-flex min-h-8 items-center justify-center rounded-md border border-app-blue/50 bg-app-blue/15 px-3 text-xs font-semibold text-app-blue transition hover:border-app-blue hover:bg-app-blue/20 disabled:cursor-not-allowed disabled:opacity-60";

export const sectionLabel =
  "text-[10px] font-semibold uppercase tracking-[0.8px] text-app-subtle";
