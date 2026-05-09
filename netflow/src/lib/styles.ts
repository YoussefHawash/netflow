export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export const panel =
  "min-w-0 rounded-lg border border-app-line bg-app-surface p-4";

export const panelHeader = "mb-3 flex items-center justify-between gap-2.5";

export const panelTitle = "text-[13px] font-semibold text-app-text";

export const panelSubtitle = "text-[10px] text-app-subtle";

export const control =
  "min-h-7 w-full rounded-md border border-app-border bg-app-raised px-2 py-[5px] text-xs text-app-text outline-none transition placeholder:text-app-subtle hover:border-app-blue/40 focus-visible:border-app-blue focus-visible:ring-2 focus-visible:ring-app-blueStrong/20";

export const iconButton =
  "grid h-6 w-6 place-items-center rounded-md border border-app-border bg-app-raised text-[10px] text-app-muted transition hover:border-app-blue/40 hover:text-app-text aria-pressed:border-app-blueStrong aria-pressed:bg-app-blueStrong aria-pressed:text-white";

export const tableShell =
  "min-h-0 flex-1 overflow-auto border-b border-app-line";

export const th =
  "sticky top-0 z-10 whitespace-nowrap border-b border-app-line bg-app-surface px-1.5 py-1 text-left text-[10px] font-bold uppercase tracking-[0.5px] text-app-subtle";

export function td(compact: boolean, extra?: string) {
  return cx(
    "overflow-hidden border-b border-app-line/10 px-1.5 align-middle text-app-text text-ellipsis whitespace-nowrap transition-colors group-hover/row:bg-app-raised/40",
    compact ? "py-1 text-[11px]" : "py-[7px] text-xs",
    extra,
  );
}

export const mutedCell = "text-app-muted";

export const numeric = "tabular-nums";

export const badge =
  "inline-flex min-h-5 items-center rounded-[5px] border border-app-border bg-app-raised px-1.5 py-px text-[10px] font-bold text-app-muted";
