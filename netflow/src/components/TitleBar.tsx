import { useSaveHistory } from "../lib/saveHistory";
import { button, cx } from "../lib/styles";
import type { ExportPeriod } from "../lib/types";

type Props = { paused: boolean };

export function TitleBar({ paused }: Props) {
  const saver = useSaveHistory();

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-app-line bg-app-shell px-5">
      <div className="min-w-0">
        <h1 className="truncate text-[15px] font-semibold text-app-text">
          Netflow Monitor
        </h1>
      </div>
      <div className="ml-auto flex items-center gap-2.5">
        <select
          value={saver.period}
          disabled={saver.saving}
          onChange={(event) =>
            saver.setPeriod(event.target.value as ExportPeriod)
          }
          className="min-h-8 rounded-md border border-app-border bg-app-raised px-2.5 text-xs font-medium text-app-muted outline-none transition hover:border-app-muted/50 hover:text-app-text focus-visible:border-app-blue focus-visible:ring-2 focus-visible:ring-app-blue/15"
          title="XML export range"
        >
          <option value="hour">Last hour</option>
          <option value="day">Today</option>
        </select>
        <button
          type="button"
          onClick={saver.save}
          disabled={saver.saving}
          className={cx(button, "gap-1.5 whitespace-nowrap")}
          title="Save the current snapshot to an XML file"
        >
          <span aria-hidden>↓</span>
          <span>{saver.saving ? "Saving…" : "Save XML"}</span>
        </button>
        {saver.lastPath && !saver.saving && (
          <span
            className="max-w-[260px] truncate text-[10px] text-app-subtle"
            title={saver.lastPath}
          >
            saved to {saver.lastPath}
          </span>
        )}
        {saver.error && (
          <span
            className="max-w-[260px] truncate text-[10px] text-app-danger"
            title={saver.error}
          >
            {saver.error}
          </span>
        )}
        <div
          className={cx(
            "ml-1 flex items-center gap-2 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
            paused
              ? "border-app-orange/30 bg-app-orange/10 text-app-orange"
              : "border-app-green/25 bg-app-green/10 text-app-green",
          )}
        >
          <div
            className={cx(
              "h-1.5 w-1.5 rounded-full transition",
              paused ? "bg-app-orange" : "bg-app-green",
            )}
          />
          <span>{paused ? "Paused" : "Live"}</span>
        </div>
      </div>
    </header>
  );
}
