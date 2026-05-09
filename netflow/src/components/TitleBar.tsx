import { useSaveHistory } from "../lib/saveHistory";
import { cx } from "../lib/styles";
import type { ExportPeriod } from "../lib/types";

type Props = { paused: boolean };

export function TitleBar({ paused }: Props) {
  const saver = useSaveHistory();

  return (
    <header className="flex shrink-0 items-center gap-3 border-b border-app-line bg-app-surface px-4 py-2">
      <div>
        <h1 className="text-[15px] font-semibold text-app-text">
          Linux Network Monitor &amp; Controller
        </h1>
      </div>
      <div className="ml-auto flex items-center gap-3.5">
        <select
          value={saver.period}
          disabled={saver.saving}
          onChange={(event) =>
            saver.setPeriod(event.target.value as ExportPeriod)
          }
          className="min-h-7 rounded-md border border-app-border bg-app-raised px-2 text-[11px] text-app-muted outline-none transition hover:border-app-blue/40 hover:text-app-text focus-visible:border-app-blue"
          title="XML export range"
        >
          <option value="hour">Last hour</option>
          <option value="day">Today</option>
        </select>
        <button
          type="button"
          onClick={saver.save}
          disabled={saver.saving}
          className={cx(
            "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-app-border bg-app-raised px-2.5 py-1 text-[11px] text-app-muted transition",
            "hover:border-app-blue/40 hover:text-app-text",
            saver.saving && "opacity-60",
          )}
          title="Save the current snapshot to an XML file"
        >
          <span aria-hidden>⤓</span>
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
            "flex items-center gap-1.5 whitespace-nowrap text-xs transition-colors",
            paused ? "text-app-orange" : "text-app-green",
          )}
        >
          <div
            className={cx(
              "h-2 w-2 rounded-full transition",
              paused
                ? "bg-app-orange shadow-[0_0_0_4px_#f0883e1f]"
                : "bg-app-green shadow-[0_0_0_4px_#3fb95018]",
            )}
          />
          <span>{paused ? "Monitoring Paused" : "Monitoring Active"}</span>
        </div>
      </div>
    </header>
  );
}
