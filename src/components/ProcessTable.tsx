import { useState } from "react";
import { formatRate, totalRate } from "../lib/format";
import {
  badge,
  cx,
  mutedCell,
  numeric,
  panel,
  panelHeader,
  panelTitle,
  tableShell,
  td,
  th,
} from "../lib/styles";
import type { ProcessTraffic, SortKey, ThreadInfo } from "../lib/types";
import { SelectField } from "./SelectField";

type Props = {
  processes: ProcessTraffic[];
  totalProcessCount: number;
  sortKey: SortKey;
  onSortChange: (key: SortKey) => void;
};

export function ProcessTable({
  processes,
  totalProcessCount,
  sortKey,
  onSortChange,
}: Props) {
  const [expandedPid, setExpandedPid] = useState<number | null>(null);

  return (
    <section className={cx(panel, "flex min-h-0 flex-col overflow-hidden")}>
      <div className={panelHeader}>
        <div>
          <div className={panelTitle}>Process Usage</div>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-app-muted">
          <span>Sort by:</span>
          <SelectField
            variant="sort"
            wrapperClassName="w-[92px]"
            value={sortKey}
            onChange={(e) => onSortChange(e.target.value as SortKey)}
          >
            <option value="sent">Sent</option>
            <option value="received">Received</option>
            <option value="total">Total</option>
          </SelectField>
        </div>
      </div>

      <div className={cx(tableShell, "min-h-0")}>
        <table className="w-full min-w-[840px] table-fixed border-collapse">
          <colgroup>
            <col className="w-[68px]" />
            <col className="w-[160px]" />
            <col className="w-[82px]" />
            <col className="w-16" />
            <col className="w-[108px]" />
            <col className="w-24" />
            <col className="w-24" />
            <col className="w-24" />
          </colgroup>
          <thead>
            <tr>
              <th className={th}>PID</th>
              <th className={th}>Process</th>
              <th className={th}>User</th>
              <th className={th}>Proto</th>
              <th className={th}>Threads</th>
              <th className={th}>Received</th>
              <th className={th}>Sent</th>
              <th className={th}>Total</th>
            </tr>
          </thead>
          <tbody>
            {processes.length === 0 ? (
              <tr>
                <td colSpan={8}>
                  <div className="px-2 py-6 text-center text-app-muted">
                    No process traffic matches the current filters.
                  </div>
                </td>
              </tr>
            ) : (
              processes.map((process) => (
                <ProcessRow
                  key={process.pid}
                  process={process}
                  expanded={expandedPid === process.pid}
                  onToggle={() =>
                    setExpandedPid((current) =>
                      current === process.pid ? null : process.pid,
                    )
                  }
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-3 text-[11px] text-app-subtle">
        Showing {processes.length} of {totalProcessCount} active processes
      </div>
    </section>
  );
}

function ProcessRow({
  process,
  expanded,
  onToggle,
}: {
  process: ProcessTraffic;
  expanded: boolean;
  onToggle: () => void;
}) {
  const threadCount = process.threads.length;
  const threadLabel = `${threadCount} ${threadCount === 1 ? "thread" : "threads"}`;

  return (
    <>
      <tr className="group/row">
        <td className={td(false, cx(mutedCell, numeric))}>{process.pid}</td>
        <td className={td(false)}>
          <div
            className="flex min-w-0 items-center gap-1.5 overflow-hidden text-ellipsis whitespace-nowrap font-semibold"
            title={process.name}
          >
            {process.flag && (
              <span className="inline-block w-[26px] shrink-0 text-center text-[10px] font-bold text-app-muted">
                {process.flag}
              </span>
            )}
            <span className="overflow-hidden text-ellipsis whitespace-nowrap">
              {process.name}
            </span>
          </div>
        </td>
        <td className={td(false, mutedCell)}>
          {process.user || <span className="text-app-muted/50">—</span>}
        </td>
        <td className={td(false)}>
          <span className={badge}>{process.protocol}</span>
        </td>
        <td className={td(false)}>
          <button
            type="button"
            className={cx(
              "min-h-6 rounded-md border border-app-border bg-app-raised px-2 text-[10px] font-semibold text-app-muted transition hover:border-app-muted/50 hover:text-app-text",
              expanded && "border-app-blue/50 bg-app-blue/10 text-app-blue",
              threadCount === 0 && "cursor-default opacity-60",
            )}
            disabled={threadCount === 0}
            onClick={onToggle}
            title={threadTitle(process.threads)}
          >
            {threadLabel}
          </button>
        </td>
        <td className={td(false, cx("text-app-blue", numeric))}>
          {formatRate(process.received)}
        </td>
        <td className={td(false, cx("text-app-green", numeric))}>
          {formatRate(process.sent)}
        </td>
        <td className={td(false, cx("font-semibold", numeric))}>
          {formatRate(totalRate(process))}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td className={td(false, "bg-app-raised/25")} colSpan={8}>
            <ThreadList threads={process.threads} />
          </td>
        </tr>
      )}
    </>
  );
}

function ThreadList({ threads }: { threads: ThreadInfo[] }) {
  const visibleThreads = threads.slice(0, 24);
  const hiddenCount = Math.max(0, threads.length - visibleThreads.length);

  return (
    <div className="flex flex-wrap gap-1.5 py-1">
      {visibleThreads.map((thread) => (
        <span
          key={thread.tid}
          className="inline-flex max-w-[220px] items-center gap-1 rounded-md border border-app-border bg-app-shell px-2 py-1 text-[10px] text-app-muted"
          title={`${thread.tid} ${thread.name}`}
        >
          <span className={cx("font-semibold text-app-text", numeric)}>
            {thread.tid}
          </span>
          <span className="truncate">{thread.name}</span>
        </span>
      ))}
      {hiddenCount > 0 && (
        <span className="px-2 py-1 text-[10px] text-app-subtle">
          +{hiddenCount} more
        </span>
      )}
    </div>
  );
}

function threadTitle(threads: ThreadInfo[]) {
  if (threads.length === 0) return "No threads reported";
  return threads
    .slice(0, 12)
    .map((thread) => `${thread.tid}: ${thread.name}`)
    .join("\n");
}
