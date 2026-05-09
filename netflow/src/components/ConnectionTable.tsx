import { formatRate } from "../lib/format";
import {
  badge,
  cx,
  mutedCell,
  numeric,
  panel,
  panelHeader,
  panelSubtitle,
  panelTitle,
  tableShell,
  td,
  th,
} from "../lib/styles";
import type { GroupedConnection, SortKey } from "../lib/types";
import { SelectField } from "./SelectField";

type Props = {
  connections: GroupedConnection[];
  sortKey: SortKey;
  onSortChange: (key: SortKey) => void;
};

export function ConnectionTable({ connections, sortKey, onSortChange }: Props) {
  return (
    <section className={cx(panel, "flex h-[380px] flex-col overflow-hidden")}>
      <div className={panelHeader}>
        <div>
          <div className={panelTitle}>Remote Connections</div>
          <div className={panelSubtitle}>
            Host, port, process, state, and throughput
          </div>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-app-muted">
          <span>Sort by:</span>
          <SelectField
            variant="sort"
            wrapperClassName="w-[98px]"
            value={sortKey}
            onChange={(e) => onSortChange(e.target.value as SortKey)}
          >
            <option value="total">Total</option>
            <option value="received">Received</option>
            <option value="sent">Sent</option>
          </SelectField>
        </div>
      </div>

      <div className={cx(tableShell, "min-h-0")}>
        <table className="w-full min-w-[920px] table-fixed border-collapse">
          <colgroup>
            <col className="w-44" />
            <col className="w-[62px]" />
            <col className="w-16" />
            <col className="w-[150px]" />
            <col className="w-[82px]" />
            <col className="w-28" />
            <col className="w-24" />
            <col className="w-24" />
            <col className="w-24" />
          </colgroup>
          <thead>
            <tr>
              <th className={th}>Remote IP / Host</th>
              <th className={th}>Port</th>
              <th className={th}>Proto</th>
              <th className={th}>Process (PID)</th>
              <th className={th}>User</th>
              <th className={th}>State</th>
              <th className={th}>Received</th>
              <th className={th}>Sent</th>
              <th className={th}>Total</th>
            </tr>
          </thead>
          <tbody>
            {connections.length === 0 ? (
              <tr>
                <td colSpan={9}>
                  <div className="px-2 py-6 text-center text-app-muted">
                    No active connections match the current filters.
                  </div>
                </td>
              </tr>
            ) : (
              connections.map((conn) => (
                <ConnectionRow key={connectionKey(conn)} connection={conn} />
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ConnectionRow({
  connection,
}: {
  connection: GroupedConnection;
}) {
  const procLabel =
    connection.processName
      ? `${connection.processName} (${connection.pid})`
      : connection.pid !== "0"
        ? `(${connection.pid})`
        : "—";

  return (
    <tr className="group/row">
      <td className={td(false)}>
        {connection.flag && (
          <span className="mr-2 inline-block min-w-[22px] text-center text-[10px] font-semibold text-app-subtle">
            {connection.flag}
          </span>
        )}
        <span className="font-semibold text-app-text" title={connection.remote}>
          {connection.remote}
        </span>
      </td>
      <td className={td(false, cx(mutedCell, numeric))}>
        {connection.port === "multi" ? (
          <span className="rounded bg-app-line px-1 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-app-muted">
            multi
          </span>
        ) : (
          connection.port
        )}
      </td>
      <td className={td(false)}>
        <span className={badge}>{connection.protocol}</span>
      </td>
      <td className={td(false, mutedCell)} title={procLabel}>
        {procLabel}
      </td>
      <td className={td(false, mutedCell)}>
        {connection.user || <span className="text-app-muted/50">—</span>}
      </td>
      <td className={td(false)}>
        {connection.state ? (
          <span className={cx(badge, stateBadgeClass(connection.state))}>
            {connection.state}
          </span>
        ) : (
          <span className="text-app-muted/50">—</span>
        )}
      </td>
      <td className={td(false, cx("text-app-blue", numeric))}>
        {formatRate(connection.received)}
      </td>
      <td className={td(false, cx("text-app-green", numeric))}>
        {formatRate(connection.sent)}
      </td>
      <td className={td(false, cx("font-semibold", numeric))}>
        {formatRate(connection.received + connection.sent)}
      </td>
    </tr>
  );
}

function stateBadgeClass(state: string) {
  if (state === "ESTABLISHED") {
    return "border-app-green/30 bg-app-green/10 text-app-green";
  }
  if (state === "LISTEN") {
    return "border-app-blue/30 bg-app-blue/10 text-app-blue";
  }
  return "border-app-border bg-app-raised text-app-muted";
}

function connectionKey(c: GroupedConnection) {
  return `${c.remote}|${c.protocol}`;
}
