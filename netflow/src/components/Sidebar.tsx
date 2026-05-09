import type { ReactNode } from "react";
import { formatRate, formatUptime } from "../lib/format";
import { control, cx } from "../lib/styles";
import type { Direction, FilterState, MonitorSnapshot } from "../lib/types";
import { FirewallPanel } from "./FirewallPanel";
import { SelectField } from "./SelectField";

type Props = {
  filters: FilterState;
  snapshot: MonitorSnapshot | null;
  activeProcessCount: number;
  onChange: (patch: Partial<FilterState>) => void;
};

export function Sidebar({
  filters,
  snapshot,
  activeProcessCount,
  onChange,
}: Props) {
  const togglePause = () => onChange({ paused: !filters.paused });
  const interfaceValue = filters.interfaceName || snapshot?.interfaceName || "";
  const interfaces = snapshot?.availableInterfaces.length
    ? snapshot.availableInterfaces
    : interfaceValue
      ? [interfaceValue]
      : [];
  const users = Array.from(
    new Set(snapshot?.processes.map((process) => process.user).filter(Boolean)),
  ).sort();
  const userOptions =
    filters.user !== "all" && !users.includes(filters.user)
      ? [...users, filters.user].sort()
      : users;

  return (
    <aside className="flex w-[214px] shrink-0 flex-col overflow-y-auto border-r border-app-line bg-app-surface">
      <section
        className="flex flex-col gap-2.5 p-3"
        aria-label="Monitor controls"
      >
        <div className="grid gap-0.5 px-0.5 pt-0.5">
          <div className="text-[10px] font-bold uppercase tracking-[0.8px] text-app-subtle">
            Options
          </div>
        </div>

        <ControlBlock>
          <Row label="Interface">
            <SelectField
              value={interfaceValue}
              onChange={(e) => onChange({ interfaceName: e.target.value })}
            >
              {interfaces.length === 0 ? (
                <option value="">Detecting...</option>
              ) : (
                interfaces.map((iface) => (
                  <option key={iface} value={iface}>
                    {iface}
                  </option>
                ))
              )}
            </SelectField>
          </Row>
        </ControlBlock>

        <ControlBlock>
          <Row label="Process or PID">
            <input
              className={control}
              type="text"
              placeholder="firefox, ssh, 1532"
              value={filters.processQuery}
              onChange={(e) => onChange({ processQuery: e.target.value })}
            />
          </Row>

          <div className="grid grid-cols-2 gap-2">
            <Row label="User">
              <SelectField
                value={filters.user}
                onChange={(e) => onChange({ user: e.target.value })}
              >
                <option value="all">All Users</option>
                {userOptions.map((user) => (
                  <option key={user} value={user}>
                    {user}
                  </option>
                ))}
              </SelectField>
            </Row>

            <Row label="Protocol">
              <SelectField
                value={filters.protocol}
                onChange={(e) => onChange({ protocol: e.target.value })}
              >
                <option value="all">All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </SelectField>
            </Row>
          </div>

          <Row label="Traffic Direction">
            <div className="grid grid-cols-3 gap-1">
              {(["all", "inbound", "outbound"] as Direction[]).map((dir) => (
                <button
                  key={dir}
                  type="button"
                  className={cx(
                    "min-h-[26px] rounded-md border border-app-border bg-app-raised text-[11px] text-app-muted transition hover:border-app-blue/40 hover:text-app-text",
                    filters.direction === dir &&
                      "border-app-blue/40 bg-app-blueStrong/15 text-app-blue",
                  )}
                  onClick={() => onChange({ direction: dir })}
                >
                  {dir === "all" ? "All" : dir === "inbound" ? "↓ In" : "↑ Out"}
                </button>
              ))}
            </div>
          </Row>

          <Row label="Minimum Rate">
            <input
              className={control}
              type="number"
              min={0}
              step={0.5}
              value={filters.minRate}
              onChange={(e) =>
                onChange({ minRate: Number(e.target.value) || 0 })
              }
            />
          </Row>
        </ControlBlock>

        <ControlBlock>
          <Row label="Refresh">
            <SelectField
              value={filters.refreshMs}
              onChange={(e) => onChange({ refreshMs: Number(e.target.value) })}
            >
              <option value={500}>500 ms</option>
              <option value={1000}>1 sec</option>
              <option value={2000}>2 sec</option>
              <option value={5000}>5 sec</option>
            </SelectField>
          </Row>

          <div className="grid grid-cols-1 gap-1.5">
            <button
              type="button"
              className={cx(
                "min-h-7 rounded-md border border-app-blueStrong bg-app-blueStrong text-[11px] font-semibold text-white transition hover:border-app-blue hover:bg-app-blue",
                filters.paused &&
                  "border-app-orange bg-app-orange hover:border-app-orangeDark hover:bg-app-orangeDark",
              )}
              onClick={togglePause}
            >
              {filters.paused ? "Resume" : "Pause"}
            </button>
          </div>
        </ControlBlock>

        <FirewallPanel />
      </section>

      <section className="mt-auto border-t border-app-line px-4 py-3">
        <div className="text-[10px] font-bold uppercase tracking-[0.8px] text-app-subtle">
          System Status
        </div>
        <StatRow
          label={
            <>
              <span className="text-app-green">↓</span> Total RX Rate
            </>
          }
          value={`↓ ${formatRate(snapshot?.receivedRate ?? 0)}`}
          valueClass="text-app-green"
        />
        <StatRow
          label={
            <>
              <span className="text-app-blue">↑</span> Total TX Rate
            </>
          }
          value={`↑ ${formatRate(snapshot?.sentRate ?? 0)}`}
          valueClass="text-app-blue"
        />
        <StatRow label="Active Processes" value={String(activeProcessCount)} />
        <StatRow
          label="Monitoring Uptime"
          value={formatUptime(snapshot?.uptimeSeconds ?? 0)}
        />
      </section>
    </aside>
  );
}

function ControlBlock({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col gap-[7px] rounded-lg border border-app-line bg-app-surface p-[9px]">
      {children}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1">
      <label className="text-[11px] text-app-muted">{label}</label>
      {children}
    </div>
  );
}

function StatRow({
  label,
  value,
  valueClass,
}: {
  label: ReactNode;
  value: string;
  valueClass?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-2 py-[3px]">
      <span className="flex items-center gap-1.5 text-[11px] text-app-muted">
        {label}
      </span>
      <span
        className={cx(
          "whitespace-nowrap text-[11px] font-semibold tabular-nums text-app-text",
          valueClass,
        )}
      >
        {value}
      </span>
    </div>
  );
}
