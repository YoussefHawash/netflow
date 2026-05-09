import type { ReactNode } from "react";
import { formatRate, formatUptime } from "../lib/format";
import { control, cx, primaryButton, sectionLabel } from "../lib/styles";
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
    <aside className="flex w-[260px] shrink-0 flex-col overflow-y-auto border-r border-app-line bg-app-shell">
      <section
        className="flex flex-col gap-4 p-4"
        aria-label="Monitor controls"
      >
        <div className="grid gap-1">
          <div className={sectionLabel}>Controls</div>
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
                    "min-h-8 rounded-md border border-app-border bg-app-raised text-[11px] font-semibold text-app-muted transition hover:border-app-muted/50 hover:text-app-text",
                    filters.direction === dir &&
                      "border-app-blue/50 bg-app-blue/10 text-app-blue",
                  )}
                  onClick={() => onChange({ direction: dir })}
                >
                  {dir === "all" ? "All" : dir === "inbound" ? "RX" : "TX"}
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
                primaryButton,
                "w-full",
                filters.paused &&
                  "border-app-orange/45 bg-app-orange/10 text-app-orange hover:border-app-orange/70 hover:bg-app-orange/15",
              )}
              onClick={togglePause}
            >
              {filters.paused ? "Resume" : "Pause"}
            </button>
          </div>
        </ControlBlock>

        <FirewallPanel />
      </section>

      <section className="mt-auto border-t border-app-line px-4 py-4">
        <div className={sectionLabel}>System</div>
        <StatRow
          label={
            <>
              <span className="text-app-blue">RX</span> Rate
            </>
          }
          value={formatRate(snapshot?.receivedRate ?? 0)}
          valueClass="text-app-blue"
        />
        <StatRow
          label={
            <>
              <span className="text-app-green">TX</span> Rate
            </>
          }
          value={formatRate(snapshot?.sentRate ?? 0)}
          valueClass="text-app-green"
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
    <div className="flex flex-col gap-3 border-t border-app-line pt-4 first:border-t-0 first:pt-0">
      {children}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1.5">
      <label className="text-[11px] font-medium text-app-muted">{label}</label>
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
    <div className="flex items-center justify-between gap-2 py-1">
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
