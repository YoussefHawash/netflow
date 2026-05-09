import { useCallback, useState } from "react";
import {
  cx,
  panel,
  panelHeader,
  panelSubtitle,
  panelTitle,
} from "../lib/styles";
import { DEFAULT_FILTERS, type FilterState } from "../lib/types";
import { useMonitor } from "../lib/useMonitor";
import { ConnectionTable } from "./ConnectionTable";
import { ProcessTable } from "./ProcessTable";
import { Sidebar } from "./Sidebar";
import { StatCards } from "./StatCards";
import { TitleBar } from "./TitleBar";
import { TrafficChart } from "./TrafficChart";

export function App() {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  const updateFilters = useCallback((patch: Partial<FilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);

  const { snapshot, trafficHistory, filteredProcesses, filteredConnections } =
    useMonitor(filters);

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-app-bg text-app-text">
      <TitleBar paused={filters.paused} />
      <main className="flex min-h-0 flex-1 overflow-hidden">
        <Sidebar
          filters={filters}
          snapshot={snapshot}
          activeProcessCount={filteredProcesses.length}
          onChange={updateFilters}
        />
        <section className="flex min-w-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
          <StatCards
            snapshot={snapshot}
            processes={filteredProcesses}
            connections={filteredConnections}
          />

          <div className="grid min-h-[380px] grid-cols-[minmax(400px,0.92fr)_minmax(560px,1.18fr)] gap-4">
            <section className={cx(panel, "flex min-h-0 flex-col")}>
              <div className={panelHeader}>
                <div>
                  <div className={panelTitle}>Traffic Flow</div>
                  <div className={panelSubtitle}>Live bandwidth in KB/s</div>
                </div>
                <div className="flex flex-wrap gap-3">
                  <Legend color="bg-app-blue" label="Received" />
                  <Legend color="bg-app-green" label="Sent" />
                </div>
              </div>
              <div className="min-h-0 flex-1">
                <TrafficChart history={trafficHistory} />
              </div>
            </section>

            <ProcessTable
              processes={filteredProcesses}
              totalProcessCount={snapshot?.processes.length ?? 0}
              sortKey={filters.processSort}
              onSortChange={(processSort) => updateFilters({ processSort })}
            />
          </div>

          <ConnectionTable
            connections={filteredConnections}
            sortKey={filters.connectionSort}
            onSortChange={(connectionSort) => updateFilters({ connectionSort })}
          />
        </section>
      </main>
    </div>
  );
}

function Legend({
  color,
  label,
  square = false,
}: {
  color: string;
  label: string;
  square?: boolean;
}) {
  return (
    <div className="flex items-center gap-1.5 whitespace-nowrap text-[11px] text-app-muted">
      <div
        className={cx(
          color,
          square ? "h-2.5 w-2.5 rounded-sm" : "h-0.5 w-4 rounded-sm",
        )}
      />
      {label}
    </div>
  );
}
