import { useCallback, useEffect, useRef, useState } from "react";
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
  const lastEventSample = useRef<number | null>(null);

  const updateFilters = useCallback((patch: Partial<FilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);

  const { snapshot, trafficHistory, filteredProcesses, filteredConnections } =
    useMonitor(filters);

  useEffect(() => {
    if (!snapshot || filters.paused) return;

    const sampleId = snapshot.uptimeSeconds;
    if (sampleId <= 0 || sampleId === lastEventSample.current) return;
  }, [filters.alertThreshold, filters.paused, snapshot]);

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
        <section className="flex min-w-0 flex-1 flex-col gap-3 overflow-y-auto p-3.5">
          <StatCards
            snapshot={snapshot}
            processes={filteredProcesses}
            connections={filteredConnections}
          />

          <div className="grid grid-cols-[minmax(360px,0.95fr)_minmax(480px,1.25fr)] gap-3">
            <section className={panel}>
              <div className={panelHeader}>
                <div>
                  <div className={panelTitle}>Real-Time Traffic Flow</div>
                  <div className={panelSubtitle}>Bandwidth (KB/s)</div>
                </div>
                <div className="flex flex-wrap gap-3">
                  <Legend color="bg-app-green" label="Inbound" />
                  <Legend color="bg-app-violet" label="Outbound" />
                </div>
              </div>
              <TrafficChart history={trafficHistory} />
            </section>

            <ProcessTable
              processes={filteredProcesses}
              totalProcessCount={snapshot?.processes.length ?? 0}
              sortKey={filters.processSort}
              onSortChange={(processSort) => updateFilters({ processSort })}
            />
          </div>

          <div>
            <ConnectionTable
              connections={filteredConnections}
              sortKey={filters.connectionSort}
              onSortChange={(connectionSort) =>
                updateFilters({ connectionSort })
              }
            />
          </div>
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
          square ? "h-2.5 w-2.5 rounded-sm" : "h-0.5 w-5 rounded-sm",
        )}
      />
      {label}
    </div>
  );
}
