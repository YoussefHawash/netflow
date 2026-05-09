import { formatRate } from "../lib/format";
import type {
  GroupedConnection,
  MonitorSnapshot,
  ProcessTraffic,
} from "../lib/types";

type Props = {
  snapshot: MonitorSnapshot | null;
  processes: ProcessTraffic[];
  connections: GroupedConnection[];
};

export function StatCards({ snapshot, processes, connections }: Props) {
  const userCount = new Set(processes.map((p) => p.user).filter(Boolean)).size;
  const hostCount = new Set(connections.map((c) => c.remote)).size;

  return (
    <div className="grid grid-cols-4 gap-4">
      <Card
        marker="RX"
        label="Received"
        value={formatRate(snapshot?.receivedRate ?? 0)}
        sub="Current rate"
      />
      <Card
        marker="TX"
        label="Sent"
        value={formatRate(snapshot?.sentRate ?? 0)}
        sub="Current rate"
      />
      <Card
        marker="PID"
        label="Active Processes"
        value={String(processes.length)}
        sub={`${userCount} users`}
      />
      <Card
        marker="IP"
        label="Active Connections"
        value={String(connections.length)}
        sub={`${hostCount} remote hosts`}
      />
    </div>
  );
}

function Card(props: {
  marker: string;
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <article className="min-h-[92px] rounded-md border border-app-line bg-app-surface p-4 shadow-[0_1px_0_rgba(255,255,255,0.03)]">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="text-[10px] font-semibold uppercase tracking-[0.6px] text-app-subtle">
          {props.label}
        </div>
        <div className="rounded border border-app-border bg-app-raised px-1.5 py-0.5 text-[10px] font-semibold text-app-muted">
          {props.marker}
        </div>
      </div>
      <div className="min-w-0">
        <div className="overflow-hidden text-ellipsis whitespace-nowrap text-[24px] font-semibold leading-tight tabular-nums text-app-text">
          {props.value}
        </div>
        <div className="mt-1 text-[11px] text-app-subtle">{props.sub}</div>
      </div>
    </article>
  );
}
