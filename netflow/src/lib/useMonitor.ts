import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import { sortableProcessValue, totalRate } from "./format";
import type {
  ConnectionTraffic,
  FilterState,
  GroupedConnection,
  MonitorSnapshot,
  ProcessTraffic,
} from "./types";

const MAX_TRAFFIC_POINTS = 34;

export type TrafficHistory = { received: number[]; sent: number[] };

export function useMonitor(filters: FilterState) {
  const [snapshot, setSnapshot] = useState<MonitorSnapshot | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<TrafficHistory>(() => ({
    received: Array.from({ length: MAX_TRAFFIC_POINTS }, () => 0),
    sent: Array.from({ length: MAX_TRAFFIC_POINTS }, () => 0),
  }));

  useEffect(() => {
    if (filters.paused) return;

    let cancelled = false;

    const tick = async () => {
      const next = await invoke<MonitorSnapshot>("get_network_snapshot", {
        interfaceName: filters.interfaceName || null,
      });

      if (cancelled) return;
      setSnapshot(next);
      setTrafficHistory((prev) =>
        pushTrafficPoint(prev, next.receivedRate, next.sentRate),
      );
    };

    tick();
    const id = window.setInterval(tick, filters.refreshMs);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [
    filters.paused,
    filters.refreshMs,
    filters.interfaceName,
  ]);

  const filteredProcesses = useMemo(
    () => (snapshot ? filterProcesses(snapshot.processes, filters) : []),
    [snapshot, filters],
  );

  const filteredConnections = useMemo(
    () => (snapshot ? filterConnections(snapshot.connections, filters) : []),
    [snapshot, filters],
  );

  return { snapshot, trafficHistory, filteredProcesses, filteredConnections };
}

function pushTrafficPoint(
  prev: TrafficHistory,
  rx: number,
  tx: number,
): TrafficHistory {
  const received = [...prev.received, rx].slice(-MAX_TRAFFIC_POINTS);
  const sent = [...prev.sent, tx].slice(-MAX_TRAFFIC_POINTS);
  return { received, sent };
}

function filterProcesses(processes: ProcessTraffic[], filters: FilterState) {
  return processes
    .filter((p) =>
      matches(
        p.name,
        p.pid,
        p.user,
        p.protocol,
        totalRate(p),
        p.received,
        p.sent,
        filters,
      ),
    )
    .sort(
      (a, b) =>
        sortableProcessValue(b, filters.processSort) -
        sortableProcessValue(a, filters.processSort),
    );
}

function filterConnections(
  connections: ConnectionTraffic[],
  filters: FilterState,
): GroupedConnection[] {
  const filtered = connections.filter((c) =>
    matches(
      c.processName,
      c.pid,
      c.user,
      c.protocol,
      c.received + c.sent,
      c.received,
      c.sent,
      filters,
    ),
  );

  const groups = new Map<string, ConnectionTraffic[]>();
  for (const c of filtered) {
    const bucket = groups.get(c.remote);
    if (bucket) bucket.push(c);
    else groups.set(c.remote, [c]);
  }

  const result: GroupedConnection[] = [];
  for (const conns of groups.values()) {
    const ports = [...new Set(conns.map((c) => c.port))];
    const pids = [...new Set(conns.map((c) => c.pid))];
    const protocols = [...new Set(conns.map((c) => c.protocol))];
    const users = [...new Set(conns.map((c) => c.user).filter(Boolean))];
    const states = [...new Set(conns.map((c) => c.state).filter(Boolean))];
    const totalRx = conns.reduce((s, c) => s + c.received, 0);
    const totalTx = conns.reduce((s, c) => s + c.sent, 0);

    result.push({
      remote: conns[0].remote,
      flag: conns[0].flag,
      port: ports.length === 1 ? String(ports[0]) : "multi",
      protocol: protocols.length === 1 ? protocols[0] : "multi",
      processName: conns[0].processName,
      pid: pids.length === 1 ? String(pids[0]) : "multi",
      user: users.length === 0 ? "" : users.length === 1 ? users[0] : "multi",
      state:
        states.length === 0 ? "" : states.length === 1 ? states[0] : "multi",
      received: totalRx,
      sent: totalTx,
    });
  }

  const sortValue = (g: GroupedConnection) => {
    if (filters.connectionSort === "received") return g.received;
    if (filters.connectionSort === "sent") return g.sent;
    return g.received + g.sent;
  };

  return result.sort((a, b) => sortValue(b) - sortValue(a));
}

function matches(
  name: string,
  pid: number,
  user: string,
  protocol: string,
  total: number,
  rx: number,
  tx: number,
  f: FilterState,
) {
  const q = f.processQuery.trim().toLowerCase();
  const queryMatches =
    !q || name.toLowerCase().includes(q) || String(pid).includes(q);
  const userMatches = f.user === "all" || user === f.user;
  const protocolMatches = f.protocol === "all" || protocol === f.protocol;
  const rateMatches = total >= f.minRate;
  const directionMatches =
    f.direction === "all" ||
    (f.direction === "inbound" && rx >= tx) ||
    (f.direction === "outbound" && tx >= rx);
  return (
    queryMatches &&
    userMatches &&
    protocolMatches &&
    rateMatches &&
    directionMatches
  );
}
