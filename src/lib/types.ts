export type Direction = "all" | "inbound" | "outbound";
export type SortKey = "sent" | "received" | "total";
export type ExportPeriod = "hour" | "day";

export type ThreadInfo = {
  tid: number;
  name: string;
};

export type ProcessTraffic = {
  pid: number;
  name: string;
  user: string;
  flag: string;
  protocol: string;
  received: number;
  sent: number;
  history: number[];
  threads: ThreadInfo[];
};

export type ConnectionTraffic = {
  remote: string;
  flag: string;
  port: number;
  protocol: string;
  processName: string;
  pid: number;
  user: string;
  received: number;
  sent: number;
  state: string;
};

export type GroupedConnection = {
  remote: string;
  flag: string;
  port: string;
  protocol: string;
  processName: string;
  pid: string;
  user: string;
  state: string;
  received: number;
  sent: number;
};

export type HistoryBucket = {
  label: string;
  received: number;
  sent: number;
};

export type MonitorSnapshot = {
  availableInterfaces: string[];
  interfaceName: string;
  receivedRate: number;
  sentRate: number;
  receivedToday: number;
  sentToday: number;
  uptimeSeconds: number;
  processes: ProcessTraffic[];
  connections: ConnectionTraffic[];
  history: HistoryBucket[];
};

export type FirewallMode = "denylist" | "allowlist";

export type FirewallState = {
  mode: FirewallMode;
  pids: number[];
  ipv4: string[];
};

export type FilterState = {
  timeRange: string;
  interfaceName: string;
  processQuery: string;
  user: string;
  protocol: string;
  direction: Direction;
  minRate: number;
  processSort: SortKey;
  connectionSort: SortKey;
  historyRange: string;
  refreshMs: number;
  alertThreshold: number;
  paused: boolean;
};

export const DEFAULT_FILTERS: FilterState = {
  timeRange: "live",
  interfaceName: "",
  processQuery: "",
  user: "all",
  protocol: "all",
  direction: "all",
  minRate: 0,
  processSort: "sent",
  connectionSort: "total",
  historyRange: "24h",
  refreshMs: 1000,
  alertThreshold: 18,
  paused: false,
};
