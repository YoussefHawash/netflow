import type { ConnectionTraffic, ProcessTraffic, SortKey } from "./types";

export function formatRate(value: number) {
  if (value >= 1024) return `${(value / 1024).toFixed(1)} MB/s`;
  return `${value.toFixed(1)} KB/s`;
}

export function formatBytes(valueInMb: number) {
  if (valueInMb >= 1024) return `${(valueInMb / 1024).toFixed(2)} GB`;
  return `${valueInMb.toFixed(1)} MB`;
}

export function formatUptime(totalSeconds: number) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

function pad(value: number) {
  return String(value).padStart(2, "0");
}

export function totalRate(p: ProcessTraffic) {
  return p.received + p.sent;
}

export function sortableProcessValue(p: ProcessTraffic, key: SortKey) {
  if (key === "received") return p.received;
  if (key === "sent") return p.sent;
  return totalRate(p);
}

export function sortableConnectionValue(c: ConnectionTraffic, key: SortKey) {
  if (key === "received") return c.received;
  if (key === "sent") return c.sent;
  return c.received + c.sent;
}

export function processIconLabel(p: ProcessTraffic) {
  return (p.name.slice(0, 1) || "?").slice(0, 2).toUpperCase();
}

export function processIconClass(name: string) {
  const n = name.toLowerCase();
  if (n.includes("firefox")) return "bg-gradient-to-br from-app-orange to-app-danger";
  if (n.includes("ssh")) return "bg-gradient-to-br from-app-subtle to-app-muted";
  if (n.includes("curl")) return "bg-gradient-to-br from-app-blueStrong to-app-cyan";
  if (n.includes("apt")) return "bg-gradient-to-br from-violet-500 to-app-violet";
  if (n.includes("docker")) return "bg-gradient-to-br from-blue-700 to-app-blue";
  if (n.includes("resolve") || n.includes("systemd")) return "bg-gradient-to-br from-green-700 to-app-green";
  if (n.includes("python")) return "bg-gradient-to-br from-app-blueStrong to-app-yellow";
  if (n.includes("node") || n.includes("vite")) return "bg-gradient-to-br from-green-700 to-green-400";
  return "bg-gradient-to-br from-app-border to-app-muted";
}

export function nowTimestamp() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
