import type { ProcessTraffic, SortKey } from "./types";

export function formatRate(value: number) {
  if (value >= 1024) return `${(value / 1024).toFixed(1)} MB/s`;
  return `${value.toFixed(1)} KB/s`;
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
