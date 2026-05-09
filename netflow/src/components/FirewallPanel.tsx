import { useState } from "react";
import { useFirewall } from "../lib/firewall";
import { badge, control, cx } from "../lib/styles";
import type { FirewallMode } from "../lib/types";

const MODE_LABEL: Record<FirewallMode, string> = {
  denylist: "Deny list",
  allowlist: "Allow list",
};

const MODE_HELP: Record<FirewallMode, string> = {
  denylist: "Listed PIDs / IPs are blocked. Everything else passes.",
  allowlist: "Only listed PIDs / IPs pass. Everything else is blocked.",
};

export function FirewallPanel() {
  const fw = useFirewall();
  const [pidInput, setPidInput] = useState("");
  const [ipInput, setIpInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const wrap = (fn: () => Promise<void>) => async () => {
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    }
  };

  const submitPid = wrap(async () => {
    const trimmed = pidInput.trim();
    if (!trimmed) return;
    const pid = Number(trimmed);
    if (!Number.isInteger(pid) || pid < 0) {
      setError("PID must be a non-negative integer");
      return;
    }
    await fw.addPid(pid);
    setPidInput("");
  });

  const submitIp = wrap(async () => {
    const trimmed = ipInput.trim();
    if (!trimmed) return;
    await fw.addIp(trimmed);
    setIpInput("");
  });

  return (
    <div className="flex flex-col gap-[7px] rounded-lg border border-app-line bg-app-surface p-[9px]">
      <div className="grid gap-0.5 px-0.5">
        <div className="text-[10px] font-bold uppercase tracking-[0.8px] text-app-subtle">
          Firewall (eBPF)
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1">
        {(["denylist", "allowlist"] as FirewallMode[]).map((m) => (
          <button
            key={m}
            type="button"
            onClick={wrap(() => fw.setMode(m))}
            className={cx(
              "min-h-[26px] rounded-md border border-app-border bg-app-raised text-[11px] text-app-muted transition hover:border-app-blue/40 hover:text-app-text",
              fw.state.mode === m &&
                "border-app-blueStrong/70 bg-app-blueStrong/15 text-app-blue",
            )}
          >
            {MODE_LABEL[m]}
          </button>
        ))}
      </div>
      <div className="px-0.5 text-[10px] leading-snug text-app-subtle">
        {MODE_HELP[fw.state.mode]}
      </div>

      <div className="grid gap-1">
        <label className="text-[11px] text-app-muted">Block PID</label>
        <div className="flex gap-1">
          <input
            className={control}
            type="text"
            inputMode="numeric"
            placeholder="e.g. 1532"
            value={pidInput}
            onChange={(e) => setPidInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitPid();
            }}
          />
          <button
            type="button"
            onClick={submitPid}
            className="min-h-7 rounded-md border border-app-border bg-app-raised px-2 text-[11px] text-app-muted transition hover:border-app-blue/40 hover:text-app-text"
          >
            Add
          </button>
        </div>
        <Chips
          items={fw.state.pids.map((p) => String(p))}
          onRemove={(item) => fw.removePid(Number(item))}
        />
        {fw.state.pids.length > 0 && (
          <button
            type="button"
            className="self-start text-[10px] text-app-subtle hover:text-app-muted"
            onClick={wrap(() => fw.clearPids())}
          >
            clear all
          </button>
        )}
      </div>

      <div className="grid gap-1">
        <label className="text-[11px] text-app-muted">Block remote IP (v4)</label>
        <div className="flex gap-1">
          <input
            className={control}
            type="text"
            placeholder="e.g. 1.2.3.4"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitIp();
            }}
          />
          <button
            type="button"
            onClick={submitIp}
            className="min-h-7 rounded-md border border-app-border bg-app-raised px-2 text-[11px] text-app-muted transition hover:border-app-blue/40 hover:text-app-text"
          >
            Add
          </button>
        </div>
        <Chips items={fw.state.ipv4} onRemove={(item) => fw.removeIp(item)} />
        {fw.state.ipv4.length > 0 && (
          <button
            type="button"
            className="self-start text-[10px] text-app-subtle hover:text-app-muted"
            onClick={wrap(() => fw.clearIps())}
          >
            clear all
          </button>
        )}
      </div>

      {error && (
        <div className="rounded border border-app-danger/40 bg-app-danger/10 px-1.5 py-1 text-[10px] text-app-danger">
          {error}
        </div>
      )}
    </div>
  );
}

function Chips({
  items,
  onRemove,
}: {
  items: string[];
  onRemove: (item: string) => Promise<void> | void;
}) {
  if (items.length === 0) {
    return (
      <div className="text-[10px] italic text-app-subtle">No entries.</div>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item) => (
        <button
          key={item}
          type="button"
          onClick={() => onRemove(item)}
          className={cx(
            badge,
            "cursor-pointer hover:border-app-danger/50 hover:text-app-danger",
          )}
          title="click to remove"
        >
          {item} ×
        </button>
      ))}
    </div>
  );
}
