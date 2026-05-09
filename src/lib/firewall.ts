import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import type { FirewallMode, FirewallState } from "./types";

export type FirewallApi = {
  state: FirewallState;
  loading: boolean;
  setMode: (mode: FirewallMode) => Promise<void>;
  addPid: (pid: number) => Promise<void>;
  removePid: (pid: number) => Promise<void>;
  clearPids: () => Promise<void>;
  addIp: (ip: string) => Promise<void>;
  removeIp: (ip: string) => Promise<void>;
  clearIps: () => Promise<void>;
  refresh: () => Promise<void>;
};

const EMPTY: FirewallState = { mode: "denylist", pids: [], ipv4: [] };

export function useFirewall(): FirewallApi {
  const [state, setState] = useState<FirewallState>(EMPTY);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const next = await invoke<FirewallState>("get_filter_state");
      setState(next);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const setMode = useCallback(
    async (mode: FirewallMode) => {
      await invoke("set_filter_mode", { mode });
      await refresh();
    },
    [refresh],
  );

  const addPid = useCallback(
    async (pid: number) => {
      await invoke("add_filter_pid", { pid });
      await refresh();
    },
    [refresh],
  );

  const removePid = useCallback(
    async (pid: number) => {
      await invoke("remove_filter_pid", { pid });
      await refresh();
    },
    [refresh],
  );

  const clearPids = useCallback(async () => {
    await invoke("clear_pid_filter");
    await refresh();
  }, [refresh]);

  const addIp = useCallback(
    async (ip: string) => {
      await invoke("add_filter_ip", { ip });
      await refresh();
    },
    [refresh],
  );

  const removeIp = useCallback(
    async (ip: string) => {
      await invoke("remove_filter_ip", { ip });
      await refresh();
    },
    [refresh],
  );

  const clearIps = useCallback(async () => {
    await invoke("clear_ip_filter");
    await refresh();
  }, [refresh]);

  return {
    state,
    loading,
    setMode,
    addPid,
    removePid,
    clearPids,
    addIp,
    removeIp,
    clearIps,
    refresh,
  };
}
