import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { useCallback, useState } from "react";
import type { ExportPeriod } from "./types";

export type SaveHistoryApi = {
  saving: boolean;
  lastPath: string | null;
  error: string | null;
  period: ExportPeriod;
  setPeriod: (period: ExportPeriod) => void;
  save: () => Promise<void>;
};

export function useSaveHistory(): SaveHistoryApi {
  const [saving, setSaving] = useState(false);
  const [lastPath, setLastPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [period, setPeriod] = useState<ExportPeriod>("hour");

  const run = useCallback(async () => {
    setError(null);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = await save({
      defaultPath: `netflow-${period}-${stamp}.xml`,
      filters: [{ name: "XML", extensions: ["xml"] }],
    });
    if (!path) return;

    setSaving(true);
    try {
      await invoke("export_history", { path, period });
      setLastPath(path);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }, [period]);

  return { saving, lastPath, error, period, setPeriod, save: run };
}
