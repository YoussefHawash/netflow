import { invoke } from "@tauri-apps/api/core";
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
    setSaving(true);
    try {
      const written = await invoke<string>("export_history", { period });
      setLastPath(written);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }, [period]);

  return { saving, lastPath, error, period, setPeriod, save: run };
}
