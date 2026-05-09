import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { useCallback, useState } from "react";

export type SaveHistoryApi = {
  saving: boolean;
  lastPath: string | null;
  error: string | null;
  save: () => Promise<void>;
};

export function useSaveHistory(): SaveHistoryApi {
  const [saving, setSaving] = useState(false);
  const [lastPath, setLastPath] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setError(null);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = await save({
      defaultPath: `netflow-${stamp}.xml`,
      filters: [{ name: "XML", extensions: ["xml"] }],
    });
    if (!path) return;

    setSaving(true);
    try {
      await invoke("export_history", { path });
      setLastPath(path);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }, []);

  return { saving, lastPath, error, save: run };
}
