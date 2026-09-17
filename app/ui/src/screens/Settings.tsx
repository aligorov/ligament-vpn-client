import { useState } from "react";
import { useApp } from "../App";
import { rpc } from "../rpc";
import { pickConfigFile } from "../shell";
import { detectKind, type Settings as SettingsT } from "../types";

export function SettingsScreen() {
  const { s, tr, go, refresh, setLoggedIn } = useApp();
  const initial = s.settings;
  const [draft, setDraft] = useState<SettingsT | null>(initial);
  const [advanced, setAdvanced] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // импорт
  const [importText, setImportText] = useState("");
  const [importName, setImportName] = useState("");
  const [importBusy, setImportBusy] = useState(false);

  if (!draft) return null;

  const patch = (p: Partial<SettingsT>) => {
    setDraft({ ...draft, ...p } as SettingsT);
  };

  const save = async () => {
    setError(null);
    try {
      await rpc.setSettings(draft);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1500);
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  const doImport = async () => {
    setError(null);
    const text = importText.trim();
    if (!text) {
      setError(tr("emptyConfig"));
      return;
    }
    if (!detectKind(text)) {
      setError(tr("badConfig"));
      return;
    }
    setImportBusy(true);
    try {
      await rpc.importProfile(importName.trim() || "Импорт", text);
      setImportText("");
      setImportName("");
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setImportBusy(false);
    }
  };

  const onPickFile = async () => {
    const content = await pickConfigFile();
    if (content) setImportText(content);
  };

  const logout = async () => {
    try {
      await rpc.portalLogout();
    } catch {
      // не критично
    }
    setLoggedIn(false);
    go("login");
  };

  return (
    <div className="screen settings-screen">
      <header className="topbar">
        <button className="icon-btn" title={tr("back")} onClick={() => go("main")}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M15 5l-7 7 7 7" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
        <div className="topbar-title">{tr("settings")}</div>
        <div className="topbar-actions">
          <button className="btn btn-primary btn-small" onClick={save}>
            {savedFlash ? tr("saved") : tr("save")}
          </button>
        </div>
      </header>

      <div className="toggles">
        <Toggle
          label={tr("autostart")}
          value={draft.autostart}
          onChange={(v) => patch({ autostart: v })}
        />
        <Toggle
          label={tr("autoConnect")}
          value={draft.autoConnect}
          onChange={(v) => patch({ autoConnect: v })}
        />
        <Toggle
          label={tr("killSwitch")}
          value={draft.killSwitch}
          onChange={(v) => patch({ killSwitch: v })}
        />
      </div>

      <button className="link-btn" onClick={() => setAdvanced((v) => !v)}>
        {tr("advanced")} {advanced ? "▾" : "▸"}
      </button>

      {advanced && (
        <div className="advanced">
          <label className="field">
            <span>{tr("socksPort")}</span>
            <input
              className="input"
              type="number"
              min={1024}
              max={65535}
              value={draft.socksPort}
              onChange={(e) => patch({ socksPort: Number(e.target.value) || 10808 })}
            />
          </label>
          <label className="field">
            <span>{tr("portalUrl")}</span>
            <input
              className="input"
              value={draft.portalUrl}
              onChange={(e) => patch({ portalUrl: e.target.value })}
            />
          </label>
          <label className="field">
            <span>{tr("language")}</span>
            <select
              className="input"
              value={draft.language}
              onChange={(e) => patch({ language: e.target.value as "ru" | "en" })}
            >
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </label>
        </div>
      )}

      <div className="section">
        <div className="section-label">{tr("importTitle")}</div>
        <button className="btn btn-ghost" onClick={onPickFile}>
          {tr("importFile")}
        </button>
        <textarea
          className="input mono"
          rows={4}
          placeholder={tr("importPaste")}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
        />
        {importText && (
          <div className="muted small">{tr("importDetected")}: {detectKind(importText) ?? "?"}</div>
        )}
        <input
          className="input"
          placeholder={tr("importName")}
          value={importName}
          onChange={(e) => setImportName(e.target.value)}
        />
        <button className="btn btn-primary" disabled={importBusy} onClick={doImport}>
          {tr("importBtn")}
        </button>
      </div>

      <div className="section">
        <button className="btn btn-ghost" onClick={() => void rpc.portalSync().then(refresh).catch((e) => setError(String(e)))}>
          {tr("syncNow")}
        </button>
        <button className="btn btn-ghost danger" onClick={logout}>
          {tr("logout")}
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
    </div>
  );
}

// AllowedIPs приходят в конфиге профиля с портала; локальная правка — v0.2.

function Toggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="toggle-row">
      <span>{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={value}
        className={`toggle ${value ? "on" : ""}`}
        onClick={() => onChange(!value)}
      >
        <span className="toggle-knob" />
      </button>
    </label>
  );
}
