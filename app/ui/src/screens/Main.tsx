import { useEffect, useRef, useState } from "react";
import { useApp } from "../App";
import { rpc } from "../rpc";
import type { Profile, VpnStatus } from "../types";

const KIND_LABEL: Record<Profile["kind"], string> = {
  wireguard: "WireGuard",
  openvpn: "OpenVPN",
  vless: "VLESS",
};

function humanBytes(n: number): string {
  if (n < 1024) return `${n} Б`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} КБ`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} МБ`;
  return `${(n / 1024 ** 3).toFixed(2)} ГБ`;
}

function fmtDuration(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function Main() {
  const { s, tr, go } = useApp();
  const [selected, setSelected] = useState<string | null>(null);
  const [needCreds, setNeedCreds] = useState<Profile | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [now, setNow] = useState(Date.now());
  const connectedSince = useRef<number | null>(null);

  const status: VpnStatus = s.state.status;
  const active =
    s.profiles.find((p) => p.id === s.state.activeProfileId) ??
    s.profiles.find((p) => p.id === selected) ??
    s.profiles[0] ??
    null;

  useEffect(() => {
    if (status === "connected" && connectedSince.current === null) {
      connectedSince.current = Date.now();
    }
    if (status !== "connected") connectedSince.current = null;
  }, [status]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const busy = status === "connecting" || status === "disconnecting";

  // На macOS/Linux работает только VLESS (SOCKS-режим): WG/OpenVPN — Windows.
  const windowsOnly = s.platform !== "windows" && active !== null && active.kind !== "vless";

  async function onButton() {
    if (status === "connected") {
      await rpc.disconnect().catch(() => undefined);
      return;
    }
    if (busy || !active) return;
    if (active.kind === "openvpn") {
      // OpenVPN требует логин/пароль AD — спрашиваем при каждом подключении.
      setNeedCreds(active);
      return;
    }
    await doConnect(active.id);
  }

  async function doConnect(profileId: string, creds?: { username: string; password: string }) {
    try {
      await rpc.connect(profileId, creds);
      setSelected(profileId);
    } catch {
      // ошибка придёт через state.changed (error-статус) — показываем из s.state.error
    } finally {
      setNeedCreds(null);
    }
  }

  const sessionSec =
    status === "connected" && connectedSince.current !== null
      ? Math.max(0, (now - connectedSince.current) / 1000)
      : 0;

  return (
    <div className="screen main-screen">
      <header className="topbar">
        <div className="topbar-title">{tr("appName")}</div>
        <div className="topbar-actions">
          <button className="icon-btn" title={tr("logs")} onClick={() => go("logs")}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 6h16M4 12h16M4 18h10" strokeLinecap="round" />
            </svg>
          </button>
          <button className="icon-btn" title={tr("settings")} onClick={() => go("settings")}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
        </div>
      </header>

      <div className="connect-zone">
        <button
          className={`connect-btn status-${status}`}
          onClick={onButton}
          disabled={busy || windowsOnly || (!active && status !== "connected")}
          aria-label={
            status === "connected" ? tr("disconnect") : tr("connect")
          }
        >
          <span className="connect-btn-inner">
            {status === "connected" && (
              <svg className="check-icon" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
            {status === "connecting" && <span className="spinner spinner-light" />}
            {status === "disconnected" && (
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M15 7a5 5 0 0 1 0 10h-2M9 7a5 5 0 0 0 0 10h2" strokeLinecap="round" />
                <path d="M12 9v6" strokeLinecap="round" />
              </svg>
            )}
            {status === "error" && (
              <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 8v5M12 16.5v.5" strokeLinecap="round" />
                <circle cx="12" cy="12" r="9" />
              </svg>
            )}
            {status === "disconnecting" && <span className="spinner spinner-light" />}
          </span>
        </button>
        <div className="connect-label">
          {status === "connected"
            ? tr("connected")
            : status === "connecting"
              ? tr("connecting")
              : status === "disconnecting"
                ? tr("disconnecting")
                : status === "error"
                  ? tr("error")
                  : tr("connect")}
        </div>
        {status === "connected" && active && (
          <div className="muted small">{tr("tapToDisconnect")} · {active.name}</div>
        )}
      </div>

      {windowsOnly && status === "disconnected" && (
        <div className="error-box">
          WireGuard и OpenVPN доступны в Windows-сборке. На этой платформе работает профиль VLESS.
        </div>
      )}

      {s.state.error && status === "error" && (
        <div className="error-box">
          {s.state.error}
          <button className="link-btn" onClick={() => go("logs")}>
            {tr("details")}
          </button>
        </div>
      )}

      {status === "connected" && (
        <div className="stats-row">
          <div className="stat">
            <div className="stat-label">{tr("sessionTime")}</div>
            <div className="stat-value">{fmtDuration(sessionSec)}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{tr("received")}</div>
            <div className="stat-value">{humanBytes(s.state.stats.rxBytes)}</div>
          </div>
          <div className="stat">
            <div className="stat-label">{tr("sent")}</div>
            <div className="stat-value">{humanBytes(s.state.stats.txBytes)}</div>
          </div>
        </div>
      )}

      {s.profiles.length > 0 ? (
        <div className="profiles">
          <div className="section-label">{tr("profiles")}</div>
          <div className="chips">
            {s.profiles.map((p) => (
              <button
                key={p.id}
                className={`chip ${active?.id === p.id ? "chip-active" : ""}`}
                onClick={() => setSelected(p.id)}
                onDoubleClick={() => void doConnect(p.id)}
                title={
                  s.platform !== "windows" && p.kind !== "vless"
                    ? `${p.name} — только в Windows-сборке`
                    : p.name
                }
              >
                <span className="chip-kind">{KIND_LABEL[p.kind]}</span>
                <span className="chip-name">{p.name}</span>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-note">{tr("noProfiles")}</div>
      )}

      {needCreds && (
        <div className="modal-overlay" onClick={() => setNeedCreds(null)}>
          <form
            className="modal"
            onClick={(e) => e.stopPropagation()}
            onSubmit={(e) => {
              e.preventDefault();
              void doConnect(needCreds.id, { username, password });
            }}
          >
            <div className="modal-title">{needCreds.name} — OpenVPN</div>
            <input
              className="input"
              placeholder={tr("username")}
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
            />
            <input
              className="input"
              type="password"
              placeholder={tr("password")}
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={() => setNeedCreds(null)}>
                {tr("cancel")}
              </button>
              <button className="btn btn-primary" type="submit">
                {tr("connect")}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
