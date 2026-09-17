import { useState } from "react";
import { useApp } from "../App";
import { rpc, isMock, RpcError } from "../rpc";

export function Login() {
  const { tr, go, refresh, setLoggedIn } = useApp();
  const [waiting, setWaiting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function oidcLogin() {
    setError(null);
    try {
      const { url } = await rpc.portalOidcStart();
      if (isMock()) {
        // В мок-режиме браузера нет Tauri-хоста — имитируем подтверждение.
        setWaiting(true);
        setTimeout(async () => {
          await finishLogin();
        }, 1500);
        return;
      }
      const { openExternal } = await import("../shell");
      await openExternal(url);
      setWaiting(true);
    } catch (e) {
      setError(e instanceof RpcError ? e.message : String(e));
    }
  }

  async function finishLogin() {
    try {
      await rpc.portalSync();
      await refresh();
      setLoggedIn(true);
      go("main");
    } catch (e) {
      setWaiting(false);
      setError(e instanceof RpcError ? e.message : String(e));
    }
  }

  async function passwordLogin() {
    setError(null);
    try {
      await rpc.portalLogin(username, password);
      await finishLogin();
    } catch (e) {
      setError(e instanceof RpcError ? e.message : String(e));
    }
  }

  return (
    <div className="screen login-screen">
      <div className="login-logo" aria-hidden />
      <h1 className="login-title">{tr("loginTitle")}</h1>
      <p className="muted login-subtitle">{tr("loginSubtitle")}</p>

      {waiting ? (
        <div className="waiting-box">
          <div className="spinner" />
          <div className="waiting-text">{tr("waitingPortal")}</div>
          <p className="muted small">{tr("waitingHint")}</p>
          <button className="btn btn-ghost" onClick={() => setWaiting(false)}>
            {tr("cancel")}
          </button>
        </div>
      ) : (
        <>
          <button className="btn btn-primary btn-big" onClick={oidcLogin}>
            {tr("login2fa")}
          </button>

          <button className="link-btn" onClick={() => setShowPassword((v) => !v)}>
            {tr("loginPassword")}
          </button>

          {showPassword && (
            <form
              className="password-form"
              onSubmit={(e) => {
                e.preventDefault();
                void passwordLogin();
              }}
            >
              <input
                className="input"
                placeholder={tr("username")}
                value={username}
                autoComplete="username"
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                className="input"
                type="password"
                placeholder={tr("password")}
                value={password}
                autoComplete="current-password"
                onChange={(e) => setPassword(e.target.value)}
              />
              <button className="btn btn-primary" type="submit">
                {tr("signIn")}
              </button>
            </form>
          )}

          <button className="link-btn muted" onClick={() => go("main")}>
            {tr("back")}
          </button>
        </>
      )}

      {error && <div className="error-box">{error}</div>}
    </div>
  );
}
