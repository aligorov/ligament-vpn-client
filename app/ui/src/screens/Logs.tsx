import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../App";

export function Logs() {
  const { s, tr, go } = useApp();
  const [filter, setFilter] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const entries = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return s.logs.filter((e) => !f || e.message.toLowerCase().includes(f) || e.level.includes(f));
  }, [s.logs, filter]);

  useEffect(() => {
    if (autoScroll && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [entries.length, autoScroll]);

  async function copyAll() {
    const text = entries
      .map((e) => `${new Date(e.ts * 1000).toLocaleTimeString()} [${e.level}] ${e.message}`)
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // буфер недоступен — игнорируем
    }
  }

  return (
    <div className="screen logs-screen">
      <header className="topbar">
        <button className="icon-btn" title={tr("back")} onClick={() => go("main")}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M15 5l-7 7 7 7" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
        <div className="topbar-title">{tr("logs")}</div>
        <div className="topbar-actions">
          <label className="check-label">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            {tr("autoScroll")}
          </label>
          <button className="btn btn-ghost btn-small" onClick={copyAll}>
            {copied ? tr("copied") : tr("copy")}
          </button>
        </div>
      </header>

      <input
        className="input"
        placeholder={tr("filter")}
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />

      <div className="logs-box" ref={boxRef}>
        {entries.length === 0 && <div className="muted small pad">—</div>}
        {entries.map((e, i) => (
          <div key={i} className={`log-line log-${e.level}`}>
            <span className="log-time">{new Date(e.ts * 1000).toLocaleTimeString()}</span>
            <span className="log-msg">{e.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
