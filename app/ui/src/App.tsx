import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useState,
} from "react";
import type { LogEntry, Profile, Settings, VpnState } from "./types";
import { rpc, RpcError, subscribeDaemonEvents } from "./rpc";
import { t, type Lang } from "./i18n";
import { Login } from "./screens/Login";
import { Main } from "./screens/Main";
import { SettingsScreen } from "./screens/Settings";
import { Logs } from "./screens/Logs";

type Screen = "login" | "main" | "settings" | "logs";

interface AppState {
  screen: Screen;
  daemonUp: boolean;
  state: VpnState;
  profiles: Profile[];
  settings: Settings | null;
  logs: LogEntry[];
  booted: boolean;
}

type Action =
  | { type: "daemon"; up: boolean }
  | { type: "screen"; screen: Screen }
  | { type: "state"; state: VpnState }
  | { type: "profiles"; profiles: Profile[] }
  | { type: "settings"; settings: Settings }
  | { type: "log"; entry: LogEntry }
  | { type: "logs"; entries: LogEntry[] }
  | { type: "booted" };

const initialState: AppState = {
  screen: "login",
  daemonUp: true,
  state: {
    status: "disconnected",
    activeProfileId: null,
    error: null,
    stats: { rxBytes: 0, txBytes: 0, handshakeAt: null },
  },
  profiles: [],
  settings: null,
  logs: [],
  booted: false,
};

function reducer(s: AppState, a: Action): AppState {
  switch (a.type) {
    case "daemon":
      return { ...s, daemonUp: a.up };
    case "screen":
      return { ...s, screen: a.screen };
    case "state":
      return { ...s, state: a.state };
    case "profiles":
      return { ...s, profiles: a.profiles };
    case "settings":
      return { ...s, settings: a.settings };
    case "log":
      return { ...s, logs: [...s.logs.slice(-499), a.entry] };
    case "logs":
      return { ...s, logs: a.entries.slice(-500) };
    case "booted":
      return { ...s, booted: true };
    default:
      return s;
  }
}

interface Ctx {
  s: AppState;
  lang: Lang;
  tr: (key: Parameters<typeof t>[1]) => string;
  go: (screen: Screen) => void;
  refresh: () => Promise<void>;
  loggedIn: boolean;
  setLoggedIn: (v: boolean) => void;
}

const AppCtx = createContext<Ctx | null>(null);

export function useApp(): Ctx {
  const ctx = useContext(AppCtx);
  if (!ctx) throw new Error("useApp outside provider");
  return ctx;
}

export default function App() {
  const [s, dispatch] = useReducer(reducer, initialState);
  const [fatal, setFatal] = useState<string | null>(null);
  const [loggedIn, setLoggedIn] = useState(false);

  const lang: Lang = s.settings?.language ?? "ru";
  const tr = useCallback((key: Parameters<typeof t>[1]) => t(lang, key), [lang]);

  const refresh = useCallback(async () => {
    try {
      const { profiles, settings } = await rpc.listProfiles();
      dispatch({ type: "profiles", profiles });
      dispatch({ type: "settings", settings });
      const st = await rpc.getState();
      dispatch({ type: "state", state: st });
      dispatch({ type: "daemon", up: true });
    } catch (e) {
      if (e instanceof RpcError) {
        dispatch({ type: "daemon", up: false });
      } else {
        setFatal(String(e));
      }
    }
  }, []);

  // Первичная загрузка: профили+настройки+состояние; залогинен = есть portal-профили.
  useEffect(() => {
    (async () => {
      await refresh();
      rpc
        .tailLogs(200)
        .then((r) => dispatch({ type: "logs", entries: r.entries }), () => undefined);
      dispatch({ type: "booted" });
    })();
  }, [refresh]);

  useEffect(() => {
    if (!s.booted) return;
    const hasPortal = s.profiles.some((p) => p.source === "portal");
    setLoggedIn(hasPortal);
    if (s.screen === "login" && hasPortal) dispatch({ type: "screen", screen: "main" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.booted]);

  // Подписка на события демона (state.changed / log.entry)
  useEffect(() => {
    let unsub: (() => void) | undefined;
    subscribeDaemonEvents(
      (st) => dispatch({ type: "state", state: st }),
      (entry) => dispatch({ type: "log", entry }),
    ).then(
      (u) => {
        unsub = u;
      },
      () => undefined,
    );
    return () => unsub?.();
  }, []);

  const go = useCallback((screen: Screen) => dispatch({ type: "screen", screen }), []);

  const ctx = useMemo<Ctx>(
    () => ({ s, lang, tr, go, refresh, loggedIn, setLoggedIn }),
    [s, lang, tr, go, refresh, loggedIn, setLoggedIn],
  );

  if (fatal) {
    return (
      <div className="center-screen">
        <div className="fatal-title">{tr("error")}</div>
        <div className="muted">{fatal}</div>
      </div>
    );
  }

  if (!s.daemonUp) {
    return (
      <div className="center-screen">
        <div className="fatal-title">{tr("daemonDown")}</div>
        <div className="muted">{tr("daemonDownHint")}</div>
        <button
          className="btn btn-primary"
          onClick={() => {
            dispatch({ type: "daemon", up: true });
            void refresh();
          }}
        >
          {tr("retry")}
        </button>
      </div>
    );
  }

  if (!s.booted) {
    return (
      <div className="center-screen">
        <div className="spinner" />
        <div className="muted">{tr("loading")}</div>
      </div>
    );
  }

  return (
    <AppCtx.Provider value={ctx}>
      {s.screen === "login" && <Login />}
      {s.screen === "main" && <Main />}
      {s.screen === "settings" && <SettingsScreen />}
      {s.screen === "logs" && <Logs />}
    </AppCtx.Provider>
  );
}
