// JSON-RPC 2.0 клиент к Tauri-хосту (команда `rpc` проксирует в демон corpvpnd).
// Мок-режим: VITE_CORPVPN_MOCK=1 или window.__CORPVPN_MOCK__ — UI работает в браузере без демона.
import type {
  LogEntry,
  Profile,
  Settings,
  VpnState,
} from "./types";

export class RpcError extends Error {
  constructor(message: string, public debug?: unknown) {
    super(message);
  }
}

async function rawRpc(method: string, params?: unknown): Promise<unknown> {
  if (isMock()) return mockRpc(method, params);
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<string>("rpc", { method, params: params ?? null }).then(
    (raw) => {
      const resp = JSON.parse(raw) as {
        result?: unknown;
        error?: { message: string; data?: { debug?: unknown } };
      };
      if (resp.error) throw new RpcError(resp.error.message, resp.error.data?.debug);
      return resp.result;
    },
  );
}

export function isMock(): boolean {
  return (
    import.meta.env.VITE_CORPVPN_MOCK === "1" ||
    (typeof window !== "undefined" && (window as never as Record<string, unknown>).__CORPVPN_MOCK__ === true)
  );
}

export const rpc = {
  getState: (): Promise<VpnState> => rawRpc("corpvpn.state.get") as Promise<VpnState>,

  listProfiles: (): Promise<{ profiles: Profile[]; settings: Settings; platform: string }> =>
    rawRpc("corpvpn.profiles.list") as Promise<{
      profiles: Profile[];
      settings: Settings;
      platform: string;
    }>,

  connect: (profileId: string, creds?: { username?: string; password?: string }): Promise<VpnState> =>
    rawRpc("corpvpn.connect", { profileId, ...creds }) as Promise<VpnState>,

  disconnect: (): Promise<VpnState> => rawRpc("corpvpn.disconnect") as Promise<VpnState>,

  importProfile: (name: string, config: string): Promise<Profile> =>
    rawRpc("corpvpn.profiles.import", { name, config }) as Promise<Profile>,

  deleteProfile: (profileId: string): Promise<boolean> =>
    rawRpc("corpvpn.profiles.delete", { profileId }) as Promise<boolean>,

  updateProfile: (profile: Profile): Promise<Profile> =>
    rawRpc("corpvpn.profiles.update", { profile }) as Promise<Profile>,

  getSettings: (): Promise<Settings> => rawRpc("corpvpn.settings.get") as Promise<Settings>,

  setSettings: (settings: Settings): Promise<Settings> =>
    rawRpc("corpvpn.settings.set", { settings }) as Promise<Settings>,

  tailLogs: (limit = 500): Promise<{ entries: LogEntry[] }> =>
    rawRpc("corpvpn.logs.tail", { limit }) as Promise<{ entries: LogEntry[] }>,

  portalOidcStart: (): Promise<{ url: string }> =>
    rawRpc("corpvpn.portal.oidc.start") as Promise<{ url: string }>,

  portalLogin: (username: string, password: string): Promise<{ ok: boolean; user?: { name: string } }> =>
    rawRpc("corpvpn.portal.login", { username, password }) as Promise<{ ok: boolean; user?: { name: string } }>,

  portalSync: (): Promise<{ user: { name: string } }> =>
    rawRpc("corpvpn.portal.sync") as Promise<{ user: { name: string } }>,

  portalLogout: (): Promise<boolean> => rawRpc("corpvpn.portal.logout") as Promise<boolean>,
};

/** Подписка на события демона (state.changed / log.entry) через Tauri events. */
export async function subscribeDaemonEvents(
  onState: (s: VpnState) => void,
  onLog: (e: LogEntry) => void,
): Promise<() => void> {
  if (isMock()) {
    const timer = window.setInterval(() => {
      onState(mockState());
    }, 2000);
    return () => window.clearInterval(timer);
  }
  const { listen } = await import("@tauri-apps/api/event");
  const un1 = await listen<VpnState>("state.changed", (ev) => onState(ev.payload));
  const un2 = await listen<LogEntry>("log.entry", (ev) => onLog(ev.payload));
  return () => {
    un1();
    un2();
  };
}

// ---------------- мок ----------------

const MOCK_PROFILES: Profile[] = [
  {
    id: "p-wg", name: "Корпоративная сеть", kind: "wireguard", source: "portal",
    wg: { config: "[Interface]…" }, overrides: { allowedIps: null, dns: null, socksOnly: false },
    createdAt: Date.now(), updatedAt: Date.now(),
  },
  {
    id: "p-ovpn", name: "OpenVPN (AD)", kind: "openvpn", source: "portal",
    ovpn: { config: "client…" }, overrides: { allowedIps: null, dns: null, socksOnly: false },
    createdAt: Date.now(), updatedAt: Date.now(),
  },
  {
    id: "p-vless", name: "Обход блокировок", kind: "vless", source: "portal",
    vless: { uri: "vless://…" }, overrides: { allowedIps: null, dns: null, socksOnly: true },
    createdAt: Date.now(), updatedAt: Date.now(),
  },
];

const mockSettings: Settings = {
  autostart: true, autoConnect: false, killSwitch: false,
  language: "ru", portalUrl: "https://vpn.example.com", socksPort: 10808,
};

let mockStatus: VpnState["status"] = "disconnected";
let mockSince = 0;

function mockState(): VpnState {
  return {
    status: mockStatus,
    activeProfileId: mockStatus === "connected" || mockStatus === "connecting" ? "p-wg" : null,
    error: null,
    stats:
      mockStatus === "connected"
        ? {
            rxBytes: 12_345_678, txBytes: 1_234_567,
            handshakeAt: Math.floor(Date.now() / 1000),
          }
        : { rxBytes: 0, txBytes: 0, handshakeAt: null },
  };
}

async function mockRpc(method: string, params?: unknown): Promise<unknown> {
  await new Promise((r) => setTimeout(r, 350));
  switch (method) {
    case "corpvpn.state.get":
      return mockState();
    case "corpvpn.profiles.list":
      return { profiles: MOCK_PROFILES, settings: mockSettings, platform: "windows" };
    case "corpvpn.connect":
      mockStatus = "connecting";
      setTimeout(() => {
        mockStatus = "connected";
        mockSince = Date.now();
      }, 1800);
      return mockState();
    case "corpvpn.disconnect":
      mockStatus = "disconnected";
      return mockState();
    case "corpvpn.profiles.import": {
      const p = params as { name: string; config: string };
      const prof: Profile = {
        id: `imp-${Date.now()}`, name: p.name || "Импорт", kind: "wireguard", source: "import",
        wg: { config: p.config }, overrides: { allowedIps: null, dns: null, socksOnly: false },
        createdAt: Date.now(), updatedAt: Date.now(),
      };
      return prof;
    }
    case "corpvpn.profiles.delete":
      return true;
    case "corpvpn.profiles.update":
      return (params as { profile: Profile }).profile;
    case "corpvpn.settings.get":
      return mockSettings;
    case "corpvpn.settings.set":
      Object.assign(mockSettings, (params as { settings: Partial<Settings> }).settings);
      return mockSettings;
    case "corpvpn.logs.tail":
      return {
        entries: [
          { ts: Date.now() / 1000, level: "info", message: "corpvpnd: запуск (мок)" },
          { ts: Date.now() / 1000, level: "warn", message: "мок-режим: демон не запущен" },
        ] as LogEntry[],
      };
    case "corpvpn.portal.oidc.start":
      return { url: "https://2fa.ligam.org/mock-login" };
    case "corpvpn.portal.login":
      return { ok: true, user: { name: "ivanov.i" } };
    case "corpvpn.portal.sync":
      return { user: { name: "ivanov.i" } };
    case "corpvpn.portal.logout":
      return true;
    default:
      throw new RpcError(`Мок: неизвестный метод ${method}`);
  }
}

export const __mockInternal = { get mockSince() { return mockSince; } };
