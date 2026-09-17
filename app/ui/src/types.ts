// Типы зеркалируют контракты IPC из спеки (docs/superpowers/specs/2026-09-16-corpvpn-client-design.md)
// и фактические ответы демона corpvpnd (crates/vpndaemon/src/rpc.rs).

export type ProfileKind = "wireguard" | "openvpn" | "vless";
export type ProfileSource = "portal" | "import";
export type VpnStatus =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "error";

export interface Overrides {
  allowedIps: string[] | null;
  dns: string[] | null;
  socksOnly: boolean;
}

export interface Profile {
  id: string;
  name: string;
  kind: ProfileKind;
  source: ProfileSource;
  wg?: { config: string } | null;
  ovpn?: { config: string } | null;
  vless?: { uri: string } | null;
  overrides: Overrides;
  createdAt: number;
  updatedAt: number;
}

export interface VpnStats {
  rxBytes: number;
  txBytes: number;
  handshakeAt: number | null;
}

export interface VpnState {
  status: VpnStatus;
  activeProfileId: string | null;
  error: string | null;
  stats: VpnStats;
}

export interface Settings {
  autostart: boolean;
  autoConnect: boolean;
  killSwitch: boolean;
  language: "ru" | "en";
  portalUrl: string;
  socksPort: number;
}

export interface LogEntry {
  ts: number;
  level: "info" | "warn" | "error";
  message: string;
}

export interface PortalUser {
  name: string;
  displayName?: string;
  tier?: string;
}

export interface Policy {
  portalUrl: string | null;
  requireLogin: boolean | null;
  defaultProtocol: string | null;
  autostart: boolean | null;
  killSwitch: boolean | null;
  splitTunnelDefault: string | null;
  disableManualImport: boolean | null;
}

export function detectKind(text: string): ProfileKind | null {
  const t = text.trim();
  if (t.startsWith("[Interface")) return "wireguard";
  if (t.startsWith("vless://")) return "vless";
  if (t.startsWith("client") || /\bremote\s+\S+/.test(t)) return "openvpn";
  return null;
}
