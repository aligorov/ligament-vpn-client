// Обёртки над Tauri API для окружения (в мок-режиме — заглушки).
import { isMock } from "./rpc";

export async function openExternal(url: string): Promise<void> {
  if (isMock()) {
    window.open(url, "_blank");
    return;
  }
  const { openUrl } = await import("@tauri-apps/plugin-opener");
  await openUrl(url);
}

/** Диалог выбора файла конфигурации; возвращает текстовое содержимое (или null). */
export async function pickConfigFile(): Promise<string | null> {
  if (isMock()) {
    return window.prompt("Вставьте конфигурацию (.conf / .ovpn / vless://)");
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<string | null>("pick_config_file");
}

export async function setAutostart(enabled: boolean): Promise<void> {
  if (isMock()) return;
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("set_autostart", { enabled });
}

export async function quitApp(): Promise<void> {
  if (isMock()) return;
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("quit_app");
}
