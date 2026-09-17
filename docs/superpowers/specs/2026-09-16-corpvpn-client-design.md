# CorpVPN Client — дизайн (2026-09-16)

Рабочее имя продукта: **Ligament VPN Client** (`corpvpn`). Публичный репозиторий, сборка артефактов через GitHub Actions.

## 1. Цели

1. Корпоративный VPN-клиент: **WireGuard + OpenVPN + VLESS** (bypass через 3x-ui), Windows в первую очередь, лёгкий кроссплатформенный Rust-кор (macOS/Linux — фаза 2).
2. Установка **админом один раз** (MSI per-machine через GPO), ежедневное использование — **без прав администратора**.
3. Понятно рядовому пользователю: одна большая кнопка «Подключить», русский язык по умолчанию, минимум настроек.
4. Авторизация через **OpenID Connect** (IdP — Ligament, `2fa.ligam.org`) поверх портала `vpn_creator_wireguard`; конфиги забираются с портала автоматически. Ручной импорт `.conf`/`.ovpn`/`vless://` — как альтернатива.
5. Стек: **Tauri 2 (React/TS UI) + Rust-демон** (модель Mullvad/Firezone), NSIS + MSI, автообновление.

## 2. Архитектура

```
┌───────────────────────────── Windows ─────────────────────────────┐
│ UI: Tauri 2 (React/TS, трей) — сессия пользователя, без admin     │
│   │ JSON-RPC 2.0 over named pipe  \\.\pipe\corpvpn-daemon         │
│ Демон: corpvpnd.exe (Rust, служба SYSTEM, windows-service crate)  │
│   ├─ WireGuard: службы WireGuardTunnel$<id> + tunnel.dll          │
│   │   (wireguard-windows embeddable-dll-service, MIT)             │
│   │   + wireguard.dll (WireGuardNT, подписан WireGuard team, PBL) │
│   ├─ OpenVPN: openvpn.exe 2.7 (dco-win) child-process,            │
│   │   креды — через management TCP 127.0.0.1                      │
│   └─ VLESS: xray.exe (MPL-2.0, socks-inbound 127.0.0.1:10808)     │
│       [+ tun2socks.exe (MIT) + wintun.dll — системный режим;      │
│        SOCKS-режим работает вовсе без admin]                      │
└───────────────────────────────────────────────────────────────────┘
        │ HTTPS (Bearer token)
        ▼
Портал vpn_creator_wireguard (Next.js) ◄── OIDC (PKCE) ── Ligament 2FA IdP (2fa.ligam.org)
```

- **OIDC напрямую через API Ligament** (Authorization Code + PKCE S256, loopback `http://127.0.0.1:<port>/cb` в системном браузере, discovery/JWKS — стандартные эндпоинты Ligament). Клиент обменивает полученный id_token на API-токен портала: `POST /api/portal/auth/exchange` — портал проверяет подпись через Ligament JWKS (существующий `verifyOidcIdToken`), находит/создаёт пользователя (`resolveOidcUser`) и выдаёт Bearer-токен. Ligament не дорабатывается; нужен только client_id «CorpVPN Desktop» в настройках Ligament.
- Fallback-вход: логин/пароль напрямую в `POST /api/portal/login` (существующий).

## 3. Контракт IPC (JSON-RPC 2.0, named pipe `\\.\pipe\corpvpn-daemon`)

Имена: `corpvpn.state.get`, `corpvpn.connect`, `corpvpn.disconnect`, `corpvpn.profiles.import`, `corpvpn.profiles.delete`, `corpvpn.profiles.update`, `corpvpn.settings.set`, `corpvpn.logs.tail`, `corpvpn.portal.login` (логин+пароль), `corpvpn.portal.oidc.start` (вернуть URL для браузера; демон слушает loopback, обменивает код у Ligament, делает exchange на портале), `corpvpn.portal.sync` (забрать профили), `corpvpn.portal.logout`. Уведомления демон→UI: `state.changed`, `log.entry`.

**Модель профиля** (id — uuid v4):
```json
{
  "id": "…", "name": "Корпоративная сеть", "kind": "wireguard|openvpn|vless",
  "source": "portal|import",
  "wg":     { "config": "[Interface]\n…" },
  "ovpn":   { "config": "client\ndev tun\n…" },
  "vless":  { "uri": "vless://…" },
  "overrides": { "allowedIps": ["0.0.0.0/0"], "dns": ["10.0.0.1"], "socksOnly": false },
  "createdAt": 0, "updatedAt": 0
}
```

**Состояние:** `{ "status": "disconnected|connecting|connected|disconnecting|error", "activeProfileId": "…", "error": "текст для пользователя", "stats": { "rxBytes": 0, "txBytes": 0, "handshakeAt": null } }`.

**Настройки:** `{ "autostart": true, "autoConnect": false, "killSwitch": false, "language": "ru", "portalUrl": "https://vpn.example.com", "socksPort": 10808 }`.

## 4. Контракт портала (новые эндпоинты, патч в репозиторий портала)

| Endpoint | Auth | Ответ |
|---|---|---|
| `POST /api/portal/auth/exchange` `{idToken}` | id_token от Ligament (проверка JWKS) | `{ accessToken, expiresInDays, user: {name, displayName, tier} }` |
| `GET /api/portal/profiles` | Bearer token или portal cookie | `{ user: {name, displayName, tier}, wgConfig?, ovpnConfig?, vlessUri?, vlessSubUrl? }` |
| `POST /api/portal/switch-protocol` | + Bearer | существующий контракт |
| `POST /api/portal/login`, `POST /api/portal/logout`, `GET /api/sub/<token>` | существующие | без изменений (клиент использует) |

Новая модель Prisma: `PortalApiToken` (id, userId, tokenHash sha256, name, createdAt, lastUsedAt, revokedAt). Токен — 32 random bytes base64url, хранится только sha256-хэш; на каждом Bearer-запросе проверяется disabled/NONE/sessionVer (как в switch-protocol), блокировка пользователя отзывает доступ. Вся OIDC-механика портала (discovery, PKCE, JWKS, resolveOidcUser) уже реализована в `src/lib/oidc.ts` — exchange-роут только переиспользует её.

## 5. GPO и политики

- Установка: MSI per-machine (WiX), назначение через GPO Software Installation; `msiexec /i corpvpn.msi /qn` — без UI.
- ADMX/ADML (`installer/gpo/CorpVPN.admx` + `.adml` ru/en): `HKLM\SOFTWARE\Policies\Ligament\CorpVPN` — PortalUrl (SZ), RequireLogin (DW), DefaultProtocol (SZ), Autostart (DW), KillSwitch (DW), SplitTunnelDefault (SZ), DisableManualImport (DW). Политики HKLM перекрывают пользовательские настройки.
- Автозапуск UI: ярлык в Startup пользователя или HKCU Run (пишется при первом запуске, если политика разрешает).

## 6. Безопасность

- Хранилище профилей: `%PROGRAMDATA%\Ligament\CorpVPN\profiles.dat` — JSON, зашифрован ключом службы (32 байта, генерируется при первом старте, файл ACL: SYSTEM+Administrators). Ограничение MVP: один пользователь на машину (задокументировано).
- Named pipe: SDDL — Interactive users (rw), запрет NETWORK; команды изменения — только Interactive.
- Портальный токен у пользователя (UI хранит в `%APPDATA%`, для refresh); креды OpenVPN не пишутся на диск (передаются в демон → management socket, `--auth-nocache`).
- Крипто-детали OIDC/portala не меняем: существующие jose/bcrypt/fail2ban.

## 7. UX (рядовой пользователь)

- Первый запуск: экран входа «Войти через 2FA (Ligament)» (кнопка открывает браузер, клиент ждёт подтверждение) + свёрнутая форма логин/пароль.
- Главный экран: большая круглая кнопка Подключить (серая→жёлтая «Подключение…»→зелёная «Подключено»), имя профиля-чипы, статус и время сессии, RX/TX. Ошибки — по-русски, с кнопкой «Подробнее» (лог).
- Настройки: тумблеры (Автозапуск, Автоподключение, Kill-switch), «Продвинутые» — split tunnel (AllowedIPs), DNS, порт SOCKS.
- Трей: серый/жёлтый/зелёный значок; меню: Подключить / Отключить / Открыть CorpVPN / Выход. Закрытие окна = свернуть в трей.
- Стиль: системная светлая/тёмная тема, акцент #2F6FED, шрифт Inter, крупные контролы ≥40px, RU по умолчанию (EN — вторая локаль).

## 8. Репозиторий и CI (public)

```
vpn_wg_client/
├── README.md  LICENSES/ (уведомления OpenVPN GPLv2, Xray MPL-2.0, Wintun PBL, tun2socks MIT)
├── Cargo.toml                # workspace: crates/vpncore, crates/vpndaemon
├── crates/vpncore/           # кроссплатформенное ядро: модели, парсеры .conf/.ovpn/vless://,
│                             #   генератор xray-конфига, HTTP-клиент портала, политики — unit-тесты
├── crates/vpndaemon/         # служба Windows: pipe RPC, оркестрация движков (cfg(windows))
├── app/                      # Tauri 2: app/src-tauri (Rust bridge) + app/ui (React/TS)
├── installer/                # ADMX/ADML, инструкция GPO, заметки о подписи
├── .github/workflows/ci.yml  # PR: cargo test+clippy, tsc, vite build
├── .github/workflows/release.yml # tag v*: windows-latest → NSIS+MSI → GitHub Release
└── docs/superpowers/specs/
```

Движки в CI скачиваются с официальных релизов (openvpn 2.7, xray-core, tun2socks, wireguard-windows embeddable zip) с пиннингом SHA256 в `app/engine-lock.json`, кладутся в sidecar-ресурсы Tauri.

## 9. Обработка ошибок и тесты

- IPC-ошибки: JSON-RPC error c `data.userMessage` (RU) и `data.debug`; таймаут подключения 30 с → статус error.
- Портал недоступен при refresh → работаем с кэшем профилей, показываем «Нет связи с порталом».
- Тесты: `vpncore` — cargo test (парсеры round-trip, xray-config, device-flow state machine, политики); портал — vitest по новым роутам (в репозитории портала); UI — `tsc --noEmit` + `vite build` в CI.

## 10. Фазы

- **P1 (этот билд):** Windows — WG+OpenVPN+VLESS(SOCKS и системный), вход OIDC device-flow + пароль, импорт, трей, GPO/ADMX, CI, публичный репозиторий.
- **P2:** macOS (NetworkExtension) / Linux (wg-quick/netdev), kill-switch на WFP, автообновление updater-плагином.
