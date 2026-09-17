# Ligament VPN Client (CorpVPN)

Корпоративный VPN-клиент для платформы **vpn_creator_wireguard**: WireGuard,
OpenVPN и VLESS в одном приложении. Вход — через SSO (**Ligament 2FA**,
OpenID Connect) или логин/пароль портала; конфиги подтягиваются с портала
автоматически, пользователю не нужно вводить адреса серверов и ключи.

Устанавливается администратором один раз (MSI per-machine, в т.ч. через GPO),
ежедневное использование прав администратора не требует. Windows 10/11 x64 —
первая очередь; macOS/Linux — фаза 2.

| | |
|---|---|
| Стек | Tauri 2 (React/TS UI) + Rust-служба `corpvpnd` (модель Mullvad/Firezone) |
| Протоколы | WireGuard (tunnel.dll / WireGuardNT), OpenVPN 2.7 (dco-win), VLESS (Xray-core) |
| Дистрибутивы | NSIS `*-setup.exe` + MSI (WiX) для GPO Software Installation |
| Политики | ADMX/ADML: портал, автозапуск, kill-switch, split tunnel, запрет импорта |

[![CI][ci-badge]][ci-link] [![Release][release-badge]][release-link]

## Архитектура

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

Полная спецификация — [docs/superpowers/specs/2026-09-16-corpvpn-client-design.md](docs/superpowers/specs/2026-09-16-corpvpn-client-design.md).

## Скриншоты

<!-- TODO: заменить плейсхолдеры реальными скриншотами перед публичным анонсом -->

| Экран входа | Главный экран | Настройки |
|---|---|---|
| ![Вход](docs/screenshots/placeholder-login.png) | ![Подключено](docs/screenshots/placeholder-main.png) | ![Настройки](docs/screenshots/placeholder-settings.png) |

*(плейсхолдеры — снимки экранов будут добавлены к первому релизу)*

## Загрузка

Готовые установщики — на странице [Releases][release-link]:

- `LigamentVPN_<версия>_x64-setup.exe` — интерактивная установка (NSIS);
- `LigamentVPN_<версия>_x64_en-US.msi` — тихая установка/GPO.

Сторонние движки (OpenVPN, Xray-core, tun2socks, tunnel.dll WireGuard) уже
внутри пакета: они скачиваются при сборке CI по пиннингу SHA256 из
[`installer/engine-lock.json`](installer/engine-lock.json) и в репозитории
не хранятся.

## Установка через GPO (для администраторов)

Массовое развертывание в домене Active Directory — MSI per-machine, без
участия пользователя, с административными шаблонами (портал, автозапуск,
kill-switch, запрет ручного импорта):

**Полная инструкция: [installer/GUIDE-GPO.md](installer/GUIDE-GPO.md).**

Кратко:

```cmd
msiexec /i LigamentVPN_1.0.0_x64_en-US.msi /qn PORTALURL=https://vpn.corp.example
```

## Настройка серверной части (для администраторов)

1. **Портал** (vpn_creator_wireguard): включить SSO в
   *Settings → OpenID Connect* (issuer/client_id/client_secret, при
   необходимости — автосоздание пользователей). Клиент использует
   существующие эндпоинты портала:
   - `POST /api/portal/auth/exchange` — обмен OIDC id_token на API-токен;
   - `GET /api/portal/profiles` — конфиги WireGuard/OpenVPN/VLESS;
   - `POST /api/portal/switch-protocol` — смена протокола доступа.
2. **Ligament 2FA** (2fa.ligam.org): отдельный клиент не нужен — используется
   **тот же client_id, что и у веб-портала**; добавьте к нему redirect_uri
   `http://127.0.0.1:*/cb` (loopback, wildcard-порт). PKCE S256 включён,
   клиентский секрет не требуется (public client).
3. **Политики**: шаблоны [`installer/gpo/`](installer/gpo) (ADMX + ADML ru/en),
   дерево *Ligament CorpVPN*, ключ
   `HKLM\SOFTWARE\Policies\Ligament\CorpVPN`.

## Разработка

Требования: Rust stable, Node 20; для полной сборки Windows-установщика —
Windows 10/11 (WiX, NSIS ставятся Tauri автоматически).

```
vpn_wg_client/
├── crates/vpncore/     # кроссплатформенное ядро: модели, парсеры, портал-клиент, политики
├── crates/vpndaemon/   # Windows-служба: pipe RPC, оркестрация движков (cfg(windows))
├── app/                # Tauri 2: src-tauri (bridge) + ui (React/TS)
├── installer/          # GPO-шаблоны, engine-lock, WiX-фрагменты, подпись
└── .github/workflows/  # ci.yml, release.yml
```

### macOS (разработка UI и vpncore)

UI-часть работает с mock-демоном — реальные туннели на macOS не поднимаются
(фаза 2), весь сетевой код в `cfg(windows)`-крэйтах:

```bash
# юнит-тесты ядра
cargo test --workspace

# UI в dev-режиме (vite, mock daemon)
cd app/ui && npm install && npm run dev
```

### Windows (полная сборка)

```powershell
# движки по пиннингу (нужны для установщика)
powershell -ExecutionPolicy Bypass -File installer\fetch-engines.ps1

cd app\ui ; npm install ; cd ..\..
cd app
npx @tauri-apps/cli build --bundles nsis,msi
# результат: app\src-tauri\target\release\bundle\{nsis,msi}\
```

### CI и релизы

- `ci.yml` — каждый push/PR: macOS — `cargo clippy -D warnings` +
  `cargo test --workspace`; Windows — `cargo check --workspace`;
  UI — `tsc --noEmit` + `vite build`.
- `release.yml` — тег `v*`: windows-latest → движки → `tauri build`
  (NSIS+MSI) → GitHub Release с ченджлогом. Подпись — опционально
  (Azure Trusted Signing, [installer/signing.md](installer/signing.md)).

## Безопасность

- Профили: `%PROGRAMDATA%\Ligament\CorpVPN\profiles.dat` — JSON, зашифрован
  ключом службы (ACL: SYSTEM + Administrators). Ограничение MVP: один
  пользователь на машину.
- Named pipe демона: SDDL — интерактивные пользователи (rw), запрет NETWORK.
- Портальный Bearer-токен (30 дней) хранится в `%APPDATA%` UI; блокировка
  пользователя на портале мгновенно прекращает действие всех его токенов.
- Креды OpenVPN не пишутся на диск (`--auth-nocache`, management-socket).

## Лицензии третьих сторон

Уведомления — в каталоге [`LICENSES/`](LICENSES). Движки скачиваются при
сборке и в репозитории не хранятся.

## Roadmap

- **Фаза 1 (текущая):** Windows — WireGuard + OpenVPN + VLESS (SOCKS и
  системный режим), вход OIDC + логин/пароль, ручной импорт, трей,
  GPO/ADMX, CI.
- **Фаза 2:** macOS (NetworkExtension) и Linux (wg-quick/netdev), kill-switch
  на WFP, автообновление через updater-плагин Tauri.

[ci-badge]: https://github.com/YOUR_ORG/vpn_wg_client/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/YOUR_ORG/vpn_wg_client/actions/workflows/ci.yml
[release-badge]: https://img.shields.io/github/v/release/YOUR_ORG/vpn_wg_client
[release-link]: https://github.com/YOUR_ORG/vpn_wg_client/releases
