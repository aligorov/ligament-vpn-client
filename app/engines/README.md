# app/engines — сайдкары VPN-движков

Содержимое этого каталога упаковывается установщиком как ресурсы приложения
(`app/src-tauri/tauri.conf.json → bundle.resources`) и устанавливается в
`<Program Files>\Ligament VPN\engines\`, где их ищет служба `corpvpnd`
(`crates/vpndaemon/src/engines/mod.rs → engine_bin`, включая подкаталоги).

В репозитории бинарники НЕ хранятся (лицензии/размер). Их скачивает CI по
пиннингу SHA256 из `installer/engine-lock.json`:

```powershell
powershell -ExecutionPolicy Bypass -File installer/fetch-engines.ps1
```

Раскладка после CI (`dest` из engine-lock.json + служба из `cargo build`):

```
engines/
├── corpvpnd[.exe]      # демон/служба (собирается из crates/vpndaemon)
├── openvpn/            # Windows: openvpn.exe 2.7 + libssl/libcrypto (из MSI)
├── xray/               # Windows: xray.exe; macOS: xray (arm64) — VLESS/REALITY
├── tun2socks/          # Windows: tun2socks.exe (системный режим VLESS)
└── wireguard/          # Windows: tunnel.dll + wireguard.dll (из официального MSI)
```

Этот README нужен и для локальной разработки: Tauri требует, чтобы glob
ресурсов `../engines/**/*` находил хотя бы один файл (`cargo check`).
