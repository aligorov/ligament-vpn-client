# Уведомления о третьих сторонах (third-party notices)

CorpVPN (Ligament VPN Client) распространяет **немодифицированные** двоичные
артефакты сторонних проектов — VPN-движки и компоненты UI-фреймворка.

**Движки не хранятся в этом репозитории**: они скачиваются при сборке CI по
пиннингу URL+SHA256 из [`installer/engine-lock.json`](../installer/engine-lock.json)
и упаковываются в установщик. Хэши артефактов проверяются на каждом билде.

| Компонент | Лицензия | Файл |
|---|---|---|
| OpenVPN (openvpn.exe и библиотеки) | GPL-2.0 с исключением для связывания с OpenSSL | [OpenVPN.txt](OpenVPN.txt) |
| Xray-core (xray.exe, geoip/geosite) | MPL-2.0 | [Xray-core.txt](Xray-core.txt) |
| Wintun (wintun.dll) | Prebuilt Binaries License (WireGuard LLC) | [Wintun-and-WireGuardNT-Prebuilt.txt](Wintun-and-WireGuardNT-Prebuilt.txt) |
| WireGuardNT (wireguard.dll внутри tunnel.dll) | Prebuilt Binaries License (WireGuard LLC) | [Wintun-and-WireGuardNT-Prebuilt.txt](Wintun-and-WireGuardNT-Prebuilt.txt) |
| wireguard-windows (tunnel.dll, embeddable-dll-service) | MIT | см. ссылку в файле Wintun-and-WireGuardNT |
| tun2socks (tun2socks.exe) | MIT | [tun2socks.txt](tun2socks.txt) |
| Tauri (фреймворк установщика/UI) | MIT ИЛИ Apache-2.0 | [Tauri.txt](Tauri.txt) |
