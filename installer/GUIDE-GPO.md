# Установка CorpVPN через групповые политики (GPO)

Инструкция для системного администратора: массовая установка **Ligament VPN
Client (CorpVPN)** на рабочие станции Windows 10/11 x64 через Active Directory
Group Policy, без участия пользователя.

Установка — **per-machine** (установщик ставит службу `CorpVPND` и UI для
всех пользователей машины), ежедневное использование прав администратора не
требует. **Всё встроено в один установщик**: приложение, служба, движки
(OpenVPN/Xray/tun2socks/WireGuard tunnel.dll) — никаких отдельных скриптов.

---

## 1. Что понадобится

| Компонент | Где взять |
|---|---|
| `Ligament.VPN_<версия>_x64-setup.exe` | GitHub Releases проекта |
| ADMX/ADML шаблоны | каталог `installer/gpo/` репозитория |
| Доступ к контроллеру домена | для правки GPO и SYSVOL |

## 2. Тихая установка (служба ставится сама)

Установщик NSIS поддерживает тихий режим `/S` — с правами администратора он
ставит приложение, **создаёт и запускает службу `CorpVPND`** (самоустановка
через WinAPI, с политикой восстановления при сбоях):

```cmd
Ligament.VPN_0.2.6_x64-setup.exe /S
```

Тихое удаление: `"%ProgramFiles%\Ligament VPN\uninstall.exe" /S`
(служба останавливается и удаляется автоматически).

Проверка после установки:

```powershell
Get-Service CorpVPND      # должна быть Running
```

## 3. Развертывание в домене

GPO *Software Installation* работает только с MSI; наш пакет — NSIS exe,
поэтому для домена используйте любой из способов:

**Способ А — startup-скрипт GPO (простой):**
1. Положите установщик в SYSVOL: `\\dc01\SYSVOL\corp.example\software\CorpVPN\`.
2. GPO → *Computer Configuration → Policies → Windows Settings → Scripts
   (Startup)* → добавьте `.cmd`-обёртку:

   ```cmd
   @echo off
   if not exist "%ProgramFiles%\Ligament VPN\Ligament VPN.exe" (
     "\\dc01\SYSVOL\corp.example\software\CorpVPN\Ligament.VPN_0.2.6_x64-setup.exe" /S
   )
   ```

   (запуск при загрузке компьютера от SYSTEM; повторная установка — замена
   файла в SYSVOL и удаление локального условия либо проверка версии)
3. Привяжите GPO к OU рабочих станций.

**Способ Б — SCCM / Intune / Ansible:** распространяйте `setup.exe` с
аргументом `/S` как обычное приложение командной строки.

**Единый корпоративный MSI** (для чистого GPO Software Installation с
апгрейдами) — в плане (v0.3, кастомный WiX-пакет `installer/wix/`).

## 4. Административные шаблоны (ADMX/ADML)

Файлы из `installer/gpo/`:

- `CorpVPN.admx` → `\\<домен>\SYSVOL\<домен>\Policies\PolicyDefinitions\CorpVPN.admx`
- `CorpVPN.adml` (русский) → `...\PolicyDefinitions\ru-RU\CorpVPN.adml`
- `CorpVPN.en-US.adml` (английский) → `...\PolicyDefinitions\en-US\CorpVPN.adml`
  (при копировании переименовать в `CorpVPN.adml`)

Политики появляются в *Computer Configuration → Administrative Templates →
Ligament CorpVPN* и пишут значения в `HKLM\SOFTWARE\Policies\Ligament\CorpVPN`:

| Политика | Тип | Описание |
|---|---|---|
| PortalUrl | строка | адрес портала (перекрывает настройку пользователя) |
| RequireLogin | dword | запрет работы без входа на портал |
| Autostart | dword | автозапуск UI при входе в Windows |
| KillSwitch | dword | блокировка трафика вне туннеля |
| DisableManualImport | dword | запрет ручного импорта .conf/.ovpn/vless:// |
| DefaultProtocol | строка | протокол по умолчанию: `auto` \| `wireguard` \| `openvpn` \| `vless` |
| SplitTunnelDefault | строка | AllowedIPs по умолчанию (CIDR через запятую, `0.0.0.0/0` — весь трафик) |

Политики HKLM перекрывают пользовательские настройки приложения.
Проверка на станции: `gpresult /h report.html` или
`reg query HKLM\SOFTWARE\Policies\Ligament\CorpVPN`.

## 5. Настройка серверной части

### 5.1 Портал (vpn_creator_wireguard)

1. Включите SSO: *Settings → OpenID Connect* — issuer (Ligament), client_id,
   client_secret; включите «Автосоздание пользователей» при необходимости.
2. Desktop-клиент ходит на те же эндпоинты, что и браузерный портал:
   - `POST /api/portal/auth/exchange` — обмен OIDC id_token на API-токен;
   - `GET  /api/portal/profiles` — конфиги (WG/OVPN/VLESS);
   - `POST /api/portal/switch-protocol` — смена протокола.
3. Токен живёт 30 дней; блокировка пользователя (disabled/NONE) на портале
   мгновенно запрещает все его Bearer-запросы.

### 5.2 Ligament (2fa.ligam.org)

Desktop-клиент использует **тот же client_id, что и веб-портал** — отдельный
клиент создавать не нужно. В настройках клиента Ligament к существующему
приложению портала добавьте разрешённый redirect_uri шаблоном:

```
http://127.0.0.1:*/cb
```

(петлевой адрес; PKCE S256 уже включён в поток клиента — секрет не требуется,
public client.)

### 5.3 Движки VPN

Сторонние движки **уже внутри установщика** (скачиваются CI по пиннингу
SHA256 из `installer/engine-lock.json` и упаковываются в каталог `engines`
рядом со службой). Для самостоятельной сборки установщика:

```powershell
pwsh -File installer\fetch-engines.ps1   # PowerShell 7+; если нет — winget install Microsoft.PowerShell
```

WireGuardNT-драйвер (`wireguard.dll`) уже подписан командой WireGuard —
дополнительная подпись драйверов не требуется. Подпись установщика —
см. `installer/signing.md` (Azure Trusted Signing).

## 6. Первый вход пользователя

1. Пользователь запускает Ligament VPN (ярлык рабочего стола/меню Пуск).
2. Нажимает «Войти через 2FA (Ligament)» — открывается системный браузер,
   клиент ждёт подтверждение на `http://127.0.0.1:<порт>/cb`.
3. После входа клиент сам забирает конфиги с портала — вводить адреса серверов
   и ключи не нужно. Fallback: логин/пароль (те же учётные данные портала).
4. Профили хранятся в `%PROGRAMDATA%\Ligament\CorpVPN\profiles.dat`
   (зашифрован ключом службы; ограничение MVP — один пользователь на машину).

## 7. Частые проблемы

| Симптом | Причина / решение |
|---|---|
| Служба CorpVPND не стартует | В приложении кнопка «Диагностика» на экране ошибки покажет `sc query/qc` и crash-лог; либо вручную по `installer/DIAGNOSTICS.md` |
| Установщик блокируется антивирусом | Defender ASR (событие 1121) блокирует неподписанный exe — добавьте исключение или подпишите (installer/signing.md) |
| «Нет связи с порталом» | Проверьте PortalUrl (политика), DNS и прокси на станции |
| SSO-вход не возвращается в клиент | redirect_uri `http://127.0.0.1:*/cb` не добавлен в клиент Ligament |
| Политики не применяются | `gpupdate /force`, проверьте что ADMX скопирован в центральное хранилище SYSVOL |
