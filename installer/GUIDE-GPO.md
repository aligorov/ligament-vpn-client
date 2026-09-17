# Установка CorpVPN через групповые политики (GPO)

Инструкция для системного администратора: массовая установка **Ligament VPN
Client (CorpVPN)** на рабочие станции Windows 10/11 x64 через Active Directory
Group Policy, без участия пользователя.

Установка — **per-machine** (MSI ставит службу `CorpVPND` и UI для всех
пользователей машины), ежедневное использование прав администратора не
требует.

---

## 1. Что понадобится

| Компонент | Где взять |
|---|---|
| `LigamentVPN_<версия>_x64-setup.exe` и `LigamentVPN_<версия>_x64_en-US.msi` | GitHub Releases проекта (раздел Downloads в README) |
| ADMX/ADML шаблоны | каталог `installer/gpo/` репозитория |
| Доступ к контроллеру домена | для правки GPO и SYSVOL |

MSI нужен именно **en-US** (нейтральный, без встроенной локализации
установщика — язык интерфейса выбирает само приложение, русский по
умолчанию). NSIS `setup.exe` — для ручной установки, GPO работает с MSI.

## 2. Добавление MSI в GPO Software Installation (per-machine)

1. Положите MSI в сетевую папку, доступную **компьютерам** домена на чтение
   (например, `\\dc01\SYSVOL\corp.example\software\CorpVPN\LigamentVPN_1.0.0_x64_en-US.msi`).
   Используйте UNC-путь, а не букву диска — установка выполняется от имени
   учётной записи компьютера.
2. Откройте **Group Policy Management** → создайте (или выберите) GPO для OU
   с рабочими станциями → **Edit**.
3. Перейдите: *Computer Configuration → Policies → Software Settings →
   Software installation* → ПКМ → **New → Package**.
4. Выберите MSI по UNC-пути. Метод deploying — **Assigned** (пакет
   ставится при загрузке компьютера, до входа пользователя).
5. (Опционально) В свойствах пакета, вкладка *Upgrades*, добавьте предыдущую
   версию MSI — обновление пройдёт автоматически при следующей политике.

При загрузке станции Windows сам выполнит `msiexec /i <msi> /qn` —
тихо, без UI. Прервать/отменить установку пользователь не может.

### Ручная тихая установка (для проверки или вне домена)

```cmd
msiexec /i LigamentVPN_1.0.0_x64_en-US.msi /qn /l*v %TEMP%\corpvpn-install.log
```

Свойства-публичные ключи MSI (можно задать в GPO: свойства пакета →
*Modifications* через transform .mst, или прямо в командной строке):

| Свойство | Значение по умолчанию | Описание |
|---|---|---|
| `PORTALURL` | (пусто) | URL портала, вшивается в настройки по умолчанию |
| `INSTALL_ENGINES` | `1` | 0 — не ставить движки (для тонких клиентов) |

Пример с трансформом через командную строку:

```cmd
msiexec /i LigamentVPN_1.0.0_x64_en-US.msi /qn PORTALURL=https://vpn.corp.example
```

Для GPO предпочтителен `.mst`-трансформ (создаётся в WiX/Orca), чтобы
значение жило внутри пакета. Но проще всего задавать `PORTALURL` политикой
ADMX (см. ниже) — политика перекрывает свойство MSI.

### Проверка установки

```powershell
# Служба установлена и запущена
Get-Service CorpVPND
# Коды продукта
Get-WmiObject Win32_Product -Filter "Name LIKE 'Ligament VPN%'"
# Лог тихой установки
Select-String -Path "$env:TEMP\corpvpn-install.log" -Pattern "Installation completed"
```

Логи самого клиента: `%PROGRAMDATA%\Ligament\CorpVPN\logs\`
(`corpvpnd.log` — служба, `ui.log` — интерфейс, `engines\*.log` — вывод
openvpn/xray). Ротация — 5 файлов по 5 МБ.

## 3. Административные шаблоны (ADMX/ADML)

Файлы из `installer/gpo/`:

- `CorpVPN.admx` → `\\<домен>\SYSVOL\<домен>\Policies\PolicyDefinitions\CorpVPN.admx`
- `CorpVPN.adml` (русский) → `...\PolicyDefinitions\ru-RU\CorpVPN.adml`
- `CorpVPN.en-US.adml` (английский) → `...\PolicyDefinitions\en-US\CorpVPN.adml`
  (при копировании переименовать в `CorpVPN.adml`)

Политики появляются в *Computer Configuration → Administrative Templates →
Ligament CorpVPN* и пишут значения в `HKLM\SOFTWARE\Policies\Ligament\CorpVPN`:

| Политика | Тип | Описание |
|---|---|---|
| PortalUrl | строка | адрес портала (перекрывает свойство MSI и настройку пользователя) |
| RequireLogin | dword | запрет работы без входа на портал |
| Autostart | dword | автозапуск UI при входе в Windows |
| KillSwitch | dword | блокировка трафика вне туннеля |
| DisableManualImport | dword | запрет ручного импорта .conf/.ovpn/vless:// |
| DefaultProtocol | строка | протокол по умолчанию: `auto` \| `wireguard` \| `openvpn` \| `vless` |
| SplitTunnelDefault | строка | AllowedIPs по умолчанию (CIDR через запятую, `0.0.0.0/0` — весь трафик) |

Политики HKLM перекрывают пользовательские настройки приложения.
Проверка на станции: `gpresult /h report.html` или
`reg query HKLM\SOFTWARE\Policies\Ligament\CorpVPN`.

## 4. Настройка серверной части

### 4.1 Портал (vpn_creator_wireguard)

1. Включите SSO: *Settings → OpenID Connect* — issuer (Ligament), client_id,
   client_secret; включите «Автосоздание пользователей» при необходимости.
2. Desktop-клиент ходит на те же эндпоинты, что и браузерный портал:
   - `POST /api/portal/auth/exchange` — обмен OIDC id_token на API-токен;
   - `GET  /api/portal/profiles` — конфиги (WG/OVPN/VLESS);
   - `POST /api/portal/switch-protocol` — смена протокола.
3. Токен живёт 30 дней; блокировка пользователя (disabled/NONE) на портале
   мгновенно запрещает все его Bearer-запросы.

### 4.2 Ligament (2fa.ligam.org)

Desktop-клиент использует **тот же client_id, что и веб-портал** — отдельный
клиент создавать не нужно. В настройках клиента Ligament к существующему
приложению портала добавьте разрешённый redirect_uri шаблоном:

```
http://127.0.0.1:*/cb
```

(петлевой адрес; Ligament поддерживает wildcard-порт. PKCE S256 уже включён
в поток клиента — секрет не требуется, public client.)

### 4.3 Движки VPN (engine-lock)

Сторонние движки (OpenVPN, Xray-core, tun2socks, tunnel.dll WireGuard) **не
хранятся в репозитории** — они скачиваются при сборке CI по пиннингу из
`installer/engine-lock.json` (URL + SHA256) скриптом
`installer/fetch-engines.ps1` и упаковываются внутрь MSI в каталог
`engines`. Если нужно собрать MSI самостоятельно — запустите:

```powershell
pwsh -File installer\fetch-engines.ps1   # PowerShell 7+; если нет — winget install Microsoft.PowerShell
```

Движки ставятся в `%PROGRAMDATA%\Ligament\CorpVPN\engines` с ACL на
SYSTEM/Administrators — подмена пользователем невозможна. WireGuardNT-драйвер
(`wireguard.dll`) уже подписан командой WireGuard — дополнительная подпись
драйверов не требуется.

## 5. Первый вход пользователя

1. Пользователь запускает CorpVPN (ярлык рабочего стола/меню Пуск).
2. Нажимает «Войти через 2FA (Ligament)» — открывается системный браузер,
   клиент ждёт подтверждение на `http://127.0.0.1:<порт>/cb`.
3. После входа клиент сам забирает конфиги с портала — вводить адреса серверов
   и ключи не нужно. Fallback: логин/пароль (те же учётные данные портала).
4. Профили хранятся в `%PROGRAMDATA%\Ligament\CorpVPN\profiles.dat`
   (зашифрован ключом службы; ограничение MVP — один пользователь на машину).

## 6. Частые проблемы

| Симптом | Причина / решение |
|---|---|
| MSI не ставится через GPO | Проверьте: пакет Assigned в *Computer* Configuration (не User), у компьютера есть чтение сетевой папки, смотрите `C:\Windows\debug\UserMode\GPO.log` и eventlog `Application` (MsiInstaller) |
| Служба CorpVPND не стартует | `sc query CorpVPND`, лог `%PROGRAMDATA%\Ligament\CorpVPN\logs\corpvpnd.log` |
| «Нет связи с порталом» | Проверьте PortalUrl (политика/свойство MSI), DNS и прокси на станции |
| SSO-вход не возвращается в клиент | redirect_uri `http://127.0.0.1:*/cb` не добавлен в клиент Ligament |
| Политики не применяются | `gpupdate /force`, проверьте что ADMX скопирован в центральное хранилище SYSVOL |
