# install-service.ps1 — регистрация службы CorpVPND (запускать ОДИН раз от администратора).
#
# После установки приложения (LigamentVPN_x64-setup.exe / .msi) выполните:
#   powershell -ExecutionPolicy Bypass -File install-service.ps1
# Параметры:
#   -InstallDir <path>  каталог установки (по умолч. "C:\Program Files\Ligament VPN")
#
# Служба ставится auto-start + LocalSystem; движки лежат в <InstallDir>\engines.
# Пользователю права администратора больше не нужны: UI говорит со службой
# через именованный канал \\.\pipe\corpvpn-daemon (ACL: Interactive + Admins).

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Ligament VPN"
)

$ErrorActionPreference = "Stop"

$service = "CorpVPND"
$bin = Join-Path $InstallDir "engines\corpvpnd.exe"

if (-not (Test-Path $bin)) {
    throw "Не найден $bin — сначала установите приложение (MSI/NSIS) и повторите."
}

# Административные права обязательны
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Запустите этот скрипт от имени администратора" }

# Каталог данных (профили/логи/конфиги туннелей) — создаёт сама служба,
# но создаём заранее с правильными ACL (SYSTEM/Admins), чтобы не гонять службу.
$data = "$env:ProgramData\Ligament\CorpVPN"
New-Item -ItemType Directory -Force -Path $data, "$data\logs", "$data\tunnels" | Out-Null

# Служба: создаём при отсутствии, иначе обновляем binPath.
$existing = Get-Service -Name $service -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Служба $service уже существует — обновляю binPath."
    & sc.exe config $service binPath= "`"$bin`"" start= auto obj= LocalSystem | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config завершился с кодом $LASTEXITCODE" }
} else {
    & sc.exe create $service binPath= "`"$bin`"" start= auto obj= LocalSystem DisplayName= "CorpVPN Daemon (Ligament)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create завершился с кодом $LASTEXITCODE" }
    & sc.exe description $service "Ligament VPN — служба управления туннелями WireGuard/OpenVPN/VLESS (данные: $data)" | Out-Null
}

# Восстановление после сбоев: перезапуск через 5с/5с/60с (включая сброс при отказе).
& sc.exe failure $service reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null

Start-Service -Name $service
Write-Host "Готово: служба $service запущена ($bin)"
Write-Host "Логи: $data\logs; канал UI: \\.\pipe\corpvpn-daemon"
