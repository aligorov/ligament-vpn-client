# install-service.ps1 — регистрация службы CorpVPND (запускать ОДИН раз от администратора).
# Требует PowerShell 7+ (pwsh): передача аргументов нативным утилитам в 5.1
# ломает кавычки. Установка: winget install Microsoft.PowerShell
#
# Нужен только для ручных/GPO-переустановок БЕЗ NSIS-инсталлятора: сами
# установщики (v0.2.4+) вызывают `corpvpnd --install-service` сами.
#
# После установки приложения (LigamentVPN_x64-setup.exe / .msi) выполните:
#   pwsh -ExecutionPolicy Bypass -File install-service.ps1
# Параметры:
#   -InstallDir <path>  каталог установки (по умолч. "C:\Program Files\Ligament VPN")
#
# Службу ставит сам демон (CreateServiceW, корректное цитирование пути с
# пробелами) — sc.exe из PowerShell больше НЕ используется: его цитирование
# binPath ломалось и служба не стартовала.

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Ligament VPN"
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "Требуется PowerShell 7+ (pwsh). Установите: winget install Microsoft.PowerShell и запустите: pwsh -File install-service.ps1"
}

$service = "CorpVPND"
$bin = Join-Path $InstallDir "engines\corpvpnd.exe"

if (-not (Test-Path $bin)) {
    throw "Не найден $bin — сначала установите приложение (MSI/NSIS) и повторите."
}

# Административные права обязательны
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Запустите этот скрипт от имени администратора" }

# Каталог данных (ACL ставит служба, но создаём заранее)
$data = "$env:ProgramData\Ligament\CorpVPN"
New-Item -ItemType Directory -Force -Path $data, "$data\logs", "$data\tunnels" | Out-Null

# Самоустановка: создаст/пересоздаст службу, пропишет recovery и запустит.
& $bin --install-service
if ($LASTEXITCODE -ne 0) { throw "corpvpnd --install-service завершился с кодом $LASTEXITCODE" }

Write-Host "Готово: служба $service установлена и запущена ($bin)"
Write-Host "Логи: $data\logs; канал UI: \\.\pipe\corpvpn-daemon"
