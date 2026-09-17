# install-service.ps1 — регистрация службы CorpVPND (запускать ОДИН раз от администратора).
#
# Требует PowerShell 7+ (pwsh): передача аргументов нативным утилитам в 5.1
# ломает кавычки. Если pwsh не найден — скрипт САМ устанавливает PowerShell 7
# (winget, фолбэк — официальный MSI с GitHub) и перезапускается под ним.
#
# Нужен только для ручных/GPO-переустановок БЕЗ NSIS-инсталлятора: сами
# установщики (v0.2.4+) вызывают `corpvpnd --install-service` сами.
#
# После установки приложения (LigamentVPN_x64-setup.exe / .msi) выполните
# (подойдёт и обычный PowerShell — всё доустановится само):
#   powershell -ExecutionPolicy Bypass -File install-service.ps1
# Параметры:
#   -InstallDir <path>  каталог установки (по умолч. "C:\Program Files\Ligament VPN")
#
# Службу ставит сам демон (CreateServiceW, корректное цитирование пути с
# пробелами) — sc.exe из PowerShell больше НЕ используется: его цитирование
# binPath ломалось и служба не стартовала.

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Ligament VPN",
    # внутренний флаг: скрипт уже перезапущен под pwsh (защита от цикла)
    [switch]$Reloaded
)

$ErrorActionPreference = "Stop"

# --- PowerShell 7+: при отсутствии доустанавливаем и перезапускаемся ----------
if ($PSVersionTable.PSVersion.Major -lt 7) {
    if ($Reloaded) { throw "Перезапуск под pwsh не сработал — запустите вручную: pwsh -File install-service.ps1" }

    $pwsh = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $pwsh)) {
        Write-Host "Требуется PowerShell 7+. Устанавливаю (winget)…" -ForegroundColor Yellow
        $wingetOk = $false
        try {
            winget install --id Microsoft.PowerShell --source winget `
                --accept-package-agreements --accept-source-agreements --silent
            $wingetOk = ($LASTEXITCODE -eq 0)
        } catch { $wingetOk = $false }

        if (-not $wingetOk -or -not (Test-Path $pwsh)) {
            Write-Host "winget не сработал — качаю официальный MSI с GitHub…" -ForegroundColor Yellow
            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" `
                -Headers @{ "User-Agent" = "ligament-vpn-installer" }
            $asset = $rel.assets | Where-Object { $_.name -match '^PowerShell-[\d.]+-win-x64\.msi$' } | Select-Object -First 1
            if (-not $asset) { throw "Не удалось найти MSI PowerShell в последнем релизе GitHub" }
            $msi = Join-Path $env:TEMP $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi
            $p = Start-Process msiexec.exe -ArgumentList @("/i", "`"$msi`"", "/qn") -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "Установка MSI PowerShell завершилась с кодом $($p.ExitCode)" }
        }
        if (-not (Test-Path $pwsh)) { throw "PowerShell 7 установлен, но $pwsh не найден" }
    }

    Write-Host "Перезапускаюсь под PowerShell 7…" -ForegroundColor Yellow
    $pwshArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Reloaded")
    if ($PSBoundParameters.ContainsKey("InstallDir")) { $pwshArgs += @("-InstallDir", $InstallDir) }
    & $pwsh @pwshArgs
    exit $LASTEXITCODE
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
