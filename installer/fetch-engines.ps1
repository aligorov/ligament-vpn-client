# fetch-engines.ps1 — скачивание сторонних VPN-движков для сборки CorpVPN.
#
# Читает installer/engine-lock.json (пиннинг: URL + SHA256), скачивает каждый
# артефакт, проверяет хэш и раскладывает в app/engines/<name> — этот каталог
# упаковывается установщиком рядом со службой CorpVPND.
#
# Использование (локально и в CI, windows-latest):
#   powershell -ExecutionPolicy Bypass -File installer\fetch-engines.ps1
# Параметры:
#   -LockFile <path>    путь к engine-lock.json (по умолч. рядом со скриптом)
#   -EnginesDir <path>  куда класть движки (по умолч. <repo>\app\engines)
#   -AllowUnverified    разрешить артефакты с sha256=null (TODO-пин) —
#                       только для локальных экспериментов, НЕ для релиза
#
# Движки в репозитории не хранятся (лицензии/размер); см. LICENSES/.

[CmdletBinding()]
param(
    [string]$LockFile = "",
    [string]$EnginesDir = "",
    [switch]$AllowUnverified
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest без прогресс-бара работает на порядок быстрее

if (-not $LockFile)   { $LockFile   = Join-Path $PSScriptRoot "engine-lock.json" }
if (-not $EnginesDir) { $EnginesDir = Join-Path (Join-Path $PSScriptRoot "..") (Join-Path "app" "engines") }

if (-not (Test-Path $LockFile)) { throw "engine-lock.json не найден: $LockFile" }
$lock = Get-Content $LockFile -Raw -Encoding UTF8 | ConvertFrom-Json

# TLS 1.2 для старых окружений; на windows-latest избыточен, но безвреден.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path $EnginesDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("corpvpn-engines-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function Get-FileSha256 {
    param([string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Expand-Msi {
    # Административная установка: распаковывает файлы MSI без установки.
    # Возвращает каталог с распакованным деревом файлов.
    param([string]$Msi)
    $nullDir = Join-Path $tmp ("msi-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $nullDir | Out-Null
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/a", "`"$Msi`"", "/qn", "TARGETDIR=`"$nullDir`"") -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec /a завершился с кодом $($p.ExitCode): $Msi" }
    return $nullDir
}

$failed = @()

foreach ($prop in $lock.engines.PSObject.Properties) {
    $name = $prop.Name
    $e = $prop.Value
    Write-Host "==> $name $($e.version)"

    if (-not $e.url) { Write-Host "    пропущен (нет url)"; continue }

    $dest = Join-Path $EnginesDir $e.dest
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $archive = Join-Path $tmp ($name + "." + $e.format)
    Write-Host "    скачиваю $($e.url)"
    try {
        Invoke-WebRequest -Uri $e.url -OutFile $archive -UseBasicParsing
    } catch {
        Write-Warning "    СКАЧИВАНИЕ НЕ УДАЛОСЬ: $($_.Exception.Message)"
        $failed += $name
        continue
    }

    if ($e.sha256) {
        $actual = Get-FileSha256 $archive
        if ($actual -ne $e.sha256.ToLowerInvariant()) {
            Write-Warning "    SHA256 НЕ СОВПАЛ: ожидался $($e.sha256), получен $actual"
            $failed += $name
            continue
        }
        Write-Host "    sha256 ok"
    } elseif ($AllowUnverified) {
        Write-Warning "    sha256 НЕ ЗАПИННОВАН (null) — продолжаю только из-за -AllowUnverified. Артефакт НЕ для релиза."
    } else {
        Write-Warning "    sha256 НЕ ЗАПИННОВАН (null) — отказ. Внесите хэш в engine-lock.json или используйте -AllowUnverified для локальной сборки."
        $failed += $name
        continue
    }

    switch ($e.format) {
        "zip" {
            Expand-Archive -Path $archive -DestinationPath $dest -Force
        }
        "msi" {
            $unpacked = Expand-Msi -Msi $archive
            # Переносим распакованное содержимое в целевой каталог.
            Get-ChildItem -Path $unpacked -Recurse -File | ForEach-Object {
                $rel = $_.FullName.Substring($unpacked.Length + 1)
                $target = Join-Path $dest $rel
                New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
                Move-Item -Force $_.FullName $target
            }
        }
        "tar.gz" {
            # tar.exe есть в Windows 10 1803+ и на runners CI.
            & tar.exe -xzf $archive -C $dest
            if ($LASTEXITCODE -ne 0) { throw "tar -xzf failed for $archive" }
        }
        default { throw "Неизвестный формат '$($e.format)' для $name" }
    }

    Write-Host "    -> $dest"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

if ($failed.Count -gt 0) {
    Write-Error ("Движки с ошибками: " + ($failed -join ", "))
    exit 1
}

Write-Host "Готово. Движки: $EnginesDir"
Write-Host "Дальше CI (release.yml) упаковывает app/engines в sidecar-ресурсы Tauri/MSI."
