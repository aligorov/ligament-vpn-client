# Диагностика Ligament VPN (если что-то не заводится)

Прогоните команды своей платформы и пришлите вывод целиком — этого достаточно
для точного диагноза.

## Windows

```powershell
# от администратора (PowerShell)

# 1. Состояние и ПУТЬ службы (кавычки в BINARY_PATH_NAME обязательны!)
sc.exe qc CorpVPND

# 2. Попытка старта с настоящим кодом ошибки (2/1053/1067/5...)
sc.exe start CorpVPND

# 3. Реестровый ImagePath
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\CorpVPND |
    Select-Object ImagePath, Start, ObjectName

# 4. События SCM (7000/7009/7034 = старт/таймаут/падение)
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 15 |
    Where-Object { $_.Message -like '*CorpVPN*' } |
    Format-List TimeCreated, Id, Message

# 5. Defender ASR/карантин (1121/1116/1117 = блокировка неподписанного exe)
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 20 |
    Where-Object { $_.Id -in 1116,1117,1121,1122 } |
    Format-List TimeCreated, Id, Message

# 6. Наши логи/крашлоги
Get-ChildItem "$env:ProgramData\Ligament\CorpVPN\logs" |
    ForEach-Object { "=== $($_.Name) ==="; Get-Content $_.FullName -Tail 30 }
```

Быстрое лечение большинства случаев (v0.2.4+; путь подставьте свой, если отличается):

```powershell
& "$env:ProgramFiles\Ligament VPN\engines\corpvpnd.exe" --install-service
```

(самоустановка через CreateServiceW — не зависит от цитирования sc.exe)

## macOS

```bash
# 1. Что реально лежит в бандле (corpvpnd есть? xray — файл или каталог?)
ls -la "/Applications/Ligament VPN.app/Contents/Resources/engines/"

# 2. Подпись вложенного демона (ожидаем Signature=adhoc)
codesign -dv "/Applications/Ligament VPN.app/Contents/Resources/engines/corpvpnd" 2>&1 | head -3

# 3. Запуск демона руками: вывод/код (Killed:9 = подпись/карантин)
"/Applications/Ligament VPN.app/Contents/Resources/engines/corpvpnd" --console; echo "exit=$?"

# 4. Карантин (должно быть пусто после xattr -cr)
xattr -r "/Applications/Ligament VPN.app"

# 5. Следы убийства процесса
ls ~/Library/Logs/DiagnosticReports/ 2>/dev/null | grep -i corpvpn | tail -5

# 6. Лог приложения (спавн демона)
tail -30 ~/Library/"Application Support"/Ligament/CorpVPN/logs/app-daemon.log 2>/dev/null
tail -30 ~/Library/"Application Support"/Ligament/CorpVPN/logs/corpvpnd*.log 2>/dev/null
```

Быстрое лечение большинства случаев:

```bash
xattr -cr "/Applications/Ligament VPN.app"
```
