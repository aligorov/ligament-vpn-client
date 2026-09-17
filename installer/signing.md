# Подпись установщиков CorpVPN (Azure Trusted Signing)

Дистрибутивы (NSIS `*-setup.exe` и WiX `*.msi`) подписываются через
**Azure Trusted Signing** — облачный сервис подписи кода без хранения
сертификата в CI. Репозиторий публичный, секретов сборки не содержит:
подпись выполняется отдельным шагом в релизном workflow с OIDC/секретами
Azure (в приватных переменных окружения GitHub, не в коде).

> Драйверы **уже подписаны их вендорами** и повторно не подписываются:
> - `wireguard.dll` (WireGuardNT) — подпись команды WireGuard, извлекается из
>   официального MSI (см. `installer/engine-lock.json`);
> - `wintun.dll` — подпись WireGuard team (архив tun2socks);
> - `openvpn.exe`, `xray.exe` — оригинальные неподписанные/подписанные
>   вендором двоичники; их хэши запиннены в `engine-lock.json`.
> Подписывать и «переподписывать» чужие двоичники нельзя (нарушение лицензий
> и смысла подписи) — ставится только наш MSI/EXE целиком.

## 1. Подготовка (один раз, администратор организации)

1. Azure Portal → создать ресурс **Trusted Signing** (регион поддерживается
   списком сервисов; требуется подписка с оплатой по факту).
2. **Identity validation**: подтвердить организацию (Individual/Organization)
   — без валидации сертификаты не выпускаются.
3. Создать **Certificate profile** (CodeSigning, EV по желанию) —
   `Profile name` понадобится дальше.
4. Создать **Access Control** → роль `Certificate Profile Signer` для
   субъекта, от имени которого будет подписывать CI (service principal
   с федерацией OIDC на GitHub Actions, либо секрет client-id/secret).

## 2. Подпись в CI (GitHub Actions)

Вариант А — официальный action:

```yaml
- uses: azure/trusted-signing-action@v0
  with:
    azure-tenant-id:    ${{ secrets.AZURE_TENANT_ID }}
    azure-client-id:    ${{ secrets.AZURE_CLIENT_ID }}
    trusted-signing-account-name: ${{ secrets.TS_ACCOUNT_NAME }}
    certificate-profile-name:     ${{ secrets.TS_PROFILE_NAME }}
    files: |
      src-tauri/target/release/bundle/nsis/LigamentVPN_*_x64-setup.exe
      src-tauri/target/release/bundle/msi/LigamentVPN_*_x64_en-US.msi
    endpoint-url: https://eus.codesigning.azure.net/
```

Вариант Б — AzureSignTool (гибче, локально тоже работает):

```powershell
AzureSignTool sign `
  -fd sha256 -tr http://timestamp.acs.microsoft.com -td sha256 `
  -azure-tenant-id    $env:AZURE_TENANT_ID `
  -azure-client-id    $env:AZURE_CLIENT_ID `
  -azure-client-secret $env:AZURE_CLIENT_SECRET `
  -endpoint  https://eus.codesigning.azure.net/ `
  -account   $env:TS_ACCOUNT_NAME `
  -profile   $env:TS_PROFILE_NAME `
  LigamentVPN_1.0.0_x64-setup.exe LigamentVPN_1.0.0_x64_en-US.msi
```

Секреты (`Settings → Secrets and variables → Actions`):
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` (+ секрет или федерация OIDC),
`TS_ACCOUNT_NAME`, `TS_PROFILE_NAME`. Сборка без них по-прежнему работает —
артефакты будут просто неподписанными (для внутреннего тестирования).

## 3. Проверка подписи

```powershell
Get-AuthenticodeSignature .\LigamentVPN_1.0.0_x64_en-US.msi | Format-List
# Ожидание: Status = Valid, SignerCertificate — Microsoft Trusted Signing
# (CN=Microsoft Identity Verification..., цепочка до Microsoft Root CA).

# Целостность движков внутри пакета — по пиннингу engine-lock.json:
powershell -File installer\fetch-engines.ps1   # sha256 всех артефактов
```

## 4. Замечания

- **SmartScreen**: репутация набирается со временем; Trusted Signing
  сокращает «период недоверия» для новых релизов.
- **Timestamp обязателен** (`-tr http://timestamp.acs.microsoft.com`) — без
  него подпись умирает вместе с сертификатом профиля.
- Подписывается финальный артефакт **после** упаковки (включая всё
  содержимое), до загрузки в GitHub Release.
- Отзыв/ротация: сертификаты Trusted Signing короткоживущие, отзывать нечего;
  при компрометации CI отключите Access Control субъекта в Azure.
