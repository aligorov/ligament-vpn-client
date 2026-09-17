; NSIS-хуки Ligament VPN (Tauri 2: bundle.windows.nsis.installerHooks).
; perMachine-инсталлятор запускается с правами администратора.
;
; Службу ставит САМ демон (`corpvpnd --install-service`, CreateServiceW с
; корректным цитированием пути). Никакого `sc.exe create` из скриптов:
; цитирование binPath с пробелами («C:\Program Files\...») через
; NSIS/PowerShell ломалось на каждом слое, и служба не стартовала.

!macro NSIS_HOOK_POSTINSTALL
  ; Каталог данных (ACL ставит служба, но создаём заранее)
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN"
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN\logs"
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN\tunnels"

  ; Идемпотентно: демон сам остановит/удалит старую и создаст новую службу,
  ; пропишет автоперезапуск при сбоях (5с/5с/60с) и запустит её.
  nsExec::ExecToLog '"$INSTDIR\engines\corpvpnd.exe" --install-service'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog '"$INSTDIR\engines\corpvpnd.exe" --uninstall-service'
  ; Данные (профили/логи) не трогаем — только службу.
!macroend
