; NSIS-хуки Ligament VPN (Tauri 2: bundle.windows.nsis.installerHooks).
; perMachine-инсталлятор запускается с правами администратора — регистрируем
; службу CorpVPND прямо в установке, чтобы пользователю не нужно было
; ничего делать вручную (v0.1.0 требовал отдельный install-service.ps1).

!macro NSIS_HOOK_POSTINSTALL
  ; Каталог данных (ACL ставит служба, но создаём заранее)
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN"
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN\logs"
  CreateDirectory "$COMMONPROGRAMDATA\Ligament\CorpVPN\tunnels"

  ; Идемпотентно: останавливаем и пересоздаём службу (апгрейд поверх старой)
  nsExec::ExecToLog 'sc.exe stop CorpVPND'
  nsExec::ExecToLog 'sc.exe delete CorpVPND'
  nsExec::ExecToLog 'sc.exe create CorpVPND binPath= "\"$INSTDIR\engines\corpvpnd.exe\"" start= auto obj= LocalSystem DisplayName= "CorpVPN Daemon (Ligament)"'
  nsExec::ExecToLog 'sc.exe description CorpVPND "Ligament VPN — служба управления туннелями WireGuard/OpenVPN/VLESS"'
  ; Автоперезапуск при сбоях: 5с/5с/60с, сброс счётчика раз в сутки
  nsExec::ExecToLog 'sc.exe failure CorpVPND reset= 86400 actions= restart/5000/restart/5000/restart/60000'
  ; tunnel.dll (embeddable-dll-service) требует зависимости Nsi/TcpIp
  nsExec::ExecToLog 'sc.exe config CorpVPND depend= Nsi/TcpIp'
  nsExec::ExecToLog 'sc.exe start CorpVPND'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'sc.exe stop CorpVPND'
  nsExec::ExecToLog 'sc.exe delete CorpVPND'
  ; Данные (профили/логи) не трогаем — только службу.
!macroend
