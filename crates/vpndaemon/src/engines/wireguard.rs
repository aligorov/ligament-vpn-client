//! WireGuard-движок (Windows): служба `WireGuardTunnel$corpvpn-<id>` + tunnel.dll.
//!
//! Схема — wireguard-windows «embeddable-dll-service» (MIT):
//! - `tunnel.dll` и `wireguard.dll` (WireGuardNT, подписан WireGuard team, PBL)
//!   лежат в каталоге установки рядом с corpvpnd.exe — их кладёт инсталлер;
//! - мы создаём службу Windows с binPath = наш собственный `corpvpnd.exe
//!   /wg-tunnel <conf>`;
//! - в этом режиме [`crate::run_wireguard_tunnel_service`] загружает tunnel.dll
//!   через `LoadLibraryW` и вызывает экспорт `WireGuardTunnelService(conf)`
//!   — tunnel.dll сам регистрируется в SCM и поднимает туннель;
//! - зависимости службы: `Nsi` + `TcpIp` (сетевой стек должен подняться раньше);
//!   SID службы: `SERVICE_SID_TYPE_UNRESTRICTED` — туннельной службе нужен
//!   доступ к сети;
//! - конфиг: `%PROGRAMDATA%\Ligament\CorpVPN\tunnels\corpvpn-<id>.conf`
//!   — рендер `.conf` с применёнными overrides (AllowedIPs/DNS из UI).
//!
//! Ограничение MVP: статистика RX/TX/рукопожатия для WireGuard не собирается
//! (туннельная служба wireguard-windows не отдаёт её через SCM; интеграция
//! с UAPI-каналом wireguard.dll — на будущее).

use crate::engines::{EngineCtx, EngineError, VpnEngine};
use crate::paths;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vpncore::model::{VpnStats, now_epoch};
use windows_service::service::{
    ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceStartType, ServiceState,
    ServiceType, ServiceSidType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Имя службы туннеля: `WireGuardTunnel$corpvpn-<profileId>`
/// (префикс `WireGuardTunnel$` — конвенция wireguard-windows).
#[must_use]
pub fn service_name(profile_id: &str) -> String {
    format!("WireGuardTunnel$corpvpn-{profile_id}")
}

#[derive(Debug, Default)]
pub struct WireguardEngine {
    profile_id: Option<String>,
    service: Option<String>,
}

impl WireguardEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn conf_path(profile_id: &str) -> PathBuf {
        paths::tunnels_dir().join(format!("corpvpn-{profile_id}.conf"))
    }
}

impl VpnEngine for WireguardEngine {
    async fn start(&mut self, ctx: EngineCtx) -> Result<(), EngineError> {
        let profile = &ctx.profile;
        let wg = profile
            .wg
            .as_ref()
            .ok_or_else(|| EngineError::failed("В профиле нет конфига WireGuard"))?;
        // рендер с overrides (split tunnel AllowedIPs, DNS)
        let rendered = vpncore::wg::render_with_overrides(&wg.config, &profile.overrides)
            .map_err(|e| EngineError::failed(format!("Некорректный конфиг WireGuard: {e}")))?;

        std::fs::create_dir_all(paths::tunnels_dir())
            .map_err(|e| EngineError::failed(format!("Не создать каталог туннелей: {e}")))?;
        let conf_path = Self::conf_path(&profile.id);
        std::fs::write(&conf_path, rendered)
            .map_err(|e| EngineError::failed(format!("Не удалось записать конфиг туннеля: {e}")))?;

        let exe = std::env::current_exe()
            .map_err(|e| EngineError::failed(format!("Не определить путь службы: {e}")))?;
        let name = service_name(&profile.id);

        // SCM-вызовы блокирующие — уводим в spawn_blocking
        let scm_name = name.clone();
        let scm_conf = conf_path.clone();
        let res = tokio::task::spawn_blocking(move || {
            sc_create_and_start(&scm_name, &exe, &scm_conf)
        })
        .await
        .map_err(|e| EngineError::failed(format!("Паника при запуске туннеля: {e}")))?;

        match res {
            Ok(()) => {
                self.profile_id = Some(profile.id.clone());
                self.service = Some(name);
                tracing::info!(profile = %profile.id, "WireGuard-туннель запущен");
                Ok(())
            }
            Err(err) => {
                // зачистка недозапущенной службы
                let _ = tokio::task::spawn_blocking(move || sc_stop_and_delete(&name)).await;
                let _ = std::fs::remove_file(&conf_path);
                Err(EngineError::failed(err))
            }
        }
    }

    async fn stop(&mut self) {
        if let Some(name) = self.service.take() {
            let _ = tokio::task::spawn_blocking(move || sc_stop_and_delete(&name)).await;
        }
        if let Some(id) = self.profile_id.take() {
            let _ = std::fs::remove_file(Self::conf_path(&id));
        }
    }

    fn stats(&self) -> VpnStats {
        // см. комментарий модуля: UAPI-статистика туннельной службы не доступна в MVP
        VpnStats {
            rx_bytes: 0,
            tx_bytes: 0,
            handshake_at: self.service.as_ref().map(|_| now_epoch()),
        }
    }
}

/// Создаёт службу туннеля и ждёт SERVICE_RUNNING (≤25 с).
fn sc_create_and_start(name: &str, exe: &Path, conf_path: &Path) -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )
    .map_err(|e| format!("Не удалось открыть Service Control Manager: {e}"))?;

    // остаток после крэша/перезагрузки — удаляем перед созданием
    if let Ok(existing) = manager.open_service(name, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS) {
        let _ = existing.stop();
        sc_wait_state(&existing, ServiceState::Stopped, Duration::from_secs(5));
        let _ = existing.delete();
    }

    // binPath = corpvpnd.exe /wg-tunnel <conf> — режим embeddable-dll-service
    let info = windows_service::service::ServiceInfo {
        name: name.into(),
        display_name: format!("CorpVPN WireGuard Tunnel ({name})").into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec!["/wg-tunnel".into(), conf_path.to_path_buf().into()],
        // сетевой стек (Nsi) и TCP/IP обязаны быть подняты
        dependencies: vec![
            ServiceDependency::Service("Nsi".into()),
            ServiceDependency::Service("TcpIp".into()),
        ],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::DELETE
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|e| format!("Не удалось создать службу туннеля: {e}"))?;

    // туннельной службе нужен неограниченный сетевой доступ
    // (SERVICE_SID_TYPE_UNRESTRICTED — в ServiceInfo поля нет, ставим через config)
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|e| format!("Не задать SID службы туннеля: {e}"))?;

    service
        .start(&[] as &[std::ffi::OsString])
        .map_err(|e| format!("Не удалось запустить службу туннеля: {e}"))?;

    sc_wait_state(&service, ServiceState::Running, Duration::from_secs(25))
        .ok_or_else(|| "Служба туннеля не перешла в состояние Running (проверьте конфиг)".to_owned())
}

/// Останавливает и удаляет службу туннеля (best-effort).
fn sc_stop_and_delete(name: &str) {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return;
    };
    let Ok(service) = manager.open_service(
        name,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) else {
        return;
    };
    let _ = service.stop();
    sc_wait_state(&service, ServiceState::Stopped, Duration::from_secs(10));
    let _ = service.delete();
}

/// Поллит состояние службы до нужного или истечения таймаута.
fn sc_wait_state(
    service: &windows_service::service::Service,
    target: ServiceState,
    timeout: Duration,
) -> Option<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match service.query_status() {
            Ok(status) => {
                if status.current_state == target {
                    return Some(());
                }
                // служба упала при старте — не ждём до таймаута
                if status.current_state == ServiceState::Stopped && target == ServiceState::Running
                {
                    return None;
                }
            }
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Режим `/wg-tunnel <conf>`: мы — исполняемый файл службы туннеля.
/// Загружаем tunnel.dll (embeddable-dll-service) и вызываем экспорт
/// `WireGuardTunnelService(LPCWSTR settings)`, который сам делает
/// service-dispatch и поднимает туннель по конфигу.
///
/// # Safety
///
/// Вызывает нативный экспорт tunnel.dll с C-строкой (UTF-16, NUL-терминатор).
pub fn run_tunnel_service_mode(conf_path: &str) -> i32 {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;

    // FARPROC = Option<unsafe extern "system" fn() -> isize>; меняем сигнатуру
    // на документированную tunnel.dll: WINSTATUS WireGuardTunnelService(LPCWSTR)
    type TunnelServiceFn = unsafe extern "system" fn(PCWSTR) -> u32;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    let dll = match crate::engines::engine_bin("tunnel.dll") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("corpvpnd /wg-tunnel: {e}");
            return 2;
        }
    };
    let dll_wide: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
    let conf_wide: Vec<u16> = std::ffi::OsString::from(conf_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // SAFETY: корректные NUL-терминированные широкие строки; tunnel.dll
    // живёт весь процесс (освобождение не нужно).
    unsafe {
        let module = match LoadLibraryW(PCWSTR(dll_wide.as_ptr())) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("corpvpnd /wg-tunnel: не загрузить tunnel.dll: {e}");
                return 3;
            }
        };
        let proc = GetProcAddress(
            module,
            windows::core::s!("WireGuardTunnelService"),
        );
        let Some(f) = proc else {
            eprintln!("corpvpnd /wg-tunnel: в tunnel.dll нет экспорта WireGuardTunnelService");
            return 4;
        };
        let wireguard_tunnel_service: TunnelServiceFn = std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            TunnelServiceFn,
        >(f);
        wireguard_tunnel_service(PCWSTR(conf_wide.as_ptr())) as i32
    }
}
