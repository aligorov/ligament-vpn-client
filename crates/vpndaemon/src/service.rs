//! Вход службы Windows (windows-service crate).
//!
//! corpvpnd работает как служба SYSTEM (спека §2): принимает Stop/Shutdown,
//! держит RPC-сервер на named pipe и активный туннель. Аргументы командной
//! строки разбираются в `main`: `/wg-tunnel` (режим туннельной службы
//! WireGuard) и `--console` (отладка в консоли).

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, windows_service_main);

/// Точка входа SCM: регистрирует обработчики и запускает рабочий цикл.
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(crate::SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

/// Реальный main службы (вызывается через макрос).
fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    // stderr/журнал событий из службы недоступны — любые паники и ошибки
    // старта пишем в %PROGRAMDATA%\Ligament\CorpVPN\logs\corpvpnd-crash.log,
    // иначе падение службы невозможно диагностировать.
    let crash_path = crate::paths::logs_dir().join("corpvpnd-crash.log");
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::fs::create_dir_all(crate::paths::logs_dir());
        let _ = std::fs::write(&crash_path, format!("panic: {info}\n"));
    }));
    if let Err(e) = run_service_loop() {
        let _ = std::fs::create_dir_all(crate::paths::logs_dir());
        let _ = std::fs::write(crate::paths::logs_dir().join("corpvpnd-crash.log"), format!("service error: {e}\n"));
    }
}

fn service_status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service_loop() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(crate::SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(service_status(ServiceState::StartPending))?;

    // поднимаем рантайм: хранилище, журналы, RPC
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let state = crate::bootstrap_state()?;

    runtime.spawn(crate::rpc::serve(Arc::clone(&state)));
    status_handle.set_service_status(service_status(ServiceState::Running))?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "служба corpvpnd запущена");

    // ждём Stop/Shutdown от SCM
    let _ = stop_rx.recv();

    status_handle.set_service_status(service_status(ServiceState::StopPending))?;
    runtime.block_on(state.shutdown());
    runtime.shutdown_timeout(Duration::from_secs(10));
    status_handle.set_service_status(service_status(ServiceState::Stopped))?;
    Ok(())
}
