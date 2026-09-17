//! Самоустановка службы Windows: `corpvpnd --install-service` / `--uninstall-service`.
//!
//! Почему не `sc.exe create` из скриптов: цитирование binPath с пробелами
//! («C:\Program Files\...») через NSIS/PowerShell → sc.exe ломается на каждом
//! слое (PowerShell съедает кавычки, NSIS экранирует иначе), в итоге SCM
//! получает обрезанный ImagePath и служба не стартует (ERROR_FILE_NOT_FOUND).
//! `ServiceManager::create_service` экранирует путь сам (`escape_wide`) —
//! вызывающий просто передаёт `current_exe()` без всяких кавычек.

use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Создаёт (или пересоздаёт при апгрейде) службу CorpVPND и запускает её.
pub fn install() -> windows_service::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    // Идемпотентность апгрейда: существующую службу останавливаем и удаляем.
    uninstall().ok();

    let info = ServiceInfo {
        name: OsString::from(crate::SERVICE_NAME),
        display_name: OsString::from("CorpVPN Daemon (Ligament)"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().unwrap_or_else(|_| "corpvpnd.exe".into()),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service_access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::DELETE;
    let service = manager.create_service(&info, service_access)?;
    service.set_description(
        "Ligament VPN — служба управления туннелями WireGuard/OpenVPN/VLESS \
         (данные: %PROGRAMDATA%\\Ligament\\CorpVPN)",
    )?;

    // Автоперезапуск при сбоях: 5с / 5с / 60с, сброс счётчика раз в сутки.
    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_hours(24)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    };
    service.update_failure_actions(failure_actions)?;

    service.start::<std::ffi::OsString>(&[])?;
    println!("Служба {} установлена и запущена", crate::SERVICE_NAME);
    Ok(())
}

/// Останавливает и удаляет службу (ошибка «нет службы» не считается ошибкой).
pub fn uninstall() -> windows_service::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = manager.open_service(crate::SERVICE_NAME, access)?;

    let running = matches!(
        service.query_status()?.current_state,
        ServiceState::StartPending | ServiceState::Running | ServiceState::ContinuePending
    );
    if running {
        service.stop()?;
        // даём SCM время перевести службу в Stopped (обычно < 2 с)
        for _ in 0..20 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    service.delete()?;
    println!("Служба {} удалена", crate::SERVICE_NAME);
    Ok(())
}
