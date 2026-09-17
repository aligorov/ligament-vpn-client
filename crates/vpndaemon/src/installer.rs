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
use std::io::Write as _;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// SDDL службы: SY/BA — полный доступ; интерактивные пользователи (IU) —
/// только QUERY/START/STOP/INTERROGATE. Без CHANGE_CONFIG — это privesc.
/// Даёт кнопке «Запустить службу» в приложении работать БЕЗ прав админа.
const SERVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCSWRPWPLOCRRC;;;IU)";

fn install_log(msg: &str) {
    // UTF-8 лог в ProgramData: stdout через nsExec превращается в кракозябры
    // (OEM-кодировка NSIS), а diagnosтика нужна читаемой (аудит #10).
    let dir = std::env::var("PROGRAMDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
        .join("Ligament")
        .join("CorpVPN")
        .join("logs");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("install.log"))
    {
        let _ = writeln!(f, "{msg}");
    }
    println!("{msg}");
}

/// Прописывает DACL службы (интерактивные пользователи: start/stop/query).
fn set_service_dacl(manager: &ServiceManager) -> windows_service::Result<()> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    use windows::Win32::System::Services::SetServiceObjectSecurity;
    use windows::core::PCWSTR;
    use windows_service::service::ServiceAccess;

    let service = manager.open_service(crate::SERVICE_NAME, ServiceAccess::ALL_ACCESS)?;
    let wide: Vec<u16> = SERVICE_SDDL.encode_utf16().chain([0]).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: wide — NUL-терминированная строка; дескриптор освобождения не
    // требует (время жизни процесса установки).
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            std::ptr::from_mut(&mut sd),
            None,
        )
        .map_err(|e| windows_service::Error::Winapi(std::io::Error::other(e)))?;
        // raw_handle() у крейта — windows-sys (isize); WinAPI-функция ждёт
        // обёртку windows 0.58 — конвертируем явно.
        let handle = windows::Win32::System::Services::SC_HANDLE(
            service.raw_handle() as *mut core::ffi::c_void,
        );
        SetServiceObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd)
            .map_err(|e| windows_service::Error::Winapi(std::io::Error::other(e)))?;
    }
    install_log("DACL службы обновлён (интерактивные пользователи: старт/стоп)");
    Ok(())
}

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
        executable_path: std::env::current_exe().map_err(|e| {
            windows_service::Error::Winapi(std::io::Error::other(format!(
                "не определить путь corpvpnd.exe: {e}"
            )))
        })?,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service_access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::DELETE;
    // После delete служба может числиться «marked for delete» (1072), пока
    // старый процесс не умер: создаём с повторами.
    let mut service = None;
    let mut last_err = None;
    for _ in 0..10 {
        match manager.create_service(&info, service_access) {
            Ok(s) => {
                service = Some(s);
                break;
            }
            // ретрай только против гонки marked-for-delete (аудит #10);
            // остальные ошибки (доступ и пр.) не «рассосутся»
            Err(e) => {
                let code = match &e {
                    windows_service::Error::Winapi(io) => io.raw_os_error(),
                    _ => None,
                };
                last_err = Some(e);
                if code != Some(1072) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    // все попытки провалились — возвращаем последнюю ошибку
    let Some(service) = service else {
        let e = last_err.unwrap();
        install_log(&format!("create_service: {e}"));
        return Err(e);
    };
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

    // Без DACL служба после сбоя поднимается только админом (аудит #5).
    if let Err(e) = set_service_dacl(&manager) {
        // не фатально: служба работает, но старт из приложения — только с админом
        install_log(&format!("set_service_dacl: {e} (не фатально)"));
    }

    service.start::<std::ffi::OsString>(&[])?;
    install_log(&format!("Служба {} установлена и запущена", crate::SERVICE_NAME));
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
