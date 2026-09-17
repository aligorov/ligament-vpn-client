// Ligament VPN — Tauri-хост: тонкий мост UI ↔ демон corpvpnd.
pub mod transport;
pub mod tray;

/// На unix демон живёт в бандле приложения (Resources/engines/corpvpn) и
/// запускается приложением в консольном режиме — служб/launchd на v0.2 нет.
#[cfg(not(windows))]
mod unix_daemon {
    use std::sync::Mutex;

    static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);

    fn socket_alive() -> bool {
        std::os::unix::net::UnixStream::connect(crate::transport::SOCK_PATH).is_ok()
    }

    /// Поднимает демона, если сокет не отвечает.
    pub fn ensure(app: &tauri::AppHandle) {
        use tauri::Manager;
        if socket_alive() {
            return;
        }
        let Ok(res) = app.path().resource_dir() else {
            return;
        };
        let bin = res.join("engines").join("corpvpnd");
        if !bin.is_file() {
            eprintln!("corpvpn: демон не найден в бандле: {}", bin.display());
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&bin) {
                let mut perm = meta.permissions();
                perm.set_mode(perm.mode() | 0o755);
                let _ = std::fs::set_permissions(&bin, perm);
            }
        }
        match std::process::Command::new(&bin)
            .arg("--console")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => {
                *CHILD.lock().unwrap() = Some(child);
            }
            Err(e) => eprintln!("corpvpn: не запустить демона {}: {e}", bin.display()),
        }
    }

    /// Завершает демона при выходе из приложения.
    pub fn kill() {
        if let Some(mut c) = CHILD.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

use serde_json::Value;
use tauri::{Manager, WindowEvent};

/// Прокси JSON-RPC к демону. Возвращает сырой конверт строкой — UI разбирает сам.
#[tauri::command]
async fn rpc(method: String, params: Option<Value>) -> Result<String, String> {
    transport::rpc_envelope(&method, params).await
}

#[tauri::command]
async fn open_external(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Диалог выбора файла конфигурации; синхронная команда (отдельный поток),
/// т.к. blocking_pick_file нельзя звать на главном потоке.
#[tauri::command]
fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let file = app
        .dialog()
        .file()
        .add_filter("VPN config", &["conf", "ovpn", "txt"])
        .blocking_pick_file();
    match file {
        Some(path) => {
            let path = path.into_path().map_err(|e| e.to_string())?;
            let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    set_autostart_impl(enabled)
}

#[cfg(windows)]
fn set_autostart_impl(enabled: bool) -> Result<(), String> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = hkcu
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            KEY_SET_VALUE,
        )
        .map_err(|e| e.to_string())?;
    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        run.set_value("LigamentVPN", &exe.to_string_lossy().to_string())
            .map_err(|e| e.to_string())
    } else {
        run.delete_value("LigamentVPN").or(Ok(()))
    }
}

#[cfg(not(windows))]
fn set_autostart_impl(_enabled: bool) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            rpc,
            open_external,
            pick_config_file,
            set_autostart,
            quit_app
        ])
        .setup(|app| {
            // unix: поднять демона из бандла, если он ещё не работает
            #[cfg(not(windows))]
            unix_daemon::ensure(app.handle());

            // Фоновое чтение уведомлений демона → события webview + трей
            transport::spawn_notification_pump(app.handle().clone());

            tray::build_tray(app.handle())?;

            // Закрытие окна = свернуть в трей (реальный выход — «Выход» в трее)
            if let Some(win) = app.get_webview_window("main") {
                let h = app.handle().clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        if let Some(w) = h.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                });
                let _ = win.show();
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("ошибка сборки Ligament VPN")
        .run(|_app, event| {
            if let tauri::RunEvent::Exit = event {
                #[cfg(not(windows))]
                unix_daemon::kill();
            }
        });
}
