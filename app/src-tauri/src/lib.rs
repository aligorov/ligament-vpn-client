// Ligament VPN — Tauri-хост: тонкий мост UI ↔ демон corpvpnd.
pub mod transport;
pub mod tray;

/// На unix демон живёт в бандле приложения (Resources/engines/corpvpnd) и
/// запускается приложением в консольном режиме. Все ошибки спавна пишем в
/// ~/Library/Application Support/Ligament/CorpVPN/logs/app-daemon.log —
/// иначе экран «Служба CorpVPN не запущена» не диагностируем.
#[cfg(not(windows))]
mod unix_daemon {
    use std::sync::Mutex;

    static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);

    fn socket_alive() -> bool {
        std::os::unix::net::UnixStream::connect(crate::transport::SOCK_PATH).is_ok()
    }

    fn log(msg: &str) {
        use std::io::Write;
        let dir = std::env::var("HOME")
            .map(|h| {
                std::path::PathBuf::from(h)
                    .join("Library/Application Support/Ligament/CorpVPN/logs")
            })
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("app-daemon.log"))
        {
            let _ = writeln!(f, "{msg}");
        }
        eprintln!("corpvpn-app: {msg}");
    }

    /// Поднимает демона, если сокет не отвечает (в фоне: ждём сокет до 5 с,
    /// один повтор — старт с холодного диска бывает медленным).
    pub fn ensure(app: &tauri::AppHandle) {
        use tauri::Manager;
        if socket_alive() {
            return;
        }
        let res = app.path().resource_dir();
        std::thread::spawn(move || ensure_blocking(res));
    }

    fn ensure_blocking(res: Result<std::path::PathBuf, tauri::Error>) {
        let Ok(res) = res else {
            log("resource_dir недоступен");
            return;
        };
        let bin = res.join("engines").join("corpvpnd");
        log(&format!(
            "запуск демона: {} (существует: {})",
            bin.display(),
            bin.is_file()
        ));
        if !bin.is_file() {
            // Показываем реальную раскладку — ловим ошибки размещения ресурсов.
            match std::fs::read_dir(res.join("engines")) {
                Ok(entries) => {
                    let names: Vec<String> = entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    log(&format!("engines/ содержит: {names:?}"));
                }
                Err(e) => log(&format!("каталог engines не читается: {e}")),
            }
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
        for attempt in 1..=2u32 {
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
                Err(e) => {
                    log(&format!("попытка {attempt}: спавн не удался: {e} ({e:?})"));
                    continue;
                }
            }
            for _ in 0..50 {
                if socket_alive() {
                    log("демон поднялся, сокет отвечает");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            log(&format!("попытка {attempt}: демон не поднял сокет за 5 с"));
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


/// Самодиагностика «служба не запущена»: показывает пользователю причину
/// без обращения к нам (Windows: sc query/qc + crash-лог; macOS: лог спавна).
#[tauri::command]
fn diagnose_service() -> String {
    let mut out = String::new();

    #[cfg(windows)]
    {
        for cmd in [
            format!("sc.exe query {}", "CorpVPND"),
            format!("sc.exe qc {}", "CorpVPND"),
        ] {
            out.push_str(&format!("$ {cmd}\n"));
            match std::process::Command::new("cmd").args(["/C", &cmd]).output() {
                Ok(o) => {
                    out.push_str(&String::from_utf8_lossy(&o.stdout));
                    out.push_str(&String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => out.push_str(&format!("ошибка запуска: {e}\n")),
            }
            out.push('\n');
        }
        let crash = std::path::PathBuf::from(
            std::env::var("PROGRAMDATA").unwrap_or_default(),
        )
        .join("Ligament")
        .join("CorpVPN")
        .join("logs")
        .join("corpvpnd-crash.log");
        if crash.is_file() {
            out.push_str("=== corpvpnd-crash.log ===\n");
            if let Ok(text) = std::fs::read_to_string(&crash) {
                let tail: String = text.lines().rev().take(20).collect::<Vec<_>>().join("\n");
                out.push_str(&tail);
                out.push('\n');
            }
        }

        // Антивирус: ASR-правило «блокировать непопулярные exe» — главный
        // корпоративный убийца неподписанной службы (события 1121/1122).
        let ps = |script: &str| -> String {
            match std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-Command", script])
                .output()
            {
                Ok(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                    s.push_str(&String::from_utf8_lossy(&o.stderr));
                    s
                }
                Err(e) => format!("powershell недоступен: {e}"),
            }
        };
        out.push_str("=== Defender: блокировки наших файлов (1121/1122) ===\n");
        let blocks = ps(
            "Get-WinEvent -LogName 'Microsoft-Windows-Windows-Defender/Operational' -MaxEvents 300 | \
             Where-Object { $_.Id -in 1121,1122 } | \
             Where-Object { $_.Message -match 'corpvpnd|xray|tun2socks|openvpn|Ligament' } | \
             Select-Object -First 5 | Format-List TimeCreated, Id",
        );
        if blocks.trim().is_empty() {
            out.push_str("(блокировок не найдено)\n");
        } else {
            out.push_str(&blocks);
        }
        out.push_str("=== SCM: события CorpVPND (System log) ===\n");
        let scm = ps(
            "Get-WinEvent -LogName System -MaxEvents 100 | \
             Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -match 'CorpVPND' } | \
             Select-Object -First 5 | Format-List TimeCreated, Id",
        );
        if scm.trim().is_empty() {
            out.push_str("(событий SCM нет)\n");
        } else {
            out.push_str(&scm);
        }
    }

    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let base = std::path::PathBuf::from(&home)
            .join("Library/Application Support/Ligament/CorpVPN/logs");
        if let Ok(entries) = std::fs::read_dir(&base) {
            let mut files: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            files.sort();
            files.reverse(); // свежие ротации первыми
            let mut shown = 0;
            for f in files {
                if shown >= 3 {
                    break;
                }
                let fname = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if !fname.starts_with("app-daemon") && !fname.starts_with("corpvpnd") {
                    continue;
                }
                out.push_str(&format!("=== {fname} (хвост) ===\n"));
                if let Ok(text) = std::fs::read_to_string(&f) {
                    let tail: String = text.lines().rev().take(20).collect::<Vec<_>>().join("\n");
                    out.push_str(&tail);
                    out.push('\n');
                }
                shown += 1;
            }
        }
    }
    out
}


/// Запуск службы CorpVPND ИЗ ПРИЛОЖЕНИЯ с полным логом попытки.
/// Работает без прав администратора, если DACL службы разрешает
/// интерактивным пользователям START (прописывает --install-service).
/// Возвращает построчный транскрипт — UI показывает его пользователю.
#[tauri::command]
fn start_service() -> String {
    let mut log: Vec<String> = Vec::new();
    let ts = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    #[cfg(windows)]
    {
        let run = |cmd: &str| -> String {
            match std::process::Command::new("cmd").args(["/C", cmd]).output() {
                Ok(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                    s.push_str(&String::from_utf8_lossy(&o.stderr));
                    s
                }
                Err(e) => format!("ошибка запуска команды: {e}"),
            }
        };

        log.push(format!("[{}] проверка состояния службы", ts()));
        let q = run("sc.exe query CorpVPND");
        log.push(q.trim().to_owned());

        if q.contains("RUNNING") {
            log.push("служба уже RUNNING".into());
        } else if q.contains("1060") {
            log.push(
                "СЛУЖБА НЕ УСТАНОВЛЕНА (1060) — запустите установщик Ligament.VPN_x64-setup.exe".into(),
            );
            return log.join("\n");
        } else {
            log.push(format!("[{}] запуск: sc start CorpVPND", ts()));
            let st = run("sc.exe start CorpVPND");
            log.push(st.trim().to_owned());
            if st.contains("1053") {
                log.push("1053: процесс не отчитался вовремя — смотри crash-лог ниже".into());
            }
            if st.contains("5 ") || st.to_lowercase().contains("access is denied") {
                log.push(
                    "ОТКАЗ ДОСТУПА: старт запрещён. Либо DACL службы, либо антивирус —                      смотри раздел Defender ниже"
                        .into(),
                );
            }
        }

        // ждём named pipe до 10 с
        log.push(format!("[{}] ожидание канала \\\\.\\pipe\\corpvpn-daemon (до 10 с)", ts()));
        #[allow(clippy::cast_possible_truncation)]
        for i in 1..=20u32 {
            if pipe_alive_windows() {
                log.push("КАНАЛ ОТВЕЧАЕТ — служба поднялась".into());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            if i == 20 {
                log.push("канал так и не появился".into());
            }
        }

        // crash-лог
        let crash = std::path::PathBuf::from(
            std::env::var("PROGRAMDATA").unwrap_or_default(),
        )
        .join("Ligament")
        .join("CorpVPN")
        .join("logs")
        .join("corpvpnd-crash.log");
        if crash.is_file() {
            log.push("=== corpvpnd-crash.log ===".into());
            if let Ok(text) = std::fs::read_to_string(&crash) {
                let tail: String = text.lines().rev().take(15).collect::<Vec<_>>().join("\n");
                log.push(tail);
            }
        }
    }
    #[cfg(not(windows))]
    log.push("Запуск службы из приложения — только в Windows-сборке.".into());

    log.join("\n")
}

#[cfg(windows)]
fn pipe_alive_windows() -> bool {
    std::fs::metadata(r"\\.\\pipe\\corpvpn-daemon").is_ok()
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
            quit_app,
            diagnose_service,
            start_service
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
