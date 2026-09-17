//! corpvpnd — исполняемый файл службы CorpVPN.
//!
//! Режимы (Windows):
//! - без аргументов: служба SCM (service_dispatcher);
//! - `--console`: RPC-сервер в консоли (отладка);
//! - `/wg-tunnel <conf>`: режим службы туннеля WireGuard — binPath-цель,
//!   загружает tunnel.dll и вызывает экспорт WireGuardTunnelService.
//!
//! macOS/Linux: приложение Tauri запускает нас в консольном режиме
//! (без SCM/launchd — фаза 3), поднимаем RPC на unix-сокете.

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Режим туннельной службы WireGuard (см. engines::wireguard)
    if let Some(pos) = args.iter().position(|a| a.eq_ignore_ascii_case("/wg-tunnel")) {
        let conf = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_default();
        std::process::exit(corpvpnd::engines::wireguard::run_tunnel_service_mode(&conf));
    }

    if args.iter().any(|a| a == "--console") {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        if let Err(e) = runtime.block_on(corpvpnd::run_console()) {
            eprintln!("corpvpnd --console: {e}");
            std::process::exit(1);
        }
        return;
    }

    // обычный запуск службой SCM
    if let Err(e) = corpvpnd::service::run_service() {
        eprintln!("corpvpnd: не запуститься как служба: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    // macOS/Linux: единственный режим — консольный RPC-сервер. Приложение
    // стартует нас само (app/src-tauri unix_daemon::ensure); раньше здесь
    // был заглушка «только Windows», из-за которой сокет не поднимался
    // и UI показывал «Служба CorpVPN не запущена» (баг v0.2.0–v0.2.2).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(corpvpnd::run_console()) {
        eprintln!("corpvpnd: {e}");
        std::process::exit(1);
    }
}
