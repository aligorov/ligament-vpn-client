//! corpvpnd — исполняемый файл службы CorpVPN.
//!
//! Режимы (Windows):
//! - без аргументов: служба SCM (service_dispatcher);
//! - `--console`: RPC-сервер в консоли (отладка);
//! - `/wg-tunnel <conf>`: режим службы туннеля WireGuard — binPath-цель,
//!   загружает tunnel.dll и вызывает экспорт WireGuardTunnelService.
//!
//! Не-Windows: печает сообщение и завершается (спека — Windows-first,
//! macOS/Linux — фаза 2); RPC доступен через библиотечный
//! `corpvpnd::run_console()` и тесты.

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
    // Фаза 2 (спека §10): macOS/Linux-демон. RPC-сервер для разработки
    // доступен как библиотека corpvpnd::run_console().
    println!("corpvpnd: только Windows (см. спеку, фаза 2)");
}
