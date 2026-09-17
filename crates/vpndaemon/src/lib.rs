//! # corpvpnd — служба Windows для CorpVPN (Ligament VPN Client)
//!
//! Демон SYSTEM (модель Mullvad/Firezone, спека §2):
//! - [`rpc`] — JSON-RPC 2.0 поверх named pipe `\\.\pipe\corpvpn-daemon`
//!   (SDDL: интерактивные пользователи + администраторы, сеть запрещена);
//! - [`state`] — профили/настройки/состояние + единственный активный туннель;
//! - [`engines`] — WireGuard (службы WireGuardTunnel$ + tunnel.dll),
//!   OpenVPN (openvpn.exe + management TCP), VLESS (xray.exe + tun2socks.exe);
//! - [`portal_flow`] — OIDC Authorization Code + PKCE и синхронизация профилей;
//! - [`service`] — glue службы Windows (windows-service crate).
//!
//! Не-Windows: RPC доступен через unix socket `/tmp/corpvpn-daemon.sock`
//! (разработка/тесты), движки — заглушки. Спека, фаза 2: macOS/Linux.

// VpnEngine — трейт только для внутреннего использования (enum-обёртка
// ActiveEngine), auto-trait bounds на Future не критичны.
#![allow(async_fn_in_trait)]

pub mod engines;
pub mod logging;
pub mod paths;
pub mod portal_flow;
pub mod rpc;
pub mod state;

#[cfg(windows)]
pub mod installer;
#[cfg(windows)]
pub mod service;

/// Имя службы Windows. ДОЛЖНО совпадать с регистрацией в SCM буква-в-букву
/// (install-service.ps1 и NSIS-хуки создают службу «CorpVPND»): диспетчер
/// windows-service соединяется с SCM по этому имени, при несовпадении
/// StartServiceCtrlDispatcher падает и служба не стартует (баг v0.1.0–v0.2.1).
pub const SERVICE_NAME: &str = "CorpVPND";

use std::sync::Arc;
use vpncore::policy::DefaultPolicyProvider;
use vpncore::store::{EncryptedFileStore, load_or_create_key};

/// Готовит состояние демона: каталоги, журналирование, ключ, хранилище,
/// коллектор логов. Используется и службой, и `--console` режимом.
///
/// На Windows политики читаются из HKLM (реестровый провайдер подключает
/// инсталлер, спека §5); до его появления — `DefaultPolicyProvider`
/// (политик нет).
pub fn bootstrap_state() -> Result<Arc<state::AppState>, Box<dyn std::error::Error>> {
    paths::ensure_dirs()?;
    let (events, _) = tokio::sync::broadcast::channel::<String>(1024);
    logging::init(&paths::logs_dir(), events.clone());

    // ключ хранилища: 32 байта, создаётся при первом старте (спека §6)
    let key = load_or_create_key(&paths::key_path())?;
    let store = Arc::new(EncryptedFileStore::new(paths::profiles_path(), key));
    let policy: Box<dyn vpncore::policy::PolicyProvider> =
        Box::new(DefaultPolicyProvider);

    let app_state = state::AppState::load(store, policy, events)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let app_state = Arc::new(app_state);

    // журнал → кольцевой буфер для corpvpn.logs.tail
    tokio::spawn(log_collector(Arc::clone(&app_state)));
    Ok(app_state)
}

/// Пишет broadcast-строчки log.entry в кольцевой буфер состояния.
async fn log_collector(state: Arc<state::AppState>) {
    let mut rx = state.events().subscribe();
    loop {
        match rx.recv().await {
            Ok(frame) => {
                let entry: Option<logging::LogEntry> = serde_json::from_str(&frame)
                    .ok()
                    .and_then(|v: serde_json::Value| {
                        serde_json::from_value(v.get("params").cloned().unwrap_or_default())
                            .ok()
                    });
                if let Some(entry) = entry {
                    state.push_log(entry).await;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Запуск в консольном режиме (`--console`): RPC в текущем процессе,
/// без SCM. Для отладки на Windows; на macOS/Linux — единственный способ
/// поднять RPC-сервер (dev).
pub async fn run_console() -> Result<(), Box<dyn std::error::Error>> {
    let state = bootstrap_state()?;
    tracing::info!("corpvpnd: консольный режим");
    rpc::serve(state).await?;
    Ok(())
}
