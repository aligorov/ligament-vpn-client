//! VLESS-движок (Windows): xray.exe (SOCKS-inbound) [+ tun2socks.exe].
//!
//! - конфиг xray генерируется в vpncore::xray_config (REALITY и т.д.),
//!   SOCKS слушает `127.0.0.1:{socksPort}` (по умолчанию 10808, спека §2);
//! - режим «только SOCKS» (`overrides.socksOnly`): поднимается один xray.exe —
//!   работает вовсе без прав администратора;
//! - системный режим (по умолчанию): дополнительно tun2socks.exe с устройством
//!   wintun (`-device wintun -proxy socks5://127.0.0.1:port`), заворачивая
//!   трафик системы в прокси;
//! - процессы под наблюдением: при падении перезапускаются с паузой 5 с,
//!   пока движок не остановлен.

use crate::engines::{EngineCtx, EngineError, VpnEngine};
use crate::paths;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::watch;
use vpncore::model::VpnStats;

/// Пауза перед перезапуском упавшего процесса-сайдкара.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct VlessEngine {
    profile_id: Option<String>,
    socks_port: u16,
    stop_tx: Option<watch::Sender<bool>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl VlessEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn config_path(profile_id: &str) -> PathBuf {
        paths::tunnels_dir().join(format!("corpvpn-{profile_id}.xray.json"))
    }
}

impl VpnEngine for VlessEngine {
    async fn start(&mut self, ctx: EngineCtx) -> Result<(), EngineError> {
        let profile = &ctx.profile;
        let vless = profile
            .vless
            .as_ref()
            .ok_or_else(|| EngineError::failed("В профиле нет ссылки vless://"))?;
        let socks_port = ctx.settings.socks_port;
        let config = vpncore::xray_config::build_xray_config(vless, socks_port)
            .map_err(|e| EngineError::failed(format!("Некорректная ссылка vless://: {e}")))?;

        std::fs::create_dir_all(paths::tunnels_dir())
            .map_err(|e| EngineError::failed(format!("Не создать каталог туннелей: {e}")))?;
        let conf_path = Self::config_path(&profile.id);
        std::fs::write(
            &conf_path,
            serde_json::to_vec_pretty(&config).unwrap_or_default(),
        )
        .map_err(|e| EngineError::failed(format!("Не удалось записать конфиг xray: {e}")))?;

        let (stop_tx, stop_rx) = watch::channel(false);

        // xray.exe — локальный SOCKS-прокси
        let xray_exe = crate::engines::engine_bin("xray.exe")?;
        let xray_args: Vec<String> = vec![
            "run".into(),
            "-c".into(),
            conf_path.to_string_lossy().into_owned(),
        ];
        self.tasks.push(supervise(
            xray_exe,
            xray_args,
            "xray".to_owned(),
            stop_rx.clone(),
        ));

        // Системный режим: tun2socks поднимает wintun-устройство и гонит
        // системный трафик в локальный SOCKS. socksOnly — без него (без admin).
        if !profile.overrides.socks_only {
            let tun2socks_exe = crate::engines::engine_bin("tun2socks.exe")?;
            let tun2socks_args: Vec<String> = vec![
                "-device".into(),
                "wintun".into(),
                "-proxy".into(),
                format!("socks5://127.0.0.1:{socks_port}"),
            ];
            self.tasks.push(supervise(
                tun2socks_exe,
                tun2socks_args,
                "tun2socks".to_owned(),
                stop_rx,
            ));
        }

        self.stop_tx = Some(stop_tx);
        self.profile_id = Some(profile.id.clone());
        self.socks_port = socks_port;

        // короткий health-check: даём процессам стартовать и проверяем,
        // что они не умерли мгновенно (битый конфиг/отсутствует dll)
        tokio::time::sleep(Duration::from_millis(500)).await;
        if self.tasks.iter().all(tokio::task::JoinHandle::is_finished) {
            let msg = "xray запустился и сразу завершился — проверьте ссылку vless:// и лог";
            self.stop().await;
            return Err(EngineError::failed(msg));
        }

        tracing::info!(
            profile = %profile.id,
            socks_port,
            socks_only = profile.overrides.socks_only,
            "VLESS-прокси запущен"
        );
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        if let Some(id) = self.profile_id.take() {
            let _ = std::fs::remove_file(Self::config_path(&id));
        }
    }

    fn stats(&self) -> VpnStats {
        // MVP: статистику xray (через его stats API) не опрашиваем
        VpnStats {
            rx_bytes: 0,
            tx_bytes: 0,
            handshake_at: self.profile_id.as_ref().map(|_| vpncore::model::now_epoch()),
        }
    }
}

/// Надзор за дочерним процессом: перезапуск с backoff, пока не просили стоп.
fn supervise(
    exe: PathBuf,
    args: Vec<String>,
    name: String,
    mut stop_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let mut cmd = tokio::process::Command::new(&exe);
            cmd.args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // без консольного окна
            #[cfg(windows)]
            {
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let mut child: Child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(%name, error = %e, "не запустить процесс — повтор через 5 с");
                    tokio::time::sleep(RESTART_BACKOFF).await;
                    continue;
                }
            };
            tokio::select! {
                status = child.wait() => {
                    match status {
                        Ok(code) => tracing::warn!(%name, ?code, "процесс завершился — перезапуск через 5 с"),
                        Err(e) => tracing::warn!(%name, error = %e, "процесс недоступен — перезапуск через 5 с"),
                    }
                }
                _ = stop_rx.changed() => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    tracing::debug!(%name, "процесс остановлен");
                    break;
                }
            }
            if *stop_rx.borrow() {
                break;
            }
            tokio::time::sleep(RESTART_BACKOFF).await;
        }
    })
}
