//! OpenVPN-движок (Windows): openvpn.exe 2.7 (dco-win) как дочерний процесс.
//!
//! Поток управления:
//! 1. нормализуем `.ovpn` (голый `auth-user-pass`, `auth-nocache`, без askpass);
//! 2. spawn `openvpn.exe --config X --management 127.0.0.1 <port> --auth-nocache --log …`
//!    (openvpn слушает management-порт на loopback — наружу не торчит);
//! 3. подключаемся к management TCP, включаем `state on`/`log on`/`bytecount 5`;
//! 4. на запрос `>PASSWORD:Auth User:Password` отправляем логин/пароль из
//!    `corpvpn.connect` — креды живут только в памяти демона (спека §6);
//! 5. `>STATE:…,CONNECTED,SUCCESS,…` → туннель поднят; `RECONNECTING` — лог;
//!    `>HOLD:` → `hold release`;
//! 6. стоп: `signal SIGTERM` по management-каналу, затем kill.

use crate::engines::{EngineCtx, EngineError, VpnEngine};
use crate::paths;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use vpncore::model::{VpnStats, now_epoch};

/// Максимальное ожидание CONNECTED от management-интерфейса.
const CONNECT_DEADLINE: Duration = Duration::from_secs(28);

#[derive(Debug)]
pub struct OpenVpnEngine {
    profile_id: Option<String>,
    port: u16,
    child: Option<tokio::process::Child>,
    session: Option<tokio::task::JoinHandle<()>>,
    stop_tx: Option<watch::Sender<bool>>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    connected: Arc<AtomicBool>,
}

impl Default for OpenVpnEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenVpnEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            profile_id: None,
            port: 0,
            child: None,
            session: None,
            stop_tx: None,
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
            connected: Arc::new(AtomicBool::new(false)),
        }
    }

    fn conf_path(profile_id: &str) -> PathBuf {
        paths::tunnels_dir().join(format!("corpvpn-{profile_id}.ovpn"))
    }
}

/// Свободный порт на loopback (listener сразу освобождаем — небольшой race
/// допустим: openvpn займёт порт в течение секунды после spawn).
async fn free_loopback_port() -> Result<u16, EngineError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| EngineError::failed(format!("Не подобрать management-порт: {e}")))?;
    Ok(listener
        .local_addr()
        .map_err(|e| EngineError::failed(e.to_string()))?
        .port())
}

/// Подключаемся к management-порту с ретраями (openvpn ещё поднимает listener).
async fn connect_management(port: u16) -> Result<TcpStream, EngineError> {
    let mut last = String::new();
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(EngineError::failed(format!(
        "OpenVPN не открыл management-порт: {last}"
    )))
}

impl VpnEngine for OpenVpnEngine {
    async fn start(&mut self, ctx: EngineCtx) -> Result<(), EngineError> {
        let profile = &ctx.profile;
        let ovpn = profile
            .ovpn
            .as_ref()
            .ok_or_else(|| EngineError::failed("В профиле нет конфига OpenVPN"))?;
        let normalized = vpncore::ovpn::normalize(&ovpn.config);

        std::fs::create_dir_all(paths::tunnels_dir())
            .map_err(|e| EngineError::failed(format!("Не создать каталог туннелей: {e}")))?;
        let conf_path = Self::conf_path(&profile.id);
        std::fs::write(&conf_path, &normalized)
            .map_err(|e| EngineError::failed(format!("Не удалось записать конфиг OpenVPN: {e}")))?;

        let exe = crate::engines::engine_bin("openvpn.exe")?;
        let log_path = paths::logs_dir().join(format!("openvpn-{}.log", profile.id));
        self.port = free_loopback_port().await?;

        let mut cmd = tokio::process::Command::new(&exe);
        cmd.arg("--config").arg(&conf_path)
            .arg("--management")
            .arg(format!("127.0.0.1 {}", self.port))
            .arg("--auth-nocache")
            .arg("--log")
            .arg(&log_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // без консольного окна у службы
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| EngineError::failed(format!("Не запустить openvpn.exe: {e}")))?;

        let stream = match connect_management(self.port).await {
            Ok(s) => s,
            Err(e) => {
                let _ = child.start_kill();
                let _ = std::fs::remove_file(&conf_path);
                return Err(e);
            }
        };

        // канал статуса сессии: Pending → Connected | Failed(msg)
        let (status_tx, mut status_rx) = watch::channel(SessionStatus::Pending);
        let (stop_tx, stop_rx) = watch::channel(false);
        let rx_counter = Arc::clone(&self.rx);
        let tx_counter = Arc::clone(&self.tx);
        let connected_flag = Arc::clone(&self.connected);
        let credentials = ctx.credentials;

        let session = tokio::spawn(management_session(
            stream,
            child.id(),
            stop_rx,
            status_tx,
            credentials,
            rx_counter,
            tx_counter,
            connected_flag,
        ));
        self.session = Some(session);
        self.stop_tx = Some(stop_tx);
        self.child = Some(child);
        self.profile_id = Some(profile.id.clone());

        // ждём CONNECTED (30-секундный таймаут на всё подключение — в state)
        let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
        loop {
            tokio::select! {
                changed = status_rx.changed() => {
                    if changed.is_err() {
                        break; // сессия умерла — разбираемся ниже
                    }
                    // клонируем статус: держать watch::Ref через .await нельзя
                    let status = status_rx.borrow_and_update().clone();
                    match status {
                        SessionStatus::Connected => {
                            tracing::info!(profile = %profile.id, "OpenVPN: CONNECTED");
                            return Ok(());
                        }
                        SessionStatus::Failed(msg) => {
                            self.stop_internal().await;
                            return Err(EngineError::failed(msg));
                        }
                        SessionStatus::Pending => {}
                    }
                }
                _sleep = tokio::time::sleep_until(deadline) => {
                    self.stop_internal().await;
                    return Err(EngineError::failed(
                        "OpenVPN не подключился за отведённое время (проверьте лог)",
                    ));
                }
            }
        }
        Err(EngineError::failed(
            "Процесс OpenVPN завершился при подключении (проверьте лог)",
        ))
    }

    async fn stop(&mut self) {
        self.stop_internal().await;
    }

    fn stats(&self) -> VpnStats {
        VpnStats {
            rx_bytes: self.rx.load(Ordering::Relaxed),
            tx_bytes: self.tx.load(Ordering::Relaxed),
            handshake_at: if self.connected.load(Ordering::Relaxed) {
                Some(now_epoch())
            } else {
                None
            },
        }
    }
}

impl OpenVpnEngine {
    async fn stop_internal(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true); // сессия отправит signal SIGTERM и закроется
        }
        if let Some(mut child) = self.child.take() {
            // SIGTERM обычно останавливает openvpn за пару секунд; иначе kill
            if tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_err()
            {
                let _ = child.start_kill();
            }
        }
        if let Some(task) = self.session.take() {
            let _ = task.await;
        }
        if let Some(id) = self.profile_id.take() {
            let _ = std::fs::remove_file(Self::conf_path(&id));
        }
    }
}

#[derive(Debug, Clone)]
enum SessionStatus {
    Pending,
    Connected,
    Failed(String),
}

/// Живой цикл management-интерфейса: авторизация, статусы, bytecount, shutdown.
#[allow(clippy::too_many_arguments)]
async fn management_session(
    stream: TcpStream,
    child_pid: Option<u32>,
    mut stop_rx: watch::Receiver<bool>,
    status_tx: watch::Sender<SessionStatus>,
    credentials: Option<crate::engines::Credentials>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    connected: Arc<AtomicBool>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    // подписки на события management-интерфейса
    let _ = write_half.write_all(b"state on\nlog on\nbytecount 5\n").await;

    loop {
        tokio::select! {
            line = lines.next_line() => {
                if let Ok(Some(line)) = line {
                    handle_management_line(
                        &line, &mut write_half, &status_tx, credentials.as_ref(), &rx, &tx,
                        &connected,
                    )
                    .await;
                } else {
                    // openvpn закрыл канал — процесс умер
                    if connected.load(Ordering::Relaxed) {
                        tracing::warn!("OpenVPN: management-канал закрыт (процесс умер?)");
                    }
                    let _ = status_tx.send(SessionStatus::Failed(
                        "Соединение с OpenVPN потеряно".into(),
                    ));
                    break;
                }
            }
            _ = stop_rx.changed() => {
                let _ = write_half.write_all(b"signal SIGTERM\n").await;
                break;
            }
        }
    }
    if let Some(pid) = child_pid {
        tracing::debug!(pid, "OpenVPN: сессия management завершена");
    }
    let _ = write_half.shutdown().await;
}

/// Разбор одной строки management-протокола.
async fn handle_management_line(
    line: &str,
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    status_tx: &watch::Sender<SessionStatus>,
    credentials: Option<&crate::engines::Credentials>,
    rx: &Arc<AtomicU64>,
    tx: &Arc<AtomicU64>,
    connected: &Arc<AtomicBool>,
) {
    // Запрос логина/пароля: креды переданы только в памяти
    if line.starts_with(">PASSWORD:Auth User:Password") {
        match credentials {
            Some(creds) => {
                let _ = write_half
                    .write_all(format!("username \"{}\"\n", creds.username).as_bytes())
                    .await;
                let _ = write_half
                    .write_all(format!("password \"{}\"\n", creds.password).as_bytes())
                    .await;
            }
            None => {
                let _ = status_tx.send(SessionStatus::Failed(
                    "Для этого профиля нужен логин и пароль OpenVPN".into(),
                ));
            }
        }
        return;
    }
    // Современный формат: >STATE:1760000000,CONNECTED,SUCCESS,10.8.0.2,...
    if let Some(rest) = line.strip_prefix(">STATE:") {
        let fields: Vec<&str> = rest.split(',').collect();
        let state = fields.get(1).copied().unwrap_or_default();
        match state {
            "CONNECTED" if fields.get(2) == Some(&"SUCCESS") => {
                connected.store(true, Ordering::Relaxed);
                let _ = status_tx.send(SessionStatus::Connected);
            }
            "RECONNECTING" => {
                tracing::warn!("OpenVPN: переподключение...");
            }
            "EXITING" => {
                let _ = status_tx
                    .send(SessionStatus::Failed("OpenVPN отключился".into()));
            }
            _ => {}
        }
        return;
    }
    // Старый формат (2.3/некоторые сборки): OPENVPN:CONNECTED,SUCCESS,...
    if let Some(rest) = line.strip_prefix("OPENVPN:") {
        if rest.starts_with("CONNECTED") {
            connected.store(true, Ordering::Relaxed);
            let _ = status_tx.send(SessionStatus::Connected);
        } else if rest.starts_with("RECONNECTING") {
            tracing::warn!("OpenVPN: переподключение...");
        }
        return;
    }
    if line.starts_with(">HOLD:") {
        let _ = write_half.write_all(b"hold release\n").await;
        return;
    }
    // >BYTECOUNT:12345,678 или >BYTECOUNT:data:12345,678
    if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
        let rest = rest.strip_prefix("data:").unwrap_or(rest);
        if let Some((rx_s, tx_s)) = rest.split_once(',') {
            if let (Ok(rx_v), Ok(tx_v)) = (rx_s.parse::<u64>(), tx_s.parse::<u64>()) {
                rx.store(rx_v, Ordering::Relaxed);
                tx.store(tx_v, Ordering::Relaxed);
            }
        }
    }
}
