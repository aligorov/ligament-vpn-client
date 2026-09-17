// Транспорт к демону corpvpnd: named pipe (Windows) / unix socket (dev).
// Протокол — newline-delimited JSON-RPC 2.0 (см. crates/vpndaemon/src/rpc.rs).
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DAEMON_ERR: &str = "Служба CorpVPN не запущена";

#[cfg(windows)]
pub const PIPE_PATH: &str = r"\\.\pipe\corpvpn-daemon";
#[cfg(not(windows))]
pub const SOCK_PATH: &str = "/tmp/corpvpn-daemon.sock";

static REQ_ID: AtomicU64 = AtomicU64::new(1);

/// Полный конверт JSON-RPC строкой (UI сам разбирает result/error).
pub async fn rpc_envelope(method: &str, params: Option<Value>) -> Result<String, String> {
    let id = REQ_ID.fetch_add(1, Ordering::Relaxed);
    let req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params.unwrap_or(Value::Null),
    });
    let resp = roundtrip(id, &req.to_string()).await?;
    Ok(resp.to_string())
}

#[cfg(windows)]
async fn roundtrip(id: u64, req_line: &str) -> Result<Value, String> {
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe = ClientOptions::new()
        .open(PIPE_PATH)
        .map_err(|_| DAEMON_ERR.to_string())?;
    let (rx, mut tx) = tokio::io::split(pipe);
    tx.write_all(req_line.as_bytes())
        .await
        .map_err(|e| format!("Запись в канал службы: {e}"))?;
    tx.write_all(b"\n")
        .await
        .map_err(|e| format!("Запись в канал службы: {e}"))?;
    read_response(id, BufReader::new(rx)).await
}

#[cfg(not(windows))]
async fn roundtrip(id: u64, req_line: &str) -> Result<Value, String> {
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(SOCK_PATH)
        .await
        .map_err(|_| DAEMON_ERR.to_string())?;
    let (rx, mut tx) = tokio::io::split(stream);
    tx.write_all(req_line.as_bytes())
        .await
        .map_err(|e| format!("Запись в сокет службы: {e}"))?;
    tx.write_all(b"\n")
        .await
        .map_err(|e| format!("Запись в сокет службы: {e}"))?;
    read_response(id, BufReader::new(rx)).await
}

async fn read_response<R: tokio::io::AsyncRead + Unpin>(
    id: u64,
    mut reader: tokio::io::BufReader<R>,
) -> Result<Value, String> {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    for _ in 0..50 {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|_| "Чтение из службы".to_string())?;
        if n == 0 || line.trim().is_empty() {
            return Err(DAEMON_ERR.into());
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if msg.get("id").and_then(Value::as_u64) == Some(id) {
            return Ok(msg);
        }
        // уведомление (без id) — пропускаем
    }
    Err("Служба не ответила".into())
}

/// Читает уведомления демона (state.changed / log.entry) и прокидывает их в webview.
/// Отдельное persistent-соединение: переподключается с задержкой при обрывах.
pub fn spawn_notification_pump(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            match notifications_once(&app).await {
                Ok(()) => {} // соединение закрыто — повторяем
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
}

#[cfg(windows)]
async fn notifications_once(app: &tauri::AppHandle) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(PIPE_PATH)
        .map_err(|_| DAEMON_ERR.to_string())?;
    let (rx, _tx) = tokio::io::split(pipe);
    let mut reader = BufReader::new(rx);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(()); // демон закрыл соединение
        }
        forward_notification(app, &line);
    }
}

#[cfg(not(windows))]
async fn notifications_once(app: &tauri::AppHandle) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stream = tokio::net::UnixStream::connect(SOCK_PATH)
        .await
        .map_err(|_| DAEMON_ERR.to_string())?;
    let (rx, _tx) = tokio::io::split(stream);
    let mut reader = BufReader::new(rx);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        forward_notification(app, &line);
    }
}

fn forward_notification(app: &tauri::AppHandle, line: &str) {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if msg.get("jsonrpc").is_none() {
        return;
    }
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return;
    };
    let payload = msg.get("params").cloned().unwrap_or(Value::Null);
    match method {
        "state.changed" => {
            let status = payload
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let _ = tauri::Emitter::emit(app, "state.changed", payload);
            if let Some(status) = status {
                crate::tray::set_tray_status(app, &status);
            }
        }
        "log.entry" => {
            let _ = tauri::Emitter::emit(app, "log.entry", payload);
        }
        _ => {}
    }
}
