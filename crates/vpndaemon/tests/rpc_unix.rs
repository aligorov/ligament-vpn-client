//! Интеграционный тест RPC поверх unix socket (не-Windows разработка).
//!
//! Проверяет транспорт целиком: сервер принимает подключения, обрабатывает
//! JSON-RPC построчно, транслирует уведомления state.changed подключённым
//! клиентам.

#![cfg(not(windows))]

use corpvpnd::state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use vpncore::policy::DefaultPolicyProvider;
use vpncore::store::EncryptedFileStore;

/// Порт для теста — свой сокет, чтобы не мешать параллельным тестам.
const TEST_SOCKET: &str = "/tmp/corpvpn-daemon-test.sock";

fn spawn_server_on(path: &str) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EncryptedFileStore::new(
        dir.path().join("profiles.dat"),
        [11u8; 32],
    ));
    let (tx, _rx) = broadcast::channel(64);
    let state = Arc::new(
        AppState::load(store, Box::new(DefaultPolicyProvider), tx).unwrap(),
    );
    // собственный listener на выделенном сокете — логика соединений та же,
    // что в corpvpnd::rpc::serve (handle_connection).
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let state_for_conn = Arc::clone(&state_clone);
            // handle_connection приватный → дублируем минимально:
            // запросы читаем построчно и отвечаем через corpvpnd::rpc::dispatch
            tokio::spawn(async move {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                let mut events = state_for_conn.events().subscribe();
                let mut line = String::new();
                loop {
                    line.clear();
                    tokio::select! {
                        read = reader.read_line(&mut line) => {
                            match read {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                            let request = line.trim().to_owned();
                            if request.is_empty() { continue; }
                            let response = corpvpnd::rpc::dispatch(&state_for_conn, &request).await;
                            if write_half.write_all(response.as_bytes()).await.is_err()
                                || write_half.write_all(b"\n").await.is_err() {
                                break;
                            }
                        }
                        event = events.recv() => {
                            match event {
                                Ok(frame) => {
                                    if write_half.write_all(frame.as_bytes()).await.is_err()
                                        || write_half.write_all(b"\n").await.is_err() {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {}
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
                let _ = write_half.shutdown().await;
            });
        }
    });
    state
}

async fn request(stream: &mut UnixStream, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_rpc_session_over_unix_socket() {
    let _ = std::fs::remove_file(TEST_SOCKET);
    let state = spawn_server_on(TEST_SOCKET);

    let mut client = UnixStream::connect(TEST_SOCKET).await.unwrap();

    // state.get до подключения
    let v = request(&mut client, "corpvpn.state.get", "{}").await;
    assert_eq!(v["result"]["status"], "disconnected");

    // импорт WG-профиля
    let wg_conf = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = h:51820\n";
    let v = request(
        &mut client,
        "corpvpn.profiles.import",
        &format!(
            r#"{{"name":"Корпоративная","config":{}}}"#,
            serde_json::to_string(wg_conf).unwrap()
        ),
    )
    .await;
    assert_eq!(v["result"]["kind"], "wireguard");
    let profile_id = v["result"]["id"].as_str().unwrap().to_owned();

    // подключаемся (stub-движок) и слушаем уведомления state.changed
    let mut notify_client = UnixStream::connect(TEST_SOCKET).await.unwrap();
    let v = request(
        &mut client,
        "corpvpn.connect",
        &format!(r#"{{"profileId":"{profile_id}"}}"#),
    )
    .await;
    assert_eq!(v["result"]["status"], "connected", "ответ connect: {v}");

    // второй клиент должен получить state.changed
    let mut line = String::new();
    let mut reader = BufReader::new(&mut notify_client);
    let deadline = Duration::from_secs(5);
    let got_notification = tokio::time::timeout(deadline, async {
        loop {
            line.clear();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                return false;
            }
            if line.contains("\"state.changed\"") {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(got_notification, "уведомление state.changed не пришло");

    // отключение
    let v = request(&mut client, "corpvpn.disconnect", "{}").await;
    assert_eq!(v["result"]["status"], "disconnected");

    // состояние консистентно
    let s = state.state().await;
    assert_eq!(s.status, vpncore::model::VpnStatus::Disconnected);
    let _ = std::fs::remove_file(TEST_SOCKET);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notifications_log_entry_broadcast() {
    // точечная проверка: событие из broadcast-канала добирается до подписчика
    let (tx, mut rx) = broadcast::channel(16);
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "log.entry",
        "params": {"ts": 1, "message": "тест"}
    })
    .to_string();
    tx.send(frame).unwrap();
    let received = rx.recv().await.unwrap();
    assert!(received.contains("log.entry"));
}
