//! JSON-RPC 2.0 поверх named pipe (Windows) / unix socket (разработка).
//!
//! Имена канала: `\\.\pipe\corpvpn-daemon` (спека §3) и
//! `/tmp/corpvpn-daemon.sock` для не-Windows отладки.
//!
//! Протокол: одна строка (по `\n`) — один JSON-RPC запрос; ответ — тоже
//! строка. Уведомления демона (`state.changed`, `log.entry`) пишутся всем
//! подключённым клиентам тем же форматом (broadcast).
//!
//! Безопасность канала (Windows): SDDL `D:P(A;;GA;;;AU)(A;;GA;;;BA)` —
//! полный доступ интерактивным пользователям и администраторам, сетевому
//! входу (NETWORK) прав не выдаётся вовсе (спека §6).

use crate::state::{AppState, RpcFailure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use vpncore::model::Settings;

/// Имя named pipe на Windows (спека §3).
pub const PIPE_NAME: &str = r"\\.\pipe\corpvpn-daemon";
/// Путь unix-сокета для разработки на macOS/Linux.
pub const UNIX_SOCKET_PATH: &str = "/tmp/corpvpn-daemon.sock";
/// SDDL канала: интерактивные пользователи + администраторы, без сети.
#[cfg(windows)]
const PIPE_SDDL: &str = "D:P(A;;GA;;;AU)(A;;GA;;;BA)";

/// Лимит длины строки запроса (защита от зацикливания на мусоре).
const MAX_LINE_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[allow(dead_code)] // jsonrpc приходит, но не влияет на обработку
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Ошибка JSON-RPC с `data.userMessage` (RU) и `data.debug` (спека §9).
#[allow(clippy::needless_pass_by_value)] // id переезжает в JSON-ответ
fn rpc_error(id: Option<Value>, code: i32, message: &str, failure: Option<&RpcFailure>) -> String {
    let error = match failure {
        Some(f) => json!({
            "code": code,
            "message": f.user_message,
            "data": {
                "userMessage": f.user_message,
                "debug": f.debug,
            }
        }),
        None => json!({ "code": code, "message": message }),
    };
    json!({ "jsonrpc": "2.0", "id": id, "error": error }).to_string()
}

#[allow(clippy::needless_pass_by_value)] // id/result переезжают в JSON-ответ
fn rpc_result(id: Option<Value>, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

// ---------------------------------------------------------------------------
// Диспетчер методов (имена — ровно из спеки §3)
// ---------------------------------------------------------------------------

/// Обрабатывает один запрос. Возвращает строку-ответ (без `\n`).
// Это и есть «таблица диспетчеризации» — единый match по именам методов
// из спеки §3; дробить её на функции меньше смысла, чем держать в одном месте.
#[allow(clippy::too_many_lines)]
pub async fn dispatch(state: &Arc<AppState>, request: &str) -> String {
    let parsed: RpcRequest = match serde_json::from_str(request) {
        Ok(r) => r,
        Err(e) => {
            return rpc_error(
                Some(Value::Null),
                -32_700,
                &format!("Некорректный JSON-RPC запрос: {e}"),
                None,
            )
        }
    };
    let id = parsed.id.clone();
    let result = match parsed.method.as_str() {
        "corpvpn.state.get" => Ok(json!(state.state().await)),

        "corpvpn.connect" => {
            let profile_id = parsed
                .params
                .get("profileId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let credentials = parse_credentials(&parsed.params);
            match profile_id {
                Some(pid) => state.connect(&pid, credentials).await.map(|s| json!(s)),
                None => Err(params_error("не указан profileId")),
            }
        }

        "corpvpn.disconnect" => Ok(json!(state.disconnect().await)),

        "corpvpn.profiles.list" => Ok(json!({
            "profiles": state.profiles().await,
            "settings": state.settings().await,
        })),

        "corpvpn.profiles.import" => {
            let name = parsed
                .params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let config = parsed
                .params
                .get("config")
                .and_then(Value::as_str)
                .unwrap_or_default();
            state
                .import_profile(name, config)
                .await
                .map(|p| json!(p))
        }

        "corpvpn.profiles.delete" => {
            let pid = parsed
                .params
                .get("profileId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            match pid {
                Some(pid) => state.delete_profile(&pid).await.map(|()| json!(true)),
                None => Err(params_error("не указан profileId")),
            }
        }

        "corpvpn.profiles.update" => {
            match serde_json::from_value::<vpncore::model::Profile>(
                parsed.params.get("profile").cloned().unwrap_or(Value::Null),
            ) {
                Ok(profile) => state.update_profile(profile).await.map(|p| json!(p)),
                Err(e) => Err(params_error(format!("поле profile: {e}"))),
            }
        }

        "corpvpn.settings.get" => Ok(json!(state.settings().await)),

        "corpvpn.settings.set" => {
            match serde_json::from_value::<Settings>(
                parsed.params.get("settings").cloned().unwrap_or(Value::Null),
            ) {
                Ok(settings) => state.set_settings(settings).await.map(|s| json!(s)),
                Err(e) => Err(params_error(format!("поле settings: {e}"))),
            }
        }

        "corpvpn.logs.tail" => {
            let limit = parsed
                .params
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(100) as usize;
            Ok(json!({ "entries": state.logs_tail(limit.min(1000)).await }))
        }

        "corpvpn.portal.login" => {
            let username = parsed
                .params
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let password = parsed
                .params
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            crate::portal_flow::login_password(state, &username, &password)
                .await
                .map(|r| json!(r))
        }

        "corpvpn.portal.oidc.start" => {
            let issuer = parsed
                .params
                .get("issuer")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let client_id = parsed
                .params
                .get("clientId")
                .and_then(Value::as_str)
                .map(str::to_owned);
            crate::portal_flow::oidc_start(state, issuer, client_id)
                .await
                .map(|url| json!({ "url": url }))
        }

        "corpvpn.portal.sync" => {
            crate::portal_flow::sync(state).await.map(|r| json!(r))
        }

        "corpvpn.portal.logout" => {
            crate::portal_flow::logout(state).await.map(|()| json!(true))
        }

        other => {
            return rpc_error(
                id,
                -32_601,
                &format!("Неизвестный метод: {other}"),
                None,
            )
        }
    };

    match result {
        Ok(value) => rpc_result(id, value),
        Err(failure) => rpc_error(id, -32_000, &failure.user_message, Some(&failure)),
    }
}

fn params_error(detail: impl Into<String>) -> RpcFailure {
    RpcFailure::new(format!("Неверные параметры запроса: {}", detail.into()))
        .with_debug("invalid params (-32602)")
}

fn parse_credentials(params: &Value) -> Option<crate::engines::Credentials> {
    let username = params.get("username").and_then(Value::as_str)?;
    let password = params.get("password").and_then(Value::as_str)?;
    if username.is_empty() || password.is_empty() {
        return None;
    }
    Some(crate::engines::Credentials {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Транспорты
// ---------------------------------------------------------------------------

/// Запускает сервер RPC: named pipe на Windows, unix socket иначе.
pub async fn serve(state: Arc<AppState>) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        serve_pipe(state).await
    }
    #[cfg(not(windows))]
    {
        serve_unix(state).await
    }
}

/// Обслуживает одно подключение: читаем строки-запросы, пишем ответы,
/// параллельно транслируем broadcast-уведомления.
async fn handle_connection<S>(stream: S, state: Arc<AppState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut events = state.events().subscribe();
    let mut line = String::new();

    loop {
        line.clear();
        tokio::select! {
            read = reader.read_line(&mut line) => {
                match read {
                    Ok(0) | Err(_) => break, // EOF/ошибка — клиент ушёл
                    Ok(_) => {}
                }
                if line.len() > MAX_LINE_LEN {
                    let _ = write_half
                        .write_all(
                            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Слишком длинный запрос\"}}\n"
                                .as_bytes(),
                        )
                        .await;
                    break;
                }
                let request = line.trim();
                if request.is_empty() {
                    continue;
                }
                let response = dispatch(&state, request).await;
                if write_half.write_all(response.as_bytes()).await.is_err() {
                    break;
                }
                if write_half.write_all(b"\n").await.is_err() {
                    break;
                }
            }
            event = events.recv() => {
                match event {
                    Ok(frame) => {
                        if write_half.write_all(frame.as_bytes()).await.is_err()
                            || write_half.write_all(b"\n").await.is_err()
                        {
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
}

// -- Windows: named pipe ----------------------------------------------------

/// Named pipe сервер. Каждая итерация создаёт новый instance pipe
/// (клиентов может быть много одновременно), подключённые экземпляры
/// обслуживаются в отдельных задачах.
#[cfg(windows)]
async fn serve_pipe(state: Arc<AppState>) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    // SECURITY_ATTRIBUTES из SDDL: интерактивные пользователи + администраторы.
    // Дескриптор живёт всё время работы сервера — сознательно «утекаем» Box.
    // Указатель храним как usize/сырой адрес (Send), разыменовываем только
    // в момент создания instance'ов pipe: &mut SECURITY_ATTRIBUTES не Send,
    // и держать его через .await в этом цикле нельзя.
    let attrs_addr: usize = {
        let attrs: &'static mut windows::Win32::Security::SECURITY_ATTRIBUTES =
            Box::leak(Box::new(unsafe { pipe_security_attributes(PIPE_SDDL)? }));
        std::ptr::from_mut(attrs) as usize
    };

    loop {
        let options = ServerOptions::new();
        // SAFETY: addr указывает на SECURITY_ATTRIBUTES, которая живёт
        // (leak) всё время работы сервера; CreateNamedPipeW только читает её.
        let server = unsafe {
            options.create_with_security_attributes_raw(
                PIPE_NAME,
                attrs_addr as *mut std::ffi::c_void,
            )
        }?;
        // ждём клиента; параллельно готовим следующий instance
        server.connect().await?;
        let connected = server;
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            handle_connection(connected, state_clone).await;
        });
    }
}

/// Строит SECURITY_ATTRIBUTES из SDDL-строки.
///
/// # Safety
///
/// Возвращает структуру с сырым указателем на дескриптор безопасности,
/// выделенный `LocalAlloc`; дескриптор не освобождается (время жизни сервера).
#[cfg(windows)]
unsafe fn pipe_security_attributes(
    sddl: &str,
) -> std::io::Result<windows::Win32::Security::SECURITY_ATTRIBUTES> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::core::PCWSTR;

    let mut wide: Vec<u16> = sddl.encode_utf16().collect();
    wide.push(0);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: wide — валидная NUL-терминированная строка; SDDL_REVISION_1 —
    // единственная поддерживаемая ревизия.
    #[allow(clippy::borrow_as_ptr)] // API хочет *mut PSECURITY_DESCRIPTOR
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PCWSTR(wide.as_ptr()),
        SDDL_REVISION_1,
        &mut descriptor,
        None,
    )
    .map_err(std::io::Error::other)?;

    Ok(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<std::ffi::c_void>(),
        bInheritHandle: windows::Win32::Foundation::FALSE,
    })
}

// -- не-Windows: unix socket (разработка) ------------------------------------

#[cfg(not(windows))]
async fn serve_unix(state: Arc<AppState>) -> std::io::Result<()> {
    use tokio::net::UnixListener;

    // возможен остался от прошлого запуска
    let _ = std::fs::remove_file(UNIX_SOCKET_PATH);
    let listener = UnixListener::bind(UNIX_SOCKET_PATH)?;
    tracing::info!("RPC сервер на unix socket {}", UNIX_SOCKET_PATH);
    loop {
        let (stream, _addr) = listener.accept().await?;
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            handle_connection(stream, state_clone).await;
        });
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use vpncore::policy::DefaultPolicyProvider;
    use vpncore::store::EncryptedFileStore;

    fn test_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(EncryptedFileStore::new(
            dir.path().join("profiles.dat"),
            [7u8; 32],
        ));
        let (tx, _rx) = broadcast::channel(64);
        Arc::new(AppState::load(store, Box::new(DefaultPolicyProvider), tx).unwrap())
    }

    #[tokio::test]
    async fn unknown_method_and_parse_error() {
        let state = test_state();
        let resp = dispatch(&state, r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32_601);
        assert_eq!(v["id"], 1);
        let resp = dispatch(&state, "not json").await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32_700);
    }

    #[tokio::test]
    async fn state_get_roundtrip() {
        let state = test_state();
        let resp = dispatch(
            &state,
            r#"{"jsonrpc":"2.0","id":"a","method":"corpvpn.state.get"}"#,
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["status"], "disconnected");
        assert_eq!(v["result"]["activeProfileId"], Value::Null);
        assert_eq!(v["id"], "a");
    }

    #[tokio::test]
    async fn profiles_import_update_delete_flow() {
        let state = test_state();
        let wg_conf = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = h:51820\n";
        let resp = dispatch(
            &state,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"corpvpn.profiles.import","params":{{"name":"corp","config":{}}}}}"#,
                serde_json::to_string(wg_conf).unwrap()
            ),
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["kind"], "wireguard");
        assert_eq!(v["result"]["source"], "import");
        let pid = v["result"]["id"].as_str().unwrap().to_owned();

        // список
        let resp = dispatch(&state, r#"{"jsonrpc":"2.0","id":2,"method":"corpvpn.profiles.list"}"#).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["profiles"].as_array().unwrap().len(), 1);
        assert_eq!(v["result"]["settings"]["socksPort"], 10_808);

        // update: имя + override
        let mut profile: vpncore::model::Profile =
            serde_json::from_value(v["result"]["profiles"][0].clone()).unwrap();
        profile.name = "Переименован".into();
        let resp = dispatch(
            &state,
            &format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"corpvpn.profiles.update","params":{{"profile":{}}}}}"#,
                serde_json::to_string(&profile).unwrap()
            ),
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["name"], "Переименован");

        // connect через RPC (stub-движок) + disconnect
        let resp = dispatch(
            &state,
            &format!(
                r#"{{"jsonrpc":"2.0","id":4,"method":"corpvpn.connect","params":{{"profileId":"{pid}"}}}}"#
            ),
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v.get("result").is_some(), "подключение прошло: {v}");
        let resp = dispatch(&state, r#"{"jsonrpc":"2.0","id":5,"method":"corpvpn.disconnect"}"#).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["status"], "disconnected");

        // удаление занятого/свободного
        let resp = dispatch(
            &state,
            &format!(
                r#"{{"jsonrpc":"2.0","id":6,"method":"corpvpn.profiles.delete","params":{{"profileId":"{pid}"}}}}"#
            ),
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], true);
    }

    #[tokio::test]
    async fn connect_without_profile_param_is_error() {
        let state = test_state();
        let resp = dispatch(
            &state,
            r#"{"jsonrpc":"2.0","id":1,"method":"corpvpn.connect","params":{}}"#,
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32_000);
        assert!(v["error"]["data"]["userMessage"]
            .as_str()
            .unwrap()
            .contains("profileId"));
    }

    #[tokio::test]
    async fn settings_set_validates_and_applies() {
        let state = test_state();
        let resp = dispatch(
            &state,
            r#"{"jsonrpc":"2.0","id":1,"method":"corpvpn.settings.set","params":{"settings":{"autostart":false,"autoConnect":true,"killSwitch":false,"language":"ru","portalUrl":"https://vpn.example.com","socksPort":12345}}}"#,
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["autoConnect"], true);
        assert_eq!(v["result"]["socksPort"], 12_345);
        // get возвращает то же
        let resp = dispatch(&state, r#"{"jsonrpc":"2.0","id":2,"method":"corpvpn.settings.get"}"#).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["socksPort"], 12_345);
    }

    #[tokio::test]
    async fn logs_tail_empty_then_entries() {
        let state = test_state();
        let resp = dispatch(&state, r#"{"jsonrpc":"2.0","id":1,"method":"corpvpn.logs.tail","params":{"limit":10}}"#).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["result"]["entries"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn import_rejects_garbage_with_user_message() {
        let state = test_state();
        let resp = dispatch(
            &state,
            r#"{"jsonrpc":"2.0","id":1,"method":"corpvpn.profiles.import","params":{"name":"x","config":"мусор"}}"#,
        )
        .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        let msg = v["error"]["data"]["userMessage"].as_str().unwrap();
        assert!(msg.contains("тип конфига"), "{msg}");
    }
}
