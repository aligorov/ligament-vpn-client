//! Портал-поток: OIDC (Authorization Code + PKCE), вход по паролю,
//! синхронизация профилей, выход.
//!
//! OIDC (`corpvpn.portal.oidc.start`):
//! 1. discovery + PKCE → URL авторизации (UI открывает системный браузер);
//! 2. демон слушает loopback `http://127.0.0.1:<port>/cb` (ручной разбор
//!    HTTP-запроса — без тяжёлых веб-зависимостей);
//! 3. код ← браузер → token endpoint (PKCE verifier) → id_token;
//! 4. `POST /api/portal/auth/exchange` → Bearer-токен → зашифрованное хранилище;
//! 5. `GET /api/portal/profiles` → upsert профилей → уведомление `state.changed`.
//!
//! issuer/client_id по умолчанию — Ligament (спека §1); переопределяются
//! параметрами RPC и переменными `CORPVPN_OIDC_ISSUER`/`CORPVPN_OIDC_CLIENT_ID`.
//! Порт loopback-callback фиксирован (`CORPVPN_OIDC_CALLBACK_PORT`, по
//! умолчанию 8400): Ligament сверяет redirect_uri точным совпадением и под
//! случайный порт (`:0`) вход всегда отвергался бы.

use crate::state::{AppState, RpcFailure};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vpncore::model::{Profile, ProfileKind, ProfileSource, now_epoch};
use vpncore::portal::{PortalClient, PortalProfiles, PortalUser};

/// IdP по умолчанию (Ligament 2FA, спека §1).
pub const DEFAULT_OIDC_ISSUER: &str = "https://2fa.ligam.org";
/// client_id «CorpVPN Desktop» регистрируется в настройках Ligament (спека §2).
pub const DEFAULT_OIDC_CLIENT_ID: &str = "CorpVPN Desktop";
/// Порт loopback-callback; именно `http://127.0.0.1:8400/cb` регистрируется
/// в Ligament как redirect_uri (сверка точная — порт обязан быть фиксированным).
pub const DEFAULT_OIDC_CALLBACK_PORT: u16 = 8400;
/// Сколько ждать ответа браузера на loopback-сервере.
const OIDC_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
/// Страница-ответ на loopback-запрос.
const CALLBACK_BODY: &str = "CorpVPN: можно закрыть это окно";

fn default_issuer(override_value: Option<String>) -> String {
    override_value
        .or_else(|| std::env::var("CORPVPN_OIDC_ISSUER").ok())
        .unwrap_or_else(|| DEFAULT_OIDC_ISSUER.to_owned())
}

fn default_client_id(override_value: Option<String>) -> String {
    override_value
        .or_else(|| std::env::var("CORPVPN_OIDC_CLIENT_ID").ok())
        .unwrap_or_else(|| DEFAULT_OIDC_CLIENT_ID.to_owned())
}

fn parse_callback_port(raw: Option<&str>) -> u16 {
    raw.and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
        .unwrap_or(DEFAULT_OIDC_CALLBACK_PORT)
}

fn callback_port() -> u16 {
    parse_callback_port(std::env::var("CORPVPN_OIDC_CALLBACK_PORT").ok().as_deref())
}

async fn portal_client_for(state: &Arc<AppState>) -> Result<PortalClient, RpcFailure> {
    let url = state.portal_url().await;
    if url.is_empty() {
        return Err(RpcFailure::new(
            "Не задан адрес портала — укажите его в настройках или обратитесь к администратору",
        ));
    }
    PortalClient::new(&url).map_err(|e| RpcFailure::new(e.to_string()))
}

/// Вход логин/пароль: сессия-кука портала + сразу забрать профили.
pub async fn login_password(
    state: &Arc<AppState>,
    username: &str,
    password: &str,
) -> Result<PortalLoginResult, RpcFailure> {
    let client = portal_client_for(state).await?;
    let cookie = client
        .login_password(username, password)
        .await
        .map_err(|e| RpcFailure::new(e.to_string()))?;
    let profiles = client
        .fetch_profiles_cookie(&cookie)
        .await
        .map_err(|e| {
            RpcFailure::new(format!("Вход выполнен, но профили не получены: {e}"))
        })?;
    let user = profiles.user.clone();
    let synced = upsert_profiles(state, profiles).await;
    state.set_portal_session(cookie, true, Some(user.clone())).await;
    Ok(PortalLoginResult { user, profiles: synced })
}

/// Результат входа/синхронизации для UI.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalLoginResult {
    pub user: PortalUser,
    pub profiles: Vec<Profile>,
}

/// Запуск OIDC: возвращает URL для системного браузера, дальше демон
/// сам дорабатывает поток (loopback → token → exchange → sync).
pub async fn oidc_start(
    state: &Arc<AppState>,
    issuer: Option<String>,
    client_id: Option<String>,
) -> Result<String, RpcFailure> {
    let client = portal_client_for(state).await?;
    let issuer = default_issuer(issuer);
    let client_id = default_client_id(client_id);

    // Порт фиксирован: redirect_uri сверяется в Ligament точным совпадением,
    // случайный порт (`:0`) не совпал бы ни с одной регистрацией.
    let port = callback_port();
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| RpcFailure::new(format!("Не открыть loopback-порт {port}: {e}")))?;

    let auth = client
        .oidc_prepare(&issuer, &client_id, port)
        .await
        .map_err(|e| RpcFailure::new(e.to_string()))?;
    let url = auth.url.clone();

    let state_clone = Arc::clone(state);
    let portal = portal_client_for(state).await?;
    tokio::spawn(async move {
        if let Err(e) = oidc_complete_flow(state_clone, &portal, listener, auth).await {
            tracing::warn!(error = %e, "OIDC-поток не завершён");
        }
    });
    Ok(url)
}

/// Полный OIDC-поток после возврата URL: ждём код на loopback, меняем на
/// id_token, обмениваем на токен портала, синхронизируем профили.
async fn oidc_complete_flow(
    state: Arc<AppState>,
    portal: &PortalClient,
    listener: TcpListener,
    auth: vpncore::portal::OidcAuth,
) -> Result<(), String> {
    let (code, returned_state) =
        match tokio::time::timeout(OIDC_CALLBACK_TIMEOUT, wait_callback_code(listener)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("Вход не подтверждён за 5 минут".into()),
        };
    if returned_state != auth.state {
        return Err("Несовпадение state в OIDC-ответе".into());
    }

    let id_token = portal
        .oidc_complete(&auth, &code, "")
        .await
        .map_err(|e| e.to_string())?;
    let token = portal
        .exchange(&id_token)
        .await
        .map_err(|e| e.to_string())?;
    let user = token.user.clone();
    let profiles = portal
        .fetch_profiles(&token.access_token)
        .await
        .map_err(|e| e.to_string())?;
    upsert_profiles(&state, profiles).await;
    state
        .set_portal_session(token.access_token, false, Some(user))
        .await;
    tracing::info!("OIDC-вход выполнен, профили синхронизированы");
    Ok(())
}

/// Принимает один HTTP-запрос на `/cb?code=…&state=…`, отвечает
/// страницей «можно закрыть окно» и возвращает (code, state).
async fn wait_callback_code(listener: TcpListener) -> Result<(String, String), String> {
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("loopback-соединение: {e}"))?;
    let mut buf = [0u8; 8192];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("чтение loopback-запроса: {e}"))?;
    let request = String::from_utf8_lossy(&buf[..n]).into_owned();
    // строка запроса: GET /cb?code=...&state=... HTTP/1.1
    let request_line = request.lines().next().unwrap_or_default().to_owned();
    let query = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|path| path.split_once('?').map(|(_, q)| q.to_owned()))
        .unwrap_or_default();

    let mut code = String::new();
    let mut state = String::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = simple_url_decode(v),
                "state" => state = simple_url_decode(v),
                _ => {}
            }
        }
    }

    let body = format!(
        "<html><body><h3>{CALLBACK_BODY}</h3></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;

    if code.is_empty() {
        return Err("браузер не вернул код авторизации".into());
    }
    Ok((code, state))
}

/// Минимальный %XX-decode (кода/state хватает).
fn simple_url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Повторная синхронизация профилей по сохранённому токену.
pub async fn sync(state: &Arc<AppState>) -> Result<PortalLoginResult, RpcFailure> {
    let (token, is_cookie) = state
        .portal_session()
        .await
        .ok_or_else(|| RpcFailure::new("Сначала выполните вход"))?;
    let client = portal_client_for(state).await?;
    let profiles = if is_cookie {
        client.fetch_profiles_cookie(&token).await
    } else {
        client.fetch_profiles(&token).await
    }
    .map_err(|e| RpcFailure::new(e.to_string()))?;
    let user = profiles.user.clone();
    let synced = upsert_profiles(state, profiles).await;
    Ok(PortalLoginResult { user, profiles: synced })
}

/// Выход: забыть токен (и попытаться завершить сессию на портале).
pub async fn logout(state: &Arc<AppState>) -> Result<(), RpcFailure> {
    if let Some((token, is_cookie)) = state.portal_session().await {
        if is_cookie {
            if let Ok(client) = portal_client_for(state).await {
                let _ = client.logout(&token).await;
            }
        }
    }
    state.clear_portal_session().await;
    Ok(())
}

/// Upsert профилей портала: существующие (по kind, source=portal) обновляем,
/// новые создаём; отсутствующие на портале — удаляем. Ручные импорты
/// (`source=import`) не трогаем никогда.
pub async fn upsert_profiles(state: &Arc<AppState>, profiles: PortalProfiles) -> Vec<Profile> {
    let mut incoming: Vec<(ProfileKind, Option<String>)> = Vec::new();
    if profiles.wg_config.is_some() {
        incoming.push((ProfileKind::Wireguard, profiles.wg_config.clone()));
    }
    if profiles.ovpn_config.is_some() {
        incoming.push((ProfileKind::Openvpn, profiles.ovpn_config.clone()));
    }
    if profiles.vless_uri.is_some() {
        incoming.push((ProfileKind::Vless, profiles.vless_uri.clone()));
    }

    {
        let mut data = state.data.write().await;
        let now = now_epoch();
        for (kind, config) in &incoming {
            if config.as_deref() == Some("") {
                continue;
            }
            if let Some(existing) = data
                .profiles
                .iter_mut()
                .find(|p| p.kind == *kind && p.source == ProfileSource::Portal)
            {
                match kind {
                    ProfileKind::Wireguard => existing.wg = config.clone().map(|c| vpncore::model::WgProfile { config: c }),
                    ProfileKind::Openvpn => existing.ovpn = config.clone().map(|c| vpncore::model::OvpnProfile { config: c }),
                    ProfileKind::Vless => existing.vless = config.clone().map(|c| vpncore::model::VlessProfile { uri: c }),
                }
                existing.updated_at = now;
            } else {
                let name = match kind {
                    ProfileKind::Wireguard => "Корпоративная сеть (WireGuard)",
                    ProfileKind::Openvpn => "Корпоративная сеть (OpenVPN)",
                    ProfileKind::Vless => "Корпоративная сеть (VLESS)",
                };
                let mut p = Profile::new(name, *kind, ProfileSource::Portal);
                match kind {
                    ProfileKind::Wireguard => p.wg = config.clone().map(|c| vpncore::model::WgProfile { config: c }),
                    ProfileKind::Openvpn => p.ovpn = config.clone().map(|c| vpncore::model::OvpnProfile { config: c }),
                    ProfileKind::Vless => p.vless = config.clone().map(|c| vpncore::model::VlessProfile { uri: c }),
                }
                data.profiles.push(p);
            }
        }
        // портал больше не выдаёт конфиг такого вида — убираем его профиль
        data.profiles.retain(|p| {
            p.source != ProfileSource::Portal
                || incoming.iter().any(|(kind, cfg)| {
                    *kind == p.kind && cfg.as_deref().is_some_and(|c| !c.is_empty())
                })
        });
        let _ = state.persist(&data);
    }

    let profiles_now = state.profiles().await;
    // профильный набор изменился — скажем UI
    let _ = state
        .events()
        .send(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "state.changed",
            "params": state.data.read().await.vpn,
        })
        .to_string());
    profiles_now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode() {
        assert_eq!(simple_url_decode("abc"), "abc");
        assert_eq!(simple_url_decode("a%20b"), "a b");
        assert_eq!(simple_url_decode("a+b"), "a b");
        assert_eq!(simple_url_decode("%D0%BF%D1%80%D0%B8"), "при");
        assert_eq!(simple_url_decode("bad%2"), "bad%2");
    }

    #[tokio::test]
    async fn callback_server_parses_code_and_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { wait_callback_code(listener).await });
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(
                b"GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        let _ = client.read_to_string(&mut response).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(CALLBACK_BODY));
        let (code, state) = server.await.unwrap().unwrap();
        assert_eq!(code, "SplxlOBeZQQYbYS6WxSbIA");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn defaults_and_env_override() {
        // без переменных — константы спеки
        let iss = std::env::var("CORPVPN_OIDC_ISSUER").is_err();
        if iss {
            assert_eq!(default_issuer(None), DEFAULT_OIDC_ISSUER);
        }
        assert_eq!(
            default_issuer(Some("https://custom.idp".into())),
            "https://custom.idp"
        );
        if std::env::var("CORPVPN_OIDC_CALLBACK_PORT").is_err() {
            assert_eq!(callback_port(), DEFAULT_OIDC_CALLBACK_PORT);
        }
    }

    #[test]
    fn callback_port_parse() {
        // валидное значение (с пробелами) применяется, 0 и мусор — нет
        assert_eq!(parse_callback_port(Some("9000")), 9000);
        assert_eq!(parse_callback_port(Some(" 9000 ")), 9000);
        assert_eq!(parse_callback_port(Some("0")), DEFAULT_OIDC_CALLBACK_PORT);
        assert_eq!(parse_callback_port(Some("не порт")), DEFAULT_OIDC_CALLBACK_PORT);
        assert_eq!(parse_callback_port(Some("99999")), DEFAULT_OIDC_CALLBACK_PORT);
        assert_eq!(parse_callback_port(None), DEFAULT_OIDC_CALLBACK_PORT);
    }

    use crate::state::AppState;
    use tokio::net::TcpStream;
    use tokio::sync::broadcast;
    use vpncore::policy::DefaultPolicyProvider;
    use vpncore::store::{EncryptedFileStore, ProfileStore};

    fn state_with_profiles(profiles: Vec<Profile>) -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(EncryptedFileStore::new(
            dir.path().join("profiles.dat"),
            [7u8; 32],
        ));
        store
            .save(&vpncore::store::StoreData {
                profiles,
                ..Default::default()
            })
            .unwrap();
        let (tx, _rx) = broadcast::channel(16);
        Arc::new(
            AppState::load(store, Box::new(DefaultPolicyProvider), tx).unwrap(),
        )
    }

    fn wg_text() -> String {
        "[Interface]\nPrivateKey = portal\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = h:51820\n".into()
    }

    #[tokio::test]
    async fn upsert_creates_updates_and_removes() {
        // готовим профиль портала WG
        let mut existing = Profile::new("старый", ProfileKind::Wireguard, ProfileSource::Portal);
        existing.wg = Some(vpncore::model::WgProfile { config: "старый конфиг".into() });
        // и ручной импорт, который трогать нельзя
        let mut manual = Profile::new("мой", ProfileKind::Wireguard, ProfileSource::Import);
        manual.wg = Some(vpncore::model::WgProfile { config: wg_text() });
        let state = state_with_profiles(vec![existing, manual]);

        let fresh = PortalProfiles {
            user: vpncore::portal::PortalUser {
                name: "ivanov.i".into(),
                display_name: "Иванов И.".into(),
                tier: "VIP".into(),
            },
            wg_config: Some(wg_text()),
            ovpn_config: None,
            vless_uri: None,
            vless_sub_url: Some("https://vpn.example.com/api/sub/tok".into()),
        };
        let result = upsert_profiles(&state, fresh.clone()).await;
        assert_eq!(result.len(), 2, "портальный WG обновлён + импорт на месте");
        let portal_wg = result
            .iter()
            .find(|p| p.source == ProfileSource::Portal)
            .unwrap();
        assert_eq!(portal_wg.wg.as_ref().unwrap().config, wg_text());

        // портал перестал выдавать WG (переключили протокол) — профиль удалён
        let without_wg = PortalProfiles {
            user: fresh.user.clone(),
            wg_config: None,
            ovpn_config: Some("client\nremote h 443\n".into()),
            vless_uri: None,
            vless_sub_url: None,
        };
        let result = upsert_profiles(&state, without_wg).await;
        assert_eq!(result.len(), 2, "ovpn добавлен, импорт остался");
        assert!(result
            .iter()
            .any(|p| p.kind == ProfileKind::Openvpn && p.source == ProfileSource::Portal));
        assert!(result
            .iter()
            .all(|p| !(p.kind == ProfileKind::Wireguard && p.source == ProfileSource::Portal)));
    }

    #[test]
    fn sync_without_session_is_user_error() {
        // smoke: портала нет → проверяем мгновенный отказ без сессии, но без
        // сессии — мгновенный отказ (проверяем через futures not hanging)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(EncryptedFileStore::new(
            dir.path().join("profiles.dat"),
            [7u8; 32],
        ));
        let (tx, _rx) = broadcast::channel(16);
        let state = Arc::new(
            AppState::load(store, Box::new(DefaultPolicyProvider), tx).unwrap(),
        );
        let err = rt
            .block_on(sync(&state))
            .unwrap_err();
        assert_eq!(err.user_message, "Сначала выполните вход");
    }
}
