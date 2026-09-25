//! HTTP-клиент портала `vpn_creator_wireguard` + OIDC (Authorization Code + PKCE).
//!
//! Контракт — спека §4 и реальные роуты портала:
//! - `POST /api/portal/login` `{username,password}` → 200 + кука `vpn_portal_session`;
//! - `GET {issuer}/.well-known/openid-configuration` — discovery Ligament;
//! - `POST {token_endpoint}` — обмен кода на id_token (grant_type=authorization_code,
//!   PKCE S256);
//! - `POST /api/portal/auth/exchange` `{idToken}` → `{accessToken, expiresInDays, user}`;
//! - `GET /api/portal/profiles` (Bearer **или** кука) → `{user, wgConfig?, ovpnConfig?, vlessUri?, vlessSubUrl?}`;
//! - `POST /api/portal/switch-protocol` `{"protocol":"WIREGUARD"|"OPENVPN"}`;
//! - `GET /api/sub/<token>` — base64-подписка vless://.
//!
//! Все сетевые куски тонкие; вся логика (URL авторизации, PKCE-челлендж,
//! разбор ответов) вынесена в чистые функции, которые тестируются без сети.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;

/// Имя куки сессии портала (см. `src/lib/portal-session.ts` портала).
pub const PORTAL_SESSION_COOKIE: &str = "vpn_portal_session";

/// Ошибка портала. `Display` — по-русски, текст уходит пользователю.
#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    #[error("Нет связи с сервером: {0}")]
    Network(String),
    /// Пользовательская ошибка авторизации (401/403/429 и ошибки токена).
    #[error("{0}")]
    Auth(String),
    /// Прочие HTTP-ошибки.
    #[error("Сервер вернул ошибку (HTTP {0})")]
    Http(u16),
    #[error("Не удалось разобрать ответ сервера")]
    Parse,
}

/// Пользователь портала (`{name, displayName, tier}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUser {
    pub name: String,
    pub display_name: String,
    /// Уровень доступа (FREE/VIP/…), значения задаёт портал.
    pub tier: String,
}

/// Ответ `POST /api/portal/auth/exchange`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalTokenResponse {
    #[serde(default)]
    pub ok: Option<bool>,
    pub access_token: String,
    #[serde(default)]
    pub expires_in_days: Option<u64>,
    pub user: PortalUser,
}

/// Ответ `GET /api/portal/profiles`. Конфиги приходят только для
/// провижиненных протоколов, поэтому всё кроме `user` — `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalProfiles {
    pub user: PortalUser,
    #[serde(default)]
    pub wg_config: Option<String>,
    #[serde(default)]
    pub ovpn_config: Option<String>,
    #[serde(default)]
    pub vless_uri: Option<String>,
    #[serde(default)]
    pub vless_sub_url: Option<String>,
}

/// Выжимка из OIDC discovery-документа.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscovery {
    #[serde(default)]
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Состояние начатого OIDC-потока. Первые четыре поля — по спеке,
/// остальные нужны `oidc_complete` (redirect_uri/client_id обязаны
/// совпадать с запросом авторизации, token_endpoint — чтобы не ходить
/// в discovery второй раз).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcAuth {
    /// URL, который UI открывает в системном браузере.
    pub url: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub client_id: String,
    /// `http://127.0.0.1:<port>/cb`
    pub redirect_uri: String,
    pub token_endpoint: String,
}

// ---------------------------------------------------------------------------
// Чистые функции (тестируются юнит-тестами, без сети)
// ---------------------------------------------------------------------------

/// URL discovery-документа для issuer (issuer нормализуем без хвостового `/`).
#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

/// Схема URL разрешена для портала/IdP? Только https; http — лишь для
/// loopback-хостов (локальная разработка портала). Аудит A-12/A-19:
/// по http логин/пароль и токены ушли бы открытым текстом.
#[must_use]
pub fn is_allowed_scheme(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => matches!(
            url.host_str().unwrap_or_default(),
            "localhost" | "127.0.0.1" | "::1"
        ),
        _ => false,
    }
}

/// Проверка URL портала/issuer перед использованием (RU-текст ошибки).
/// Пустая строка проходит («не задан» — не проверяем).
pub fn validate_external_url(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    match Url::parse(trimmed) {
        Ok(url) if is_allowed_scheme(&url) => Ok(()),
        _ => Err("Адрес должен быть https:// (http допускается только для localhost)".into()),
    }
}

/// PKCE code_verifier: 32 случайных байта → base64url без padding = ровно 43
/// символа из unreserved-набора (RFC 7636 §4.1).
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256: `BASE64URL(SHA256(verifier))` без padding.
#[must_use]
pub fn pkce_s256_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Случайная hex-строка (state/nonce).
pub fn generate_random_hex() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Собирает URL авторизации OIDC (Authorization Code + PKCE S256).
pub fn build_authorization_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> Result<String, PortalError> {
    let mut url = Url::parse(authorization_endpoint).map_err(|_| PortalError::Parse)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// Разбирает discovery-документ (чистая функция над JSON).
pub fn parse_discovery(doc: &Value) -> Result<OidcDiscovery, PortalError> {
    serde_json::from_value(doc.clone()).map_err(|_| PortalError::Parse)
}

/// Разбирает ответ token endpoint: `{"id_token": "…"}`.
/// При `{"error": "…"}` возвращает `PortalError::Auth` с RU-текстом.
pub fn parse_token_response(doc: &Value) -> Result<String, PortalError> {
    if let Some(err) = doc.get("error").and_then(Value::as_str) {
        return Err(PortalError::Auth(format!(
            "Не удалось завершить вход: {err}"
        )));
    }
    doc.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(PortalError::Parse)
}

/// Достаёт значение куки `vpn_portal_session` из набора `Set-Cookie`-заголовков.
#[must_use]
pub fn extract_session_cookie(set_cookie_values: &[&str]) -> Option<String> {
    for header in set_cookie_values {
        // делим по ПЕРВОМУ '=': значение куки само может содержать '=' (base64)
        let Some((name, rest)) = header.split_once('=') else {
            continue;
        };
        if name.trim() != PORTAL_SESSION_COOKIE {
            continue;
        }
        // после имени — значение до атрибутов (';')
        let value = rest.split(';').next().unwrap_or("").trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

/// Раскодирует подписку `/api/sub/<token>`: портал отдаёт base64(vless://…).
/// Если тело уже содержит `vless://` (plain-text подписка) — возвращаем как есть.
#[must_use]
pub fn decode_subscription(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.contains("vless://") {
        return Some(trimmed.to_owned());
    }
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        if let Ok(decoded) = engine.decode(trimmed.as_bytes()) {
            if let Ok(text) = String::from_utf8(decoded) {
                if text.contains("vless://") {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Достаёт поле `error` из тела ошибки (портал пишет RU-тексты) или берёт
/// стандартный текст по коду.
fn auth_error_message(status: u16, body: &str) -> String {
    let default = match status {
        400 => "Неверный запрос",
        401 => "Неверный логин или пароль",
        403 => "Доступ запрещён",
        429 => "Слишком много попыток, попробуйте позже",
        _ => "Ошибка авторизации",
    };
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| default.to_owned())
}

/// Переводит HTTP-статус + тело в типизированную ошибку портала.
fn map_status(status: u16, body: &str) -> PortalError {
    match status {
        400 | 401 | 403 | 429 => PortalError::Auth(auth_error_message(status, body)),
        code => PortalError::Http(code),
    }
}

/// Выполняет запрос: (статус, тело). Сетевые сбои → `PortalError::Network`.
async fn execute(request: reqwest::RequestBuilder) -> Result<(u16, String), PortalError> {
    let resp = request
        .send()
        .await
        .map_err(|e| PortalError::Network(e.to_string()))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| PortalError::Network(e.to_string()))?;
    Ok((status, body))
}

// ---------------------------------------------------------------------------
// Клиент
// ---------------------------------------------------------------------------

/// HTTP-клиент портала. rustls-tls, без системных TLS-библиотек.
pub struct PortalClient {
    http: reqwest::Client,
    portal_url: Url,
}

impl PortalClient {
    /// Создаёт клиент для базового URL портала (например `https://vpn.example.com`).
    /// Аудит A-12/A-19: только `https://`; `http://` — исключительно для
    /// loopback (локальная разработка портала).
    pub fn new(portal_url: &str) -> Result<Self, PortalError> {
        let mut url = Url::parse(portal_url.trim_end_matches('/'))
            .map_err(|_| PortalError::Parse)?;
        url.set_fragment(None);
        url.set_query(None);
        if !is_allowed_scheme(&url) {
            return Err(PortalError::Parse);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| PortalError::Network(e.to_string()))?;
        Ok(Self { http, portal_url: url })
    }

    /// Базовый URL портала.
    #[must_use]
    pub fn portal_url(&self) -> &str {
        self.portal_url.as_str()
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.portal_url.as_str().trim_end_matches('/'))
    }

    async fn response_json(&self, request: reqwest::RequestBuilder) -> Result<Value, PortalError> {
        let (status, body) = execute(request).await?;
        if !(200..300).contains(&status) {
            return Err(map_status(status, &body));
        }
        serde_json::from_str(&body).map_err(|_| PortalError::Parse)
    }

    /// Fallback-вход логин/пароль: `POST /api/portal/login`.
    /// Возвращает значение куки `vpn_portal_session` (токен сессии).
    pub async fn login_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, PortalError> {
        let request = self
            .http
            .post(self.endpoint("/api/portal/login"))
            .json(&serde_json::json!({ "username": username, "password": password }));
        // заголовки Set-Cookie нужно прочитать ДО .text(), поэтому ручной путь
        let resp = request
            .send()
            .await
            .map_err(|e| PortalError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let cookies: Vec<String> = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let body = resp
            .text()
            .await
            .map_err(|e| PortalError::Network(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(map_status(status, &body));
        }
        let refs: Vec<&str> = cookies.iter().map(String::as_str).collect();
        extract_session_cookie(&refs).ok_or(PortalError::Parse)
    }

    /// Начинает OIDC-поток: discovery → PKCE → URL авторизации.
    /// `redirect_port` — порт loopback-листенера `http://127.0.0.1:{port}/cb`.
    pub async fn oidc_prepare(
        &self,
        issuer: &str,
        client_id: &str,
        redirect_port: u16,
    ) -> Result<OidcAuth, PortalError> {
        let discovery = self.fetch_discovery(issuer).await?;
        let code_verifier = generate_code_verifier();
        let state = generate_random_hex();
        let nonce = generate_random_hex();
        let redirect_uri = format!("http://127.0.0.1:{redirect_port}/cb");
        let challenge = pkce_s256_challenge(&code_verifier);
        let url = build_authorization_url(
            &discovery.authorization_endpoint,
            client_id,
            &redirect_uri,
            &state,
            &nonce,
            &challenge,
        )?;
        Ok(OidcAuth {
            url,
            state,
            nonce,
            code_verifier,
            client_id: client_id.to_owned(),
            redirect_uri,
            token_endpoint: discovery.token_endpoint,
        })
    }

    /// Загружает и разбирает discovery-документ issuer.
    pub async fn fetch_discovery(&self, issuer: &str) -> Result<OidcDiscovery, PortalError> {
        let doc = self
            .response_json(self.http.get(discovery_url(issuer)))
            .await?;
        parse_discovery(&doc)
    }

    /// Шаг 2 OIDC: код из браузера → id_token на token endpoint
    /// (`grant_type=authorization_code` + `code_verifier`, PKCE).
    pub async fn oidc_complete(
        &self,
        auth: &OidcAuth,
        code: &str,
        token_endpoint: &str,
    ) -> Result<String, PortalError> {
        let endpoint = if token_endpoint.is_empty() {
            auth.token_endpoint.as_str()
        } else {
            token_endpoint
        };
        let (status, body) = execute(self.http.post(endpoint).form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", auth.redirect_uri.as_str()),
            ("client_id", auth.client_id.as_str()),
            ("code_verifier", auth.code_verifier.as_str()),
        ]))
        .await?;
        if !(200..300).contains(&status) {
            return Err(map_status(status, &body));
        }
        let doc: Value = serde_json::from_str(&body).map_err(|_| PortalError::Parse)?;
        parse_token_response(&doc)
    }

    /// Обмен id_token на Bearer-токен портала: `POST /api/portal/auth/exchange`.
    pub async fn exchange(&self, id_token: &str) -> Result<PortalTokenResponse, PortalError> {
        let doc = self
            .response_json(
                self.http
                    .post(self.endpoint("/api/portal/auth/exchange"))
                    .json(&serde_json::json!({ "idToken": id_token })),
            )
            .await?;
        serde_json::from_value(doc).map_err(|_| PortalError::Parse)
    }

    /// Конфиги пользователя: `GET /api/portal/profiles` c Bearer-токеном.
    pub async fn fetch_profiles(&self, bearer: &str) -> Result<PortalProfiles, PortalError> {
        self.fetch_profiles_auth(&format!("Bearer {bearer}")).await
    }

    /// То же, но с кукой сессии (после `login_password`).
    pub async fn fetch_profiles_cookie(&self, cookie: &str) -> Result<PortalProfiles, PortalError> {
        self.fetch_profiles_auth(&format!("{PORTAL_SESSION_COOKIE}={cookie}"))
            .await
    }

    async fn fetch_profiles_auth(&self, authorization_or_cookie: &str) -> Result<PortalProfiles, PortalError> {
        let doc = self
            .response_json(
                self.http
                    .get(self.endpoint("/api/portal/profiles"))
                    .header(reqwest::header::AUTHORIZATION, authorization_or_cookie),
            )
            .await?;
        serde_json::from_value(doc).map_err(|_| PortalError::Parse)
    }

    /// Смена протокола корп-доступа: `POST /api/portal/switch-protocol`
    /// с `{"protocol": "WIREGUARD" | "OPENVPN"}`.
    pub async fn switch_protocol(&self, bearer: &str, protocol: &str) -> Result<(), PortalError> {
        self.response_json(
            self.http
                .post(self.endpoint("/api/portal/switch-protocol"))
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
                .json(&serde_json::json!({ "protocol": protocol })),
        )
        .await?;
        Ok(())
    }

    /// Подписка vless://: `GET {sub_url}` (полный URL) → тело ответа
    /// (base64 от vless://…; декодирует [`decode_subscription`]).
    pub async fn fetch_subscription(&self, sub_url: &str) -> Result<String, PortalError> {
        let (status, body) = execute(self.http.get(sub_url)).await?;
        if !(200..300).contains(&status) {
            return Err(map_status(status, &body));
        }
        Ok(body)
    }

    /// Выход из сессии портала: `POST /api/portal/logout` (с кукой).
    pub async fn logout(&self, cookie: &str) -> Result<(), PortalError> {
        self.response_json(
            self.http
                .post(self.endpoint("/api/portal/logout"))
                .header(reqwest::header::COOKIE, format!("{PORTAL_SESSION_COOKIE}={cookie}")),
        )
        .await?;
        Ok(())
    }

    /// Выход устройства с Bearer-токеном: портал отзывает именно этот
    /// токен (аудит P-1 — раньше Bearer жил вечно и не отзывался вовсе).
    pub async fn logout_bearer(&self, bearer: &str) -> Result<(), PortalError> {
        self.response_json(
            self.http
                .post(self.endpoint("/api/portal/logout"))
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}")),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Вектор из RFC 7636, Appendix B.
    #[test]
    fn pkce_challenge_rfc7636_vector() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn code_verifier_shape() {
        for _ in 0..16 {
            let v = generate_code_verifier();
            assert_eq!(v.len(), 43, "RFC 7636: 43–128, берём ровно 43");
            assert!(v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        }
        assert_ne!(generate_code_verifier(), generate_code_verifier());
        assert_eq!(generate_random_hex().len(), 64);
    }

    #[test]
    fn authorization_url_contains_all_params() {
        let url = build_authorization_url(
            "https://2fa.ligam.org/authorize",
            "CorpVPN Desktop",
            "http://127.0.0.1:8400/cb",
            "state123",
            "nonce456",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(parsed.host_str(), Some("2fa.ligam.org"));
        assert_eq!(parsed.path(), "/authorize");
        let q: std::collections::BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(q.get("scope").map(String::as_str), Some("openid"));
        assert_eq!(q.get("client_id").map(String::as_str), Some("CorpVPN Desktop"));
        // пробел в client_id закодирован (%20 или + — обе формы form-urlencoded валидны)
        assert!(!url.contains("client_id=CorpVPN Desktop"));
        assert!(url.contains("CorpVPN%20Desktop") || url.contains("CorpVPN+Desktop"));
        assert_eq!(q.get("redirect_uri").map(String::as_str), Some("http://127.0.0.1:8400/cb"));
        assert_eq!(q.get("state").map(String::as_str), Some("state123"));
        assert_eq!(q.get("nonce").map(String::as_str), Some("nonce456"));
        assert_eq!(
            q.get("code_challenge").map(String::as_str),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        );
        assert_eq!(q.get("code_challenge_method").map(String::as_str), Some("S256"));
        // кривой endpoint — Parse
        assert!(build_authorization_url("not a url", "c", "r", "s", "n", "ch").is_err());
    }

    #[test]
    fn discovery_url_and_parsing() {
        assert_eq!(
            discovery_url("https://2fa.ligam.org/"),
            "https://2fa.ligam.org/.well-known/openid-configuration"
        );
        let doc = json!({
            "issuer": "https://2fa.ligam.org",
            "authorization_endpoint": "https://2fa.ligam.org/oauth2/authorize",
            "token_endpoint": "https://2fa.ligam.org/oauth2/token",
            "jwks_uri": "https://2fa.ligam.org/.well-known/jwks.json",
            "userinfo_endpoint": "https://2fa.ligam.org/userinfo"
        });
        let d = parse_discovery(&doc).unwrap();
        assert_eq!(d.authorization_endpoint, "https://2fa.ligam.org/oauth2/authorize");
        assert_eq!(d.token_endpoint, "https://2fa.ligam.org/oauth2/token");
        // без token_endpoint — ошибка разбора
        assert!(parse_discovery(&json!({"authorization_endpoint": "x"})).is_err());
    }

    #[test]
    fn token_response_parsing() {
        assert_eq!(
            parse_token_response(&json!({"id_token": "eyJh.e30.x"})).unwrap(),
            "eyJh.e30.x"
        );
        let err = parse_token_response(&json!({"error": "invalid_grant"})).unwrap_err();
        assert_eq!(err.to_string(), "Не удалось завершить вход: invalid_grant");
        assert!(matches!(parse_token_response(&json!({})), Err(PortalError::Parse)));
    }

    #[test]
    fn session_cookie_extraction() {
        let headers = [
            "vpn_portal_session=abc.def.ghi; Path=/; HttpOnly",
            "other=1",
            "vpn_portal_session=expired",
        ];
        assert_eq!(extract_session_cookie(&headers).unwrap(), "abc.def.ghi");
        assert_eq!(
            extract_session_cookie(&["vpn_portal_session=tok"]).unwrap(),
            "tok"
        );
        assert!(extract_session_cookie(&["other=1"]).is_none());
        assert!(extract_session_cookie(&["vpn_portal_session="]).is_none());
        assert!(extract_session_cookie(&[]).is_none());
    }

    #[test]
    fn subscription_decoding() {
        let plain = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:443?type=tcp#n";
        assert_eq!(decode_subscription(plain).unwrap(), plain);
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        assert_eq!(decode_subscription(&b64).unwrap(), plain);
        assert_eq!(decode_subscription(&format!("  {b64}\n")).unwrap(), plain);
        assert!(decode_subscription("bm90IHZsZXNz").is_none()); // "not vless"
        assert!(decode_subscription("!!!not base64").is_none());
    }

    #[test]
    fn client_validates_portal_url() {
        assert!(PortalClient::new("https://vpn.example.com/").is_ok());
        assert!(PortalClient::new("http://localhost:3000").is_ok());
        assert!(PortalClient::new("http://127.0.0.1:3000").is_ok());
        assert!(matches!(PortalClient::new("garbage"), Err(PortalError::Parse)));
        assert!(matches!(PortalClient::new("ftp://x"), Err(PortalError::Parse)));
        // аудит A-12: http на внешний хост — пароли/токены ушли бы открытым текстом
        assert!(matches!(
            PortalClient::new("http://vpn.example.com"),
            Err(PortalError::Parse)
        ));
        let c = PortalClient::new("https://vpn.example.com").unwrap();
        assert_eq!(
            c.endpoint("/api/portal/profiles"),
            "https://vpn.example.com/api/portal/profiles"
        );
    }

    #[test]
    fn validate_external_url_scheme_rules() {
        assert!(validate_external_url("https://2fa.ligam.org").is_ok());
        assert!(validate_external_url("http://localhost:3000").is_ok());
        assert!(validate_external_url("http://127.0.0.1:8400").is_ok());
        assert!(validate_external_url("").is_ok()); // не задан — не проверяем
        assert!(validate_external_url("http://evil.example.com").is_err());
        assert!(validate_external_url("file:///etc/passwd").is_err());
        assert!(validate_external_url("not a url").is_err());
    }

    #[test]
    fn auth_error_mapping_prefers_server_text() {
        assert_eq!(
            map_status(401, r#"{"error":"Неверный логин или пароль"}"#).to_string(),
            "Неверный логин или пароль"
        );
        assert_eq!(map_status(403, "").to_string(), "Доступ запрещён");
        assert_eq!(map_status(429, "not json").to_string(),
            "Слишком много попыток, попробуйте позже");
        assert!(matches!(map_status(500, ""), PortalError::Http(500)));
        assert!(matches!(map_status(503, r#"{"error":"SSO отключён"}"#), PortalError::Http(503)));
    }
}
