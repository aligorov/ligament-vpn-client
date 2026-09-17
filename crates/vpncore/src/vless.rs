//! Парсер ссылок `vless://` (share-ссылки 3x-ui / v2rayN-формата).
//!
//! Формат: `vless://<uuid>@<host>[:<port>]?<params>#<имя>`.
//! Поддерживаемые параметры (регистр ключей как в генераторе портала
//! `src/lib/vless.ts`): `security` (reality/tls/none), `sni`, `pbk`
//! (publicKey), `sid` (shortId), `fp` (fingerprint), `type` (network),
//! `flow`, `encryption`. Fragment — человекочитаемое имя профиля.
//!
//! Ошибки валидации — по-русски, они показываются пользователю напрямую.

use std::collections::BTreeMap;

/// Ошибка разбора ссылки. `Display` — пользовательское сообщение (RU).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VlessParseError {
    #[error("Адрес должен начинаться с vless://")]
    NotVless,
    #[error("Некорректный UUID пользователя: {0}")]
    BadUuid(String),
    #[error("Не указан сервер (host)")]
    MissingHost,
    #[error("Некорректный порт: {0}")]
    BadPort(String),
}

/// Порт по умолчанию, если в ссылке не указан (REALITY обычно на 443).
pub const DEFAULT_PORT: u16 = 443;

/// Разобранная ссылка `vless://`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlessUri {
    /// UUID пользователя (нормализованный, дефисы, нижний регистр).
    pub id: String,
    pub host: String,
    pub port: u16,
    /// `security=reality|tls|none`.
    pub security: Option<String>,
    /// `sni` — serverName для REALITY/TLS.
    pub sni: Option<String>,
    /// `pbk` — publicKey REALITY.
    pub public_key: Option<String>,
    /// `sid` — shortId REALITY.
    pub short_id: Option<String>,
    /// `fp` — fingerprint (например chrome).
    pub fingerprint: Option<String>,
    /// `type` — транспорт (tcp/ws/grpc/...).
    pub network: Option<String>,
    /// `flow` — например xtls-rprx-vision.
    pub flow: Option<String>,
    /// `encryption` (обычно none).
    pub encryption: Option<String>,
    /// Fragment (#имя) после percent-decoding.
    pub name: Option<String>,
    /// Все параметры запроса (percent-decoded), включая неизвестные.
    pub params: BTreeMap<String, String>,
}

/// Percent-decoding (`%XX`). `+` не трогаем: генераторы vless используют
/// `encodeURIComponent`, где плюс — литеральный плюс.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // %XX: нужны ровно два hex-символа после процента
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Разбирает `vless://…` в [`VlessUri`].
pub fn parse(uri: &str) -> Result<VlessUri, VlessParseError> {
    let rest = uri
        .strip_prefix("vless://")
        .or_else(|| uri.strip_prefix("VLESS://"))
        .ok_or(VlessParseError::NotVless)?;

    // fragment (#имя) и query (?params) отрезаем до разбора authority
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(percent_decode(f))),
        None => (rest, None),
    };
    let (authority, query) = match before_fragment.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (before_fragment, None),
    };
    // path (после первого '/') игнорируем — vless-ссылки его не используют
    let authority = authority.split('/').next().unwrap_or("");

    // userinfo (uuid) — до ПОСЛЕДНЕГО '@': сам uuid '@' не содержит
    let Some((uuid_raw, hostport)) = authority.rsplit_once('@') else {
        return Err(VlessParseError::BadUuid(String::new()));
    };
    let uuid = uuid::Uuid::parse_str(uuid_raw)
        .map_err(|_| VlessParseError::BadUuid(uuid_raw.to_owned()))?
        .to_string();

    // host:port с поддержкой IPv6 в скобках: [::1]:443
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, rest) = stripped.split_once(']').ok_or(VlessParseError::MissingHost)?;
        let port = rest
            .strip_prefix(':')
            .map(parse_port)
            .transpose()?
            .unwrap_or(DEFAULT_PORT);
        (h.to_owned(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), parse_port(p)?),
            None => (hostport.to_owned(), DEFAULT_PORT),
        }
    };
    if host.is_empty() {
        return Err(VlessParseError::MissingHost);
    }

    let mut out = VlessUri {
        id: uuid,
        host,
        port,
        name: fragment.filter(|f| !f.is_empty()),
        ..VlessUri::default()
    };

    if let Some(q) = query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            out.params
                .insert(percent_decode(k), percent_decode(v));
        }
    }
    let get = |k: &str| out.params.get(k).cloned();
    out.security = get("security");
    out.sni = get("sni");
    out.public_key = get("pbk");
    out.short_id = get("sid");
    out.fingerprint = get("fp");
    out.network = get("type");
    out.flow = get("flow");
    out.encryption = get("encryption");
    Ok(out)
}

fn parse_port(raw: &str) -> Result<u16, VlessParseError> {
    raw.parse::<u16>()
        .map_err(|_| VlessParseError::BadPort(raw.to_owned()))
}

/// Эвристика «это ссылка vless://» (для автоопределения импорта).
#[must_use]
pub fn looks_like_vless(text: &str) -> bool {
    text.trim_start().to_ascii_lowercase().starts_with("vless://")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALITY: &str = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?security=reality&pbk=xpubKEY123&sid=ab12cd34&sni=vpn.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#CorpVPN";

    #[test]
    fn parses_reality_uri() {
        let v = parse(REALITY).unwrap();
        assert_eq!(v.id, "d342d11e-d424-4583-b36e-524ab1f0afa4");
        assert_eq!(v.host, "vpn.example.com");
        assert_eq!(v.port, 443);
        assert_eq!(v.security.as_deref(), Some("reality"));
        assert_eq!(v.public_key.as_deref(), Some("xpubKEY123"));
        assert_eq!(v.short_id.as_deref(), Some("ab12cd34"));
        assert_eq!(v.sni.as_deref(), Some("vpn.example.com"));
        assert_eq!(v.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(v.network.as_deref(), Some("tcp"));
        assert_eq!(v.encryption, None);
        assert_eq!(v.name.as_deref(), Some("CorpVPN"));
        // raw params тоже на месте
        assert_eq!(v.params.get("pbk").map(String::as_str), Some("xpubKEY123"));
        assert!(looks_like_vless(REALITY));
    }

    /// Ровно формат генератора портала (src/lib/vless.ts): encryption=none,
    /// без flow/sid-опциональности.
    #[test]
    fn parses_portal_fallback_format() {
        let uri = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@bypass.ligam.org:8443?type=tcp&security=reality&encryption=none&fp=chrome&sni=bypass.ligam.org&pbk=PBK&sid=SID#Ivanov%20I.";
        let v = parse(uri).unwrap();
        assert_eq!(v.host, "bypass.ligam.org");
        assert_eq!(v.port, 8443);
        assert_eq!(v.encryption.as_deref(), Some("none"));
        assert_eq!(v.name.as_deref(), Some("Ivanov I."));
    }

    #[test]
    fn default_port_443_and_ipv6_brackets() {
        let v = parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com").unwrap();
        assert_eq!(v.port, DEFAULT_PORT);
        let v6 = parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@[2001:db8::1]:8443?type=tcp").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.port, 8443);
    }

    #[test]
    fn percent_decoding_of_params_and_name() {
        let v = parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:1?sni=a%20b&fp=chrome#%D0%9C%D0%BE%D0%B9%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80").unwrap();
        assert_eq!(v.sni.as_deref(), Some("a b"));
        assert_eq!(v.name.as_deref(), Some("Мой сервер"));
    }

    #[test]
    fn validation_errors_are_russian() {
        assert_eq!(parse("https://example.com").unwrap_err().to_string(),
            "Адрес должен начинаться с vless://");
        assert_eq!(parse("vless://not-a-uuid@h:443").unwrap_err().to_string(),
            "Некорректный UUID пользователя: not-a-uuid");
        assert_eq!(parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@:443").unwrap_err().to_string(),
            "Не указан сервер (host)");
        assert_eq!(
            parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:notaport").unwrap_err().to_string(),
            "Некорректный порт: notaport"
        );
        assert_eq!(
            parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:99999").unwrap_err(),
            VlessParseError::BadPort("99999".to_owned())
        );
        // без userinfo вовсе — тоже ошибка UUID
        assert!(matches!(parse("vless://host:443"), Err(VlessParseError::BadUuid(_))));
        // регистр схемы не важен
        assert!(parse("VLESS://d342d11e-d424-4583-b36e-524ab1f0afa4@h:443").is_ok());
    }
}
