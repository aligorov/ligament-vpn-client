//! Генератор клиентского конфига Xray (`xray.exe run -c config.json`).
//!
//! Схема минимальная по спеке: локальный SOCKS-inbound на `127.0.0.1:{socksPort}`
//! с UDP, основной outbound — VLESS (для REALITY — `streamSettings.realitySettings`
//! с serverName/publicKey/shortId/fingerprint), плюс `freedom` как прямое
//! соединение и пустая таблица маршрутов (маршрут по умолчанию — первый
//! outbound, т.е. VLESS). Блокировать приватные адреса не нужно — trafik до
//! корпоративных подсетей должен идти через туннель.

use crate::model::{Profile, VlessProfile};
use crate::vless::{self, VlessUri};
use serde_json::{json, Value};

/// Собирает JSON-конфиг Xray из VLESS-профиля.
///
/// `socks_port` — локальный порт SOCKS-прокси из настроек (`socksPort`,
/// по умолчанию 10808); на нём же слушает tun2socks в системном режиме.
pub fn build_xray_config(profile: &VlessProfile, socks_port: u16) -> Result<Value, vless::VlessParseError> {
    let uri = vless::parse(&profile.uri)?;
    Ok(build_from_uri(&uri, socks_port))
}

/// То же из уже разобранной ссылки.
#[must_use]
pub fn build_from_uri(uri: &VlessUri, socks_port: u16) -> Value {
    let network = uri.network.clone().unwrap_or_else(|| "tcp".to_owned());
    // encryption в VLESS всегда "none" (значение из ссылки игнорируем,
    // xray требует именно "none")
    let mut user = json!({
        "id": uri.id,
        "encryption": "none",
    });
    if let Some(flow) = &uri.flow {
        user["flow"] = json!(flow);
    }

    let mut stream_settings = json!({
        "network": network,
    });
    match uri.security.as_deref() {
        Some("reality") => {
            stream_settings["security"] = json!("reality");
            stream_settings["realitySettings"] = json!({
                "serverName": uri.sni.clone().unwrap_or_default(),
                "publicKey": uri.public_key.clone().unwrap_or_default(),
                "shortId": uri.short_id.clone().unwrap_or_default(),
                "fingerprint": uri.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
                "show": false,
            });
        }
        Some("tls") => {
            stream_settings["security"] = json!("tls");
            stream_settings["tlsSettings"] = json!({
                "serverName": uri.sni.clone().unwrap_or_default(),
                "allowInsecure": false,
                "fingerprint": uri.fingerprint.clone().unwrap_or_else(|| "chrome".to_owned()),
            });
        }
        _ => {
            stream_settings["security"] = json!("none");
        }
    }

    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                    "userLevel": 0
                },
                "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": uri.host,
                            "port": uri.port,
                            "users": [user]
                        }
                    ]
                },
                "streamSettings": stream_settings,
                "mux": { "enabled": false, "concurrency": -1 }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": []
        }
    })
}

/// Конфиг Xray для целого [`Profile`] (проверяет, что профиль VLESS).
pub fn for_profile(profile: &Profile, socks_port: u16) -> Result<Value, vless::VlessParseError> {
    profile
        .vless
        .as_ref()
        .ok_or(vless::VlessParseError::NotVless)
        .and_then(|v| build_xray_config(v, socks_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::parse;

    const REALITY: &str = "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?security=reality&pbk=xpubKEY123&sid=ab12cd34&sni=vpn.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#CorpVPN";

    #[test]
    fn reality_config_fields() {
        let uri = parse(REALITY).unwrap();
        let cfg = build_from_uri(&uri, 10_808);

        // inbound: socks 127.0.0.1:10808 udp:true
        let inb = &cfg["inbounds"][0];
        assert_eq!(inb["listen"], "127.0.0.1");
        assert_eq!(inb["port"], 10_808);
        assert_eq!(inb["protocol"], "socks");
        assert_eq!(inb["settings"]["udp"], true);

        // outbound[0]: vless → vnext[0]
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["settings"]["vnext"][0]["address"], "vpn.example.com");
        assert_eq!(out["settings"]["vnext"][0]["port"], 443);
        let user = &out["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["id"], "d342d11e-d424-4583-b36e-524ab1f0afa4");
        assert_eq!(user["encryption"], "none");
        assert_eq!(user["flow"], "xtls-rprx-vision");

        let ss = &out["streamSettings"];
        assert_eq!(ss["network"], "tcp");
        assert_eq!(ss["security"], "reality");
        let rs = &ss["realitySettings"];
        assert_eq!(rs["serverName"], "vpn.example.com");
        assert_eq!(rs["publicKey"], "xpubKEY123");
        assert_eq!(rs["shortId"], "ab12cd34");
        assert_eq!(rs["fingerprint"], "chrome");

        // freedom direct присутствует, routing минимален
        assert!(cfg["outbounds"].as_array().unwrap().iter().any(|o| o["protocol"] == "freedom"));
        assert_eq!(cfg["routing"]["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn custom_socks_port_and_defaults() {
        let uri = parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:8443?type=ws&security=tls&sni=h.example").unwrap();
        let cfg = build_from_uri(&uri, 20_000);
        assert_eq!(cfg["inbounds"][0]["port"], 20_000);
        let ss = &cfg["outbounds"][0]["streamSettings"];
        assert_eq!(ss["network"], "ws");
        assert_eq!(ss["security"], "tls");
        assert_eq!(ss["tlsSettings"]["serverName"], "h.example");
        // без flow поле не добавляется
        assert!(cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0].get("flow").is_none());
    }

    #[test]
    fn no_security_means_none() {
        let uri = parse("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:443?type=tcp").unwrap();
        let cfg = build_from_uri(&uri, 10_808);
        assert_eq!(cfg["outbounds"][0]["streamSettings"]["security"], "none");
    }

    #[test]
    fn for_profile_requires_vless_part() {
        let mut p = crate::model::Profile::new("t", crate::model::ProfileKind::Vless, crate::model::ProfileSource::Import);
        assert!(for_profile(&p, 10_808).is_err());
        p.vless = Some(VlessProfile { uri: REALITY.to_owned() });
        let cfg = for_profile(&p, 10_808).unwrap();
        assert_eq!(cfg["inbounds"][0]["port"], 10_808);
        // битая ссылка → ошибка парсера
        p.vless = Some(VlessProfile { uri: "vless://zzz@h".to_owned() });
        assert!(for_profile(&p, 10_808).is_err());
    }
}
