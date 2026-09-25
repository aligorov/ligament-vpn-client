//! Модель данных CorpVPN (профили, состояние VPN, настройки).
//!
//! Сериализация — camelCase, ровно как в JSON из спеки дизайна
//! (`docs/superpowers/specs/2026-09-16-corpvpn-client-design.md`, §3):
//! `{"id":"…","name":"…","kind":"wireguard","overrides":{"allowedIps":[…]}}`.
//! Все типы — `Serialize + Deserialize + Clone + Debug + PartialEq`,
//! чтобы гонять их через IPC и зашифрованное хранилище без ручных конвертеров.

use serde::{Deserialize, Serialize};

/// unix epoch (секунды) — для `createdAt`/`updatedAt` и `handshakeAt`.
pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Тип VPN-профиля. Сериализуется как `"wireguard" | "openvpn" | "vless"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileKind {
    Wireguard,
    Openvpn,
    Vless,
}

/// Происхождение профиля: выдан порталом или импортирован вручную.
/// Сериализуется как `"portal" | "import"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileSource {
    Portal,
    Import,
}

/// Язык интерфейса: `"ru" | "en"` (RU — по умолчанию, спека §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    Ru,
    En,
}

/// WireGuard-часть профиля: сырой `.conf` текстом.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgProfile {
    /// Содержимое `.conf` (`[Interface]/[Peer]`), как выдано порталом.
    pub config: String,
}

/// OpenVPN-часть профиля: сырой `.ovpn` текстом.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OvpnProfile {
    pub config: String,
}

/// VLESS-часть профиля: share-ссылка `vless://…`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessProfile {
    pub uri: String,
}

/// Пользовательские переопределения поверх конфига профиля
/// (экран «Продвинутые» в UI: split tunnel AllowedIPs, DNS, SOCKS-only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overrides {
    /// Если задан — подменяет `AllowedIPs` всех пиров WireGuard
    /// (split tunnel: например `["0.0.0.0/0"]` или корпоративные подсети).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// Если задан — подменяет `DNS` в `[Interface]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    /// VLESS: не поднимать системный tun2socks — только локальный SOCKS-прокси
    /// (работает вовсе без admin, спека §2).
    #[serde(default)]
    pub socks_only: bool,
}

/// VPN-профиль — модель из спеки §3. `id` — uuid v4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    pub source: ProfileSource,
    /// Заполнен только для `kind == Wireguard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgProfile>,
    /// Заполнен только для `kind == Openvpn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovpn: Option<OvpnProfile>,
    /// Заполнен только для `kind == Vless`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<VlessProfile>,
    #[serde(default)]
    pub overrides: Overrides,
    /// unix epoch, секунды.
    pub created_at: u64,
    /// unix epoch, секунды.
    pub updated_at: u64,
}

impl Profile {
    /// Новый профиль с uuid v4 и текущими метками времени.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: ProfileKind,
        source: ProfileSource,
    ) -> Self {
        let now = now_epoch();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            kind,
            source,
            wg: None,
            ovpn: None,
            vless: None,
            overrides: Overrides::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Проверка целостности: конфиг соответствующего вида должен быть на месте.
    /// Возвращает пользовательское (RU) сообщение об ошибке, если что-то не так.
    pub fn validate(&self) -> Result<(), String> {
        match self.kind {
            ProfileKind::Wireguard => {
                let wg = self.wg.as_ref().ok_or("В профиле нет конфига WireGuard")?;
                crate::wg::parse(&wg.config)
                    .map(|_| ())
                    .map_err(|e| format!("Некорректный конфиг WireGuard: {e}"))?;
                Ok(())
            }
            ProfileKind::Openvpn => {
                if self.ovpn.as_ref().is_none() {
                    return Err("В профиле нет конфига OpenVPN".into());
                }
                Ok(())
            }
            ProfileKind::Vless => {
                let vless = self
                    .vless
                    .as_ref()
                    .ok_or("В профиле нет ссылки vless://")?;
                crate::vless::parse(&vless.uri)
                    .map(|_| ())
                    .map_err(|e| format!("Некорректная ссылка vless://: {e}"))?;
                Ok(())
            }
        }
    }

    /// Сырой текст конфига профиля (независимо от вида), если задан.
    #[must_use]
    pub fn config_text(&self) -> Option<&str> {
        match self.kind {
            ProfileKind::Wireguard => self.wg.as_ref().map(|w| w.config.as_str()),
            ProfileKind::Openvpn => self.ovpn.as_ref().map(|o| o.config.as_str()),
            ProfileKind::Vless => self.vless.as_ref().map(|v| v.uri.as_str()),
        }
    }

    /// Копия профиля без секретов — для RPC-ответов UI и логов (аудит A-2:
    /// канал RPC доступен любому локальному пользователю, приватные ключи
    /// WG, конфиги OpenVPN и vless://-ссылки наружу не отдаются; пустое
    /// секретное поле в `corpvpn.profiles.update` означает «не менять»).
    #[must_use]
    pub fn public_view(&self) -> Self {
        let mut p = self.clone();
        if let Some(wg) = &mut p.wg {
            wg.config = String::new();
        }
        if let Some(ovpn) = &mut p.ovpn {
            ovpn.config = String::new();
        }
        if let Some(vless) = &mut p.vless {
            vless.uri = String::new();
        }
        p
    }
}

/// Статус туннеля. Сериализуется как `"disconnected" | "connecting" | …`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl VpnStatus {
    /// Короткое имя для логов.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::Error => "error",
        }
    }
}

/// Трафик туннеля (camelCase: `rxBytes`, `txBytes`, `handshakeAt`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStats {
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    /// Время последнего рукопожатия (unix epoch, секунды) или `null`.
    #[serde(default)]
    pub handshake_at: Option<u64>,
}

/// Полное состояние VPN для IPC (`corpvpn.state.get` / `state.changed`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnState {
    pub status: VpnStatus,
    /// id активного профиля или `null`.
    #[serde(default)]
    pub active_profile_id: Option<String>,
    /// Пользовательский (RU) текст ошибки или `null`.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub stats: VpnStats,
}

impl Default for VpnState {
    fn default() -> Self {
        Self {
            status: VpnStatus::Disconnected,
            active_profile_id: None,
            error: None,
            stats: VpnStats::default(),
        }
    }
}

/// Настройки приложения (спека §3): тумблеры + портал + порт SOCKS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default = "default_true")]
    pub autostart: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub language: Language,
    /// Базовый URL портала (например `https://vpn.example.com`).
    /// Заполняется политикой HKLM или при первом входе.
    #[serde(default)]
    pub portal_url: String,
    /// Порт локального SOCKS-прокси xray (по умолчанию 10808, спека §2).
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
}

const fn default_true() -> bool {
    true
}
const fn default_socks_port() -> u16 {
    10_808
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            autostart: default_true(),
            auto_connect: false,
            kill_switch: false,
            language: Language::Ru,
            portal_url: String::new(),
            socks_port: default_socks_port(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Профиль должен сериализоваться ровно в JSON из спеки §3 (camelCase).
    #[test]
    fn profile_serializes_to_spec_camel_case() {
        let p = Profile {
            id: "0d0d78f6-b6c5-4d85-9c18-c4b8f4a58b52".into(),
            name: "Корпоративная сеть".into(),
            kind: ProfileKind::Wireguard,
            source: ProfileSource::Portal,
            wg: Some(WgProfile {
                config: "[Interface]\n…".into(),
            }),
            ovpn: None,
            vless: None,
            overrides: Overrides {
                allowed_ips: Some(vec!["0.0.0.0/0".into()]),
                dns: Some(vec!["10.0.0.1".into()]),
                socks_only: false,
            },
            created_at: 0,
            updated_at: 0,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["id"], "0d0d78f6-b6c5-4d85-9c18-c4b8f4a58b52");
        assert_eq!(json["kind"], "wireguard");
        assert_eq!(json["source"], "portal");
        assert_eq!(json["wg"]["config"], "[Interface]\n…");
        assert_eq!(json["overrides"]["allowedIps"][0], "0.0.0.0/0");
        assert_eq!(json["overrides"]["dns"][0], "10.0.0.1");
        assert_eq!(json["overrides"]["socksOnly"], false);
        assert_eq!(json["createdAt"], 0);
        // и обратно
        let back: Profile = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn vpn_state_serializes_to_spec() {
        let s = VpnState {
            status: VpnStatus::Connected,
            active_profile_id: Some("abc".into()),
            error: None,
            stats: VpnStats {
                rx_bytes: 1,
                tx_bytes: 2,
                handshake_at: Some(1_758_000_000),
            },
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["status"], "connected");
        assert_eq!(j["activeProfileId"], "abc");
        assert_eq!(j["stats"]["rxBytes"], 1);
        assert_eq!(j["stats"]["handshakeAt"], 1_758_000_000);

        let idle: VpnState = serde_json::from_str(r#"{"status":"disconnected","activeProfileId":null,"error":null,"stats":{"rxBytes":0,"txBytes":0,"handshakeAt":null}}"#).unwrap();
        assert_eq!(idle.status, VpnStatus::Disconnected);
        assert_eq!(idle.stats.handshake_at, None);
    }

    #[test]
    fn settings_defaults_match_spec_example() {
        let s = Settings::default();
        assert!(s.autostart);
        assert!(!s.auto_connect);
        assert!(!s.kill_switch);
        assert_eq!(s.language, Language::Ru);
        assert_eq!(s.socks_port, 10_808);
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["autoConnect"], false);
        assert_eq!(j["killSwitch"], false);
        assert_eq!(j["socksPort"], 10_808);
        assert_eq!(j["language"], "ru");
        // unknown language fails fast (RU|EN only)
        assert!(serde_json::from_value::<Settings>(
            serde_json::json!({"language": "de"})
        )
        .is_err());
    }

    #[test]
    fn profile_new_generates_uuid_v4_and_validates() {
        let mut p = Profile::new("test", ProfileKind::Vless, ProfileSource::Import);
        assert_eq!(p.vless, None);
        assert!(p.validate().is_err()); // нет uri
        p.vless = Some(VlessProfile {
            uri: "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?type=tcp".into(),
        });
        assert!(p.validate().is_ok());
        // uuid v4: версия в старших битах третьей группы
        assert!(p.id.starts_with(|c: char| c.is_ascii_hexdigit()));
        let parsed = uuid::Uuid::parse_str(&p.id).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
    }
}
