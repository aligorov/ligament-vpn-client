//! # vpncore — кроссплатформенное ядро CorpVPN (Ligament VPN Client)
//!
//! Библиотека без платформенных зависимостей: её используют и Windows-служба
//! `corpvpnd`, и Rust-бридж Tauri-приложения. Здесь живут:
//!
//! - [`model`] — модель профиля/состояния/настроек (JSON — camelCase, спека §3);
//! - [`wg`] — парсер/рендерер WireGuard `.conf` + применение [`model::Overrides`];
//! - [`ovpn`] — лёгкий парсер `.ovpn` + нормализатор (auth-user-pass/auth-nocache);
//! - [`vless`] — парсер `vless://`-ссылок (REALITY), ошибки — по-русски;
//! - [`xray_config`] — генератор клиентского конфига Xray;
//! - [`portal`] — HTTP-клиент портала и OIDC Authorization Code + PKCE S256;
//! - [`policy`] — GPO-политики HKLM и их слияние с настройками;
//! - [`store`] — зашифрованное (AES-256-GCM) хранилище профилей и настроек.
//!
//! Спецификация: `docs/superpowers/specs/2026-09-16-corpvpn-client-design.md`.
//! Контракт портала сверен с реальными роутами `vpn_creator_wireguard`.

pub mod model;
pub mod ovpn;
pub mod policy;
pub mod portal;
pub mod store;
pub mod vless;
pub mod wg;
pub mod xray_config;

// Удобные ре-экспорты: `vpncore::Profile` вместо `vpncore::model::Profile`.
pub use model::{
    Language, OvpnProfile, Overrides, Profile, ProfileKind, ProfileSource, Settings, VlessProfile,
    VpnState, VpnStats, VpnStatus, WgProfile,
};
pub use ovpn::{normalize as normalize_ovpn, parse as parse_ovpn};
pub use policy::{Policies, PolicyProvider};
pub use portal::{
    PortalClient, PortalError, PortalProfiles, PortalTokenResponse, PortalUser, OidcAuth,
    OidcDiscovery,
};
pub use store::{EncryptedFileStore, ProfileStore, StoreData, StoreError};
pub use vless::{parse as parse_vless, VlessParseError, VlessUri};
pub use wg::{parse as parse_wg, WgConfig};

/// Определяет вид импортируемого профиля по тексту:
/// `vless://…` → VLESS, `[Interface]` → WireGuard, `remote`/`client` → OpenVPN.
#[must_use]
pub fn infer_profile_kind(text: &str) -> Option<ProfileKind> {
    let trimmed = text.trim();
    if vless::looks_like_vless(trimmed) {
        return Some(ProfileKind::Vless);
    }
    if wg::looks_like_wg_config(trimmed) {
        return Some(ProfileKind::Wireguard);
    }
    if ovpn::looks_like_ovpn(trimmed) {
        return Some(ProfileKind::Openvpn);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_kind_for_all_three() {
        assert_eq!(
            infer_profile_kind("vless://d342d11e-d424-4583-b36e-524ab1f0afa4@h:443?type=tcp"),
            Some(ProfileKind::Vless)
        );
        assert_eq!(
            infer_profile_kind("[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\n"),
            Some(ProfileKind::Wireguard)
        );
        assert_eq!(
            infer_profile_kind("client\ndev tun\nremote h 443\n"),
            Some(ProfileKind::Openvpn)
        );
        assert_eq!(infer_profile_kind("просто текст"), None);
    }
}
