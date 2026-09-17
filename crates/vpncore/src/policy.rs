//! GPO-политики (`HKLM\SOFTWARE\Policies\Ligament\CorpVPN`, спека §5).
//!
//! Демон читает политики через [`PolicyProvider`]. Любое поле `None` —
//! «политика не задана», тогда действует пользовательское значение.
//! Заданная политика **перекрывает** пользовательские настройки
//! ([`apply_policies`]) и часть RPC (например, `disable_manual_import`
//! запрещает `corpvpn.profiles.import`).

use crate::model::Settings;

/// Снимок политик. Все поля опциональны: `None` = не задана.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policies {
    /// SZ `PortalUrl` — адрес портала (https://…).
    pub portal_url: Option<String>,
    /// DW `RequireLogin` — требовать вход перед подключением.
    pub require_login: Option<bool>,
    /// SZ `DefaultProtocol` — протокол по умолчанию (WIREGUARD/OPENVPN/VLESS).
    pub default_protocol: Option<String>,
    /// DW `Autostart` — автозапуск UI.
    pub autostart: Option<bool>,
    /// DW `KillSwitch` — kill-switch.
    pub kill_switch: Option<bool>,
    /// SZ `SplitTunnelDefault` — AllowedIPs по умолчанию (список подсетей).
    pub split_tunnel_default: Option<Vec<String>>,
    /// DW `DisableManualImport` — запретить ручной импорт конфигов.
    pub disable_manual_import: Option<bool>,
}

/// Источник политик. Читается при старте демона и по требованию.
pub trait PolicyProvider: Send + Sync {
    fn read(&self) -> Policies;
}

/// Провайдер с политиками в памяти — для тестов и для `--console` режима.
#[derive(Debug, Clone, Default)]
pub struct MemoryPolicyProvider {
    pub policies: Policies,
}

impl MemoryPolicyProvider {
    #[must_use]
    pub fn new(policies: Policies) -> Self {
        Self { policies }
    }
}

impl PolicyProvider for MemoryPolicyProvider {
    fn read(&self) -> Policies {
        self.policies.clone()
    }
}

/// Провайдер по умолчанию: политик нет (все поля `None`).
/// На Windows демон подменит его чтением реестра (фаза установщика),
/// значения передаются конструктором — см. спека §5.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPolicyProvider;

impl PolicyProvider for DefaultPolicyProvider {
    fn read(&self) -> Policies {
        Policies::default()
    }
}

/// Применяет политики к настройкам: каждое заданное поле политики
/// перекрывает пользовательское значение (спека §5 — «Политики HKLM
/// перекрывают пользовательские настройки»).
///
/// `require_login`, `default_protocol`, `split_tunnel_default` и
/// `disable_manual_import` не входят в `Settings` — их потребляют
/// RPC-слой и UI напрямую через [`Policies`].
pub fn apply_policies(settings: &mut Settings, policies: &Policies) {
    if let Some(url) = &policies.portal_url {
        settings.portal_url.clone_from(url);
    }
    if let Some(autostart) = policies.autostart {
        settings.autostart = autostart;
    }
    if let Some(kill_switch) = policies.kill_switch {
        settings.kill_switch = kill_switch;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Language;

    #[test]
    fn empty_policy_changes_nothing() {
        let mut s = Settings {
            autostart: false,
            kill_switch: true,
            portal_url: "https://user.example.com".into(),
            ..Settings::default()
        };
        let before = s.clone();
        apply_policies(&mut s, &Policies::default());
        assert_eq!(s, before);
    }

    #[test]
    fn policy_overrides_settings() {
        let mut s = Settings {
            autostart: false,
            auto_connect: true,
            kill_switch: false,
            language: Language::En,
            portal_url: "https://user.example.com".into(),
            socks_port: 1234,
        };
        let p = Policies {
            portal_url: Some("https://corp.example.com".into()),
            autostart: Some(true),
            kill_switch: Some(true),
            require_login: Some(true),
            default_protocol: Some("WIREGUARD".into()),
            split_tunnel_default: Some(vec!["10.0.0.0/8".into()]),
            disable_manual_import: Some(true),
        };
        apply_policies(&mut s, &p);
        // перекрытые политикой
        assert_eq!(s.portal_url, "https://corp.example.com");
        assert!(s.autostart);
        assert!(s.kill_switch);
        // не тронутые политикой — пользовательские
        assert!(s.auto_connect);
        assert_eq!(s.language, Language::En);
        assert_eq!(s.socks_port, 1234);
    }

    #[test]
    fn memory_provider_roundtrip() {
        let p = Policies {
            disable_manual_import: Some(true),
            ..Policies::default()
        };
        let prov = MemoryPolicyProvider::new(p.clone());
        assert_eq!(prov.read(), p);
        assert_eq!(DefaultPolicyProvider.read(), Policies::default());
    }
}
