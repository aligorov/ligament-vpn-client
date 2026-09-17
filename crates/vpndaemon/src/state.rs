//! Состояние демона: профили, настройки, состояние VPN, активный движок,
//! события для UI. Единственный активный туннель (спека §3).
//!
//! Подключение: проверка профиля → `connecting` → запуск движка →
//! `connected` / `error` (таймаут 30 с). Отключение: `disconnecting` →
//! остановка движка → `disconnected`. Каждое изменение состояния
//! рассылается уведомлением `state.changed`.

use crate::engines::{ActiveEngine, Credentials, EngineCtx, VpnEngine};
use crate::logging::LogEntry;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use vpncore::model::{
    Profile, ProfileKind, ProfileSource, Settings, VpnState, VpnStatus, now_epoch,
};
use vpncore::policy::{Policies, PolicyProvider, apply_policies};
use vpncore::portal::PortalUser;
use vpncore::store::{EncryptedFileStore, ProfileStore, StoreData};

/// Таймаут подключения: 30 с, потом статус `error` (спека §9).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Ёмкость кольцевого буфера журналов для `corpvpn.logs.tail`.
const LOG_RING_CAPACITY: usize = 1000;

/// Ошибка уровня приложения с пользовательским текстом (RU) и debug-полем
/// для JSON-RPC `error.data` (спека §9).
#[derive(Debug, Clone)]
pub struct RpcFailure {
    pub user_message: String,
    pub debug: Option<String>,
}

impl RpcFailure {
    #[must_use]
    pub fn new(user_message: impl Into<String>) -> Self {
        Self {
            user_message: user_message.into(),
            debug: None,
        }
    }

    #[must_use]
    pub fn with_debug(mut self, debug: impl Into<String>) -> Self {
        self.debug = Some(debug.into());
        self
    }
}

impl From<vpncore::store::StoreError> for RpcFailure {
    fn from(e: vpncore::store::StoreError) -> Self {
        RpcFailure::new(e.to_string())
    }
}

/// Данные под write-lock: профили, настройки, состояние, сессия портала.
#[derive(Default)]
pub struct SharedData {
    pub profiles: Vec<Profile>,
    pub settings: Settings,
    pub vpn: VpnState,
    pub portal_token: Option<String>,
    /// true — токен это кука `vpn_portal_session` (логин/пароль),
    /// false — Bearer API-токен (OIDC exchange).
    pub portal_token_is_cookie: bool,
    pub portal_user: Option<PortalUser>,
}

/// Глобальное состояние демона (клонируемый Arc).
pub struct AppState {
    pub(crate) store: Arc<EncryptedFileStore>,
    policy: Box<dyn PolicyProvider>,
    pub(crate) data: RwLock<SharedData>,
    engine: tokio::sync::Mutex<Option<ActiveEngine>>,
    events: broadcast::Sender<String>,
    log_ring: RwLock<VecDeque<LogEntry>>,
}

impl AppState {
    /// Продакшн-инициализация: загрузка хранилища + применение политик.
    pub fn load(
        store: Arc<EncryptedFileStore>,
        policy: Box<dyn PolicyProvider>,
        events: broadcast::Sender<String>,
    ) -> Result<Self, String> {
        let mut data = match store.load() {
            Ok(d) => SharedData {
                profiles: d.profiles,
                settings: d.settings,
                vpn: VpnState::default(),
                portal_token: d.portal_token,
                portal_token_is_cookie: d.portal_token_is_cookie,
                portal_user: None,
            },
            Err(vpncore::store::StoreError::Io(_)) => SharedData::default(), // первого старта ещё нет
            Err(e) => return Err(format!("Хранилище профилей: {e}")),
        };
        // политики HKLM перекрывают пользовательские настройки (спека §5)
        apply_policies(&mut data.settings, &policy.read());
        Ok(Self {
            store,
            policy,
            data: RwLock::new(data),
            engine: tokio::sync::Mutex::new(None),
            events,
            log_ring: RwLock::new(VecDeque::new()),
        })
    }

    /// Снимок политик (для RPC-проверок вроде `disable_manual_import`).
    pub fn policies(&self) -> Policies {
        self.policy.read()
    }

    /// Broadcast-канал уведомлений (`state.changed`, `log.entry`).
    pub fn events(&self) -> broadcast::Sender<String> {
        self.events.clone()
    }

    fn notify_state(&self, state: &VpnState) {
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "state.changed",
            "params": state,
        });
        let _ = self.events.send(frame.to_string());
    }

    /// Обновляет статус VPN (без изменения движка) и рассылает `state.changed`.
    pub async fn set_status(
        &self,
        status: VpnStatus,
        active_profile_id: Option<String>,
        error: Option<String>,
    ) -> VpnState {
        let mut data = self.data.write().await;
        data.vpn = VpnState {
            status,
            active_profile_id,
            error,
            stats: data.vpn.stats,
        };
        self.notify_state(&data.vpn);
        data.vpn.clone()
    }

    /// Текущее состояние (со свежей статистикой движка).
    pub async fn state(&self) -> VpnState {
        {
            let engine = self.engine.lock().await;
            let stats = engine
                .as_ref()
                .map_or_else(vpncore::model::VpnStats::default, VpnEngine::stats);
            let mut data = self.data.write().await;
            data.vpn.stats = stats;
        }
        self.data.read().await.vpn.clone()
    }

    /// Подключение к профилю. Блокируется до результата (≤30 с); статусы
    /// `connecting`/`connected`/`error` рассылаются уведомлениями.
    pub async fn connect(
        &self,
        profile_id: &str,
        credentials: Option<Credentials>,
    ) -> Result<VpnState, RpcFailure> {
        let mut engine_slot = self
            .engine
            .lock()
            .await;
        if engine_slot.is_some() {
            return Err(RpcFailure::new(
                "Уже есть активное подключение — сначала отключитесь",
            ));
        }

        // валидация профиля
        let (profile, settings) = {
            let data = self.data.read().await;
            let profile = data
                .profiles
                .iter()
                .find(|p| p.id == profile_id)
                .cloned()
                .ok_or_else(|| RpcFailure::new("Профиль не найден"))?;
            (profile, data.settings.clone())
        };
        profile
            .validate()
            .map_err(RpcFailure::new)?;

        self.set_status(VpnStatus::Connecting, Some(profile.id.clone()), None)
            .await;

        let kind = profile.kind;
        let mut engine =
            ActiveEngine::for_profile(&profile).ok_or_else(|| RpcFailure::new(
                "Этот протокол доступен только в Windows-сборке клиента",
            ))?;
        let ctx = EngineCtx {
            profile: profile.clone(),
            settings,
            credentials,
        };

        let result = match tokio::time::timeout(CONNECT_TIMEOUT, engine.start(ctx)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("Не удалось подключиться за 30 секунд".to_owned()),
        };

        match result {
            Ok(()) => {
                tracing::info!(profile = %profile.id, kind = ?kind, "подключено");
                *engine_slot = Some(engine);
                Ok(self
                    .set_status(VpnStatus::Connected, Some(profile.id), None)
                    .await)
            }
            Err(msg) => {
                tracing::warn!(profile = %profile.id, error = %msg, "подключение не удалось");
                engine.stop().await;
                // спека §9: таймаут/ошибка подключения → статус error с текстом для пользователя
                self.set_status(
                    VpnStatus::Error,
                    Some(profile.id),
                    Some(msg.clone()),
                )
                .await;
                Err(RpcFailure::new(msg))
            }
        }
    }

    /// Отключение активного туннеля (идемпотентно).
    pub async fn disconnect(&self) -> VpnState {
        let active_id = {
            let data = self.data.read().await;
            data.vpn.active_profile_id.clone()
        };
        self.set_status(VpnStatus::Disconnecting, active_id, None)
            .await;
        let mut engine_slot = self.engine.lock().await;
        if let Some(mut engine) = engine_slot.take() {
            engine.stop().await;
            tracing::info!("туннель остановлен");
        }
        self.set_status(VpnStatus::Disconnected, None, None).await
    }

    /// Полная остановка демона: отключить туннель, сохранить данные.
    pub async fn shutdown(&self) {
        self.disconnect().await;
        let _ = self.persist_current().await;
    }

    // -- профили ----------------------------------------------------------

    /// Список профилей.
    pub async fn profiles(&self) -> Vec<Profile> {
        self.data.read().await.profiles.clone()
    }

    /// Импорт профиля по тексту конфига (вид определяется автоматически).
    pub async fn import_profile(&self, name: &str, config: &str) -> Result<Profile, RpcFailure> {
        if self.policies().disable_manual_import == Some(true) {
            return Err(RpcFailure::new("Импорт профилей запрещён политикой"));
        }
        let kind = vpncore::infer_profile_kind(config)
            .ok_or_else(|| RpcFailure::new(
                "Не удалось определить тип конфига (поддерживаются WireGuard .conf, OpenVPN .ovpn и vless://)",
            ))?;
        let mut profile = Profile::new(
            if name.trim().is_empty() { "Импортированный профиль" } else { name.trim() },
            kind,
            ProfileSource::Import,
        );
        match kind {
            ProfileKind::Wireguard => {
                vpncore::wg::parse(config)
                    .map_err(|e| RpcFailure::new(format!("Некорректный конфиг WireGuard: {e}")))?;
                profile.wg = Some(vpncore::model::WgProfile {
                    config: config.to_owned(),
                });
            }
            ProfileKind::Openvpn => {
                profile.ovpn = Some(vpncore::model::OvpnProfile {
                    config: config.to_owned(),
                });
            }
            ProfileKind::Vless => {
                vpncore::vless::parse(config)
                    .map_err(|e| RpcFailure::new(format!("Некорректная ссылка vless://: {e}")))?;
                profile.vless = Some(vpncore::model::VlessProfile {
                    uri: config.trim().to_owned(),
                });
            }
        }
        let mut data = self.data.write().await;
        data.profiles.push(profile.clone());
        self.persist(&data)?;
        Ok(profile)
    }

    /// Удаление профиля.
    pub async fn delete_profile(&self, profile_id: &str) -> Result<(), RpcFailure> {
        let mut data = self.data.write().await;
        if data.vpn.active_profile_id.as_deref() == Some(profile_id)
            && data.vpn.status != VpnStatus::Disconnected
        {
            return Err(RpcFailure::new(
                "Профиль используется — сначала отключитесь",
            ));
        }
        let before = data.profiles.len();
        data.profiles.retain(|p| p.id != profile_id);
        if data.profiles.len() == before {
            return Err(RpcFailure::new("Профиль не найден"));
        }
        self.persist(&data)
    }

    /// Обновление профиля (имя, overrides) поверх существующего id.
    pub async fn update_profile(&self, profile: Profile) -> Result<Profile, RpcFailure> {
        profile.validate().map_err(RpcFailure::new)?;
        let mut data = self.data.write().await;
        let existing = data
            .profiles
            .iter_mut()
            .find(|p| p.id == profile.id)
            .ok_or_else(|| RpcFailure::new("Профиль не найден"))?;
        let mut updated = profile;
        updated.created_at = existing.created_at;
        updated.updated_at = now_epoch();
        *existing = updated.clone();
        self.persist(&data)?;
        Ok(updated)
    }

    // -- настройки ---------------------------------------------------------

    /// Пользовательские настройки с наложенными политиками.
    pub async fn settings(&self) -> Settings {
        let mut settings = self.data.read().await.settings.clone();
        apply_policies(&mut settings, &self.policies());
        settings
    }

    /// Сохраняет пользовательские настройки; политики поверх — всегда.
    pub async fn set_settings(&self, mut settings: Settings) -> Result<Settings, RpcFailure> {
        let mut data = self.data.write().await;
        data.settings = settings.clone();
        apply_policies(&mut data.settings, &self.policies());
        settings = data.settings.clone();
        self.persist(&data)?;
        Ok(settings)
    }

    // -- журнал -------------------------------------------------------------

    /// Хвост журнала.
    pub async fn logs_tail(&self, limit: usize) -> Vec<LogEntry> {
        let ring = self.log_ring.read().await;
        ring.iter().rev().take(limit).cloned().collect()
    }

    /// Добавляет запись в кольцевой буфер (вызывается сборщиком log.entry).
    pub async fn push_log(&self, entry: LogEntry) {
        let mut ring = self.log_ring.write().await;
        if ring.len() >= LOG_RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(entry);
    }

    // -- портал -------------------------------------------------------------

    /// Сессия портала: (токен, is_cookie).
    pub async fn portal_session(&self) -> Option<(String, bool)> {
        let data = self.data.read().await;
        data.portal_token
            .clone()
            .map(|t| (t, data.portal_token_is_cookie))
    }

    /// Запоминает сессию портала и пользователя.
    pub async fn set_portal_session(
        &self,
        token: String,
        is_cookie: bool,
        user: Option<PortalUser>,
    ) {
        let mut data = self.data.write().await;
        data.portal_token = Some(token);
        data.portal_token_is_cookie = is_cookie;
        data.portal_user = user;
        let _ = self.persist(&data);
    }

    /// Забывает сессию портала.
    pub async fn clear_portal_session(&self) {
        let mut data = self.data.write().await;
        data.portal_token = None;
        data.portal_token_is_cookie = false;
        data.portal_user = None;
        let _ = self.persist(&data);
    }

    /// Пользователь портала, если входили.
    pub async fn portal_user(&self) -> Option<PortalUser> {
        self.data.read().await.portal_user.clone()
    }

    /// Портал-URL (из настроек с политиками).
    pub async fn portal_url(&self) -> String {
        self.data.read().await.settings.portal_url.clone()
    }

    // -- хранилище -----------------------------------------------------------

    async fn persist_current(&self) -> Result<(), RpcFailure> {
        let data = self.data.read().await;
        self.persist(&data)
    }

    pub(crate) fn persist(&self, data: &SharedData) -> Result<(), RpcFailure> {
        let store_data = StoreData {
            profiles: data.profiles.clone(),
            settings: data.settings.clone(),
            portal_token: data.portal_token.clone(),
            portal_token_is_cookie: data.portal_token_is_cookie,
        };
        self.store.save(&store_data).map_err(|e| {
            tracing::error!(error = %e, "не сохранить хранилище");
            RpcFailure::new(e.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpncore::policy::{DefaultPolicyProvider, MemoryPolicyProvider};
    use vpncore::store::EncryptedFileStore;

    fn test_state(dir: &tempfile::TempDir, policies: Policies) -> Arc<AppState> {
        let store = Arc::new(EncryptedFileStore::new(
            dir.path().join("profiles.dat"),
            [7u8; 32],
        ));
        let provider: Box<dyn PolicyProvider> = if policies == Policies::default() {
            Box::new(DefaultPolicyProvider)
        } else {
            Box::new(MemoryPolicyProvider::new(policies))
        };
        let (tx, _rx) = broadcast::channel(64);
        Arc::new(AppState::load(store, provider, tx).unwrap())
    }

    fn wg_profile() -> Profile {
        let mut p = Profile::new("Корпоративная", ProfileKind::Wireguard, ProfileSource::Import);
        p.wg = Some(vpncore::model::WgProfile {
            config: "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = h:51820\n".into(),
        });
        p
    }


    /// Валидная VLESS/REALITY ссылка для тестов.
    fn vless_uri() -> String {
        "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?security=reality&pbk=pubkey&sid=abcd1234&sni=vpn.example.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#test".to_owned()
    }

    /// Каталог движков с фейковым `xray` (sleep-скрипт): реальные тесты
    /// запуска VLESS-движка на unix без бинарника xray. Один на процесс.
    fn ensure_fake_xray() {
        use std::sync::OnceLock;
        static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
        let dir = DIR.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let xray = dir.path().join("xray");
                std::fs::write(&xray, "#!/bin/sh\nsleep 3600\n").unwrap();
                let mut perm = std::fs::metadata(&xray).unwrap().permissions();
                perm.set_mode(0o755);
                std::fs::set_permissions(&xray, perm).unwrap();
            }
            dir
        });
        std::env::set_var("CORPVPN_ENGINE_DIR", dir.path());
    }

    #[tokio::test]
    async fn connect_disconnect_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir, Policies::default());
        ensure_fake_xray();
        let profile = state.import_profile("corp", &vless_uri()).await.unwrap();
        let _ = state.connect(&profile.id, None).await.unwrap();
        // VLESS-движок (фейковый xray) подключается мгновенно
        let s = state.state().await;
        assert_eq!(s.status, VpnStatus::Connected);
        assert_eq!(s.active_profile_id.as_deref(), Some(profile.id.as_str()));
        let s = state.disconnect().await;
        assert_eq!(s.status, VpnStatus::Disconnected);
        assert_eq!(s.active_profile_id, None);
    }

    #[tokio::test]
    async fn single_active_tunnel_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir, Policies::default());
        ensure_fake_xray();
        let p1 = state.import_profile("a", &vless_uri()).await.unwrap();
        let p2 = state.import_profile("b", &vless_uri()).await.unwrap();
        state.connect(&p1.id, None).await.unwrap();
        let err = state.connect(&p2.id, None).await.unwrap_err();
        assert!(err.user_message.contains("Уже есть активное"));
        state.disconnect().await;
    }

    #[tokio::test]
    async fn connect_unknown_profile_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir, Policies::default());
        let err = state.connect("no-such-id", None).await.unwrap_err();
        assert_eq!(err.user_message, "Профиль не найден");
        assert_eq!(state.state().await.status, VpnStatus::Disconnected);
    }

    #[tokio::test]
    async fn import_forbidden_by_policy() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            &dir,
            Policies {
                disable_manual_import: Some(true),
                ..Policies::default()
            },
        );
        let err = state.import_profile("x", &wg_profile().wg.unwrap().config).await.unwrap_err();
        assert!(err.user_message.contains("запрещён политикой"));
    }

    #[tokio::test]
    async fn settings_policy_merge_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(
            &dir,
            Policies {
                kill_switch: Some(true),
                ..Policies::default()
            },
        );
        let s = Settings {
            kill_switch: false, // пользователь выключил — политика вернёт
            socks_port: 1234,
            ..Settings::default()
        };
        let effective = state.set_settings(s).await.unwrap();
        assert!(effective.kill_switch, "политика перекрывает пользователя");
        assert_eq!(effective.socks_port, 1234);
        // после перезагрузки состояния — то же
        assert!(state.settings().await.kill_switch);
    }

    #[tokio::test]
    async fn update_delete_profile() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir, Policies::default());
        let p = state.import_profile("corp", &wg_profile().wg.unwrap().config).await.unwrap();
        let mut updated = p.clone();
        updated.name = "Переименованный".into();
        updated.overrides.dns = Some(vec!["10.0.0.53".into()]);
        let saved = state.update_profile(updated).await.unwrap();
        assert_eq!(saved.name, "Переименованный");
        assert_eq!(state.profiles().await.len(), 1);
        state.delete_profile(&saved.id).await.unwrap();
        assert!(state.profiles().await.is_empty());
        assert!(state.delete_profile(&saved.id).await.is_err());
    }

    #[tokio::test]
    async fn portal_session_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir, Policies::default());
        assert!(state.portal_session().await.is_none());
        state
            .set_portal_session("tok".into(), true, None)
            .await;
        assert_eq!(state.portal_session().await, Some(("tok".into(), true)));
        state.clear_portal_session().await;
        assert!(state.portal_session().await.is_none());
    }
}
