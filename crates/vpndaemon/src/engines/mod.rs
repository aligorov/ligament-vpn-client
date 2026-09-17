//! Движки VPN (WireGuard / OpenVPN / VLESS).
//!
//! Каждый движок реализует [`VpnEngine`]: запуск туннеля по профилю,
//! остановку и сбор статистики. Реальная Windows-логика — в дочерних
//! модулях за `#[cfg(windows)]`; на других платформах используется
//! [`StubEngine`] (разработка/тесты, фаза 2 по спеке — macOS/Linux).
//!
//! Сайдкары (openvpn.exe, xray.exe, tun2socks.exe, tunnel.dll, wireguard.dll)
//! лежат рядом с corpvpnd.exe (их кладёт инсталлер/CI). Для разработки
//! каталог переопределяется переменной окружения `CORPVPN_ENGINE_DIR`.

#[cfg(windows)]
pub mod openvpn;
pub mod vless;
#[cfg(windows)]
pub mod wireguard;

use std::path::{Path, PathBuf};
use vpncore::model::{Profile, ProfileKind, Settings, VpnStats};

/// Учётные данные OpenVPN (`auth-user-pass`). Живут только в памяти демона,
/// на диск не пишутся (спека §6); передаются в движок из `corpvpn.connect`.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Контекст запуска движка.
pub struct EngineCtx {
    pub profile: Profile,
    pub settings: Settings,
    pub credentials: Option<Credentials>,
}

/// Ошибка движка. `Display` — пользовательский текст (RU).
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Пользовательский текст ошибки (уже по-русски).
    #[error("{0}")]
    Failed(String),
    #[error("Эта часть клиента доступна только в Windows-сборке")]
    WindowsOnly,
}

impl EngineError {
    #[must_use]
    pub fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }
}

/// Договор с VPN-движком: запустить туннель (с учётом 30-секундного
/// таймаута на стороне [`crate::state`]), остановить, отдать статистику.
pub trait VpnEngine: Send {
    /// Запускает туннель. Возвращает `Ok` только когда туннель реально
    /// поднялся (служба RUNNING / management CONNECTED / процессы живы).
    async fn start(&mut self, ctx: EngineCtx) -> Result<(), EngineError>;
    /// Полная остановка и очистка (убить процессы, удалить службы,
    /// подчистить конфиги-времянки).
    async fn stop(&mut self);
    /// Трафик/рукопожатие туннеля прямо сейчас.
    fn stats(&self) -> VpnStats;
}

/// Активный движок — обёртка-сумка над реализациями (dyn с async-методами
/// не работает, поэтому enum). Box внутри выравнивает размер вариантов —
/// движки живут по одному, аллокация не критична.
pub enum ActiveEngine {
    #[cfg(windows)]
    Wireguard(Box<wireguard::WireguardEngine>),
    #[cfg(windows)]
    Openvpn(Box<openvpn::OpenVpnEngine>),
    Vless(Box<vless::VlessEngine>),
}

impl ActiveEngine {
    /// Создаёт движок под вид профиля.
    ///
    /// На unix VLESS реальный (xray SOCKS, без root); WireGuard/OpenVPN
    /// требуют драйверов/служб Windows — возвращаем `None`, state отдаст
    /// пользователю ошибку «только в Windows-сборке».
    #[must_use]
    pub fn for_profile(profile: &Profile) -> Option<Self> {
        match profile.kind {
            #[cfg(windows)]
            ProfileKind::Wireguard => Some(Self::Wireguard(Box::default())),
            #[cfg(windows)]
            ProfileKind::Openvpn => Some(Self::Openvpn(Box::default())),
            ProfileKind::Vless => Some(Self::Vless(Box::default())),
            #[cfg(not(windows))]
            ProfileKind::Wireguard | ProfileKind::Openvpn => None,
        }
    }
}

impl VpnEngine for ActiveEngine {
    async fn start(&mut self, ctx: EngineCtx) -> Result<(), EngineError> {
        match self {
            #[cfg(windows)]
            Self::Wireguard(e) => e.start(ctx).await,
            #[cfg(windows)]
            Self::Openvpn(e) => e.start(ctx).await,
            Self::Vless(e) => e.start(ctx).await,
        }
    }

    async fn stop(&mut self) {
        match self {
            #[cfg(windows)]
            Self::Wireguard(e) => e.stop().await,
            #[cfg(windows)]
            Self::Openvpn(e) => e.stop().await,
            Self::Vless(e) => e.stop().await,
        }
    }

    fn stats(&self) -> VpnStats {
        match self {
            #[cfg(windows)]
            Self::Wireguard(e) => e.stats(),
            #[cfg(windows)]
            Self::Openvpn(e) => e.stats(),
            Self::Vless(e) => e.stats(),
        }
    }
}

/// Каталог сайдкаров: `CORPVPN_ENGINE_DIR` (разработка) или каталог
/// рядом с текущим исполняемым файлом (устанавливается инсталлером).
#[must_use]
pub fn engine_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CORPVPN_ENGINE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Полный путь к бинарнику сайдкара с проверкой наличия.
///
/// Поиск: сначала рядом со службой (`engines/xray.exe`), затем в подкаталогах
/// (`engines/xray/xray.exe` и т.п.) — инсталлер кладёт каждый движок в свой
/// подкаталог вместе с его DLL (openvpn.exe требует libssl/libcrypto рядом).
pub fn engine_bin(name: &str) -> Result<PathBuf, EngineError> {
    let dir = engine_dir();
    let direct = dir.join(name);
    if direct.is_file() {
        return Ok(direct);
    }
    // Подкаталоги движков: <engine_dir>/<подкаталог>/<name>
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut candidates: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.path().join(name))
            .filter(|p| p.is_file())
            .collect();
        candidates.sort();
        if let Some(first) = candidates.first() {
            return Ok(first.clone());
        }
    }
    Err(EngineError::failed(format!(
        "Не найден {name} (ожидался рядом со службой или в подкаталоге: {})",
        direct.display()
    )))
}

// Заглушка удалена: на unix реален VLESS (xray SOCKS), WireGuard/OpenVPN
// возвращают None из ActiveEngine::for_profile — state отдаёт
// пользователю ошибку «только в Windows-сборке».

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use vpncore::model::{Profile, ProfileKind, ProfileSource};

    #[tokio::test]
    async fn vless_engine_created_on_unix_others_none() {
        // VLESS — реальный движок на любой платформе
        let vless = Profile::new("t", ProfileKind::Vless, ProfileSource::Import);
        assert!(matches!(
            ActiveEngine::for_profile(&vless),
            Some(ActiveEngine::Vless(_))
        ));
        // WireGuard/OpenVPN на unix не поддерживаются (драйверы Windows)
        let mut wg = Profile::new("w", ProfileKind::Wireguard, ProfileSource::Import);
        wg.wg = Some(vpncore::model::WgProfile {
            config: "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\n".into(),
        });
        assert!(ActiveEngine::for_profile(&wg).is_none());
        let mut ovpn = Profile::new("o", ProfileKind::Openvpn, ProfileSource::Import);
        ovpn.ovpn = Some(vpncore::model::OvpnProfile {
            config: "client\nremote h 1194\n".into(),
        });
        assert!(ActiveEngine::for_profile(&ovpn).is_none());
    }

    #[test]
    fn engine_dir_env_override() {
        // без переменной — каталог текущего exe
        let dir = engine_dir();
        assert!(dir.is_absolute() || dir == *PathBuf::from("."));
    }
}
