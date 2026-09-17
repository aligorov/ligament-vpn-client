//! Пути файловой системы демона (спека §6).
//!
//! Windows: всё живёт в `%PROGRAMDATA%\Ligament\CorpVPN`
//! (`profiles.dat`, `corpvpnd.key`, `tunnels\`, `logs\`).
//! Другие платформы (разработка, фаза 2): `./corpvpnd-data/`.

use std::path::PathBuf;

pub const COMPANY_DIR: &str = "Ligament";
pub const APP_DIR: &str = "CorpVPN";

/// Корневой каталог данных.
#[must_use]
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let program_data = std::env::var("PROGRAMDATA")
            .unwrap_or_else(|_| r"C:\ProgramData".to_owned());
        PathBuf::from(program_data).join(COMPANY_DIR).join(APP_DIR)
    }
    #[cfg(not(windows))]
    {
        std::env::current_dir().unwrap_or_default().join("corpvpnd-data")
    }
}

/// Каталог туннельных конфигов (времянки движков).
#[must_use]
pub fn tunnels_dir() -> PathBuf {
    data_dir().join("tunnels")
}

/// Каталог журналов.
#[must_use]
pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

/// Зашифрованное хранилище профилей/настроек.
#[must_use]
pub fn profiles_path() -> PathBuf {
    data_dir().join("profiles.dat")
}

/// Ключ хранилища (32 байта; ACL SYSTEM+Administrators ставит инсталлер).
#[must_use]
pub fn key_path() -> PathBuf {
    data_dir().join("corpvpnd.key")
}

/// Создаёт каталоги данных.
pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(tunnels_dir())?;
    std::fs::create_dir_all(logs_dir())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nested_consistently() {
        #[cfg(windows)]
        assert!(data_dir().ends_with(r"Ligament\CorpVPN"));
        #[cfg(not(windows))]
        assert!(data_dir().ends_with("corpvpnd-data"));
        assert!(tunnels_dir().starts_with(data_dir()));
        assert!(logs_dir().starts_with(data_dir()));
        assert!(profiles_path().ends_with("profiles.dat"));
        assert!(key_path().ends_with("corpvpnd.key"));
    }
}
