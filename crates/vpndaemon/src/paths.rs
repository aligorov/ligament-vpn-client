//! Пути файловой системы демона (спека §6).
//!
//! Windows: всё живёт в `%PROGRAMDATA%\Ligament\CorpVPN`
//! (`profiles.dat`, `corpvpnd.key`, `tunnels\`, `logs\`).
//! macOS: `~/Library/Application Support/Ligament/CorpVPN`
//! (демон стартует приложением от пользователя — без root).
//! Linux: `~/.local/share/Ligament/CorpVPN`.

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
    #[cfg(target_os = "macos")]
    {
        home_data_dir(&[
            "Library",
            "Application Support",
            COMPANY_DIR,
            APP_DIR,
        ])
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        home_data_dir(&[".local", "share", COMPANY_DIR, APP_DIR])
    }
}

/// `~/путь/из/частей` с фолбэком на `./corpvpnd-data`, если HOME недоступен.
#[cfg(not(windows))]
fn home_data_dir(parts: &[&str]) -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let mut p = PathBuf::from(home);
        for part in parts {
            p = p.join(part);
        }
        p
    } else {
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

/// Готовит каталоги данных к безопасной работе (аудит A-3/A-21):
/// закрывает права и вычищает конфиги туннелей, оставшиеся от прошлых
/// запусков (в них приватные ключи WireGuard). Ошибки не фатальны —
/// служба обязана подниматься, — но логируются.
pub fn secure_data_paths() {
    restrict(&data_dir());
    restrict(&tunnels_dir());
    restrict(&logs_dir());
    if profiles_path().exists() {
        restrict(&profiles_path());
    }
    if key_path().exists() {
        restrict(&key_path());
    }
    if let Ok(entries) = std::fs::read_dir(tunnels_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("corpvpn-") {
                if let Err(e) = std::fs::remove_file(entry.path()) {
                    tracing::warn!(path = %entry.path().display(), error = %e,
                        "не удалить остаток конфига туннеля");
                }
            }
        }
    }
}

/// SDDL данных демона: полный доступ только SYSTEM и Администраторам,
/// наследование от ProgramData отключено (PROTECTED) — по умолчанию
/// Users получают право чтения, а здесь ключ шифрования и профили
/// с приватными ключами (аудит A-3).
#[cfg(windows)]
const DATA_SDDL: &str = "D:PA(A;;FA;;;SY)(A;;FA;;;BA)";

/// Закрывает файл/каталог для всех, кроме владельца-службы:
/// Windows — DACL SYSTEM+Админы без наследования, unix — 0700/0600.
pub fn restrict(path: &std::path::Path) {
    if let Err(e) = restrict_impl(path) {
        tracing::warn!(path = %path.display(), error = %e, "не ограничить права пути");
    }
}

#[cfg(windows)]
fn restrict_impl(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{LocalFree, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::core::PCWSTR;

    let mut sddl: Vec<u16> = DATA_SDDL.encode_utf16().chain([0]).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl — NUL-терминированная строка; дескриптор освобождаем ниже.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(std::io::Error::other)?;

        let mut dacl_present = windows::Win32::Foundation::BOOL::default();
        let mut dacl_defaulted = windows::Win32::Foundation::BOOL::default();
        let mut dacl = std::ptr::null_mut();
        // GetSecurityDescriptorDacl возвращает windows_result::Error —
        // приводим к io::Error (единый тип функции)
        let result = GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))
        .and_then(|()| {
            if !dacl_present.as_bool() {
                return Err(std::io::Error::other("SDDL без DACL"));
            }
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
            // null-PSID: владелец/группа не меняются, только DACL
            let res = SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                PSID(std::ptr::null_mut()),
                PSID(std::ptr::null_mut()),
                Some(dacl.cast_const()),
                None,
            );
            if res != WIN32_ERROR(0) {
                return Err(std::io::Error::from_raw_os_error(res.0 as i32));
            }
            Ok(())
        });
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(descriptor.0));
        result
    }
}

/// На unix демон работает от пользователя: 0700 каталоги, 0600 файлы.
#[cfg(unix)]
fn restrict_impl(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nested_consistently() {
        #[cfg(windows)]
        assert!(data_dir().ends_with(r"Ligament\CorpVPN"));
        #[cfg(target_os = "macos")]
        assert!(data_dir().ends_with("Ligament/CorpVPN"));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(data_dir().ends_with("Ligament/CorpVPN"));
        assert!(tunnels_dir().starts_with(data_dir()));
        assert!(logs_dir().starts_with(data_dir()));
        assert!(profiles_path().ends_with("profiles.dat"));
        assert!(key_path().ends_with("corpvpnd.key"));
    }
}
