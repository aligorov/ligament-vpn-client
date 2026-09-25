//! Чтение GPO-политик из реестра: `HKLM\SOFTWARE\Policies\Ligament\CorpVPN`
//! (спека §5, GUIDE-GPO §4). Аудит A-7: политики были объявлены в ADMX и
//! документации, но демон всегда использовал «политик нет» — теперь читаем.
//!
//! Значения (тип — как в GUIDE-GPO):
//! - SZ: `PortalUrl`, `DefaultProtocol`, `SplitTunnelDefault` (CIDR через запятую);
//! - DWORD: `RequireLogin`, `Autostart`, `KillSwitch`, `DisableManualImport`
//!   (0 — «выключено», любое другое — «включено»).
//!
//! Провайдер перечитывает реестр на каждый `read()` — `gpupdate /force`
//! применяется без перезапуска службы.

use vpncore::policy::{Policies, PolicyProvider};

/// Путь в реестре (относительно HKEY_LOCAL_MACHINE).
#[cfg(windows)]
const POLICY_KEY: &str = r"SOFTWARE\Policies\Ligament\CorpVPN";

/// Реестровый провайдер политик (HKLM, только чтение).
pub struct RegistryPolicyProvider;

impl PolicyProvider for RegistryPolicyProvider {
    fn read(&self) -> Policies {
        read_policies()
    }
}

#[cfg(not(windows))]
fn read_policies() -> Policies {
    Policies::default()
}

#[cfg(windows)]
fn read_policies() -> Policies {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_DWORD, REG_SZ, REG_VALUE_TYPE,
    };
    use windows::core::PCWSTR;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Читает REG_SZ → String.
    fn query_sz(key: HKEY, name: &str) -> Option<String> {
        let mut ty = REG_VALUE_TYPE(0);
        let mut len: u32 = 2048;
        let mut buf = vec![0u8; len as usize];
        // SAFETY: key — валидный открытый раздел (проверен вызывающим).
        let res = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr()),
                Some(&mut len),
            )
        };
        if res != WIN32_ERROR(0) || ty != REG_SZ {
            return None;
        }
        let chars: Vec<u16> = buf[..len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        Some(String::from_utf16_lossy(&chars))
    }

    /// Читает REG_DWORD → bool.
    fn query_dw(key: HKEY, name: &str) -> Option<bool> {
        let mut ty = REG_VALUE_TYPE(0);
        let mut buf = [0u8; 4];
        let mut len: u32 = 4;
        // SAFETY: key — валидный открытый раздел (проверен вызывающим).
        let res = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr()),
                Some(&mut len),
            )
        };
        if res != WIN32_ERROR(0) || ty != REG_DWORD || len != 4 {
            return None;
        }
        Some(u32::from_le_bytes(buf) != 0)
    }

    // SAFETY: POLICY_KEY — статическая строка; key закрываем во всех ветках.
    unsafe {
        let mut key = HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide(POLICY_KEY).as_ptr()),
            0,
            KEY_READ,
            &mut key,
        );
        if opened != WIN32_ERROR(0) {
            return Policies::default(); // политик нет — штатно
        }
        let sz = |name: &str| query_sz(key, name).filter(|s| !s.trim().is_empty());
        let dw = |name: &str| query_dw(key, name);
        let policies = Policies {
            portal_url: sz("PortalUrl"),
            require_login: dw("RequireLogin"),
            autostart: dw("Autostart"),
            kill_switch: dw("KillSwitch"),
            disable_manual_import: dw("DisableManualImport"),
            default_protocol: sz("DefaultProtocol"),
            // CIDR через запятую (GUIDE-GPO §4)
            split_tunnel_default: sz("SplitTunnelDefault").map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            }),
        };
        let _ = RegCloseKey(key);
        policies
    }
}
