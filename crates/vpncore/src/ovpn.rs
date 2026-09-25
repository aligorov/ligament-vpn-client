//! Лёгкий парсер и нормализатор `.ovpn` конфигов OpenVPN.
//!
//! Парсер вытаскивает только то, что нужно клиенту: `remote host port`,
//! `proto`, `dev`, наличие блока `<ca>` и директивы `auth-user-pass`.
//! Нормализатор [`normalize`] готовит конфиг к запуску демоном:
//! гарантирует голый `auth-user-pass` (креды придут через management
//! socket, а не из файла) и `auth-nocache`, выкидывает `askpass`.
//!
//! Флаги `--management 127.0.0.1 <port> --management-client` демон добавляет
//! в командной строке openvpn.exe — здесь их нет намеренно.

/// Выжимка из `.ovpn`, нужная клиенту.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OvpnInfo {
    /// Первый `remote host port [proto]`.
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
    /// `proto tcp-client` / `proto udp` и т.п.
    pub proto: Option<String>,
    /// `dev tun` / `dev tap`.
    pub dev: Option<String>,
    /// Есть ли встроенный блок `<ca>…</ca>`.
    pub has_ca: bool,
    /// Есть ли директива `auth-user-pass` (с файлом или без).
    pub auth_user_pass: bool,
}

/// Полностью закомментированная строка (`#`/`;` в начале)?
/// OpenVPN понимает только комментарии целой строкой; инлайновых нет.
fn is_comment(trimmed: &str) -> bool {
    trimmed.starts_with('#') || trimmed.starts_with(';')
}

/// Разбирает ключевые директивы `.ovpn`.
#[must_use]
pub fn parse(config: &str) -> OvpnInfo {
    let mut info = OvpnInfo::default();
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || is_comment(line) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(directive) = parts.next() else { continue };
        match directive.to_ascii_lowercase().as_str() {
            "remote" => {
                if info.remote_host.is_none() {
                    info.remote_host = parts.next().map(str::to_owned);
                    info.remote_port = parts
                        .next()
                        .and_then(|p| p.parse::<u16>().ok());
                }
            }
            "proto" => {
                if info.proto.is_none() {
                    info.proto = parts.next().map(str::to_owned);
                }
            }
            "dev" => {
                if info.dev.is_none() {
                    info.dev = parts.next().map(str::to_owned);
                }
            }
            "auth-user-pass" => info.auth_user_pass = true,
            _ => {
                if line.eq_ignore_ascii_case("<ca>") {
                    info.has_ca = true;
                }
            }
        }
    }
    info
}

/// Нормализует конфиг для запуска демоном:
/// - `auth-user-pass <файл>` → голый `auth-user-pass` (креды придут по
///   management-интерфейсу; файл с паролем на диске нам не нужен);
/// - если `auth-user-pass` нет — добавляет (портал выдаёт конфиги с авторизацией);
/// - гарантирует `auth-nocache` (пароль не оседает в памяти openvpn);
/// - удаляет `askpass <файл>` (интерактивных запросов быть не может);
/// - **вырезает директивы запуска внешних программ** (`script-security`,
///   `up`, `down`, `route-up`, `iproute`, `client-connect`/`-disconnect`,
///   `learn-address`, `tls-verify`, `ipchange`): конфиг исполняется службой
///   от SYSTEM, и .ovpn с `script-security 2` + `up "cmd /c …"` — это
///   локальное повышение привилегий (аудит A-1). Демон дополнительно
///   форсирует `--script-security 1` в командной строке openvpn.
///
/// Остальные строки (включая комментарии и `<ca>`-блоки) сохраняются как есть.
#[must_use]
pub fn normalize(config: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut has_auth_user_pass = false;
    let mut has_auth_nocache = false;

    for raw in config.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || is_comment(trimmed) {
            out.push(raw.to_owned()); // комментарии/пустые строки сохраняются как есть
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let first = lower.split_whitespace().next().unwrap_or_default();
        if SCRIPT_DIRECTIVES.contains(&first) {
            continue; // внешние программы из конфига не запускаем (аудит A-1)
        }
        if lower.starts_with("askpass") {
            continue; // выкинуть интерактивный запрос пароля
        }
        if lower.starts_with("auth-user-pass") {
            has_auth_user_pass = true;
            // переиспользуем исходный отступ, аргумент (файл) убираем
            let indent = &raw[..raw.len() - trimmed.len()];
            out.push(format!("{indent}auth-user-pass"));
            continue;
        }
        if lower.starts_with("auth-nocache") {
            has_auth_nocache = true;
        }
        out.push(raw.to_owned());
    }

    if !has_auth_user_pass {
        out.push("auth-user-pass".to_owned());
    }
    if !has_auth_nocache {
        out.push("auth-nocache".to_owned());
    }
    let mut result = out.join("\n");
    result.push('\n');
    result
}

/// Директивы, запускающие внешние программы или загружающие код
/// (вырезаются при normalize). Сравнение — по первому токену строки
/// (`up` не задевает `update…`), регистр не важен.
const SCRIPT_DIRECTIVES: &[&str] = &[
    "script-security",
    "up",
    "down",
    "route-up",
    "iproute",
    "iproute-netnspath",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "tls-verify",
    "ipchange",
    "tls-export-cert",
    "plugin",
];

/// Эвристика «похоже ли на .ovpn» (для автоопределения импорта).
#[must_use]
pub fn looks_like_ovpn(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !is_comment(l))
        .any(|l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("client") || lower.starts_with("remote ") || lower.starts_with("<ca>")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Корпоративный OpenVPN
client
dev tun
proto tcp-client
remote vpn.example.com 1194
resolv-retry infinite
nobind
auth-user-pass pass.txt
askpass secret.key
<ca>
-----BEGIN CERTIFICATE-----
MIIF...
-----END CERTIFICATE-----
</ca>
";

    #[test]
    fn parses_key_directives() {
        let info = parse(SAMPLE);
        assert_eq!(info.remote_host.as_deref(), Some("vpn.example.com"));
        assert_eq!(info.remote_port, Some(1194));
        assert_eq!(info.proto.as_deref(), Some("tcp-client"));
        assert_eq!(info.dev.as_deref(), Some("tun"));
        assert!(info.has_ca);
        assert!(info.auth_user_pass);
        assert!(looks_like_ovpn(SAMPLE));
    }

    #[test]
    fn remote_without_port_and_comments() {
        let info = parse("; remote old.example.com 1111\nremote 10.0.0.1\nproto udp\n");
        // закомментированный remote не считается
        assert_eq!(info.remote_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(info.remote_port, None);
        assert_eq!(info.proto.as_deref(), Some("udp"));
        assert!(!info.has_ca);
    }

    #[test]
    fn normalize_strips_files_adds_nocache() {
        let norm = normalize(SAMPLE);
        // голый auth-user-pass (без файла), auth-nocache добавлен, askpass удалён
        assert!(norm.lines().any(|l| l.trim() == "auth-user-pass"));
        assert!(!norm.contains("pass.txt"));
        assert!(!norm.contains("askpass"));
        assert!(!norm.contains("secret.key"));
        assert!(norm.lines().any(|l| l.trim() == "auth-nocache"));
        // <ca>-блок и остальные директивы сохранены
        assert!(norm.contains("<ca>"));
        assert!(norm.contains("resolv-retry infinite"));
        assert!(norm.contains("# Корпоративный OpenVPN"));
        // повторная нормализация идемпотентна
        assert_eq!(normalize(&norm), norm);
    }

    #[test]
    fn normalize_strips_script_directives() {
        // аудит A-1: script-директивы = код от SYSTEM, вырезаем целиком
        let evil = "client\n\
            script-security 2\n\
            up \"cmd /c net user evil P@ss /add\"\n\
            down /tmp/cleanup.sh\n\
            route-up C:\\\\evil.bat\n\
            iproute /sbin/ip\n\
            client-connect hook.sh\n\
            learn-address addr.sh\n\
            tls-verify check.sh\n\
            ipchange change.cmd\n\
            plugin openvpn-plugin-down-root.so\n\
            remote vpn.example.com 1194\n\
            verb 3\n";
        let norm = normalize(evil);
        for banned in [
            "script-security",
            "cmd /c",
            "cleanup.sh",
            "evil.bat",
            "hook.sh",
            "addr.sh",
            "check.sh",
            "change.cmd",
            "iproute",
            "plugin",
        ] {
            assert!(!norm.contains(banned), "«{banned}» должен быть вырезан: {norm}");
        }
        // легитимные директивы не задеты
        assert!(norm.contains("remote vpn.example.com 1194"));
        assert!(norm.contains("verb 3"));
        assert!(norm.lines().any(|l| l.trim() == "auth-user-pass"));
        // идемпотентность
        assert_eq!(normalize(&norm), norm);
    }

    #[test]
    fn normalize_adds_auth_user_pass_when_missing() {
        let norm = normalize("client\nremote h 443\n");
        assert!(norm.lines().any(|l| l.trim() == "auth-user-pass"));
        assert!(norm.lines().any(|l| l.trim() == "auth-nocache"));
        assert_eq!(parse(&norm).remote_host.as_deref(), Some("h"));
    }

    #[test]
    fn normalize_preserves_indentation_of_replaced_directive() {
        let norm = normalize("client\n  auth-user-pass /etc/creds");
        assert!(norm.contains("\n  auth-user-pass\n") || norm.starts_with("  auth-user-pass"));
    }

    #[test]
    fn not_ovpn() {
        assert!(!looks_like_ovpn("[Interface]\nPrivateKey = k\n"));
        assert!(!looks_like_ovpn("random text"));
    }
}
