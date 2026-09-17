//! Парсер и рендерер конфигов WireGuard (`.conf`).
//!
//! Формат — INI-подобный: секции `[Interface]` / `[Peer]`, строки `Ключ = Значение`,
//! списки через запятую (`Address`, `DNS`, `AllowedIPs`). Комментарии — `#` и `;`
//! (в начале строки и после значения). Неизвестные ключи сохраняются в `extra`
//! и переживают round-trip.
//!
//! Рендер [`WgConfig::render`] выдаёт канонический вид; [`apply_overrides`]
//! подменяет `AllowedIPs`/`DNS` пользовательскими переопределениями
//! (split tunnel / DNS из «Продвинутых» настроек UI).

use crate::model::Overrides;

/// Ошибка разбора `.conf`. `Display` — по-русски (текст уходит в UI).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WgParseError {
    #[error("нет секции [Interface]")]
    NoInterface,
    #[error("две секции [Interface]")]
    DuplicateInterface,
    #[error("строка вне секции: «{0}»")]
    LineOutsideSection(String),
    #[error("неверная строка (ожидалось «Ключ = Значение»): «{0}»")]
    MalformedLine(String),
    #[error("неизвестная секция: «{0}»")]
    UnknownSection(String),
    #[error("неверное значение ключа {key}: «{value}»")]
    InvalidValue { key: &'static str, value: String },
}

/// Секция `[Interface]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgInterface {
    pub private_key: Option<String>,
    /// `Address` — список адресов через запятую.
    pub address: Vec<String>,
    /// `DNS` — список серверов через запятую.
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<String>,
    pub mtu: Option<u32>,
    /// Неизвестные ключи (сохраняются как есть, в порядке появления).
    pub extra: Vec<(String, String)>,
}

/// Секция `[Peer]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgPeer {
    pub public_key: Option<String>,
    pub preshared_key: Option<String>,
    /// `AllowedIPs` — список подсетей через запятую.
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u32>,
    /// Неизвестные ключи.
    pub extra: Vec<(String, String)>,
}

/// Разобранный конфиг WireGuard: один `[Interface]` + ноль и более `[Peer]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WgConfig {
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
}

/// Убирает комментарий: всё от первого `#` или `;` (в значениях WireGuard
/// эти символы не встречаются: base64/IP/хосты их не содержат).
fn strip_comment(line: &str) -> &str {
    let cut = line.find(['#', ';']).unwrap_or(line.len());
    &line[..cut]
}

/// Разделяет список значений `a, b,,c` по запятым, отбрасывая пустые.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Текущая секция при построчном разборе.
#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

impl WgConfig {
    /// Разбирает текст `.conf`. Комментарии `#`/`;` пропускаются.
    pub fn parse(input: &str) -> Result<Self, WgParseError> {
        let mut cfg = Self::default();
        let mut saw_interface = false;
        let mut section = Section::None;

        for raw in input.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                let name = line
                    .strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
                    .map(str::trim)
                    .ok_or_else(|| WgParseError::MalformedLine(raw.trim().to_owned()))?;
                match name.to_ascii_lowercase().as_str() {
                    "interface" => {
                        if saw_interface {
                            return Err(WgParseError::DuplicateInterface);
                        }
                        saw_interface = true;
                        section = Section::Interface;
                    }
                    "peer" => {
                        cfg.peers.push(WgPeer::default());
                        section = Section::Peer;
                    }
                    _ => return Err(WgParseError::UnknownSection(name.to_owned())),
                }
                continue;
            }

            let (key_raw, value_raw) = line.split_once('=').ok_or_else(|| {
                WgParseError::MalformedLine(raw.trim().to_owned())
            })?;
            let key = key_raw.trim();
            let value = value_raw.trim().to_owned();
            if key.is_empty() || value.is_empty() {
                return Err(WgParseError::MalformedLine(raw.trim().to_owned()));
            }

            match section {
                Section::None => {
                    return Err(WgParseError::LineOutsideSection(raw.trim().to_owned()))
                }
                Section::Interface => match key.to_ascii_lowercase().as_str() {
                    "privatekey" => cfg.interface.private_key = Some(value),
                    "address" => cfg.interface.address.extend(split_list(&value)),
                    "dns" => cfg.interface.dns.extend(split_list(&value)),
                    "listenport" => {
                        cfg.interface.listen_port = Some(value.parse::<u16>().map_err(
                            |_| WgParseError::InvalidValue {
                                key: "ListenPort",
                                value,
                            },
                        )?);
                    }
                    "fwmark" => cfg.interface.fwmark = Some(value),
                    "mtu" => {
                        cfg.interface.mtu = Some(value.parse::<u32>().map_err(|_| {
                            WgParseError::InvalidValue { key: "MTU", value }
                        })?);
                    }
                    _ => cfg.interface.extra.push((key.to_owned(), value)),
                },
                Section::Peer => {
                    let peer = cfg
                        .peers
                        .last_mut()
                        .expect("Section::Peer устанавливается вместе с новым пиром");
                    match key.to_ascii_lowercase().as_str() {
                        "publickey" => peer.public_key = Some(value),
                        "presharedkey" => peer.preshared_key = Some(value),
                        "allowedips" => peer.allowed_ips.extend(split_list(&value)),
                        "endpoint" => peer.endpoint = Some(value),
                        "persistentkeepalive" => {
                            peer.persistent_keepalive = Some(value.parse::<u32>().map_err(
                                |_| WgParseError::InvalidValue {
                                    key: "PersistentKeepalive",
                                    value,
                                },
                            )?);
                        }
                        _ => peer.extra.push((key.to_owned(), value)),
                    }
                }
            }
        }

        if !saw_interface {
            return Err(WgParseError::NoInterface);
        }
        Ok(cfg)
    }

    /// Рендерит канонический текст `.conf` (ключи в привычном порядке,
    /// известные ключи — CamelCase, секции разделены пустой строкой).
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("[Interface]\n");
        let i = &self.interface;
        if let Some(v) = &i.private_key {
            let _ = writeln!(out, "PrivateKey = {v}");
        }
        if !i.address.is_empty() {
            let _ = writeln!(out, "Address = {}", i.address.join(", "));
        }
        if !i.dns.is_empty() {
            let _ = writeln!(out, "DNS = {}", i.dns.join(", "));
        }
        if let Some(v) = i.listen_port {
            let _ = writeln!(out, "ListenPort = {v}");
        }
        if let Some(v) = &i.fwmark {
            let _ = writeln!(out, "Fwmark = {v}");
        }
        if let Some(v) = i.mtu {
            let _ = writeln!(out, "MTU = {v}");
        }
        for (k, v) in &i.extra {
            let _ = writeln!(out, "{k} = {v}");
        }
        for p in &self.peers {
            out.push_str("\n[Peer]\n");
            if let Some(v) = &p.public_key {
                let _ = writeln!(out, "PublicKey = {v}");
            }
            if let Some(v) = &p.preshared_key {
                let _ = writeln!(out, "PresharedKey = {v}");
            }
            if !p.allowed_ips.is_empty() {
                let _ = writeln!(out, "AllowedIPs = {}", p.allowed_ips.join(", "));
            }
            if let Some(v) = &p.endpoint {
                let _ = writeln!(out, "Endpoint = {v}");
            }
            if let Some(v) = p.persistent_keepalive {
                let _ = writeln!(out, "PersistentKeepalive = {v}");
            }
            for (k, v) in &p.extra {
                let _ = writeln!(out, "{k} = {v}");
            }
        }
        out
    }

    /// Применяет переопределения пользователя: `allowed_ips` подменяет
    /// `AllowedIPs` **всех** пиров, `dns` — `DNS` интерфейса.
    /// `socks_only` к WireGuard неприменим и игнорируется.
    #[must_use]
    pub fn with_overrides(&self, o: &Overrides) -> Self {
        let mut cfg = self.clone();
        if let Some(ips) = &o.allowed_ips {
            for peer in &mut cfg.peers {
                peer.allowed_ips.clone_from(ips);
            }
        }
        if let Some(dns) = &o.dns {
            cfg.interface.dns.clone_from(dns);
        }
        cfg
    }
}

/// Разбирает текст `.conf` (удобная обёртка над [`WgConfig::parse`]).
pub fn parse(input: &str) -> Result<WgConfig, WgParseError> {
    WgConfig::parse(input)
}

/// Рендер конфига с применёнными переопределениями:
/// `parse(config) → with_overrides → render` — то, что демон кладёт в
/// `tunnels\<id>.conf` для службы WireGuardTunnel$.
pub fn render_with_overrides(
    input: &str,
    overrides: &Overrides,
) -> Result<String, WgParseError> {
    Ok(parse(input)?.with_overrides(overrides).render())
}

/// Грубая эвристика «похоже ли на WireGuard .conf» (для автоопределения
/// вида импортируемого профиля).
#[must_use]
pub fn looks_like_wg_config(text: &str) -> bool {
    text.lines().any(|l| {
        let l = strip_comment(l).trim();
        l.eq_ignore_ascii_case("[interface]") || l.eq_ignore_ascii_case("[peer]")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Корпоративный WireGuard
[Interface]
PrivateKey = qOlQPykMFnw2a+gGtM4XTiqyh3V0AisTyzkyEWS2yWo= ; inline comment
Address = 10.7.0.5/32, fd00:7::5/128
DNS = 10.0.0.1
MTU = 1420
Table = off
; comment line
[Peer]
PublicKey = 6CjIw5tV3Zg+vR6m4F7Y4cVUXjVQ8eQzjDhX8k1c9Uo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
";

    #[test]
    fn parses_sample_with_comments_and_lists() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(
            cfg.interface.private_key.as_deref(),
            Some("qOlQPykMFnw2a+gGtM4XTiqyh3V0AisTyzkyEWS2yWo=")
        );
        assert_eq!(cfg.interface.address, ["10.7.0.5/32", "fd00:7::5/128"]);
        assert_eq!(cfg.interface.dns, ["10.0.0.1"]);
        assert_eq!(cfg.interface.mtu, Some(1420));
        assert_eq!(cfg.interface.extra, [("Table".to_owned(), "off".to_owned())]);
        assert_eq!(cfg.peers.len(), 1);
        let p = &cfg.peers[0];
        assert_eq!(p.endpoint.as_deref(), Some("vpn.example.com:51820"));
        assert_eq!(p.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(p.persistent_keepalive, Some(25));
        assert!(looks_like_wg_config(SAMPLE));
    }

    #[test]
    fn round_trip_render_parse() {
        let one = parse(SAMPLE).unwrap();
        let text = one.render();
        let two = parse(&text).unwrap();
        assert_eq!(one, two);
        // и повторно — стабильно
        assert_eq!(two.render(), text);
    }

    #[test]
    fn override_allowed_ips_and_dns() {
        let o = Overrides {
            allowed_ips: Some(vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()]),
            dns: Some(vec!["10.0.0.53".into()]),
            socks_only: false,
        };
        let cfg = parse(SAMPLE).unwrap().with_overrides(&o);
        assert_eq!(cfg.peers[0].allowed_ips, ["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(cfg.interface.dns, ["10.0.0.53"]);
        // ничего другого не трогаем
        assert_eq!(cfg.peers[0].endpoint.as_deref(), Some("vpn.example.com:51820"));

        let rendered = render_with_overrides(SAMPLE, &o).unwrap();
        assert!(rendered.contains("AllowedIPs = 10.0.0.0/8, 192.168.0.0/16"));
        assert!(rendered.contains("DNS = 10.0.0.53"));
        assert!(!rendered.contains("0.0.0.0/0"));
    }

    #[test]
    fn override_none_keeps_config() {
        let o = Overrides::default();
        let cfg = parse(SAMPLE).unwrap().with_overrides(&o);
        assert_eq!(cfg.peers[0].allowed_ips, ["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn malformed_inputs() {
        assert_eq!(parse("").unwrap_err(), WgParseError::NoInterface);
        assert_eq!(parse("   \n# только комментарии").unwrap_err(), WgParseError::NoInterface);
        // текст без '=' — ошибка строки (до проверки наличия [Interface])
        assert!(matches!(parse("Hello World"), Err(WgParseError::MalformedLine(_))));
        assert_eq!(
            parse("[Interface]\nPrivateKey = k\n[Interface]\nDNS = 1.1.1.1").unwrap_err(),
            WgParseError::DuplicateInterface
        );
        assert_eq!(
            parse("[Bogus]\nFoo = 1").unwrap_err(),
            WgParseError::UnknownSection("Bogus".to_owned())
        );
        // «Ключ» без «=» внутри секции
        assert!(matches!(
            parse("[Interface]\njusttext"),
            Err(WgParseError::MalformedLine(_))
        ));
        // строка ДО любой секции
        assert!(matches!(
            parse("PrivateKey = k\n[Interface]"),
            Err(WgParseError::LineOutsideSection(_))
        ));
        // нечисловой PersistentKeepalive
        assert!(matches!(
            parse("[Peer]\nPersistentKeepalive = often"),
            Err(WgParseError::InvalidValue { key: "PersistentKeepalive", .. })
        ));
        // ListenPort вне диапазона u16
        assert!(matches!(
            parse("[Interface]\nListenPort = 99999"),
            Err(WgParseError::InvalidValue { key: "ListenPort", .. })
        ));
        // пустое значение
        assert!(matches!(
            parse("[Interface]\nPrivateKey ="),
            Err(WgParseError::MalformedLine(_))
        ));
    }

    #[test]
    fn empty_peers_ok_and_multiple_peers_roundtrip() {
        let multi = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = a\nAllowedIPs = 10.0.0.0/8\n\n[Peer]\nPublicKey = b\nAllowedIPs = 10.1.0.0/16\nEndpoint = h:1\nPresharedKey = psk\n";
        let cfg = parse(multi).unwrap();
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(parse(&cfg.render()).unwrap(), cfg);
        // конфиг без пиров валиден для парсера
        assert!(parse("[Interface]\nPrivateKey = k\n").is_ok());
        assert!(!looks_like_wg_config("random text"));
    }
}
