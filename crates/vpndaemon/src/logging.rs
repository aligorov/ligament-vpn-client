//! Журналирование: tracing → файл (daily rolling, хранение 7 дней) +
//! рассылка каждой строки в UI как уведомление `log.entry`.
//!
//! Windows: `%PROGRAMDATA%\Ligament\CorpVPN\logs\corpvpnd.log.YYYY-MM-DD`,
//! иначе — `./corpvpnd-data/logs/` (разработка). Уведомления идут через
//! общий broadcast-канал демона (см. [`crate::rpc`]).

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::fmt::MakeWriter;

/// Строка журнала для `corpvpn.logs.tail` / `log.entry`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// unix epoch, секунды.
    pub ts: u64,
    /// Уровень, если удалось извлечь (INFO/WARN/ERROR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Полная отформатированная строка журнала.
    pub message: String,
}

/// Извлекает уровень из строки формата tracing (`… INFO module: msg`).
fn guess_level(line: &str) -> Option<String> {
    for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"] {
        if line.contains(&format!(" {level} ")) {
            return Some(level.to_owned());
        }
    }
    None
}

/// Writer, дублирующий события: в файл и (построчно) в broadcast-канал.
/// Файловый аппендер общий (Arc<Mutex>) — RollingFileAppender не Clone.
struct TeeWriter {
    file: Arc<std::sync::Mutex<RollingFileAppender>>,
    tx: broadcast::Sender<String>,
    buf: Vec<u8>,
}

impl TeeWriter {
    fn emit(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let line = String::from_utf8_lossy(&self.buf).trim_end().to_owned();
        self.buf.clear();
        if line.is_empty() {
            return;
        }
        let entry = LogEntry {
            ts: vpncore::model::now_epoch(),
            level: guess_level(&line),
            message: line,
        };
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "log.entry",
            "params": entry,
        });
        // нет подписчиков — не беда
        let _ = self.tx.send(frame.to_string());
    }
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        {
            let mut file = self
                .file
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            file.write(buf)?;
        }
        self.buf.extend_from_slice(buf);
        if buf.last() == Some(&b'\n') {
            self.emit();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.emit();
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.flush()
    }
}

impl Drop for TeeWriter {
    fn drop(&mut self) {
        self.emit();
    }
}

#[derive(Clone)]
struct TeeMakeWriter {
    file: Arc<std::sync::Mutex<RollingFileAppender>>,
    tx: broadcast::Sender<String>,
}

impl<'a> MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            file: Arc::clone(&self.file),
            tx: self.tx.clone(),
            buf: Vec::new(),
        }
    }
}

/// Инициализирует глобальный подписчик tracing.
/// Файл — daily rolling; строки дополнительно уходят в `events`.
pub fn init(logs_dir: &Path, events: broadcast::Sender<String>) {
    let _ = std::fs::create_dir_all(logs_dir);
    cleanup_old_logs(logs_dir, 7);

    let appender = tracing_appender::rolling::daily(logs_dir, "corpvpnd.log");
    let tee = TeeMakeWriter {
        file: Arc::new(std::sync::Mutex::new(appender)),
        tx: events,
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(tee)
        .with_ansi(false)
        .init();
}

/// Ротация: удаляет `corpvpnd.log.YYYY-MM-DD` старше `keep_days` дней.
pub fn cleanup_old_logs(dir: &Path, keep_days: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let prefix = "corpvpnd.log.";
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().saturating_sub(keep_days * 86_400));
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(date) = name.strip_prefix(prefix) else {
            continue;
        };
        if date.len() != 10 || !date.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let Ok(file_ts) = date_to_unix(date) else {
            continue;
        };
        if file_ts < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// YYYY-MM-DD → unix epoch (UTC, без часовых поясов — грубая оценка).
fn date_to_unix(date: &str) -> Result<u64, ()> {
    let mut parts = date.split('-');
    let year: i64 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let month: i64 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let day: i64 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(());
    }
    // дни от 1970-01-01: високосные годы учитываем упрощённо
    let leap_years = ((year - 1970) / 4).max(0);
    let days = (year - 1970) * 365 + leap_years + cum_days(month) + (day - 1);
    Ok((days * 86_400).max(0) as u64)
}

const MONTH_DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
fn cum_days(month: i64) -> i64 {
    MONTH_DAYS.get((month - 1) as usize).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tee_writer_broadcasts_lines() {
        let (tx, mut rx) = broadcast::channel(16);
        let dir = tempfile::tempdir().unwrap();
        let file = tracing_appender::rolling::never(dir.path(), "test.log");
        let mut w = TeeWriter {
            file: Arc::new(std::sync::Mutex::new(file)),
            tx,
            buf: Vec::new(),
        };
        w.write_all("2026-09-16 INFO corpvpnd: привет\n".as_bytes()).unwrap();
        let frame = rx.recv().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["method"], "log.entry");
        assert_eq!(v["params"]["level"], "INFO");
        assert!(v["params"]["message"].as_str().unwrap().contains("привет"));
    }

    #[test]
    fn cleanup_removes_only_old_logs() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("corpvpnd.log.2020-01-01");
        let now_name = format!(
            "corpvpnd.log.{}",
            chrono_like_today()
        );
        let now = dir.path().join(&now_name);
        let other = dir.path().join("corpvpnd.log");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&now, b"x").unwrap();
        std::fs::write(&other, b"x").unwrap();
        cleanup_old_logs(dir.path(), 7);
        assert!(!old.exists(), "старый журнал удалён");
        assert!(now.exists(), "свежий журнал остался");
        assert!(other.exists(), "текущий журнал не тронут");
    }

    fn chrono_like_today() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let days = secs / 86_400;
        // обратный пересчёт дней в дату (алгоритм Ховарда Хиннанта, упрощённо)
        let z = days as i64 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}")
    }

    #[test]
    fn date_to_unix_sanity() {
        assert_eq!(date_to_unix("1970-01-01"), Ok(0));
        assert!(date_to_unix("2026-09-16").unwrap() > 1_700_000_000);
        assert!(date_to_unix("garbage").is_err());
        assert!(date_to_unix("2026-13-40").is_err());
    }
}
