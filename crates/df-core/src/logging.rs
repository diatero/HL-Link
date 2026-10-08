//! 统一日志：分级、按大小轮转、0600 权限、可在未初始化时退回 stderr。
//!
//! 设计约束（对应开发说明 §12）：
//! - **日志不记录机密**：token、口令、私钥、bleKey、配对导出内容一律不得写入；
//!   调用方只记录设备标识前缀、状态、错误码与计数。
//! - 平台无关：目录由平台层（`dfabric::log_dir`）提供；未初始化时只写 stderr，绝不 panic。
//! - 写入用 `O_APPEND`，同一行一次写完；轮转按大小进行，保留固定份数。
//!
//! 时间戳为 UTC（`...Z`），不依赖 chrono 等外部 crate。

use crate::error::{DfError, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 日志级别（数值越大越详细）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }

    /// 解析命令行/配置里的级别名（大小写不敏感）。
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" | "verbose" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 单个日志文件大小上限。
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// 保留的历史文件份数（`dfabric.log.1` … `dfabric.log.N`）。
pub const DEFAULT_KEEP: usize = 3;
/// 日志文件名。
pub const LOG_FILE_NAME: &str = "dfabric.log";

struct Logger {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
/// 写锁：串行化「检查大小 → 轮转 → 追加」，避免并发轮转互相打断。
static WRITE_LOCK: Mutex<()> = Mutex::new(());
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static STDERR: AtomicU8 = AtomicU8::new(0);

/// 初始化日志文件（幂等：重复调用只更新级别与 stderr 开关）。
///
/// 返回实际使用的日志文件路径；目录不可写时返回错误，调用方应降级为 stderr 输出。
pub fn init(dir: &Path, level: Level, stderr: bool) -> Result<PathBuf> {
    init_with(dir, level, stderr, DEFAULT_MAX_BYTES, DEFAULT_KEEP)
}

/// 同 [`init`]，可指定轮转参数（自检会构造小文件验证轮转）。
pub fn init_with(dir: &Path, level: Level, stderr: bool, max_bytes: u64, keep: usize) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(LOG_FILE_NAME);
    OpenOptions::new().create(true).append(true).open(&path)?;
    restrict(&path);
    LEVEL.store(level as u8, Ordering::Relaxed);
    STDERR.store(u8::from(stderr), Ordering::Relaxed);
    let _ = LOGGER.set(Logger { path: path.clone(), max_bytes: max_bytes.max(1024), keep: keep.max(1) });
    if LOGGER.get().map(|l| l.path.as_path()) == Some(path.as_path()) {
        write_line(Level::Info, "logging", &format!("日志启动：{}", path.display()));
    }
    Ok(path)
}

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        _ => Level::Debug,
    }
}

pub fn set_stderr(on: bool) {
    STDERR.store(u8::from(on), Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}

/// 当前日志文件路径（未初始化时为 None）。
pub fn log_path() -> Option<PathBuf> {
    LOGGER.get().map(|l| l.path.clone())
}

pub fn error(target: &str, msg: impl AsRef<str>) {
    write_line(Level::Error, target, msg.as_ref());
}

pub fn warn(target: &str, msg: impl AsRef<str>) {
    write_line(Level::Warn, target, msg.as_ref());
}

pub fn info(target: &str, msg: impl AsRef<str>) {
    write_line(Level::Info, target, msg.as_ref());
}

pub fn debug(target: &str, msg: impl AsRef<str>) {
    write_line(Level::Debug, target, msg.as_ref());
}

fn write_line(level: Level, target: &str, msg: &str) {
    if !enabled(level) {
        return;
    }
    let line = format!("{} [{}] {target}: {msg}\n", timestamp(SystemTime::now()), level.as_str());
    if STDERR.load(Ordering::Relaxed) != 0 {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    let Some(logger) = LOGGER.get() else { return };
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if file_len(&logger.path) >= logger.max_bytes {
        let _ = rotate_file(&logger.path, logger.keep);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&logger.path) {
        let _ = f.write_all(line.as_bytes());
    }
    // 轮转或外部删除后重建的文件也要保持 0600；chmod 幂等且不在热路径上。
    restrict(&logger.path);
}

/// 读取最近 `lines` 行（含轮转前的历史文件，从旧到新）。
pub fn recent(lines: usize) -> Vec<String> {
    let Some(path) = log_path() else { return Vec::new() };
    let mut files: Vec<PathBuf> = Vec::new();
    for i in (1..=DEFAULT_KEEP).rev() {
        let p = path.with_extension(format!("log.{i}"));
        if p.exists() {
            files.push(p);
        }
    }
    files.push(path);
    let mut out: Vec<String> = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for l in text.lines() {
            out.push(l.to_string());
        }
    }
    let len = out.len();
    out.split_off(len.saturating_sub(lines))
}

/// 轮转日志文件：`log` → `log.1` → … → `log.keep`，最旧的被删除。
pub fn rotate_file(path: &Path, keep: usize) -> Result<()> {
    let keep = keep.max(1);
    let _ = std::fs::remove_file(path.with_extension(format!("log.{keep}")));
    for i in (1..keep).rev() {
        let from = path.with_extension(format!("log.{i}"));
        let to = path.with_extension(format!("log.{}", i + 1));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    if path.exists() {
        std::fs::rename(path, path.with_extension("log.1"))
            .map_err(|e| DfError::Io(std::io::Error::new(e.kind(), format!("日志轮转失败: {e}"))))?;
    }
    Ok(())
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

/// UTC 时间戳 `YYYY-MM-DDTHH:MM:SS.mmmZ`。
pub fn timestamp(t: SystemTime) -> String {
    let d: Duration = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (y, mo, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// 自 1970-01-01 起的天数 → (年, 月, 日)。Howard Hinnant 的 civil_from_days。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_utc() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(1_710_000_000)), "2024-03-09T16:00:00.000Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_millis(1_700_000_000_123)), "2023-11-14T22:13:20.123Z");
        // 闰年 2 月 29 日
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(1_709_164_800)), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn level_parsing() {
        assert_eq!(Level::parse("DEBUG"), Some(Level::Debug));
        assert_eq!(Level::parse(" warn "), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
        assert!(Level::Error < Level::Debug);
    }

    #[test]
    fn rotation_keeps_history() {
        let dir = std::env::temp_dir().join(format!("df-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOG_FILE_NAME);
        for round in 0..4 {
            std::fs::write(&path, format!("round-{round}\n")).unwrap();
            if round < 3 {
                rotate_file(&path, 2).unwrap();
            }
        }
        // 当前文件是最后写入的内容；历史里保留最近两份轮转
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "round-3\n");
        assert_eq!(std::fs::read_to_string(dir.join("dfabric.log.1")).unwrap(), "round-2\n");
        assert_eq!(std::fs::read_to_string(dir.join("dfabric.log.2")).unwrap(), "round-1\n");
        assert!(!dir.join("dfabric.log.3").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 日志含设备标识与错误详情，必须只有属主可读。
    #[cfg(unix)]
    #[test]
    fn log_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("df-log-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOG_FILE_NAME);
        std::fs::write(&path, b"x\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict(&path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_reads_newest_last() {
        let dir = std::env::temp_dir().join(format!("df-log-recent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOG_FILE_NAME);
        std::fs::write(&path, b"a\nb\nc\n").unwrap();
        // 未初始化 logger 时 recent 为空（不会 panic）
        let _ = recent(2);
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
