//! 平台日志目录与初始化（等级、轮转、权限由 `df_core::logging` 实现）。
//!
//! 目录按各平台惯例放置，便于用户在自己的系统里找到日志：
//! - macOS：`~/Library/Logs/DeviceFabric`（Console.app「日志报告」可见）
//! - Linux：`$XDG_STATE_HOME/dfabric/logs`（缺省 `~/.local/state/dfabric/logs`）
//! - Windows：`%LOCALAPPDATA%\dfabric\logs`
//!
//! 日志**不记录** token、口令、私钥、bleKey 或配对导出内容。

use df_core::error::Result;
use df_core::logging::{self, Level};
use std::path::PathBuf;

/// 平台日志目录。
#[cfg(target_os = "macos")]
pub fn log_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/Logs/DeviceFabric")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn log_dir() -> PathBuf {
    dirs::state_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dfabric/logs")
}

#[cfg(windows)]
pub fn log_dir() -> PathBuf {
    crate::data_dir().join("logs")
}

/// 初始化日志。`level` 为 None 时用 Info。
pub fn init(level: Option<Level>, stderr: bool) -> Result<PathBuf> {
    logging::init(&log_dir(), level.unwrap_or(Level::Info), stderr)
}

/// 初始化日志，失败时降级为「只写 stderr」而不是让程序起不来。
pub fn init_or_stderr(level: Option<Level>, stderr: bool) -> Option<PathBuf> {
    match init(level, stderr) {
        Ok(p) => Some(p),
        Err(e) => {
            logging::set_stderr(true);
            logging::warn("logging", format!("日志文件初始化失败，仅输出到 stderr：{e}"));
            eprintln!("日志文件初始化失败（继续运行，仅输出到 stderr）: {e}");
            None
        }
    }
}

/// 从环境变量读取日志级别（`DFABRIC_LOG` / `RUST_LOG`）。
pub fn level_from_env() -> Option<Level> {
    ["DFABRIC_LOG", "RUST_LOG"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .and_then(|v| Level::parse(&v))
}
