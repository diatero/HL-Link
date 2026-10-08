//! 本地文件 I/O 要求（10.3 节）：
//! - 写入顺序永远是“私有暂存 → 校验 → 原子移动”；
//! - 持久化：Linux fsync（含目录）；macOS F_FULLFSYNC；Windows FlushFileBuffers（sync_all）。
//! - ACK 必须在持久化之后发出。

use crate::error::{DfError, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// 落盘单个文件句柄（数据 fsync / F_FULLFSYNC / FlushFileBuffers）。
pub fn sync_file(f: &mut File) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        sync_raw_fd(f.as_raw_fd())?;
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        f.sync_all()?;
        Ok(())
    }
}

/// 按 raw fd 落盘（供 tokio::fs::File 等 AsRawFd 使用）。
#[cfg(unix)]
pub fn sync_raw_fd(fd: std::os::unix::io::RawFd) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // macOS 的 fsync 不保证落盘，需要 F_FULLFSYNC
        let rc = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
        if rc != 0 {
            // 某些文件系统不支持，退回 fsync
            use std::os::unix::io::FromRawFd;
            let f = unsafe { std::mem::ManuallyDrop::new(File::from_raw_fd(fd)) };
            f.sync_all()?;
        }
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::io::FromRawFd;
        let f = unsafe { std::mem::ManuallyDrop::new(File::from_raw_fd(fd)) };
        f.sync_all()?;
        Ok(())
    }
}

/// fsync 目录（确保 rename 落盘）。Windows 无此概念，直接成功。
pub fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let d = std::fs::File::open(dir)?;
        d.sync_all()?;
    }
    Ok(())
}

/// 原子写入整个文件（临时文件 + fsync + rename + 目录 fsync）。
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        sync_file(&mut f)?;
    }
    std::fs::rename(&tmp, path)?;
    sync_dir(parent)?;
    Ok(())
}

/// 原子移动（校验完成后提交到可见位置）。
pub fn atomic_move(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(from, to)?;
    if let Some(parent) = to.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// 磁盘可用空间（字节）。预检按峰值（暂存 + 最终副本可能同时占两份）由调用方计算。
pub fn free_space(path: &Path) -> Result<u64> {
    fs4::available_space(path).map_err(|e| DfError::Io(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_move() {
        let dir = std::env::temp_dir().join("df-fsutil-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a/b.json");
        atomic_write(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        atomic_move(&p, &dir.join("b.txt")).unwrap();
        assert!(!p.exists());
        assert_eq!(std::fs::read(dir.join("b.txt")).unwrap(), b"hello");
        assert!(free_space(&dir).unwrap() > 0);
        // 无残留临时文件
        assert!(std::fs::read_dir(&dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.')));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
