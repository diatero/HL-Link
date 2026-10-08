//! DeviceFabric 桌面端（Linux / macOS / Windows）。
//!
//! 结构与开发说明一致：协议核心在 `df-core`；本 crate 是平台适配层与
//! CLI/Agent（UI 进程通过 IPC 与 Agent 交接任务，入口进程退出不影响队列）。

pub mod agent;
pub mod ble;
pub mod logging;
pub mod mdns;
pub mod secrets;
pub mod selfcheck;
pub mod wifi;

use df_core::error::{DfError, Result};
use df_core::msg::FileMeta;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 应用数据目录（`$XDG_DATA_HOME/dfabric` / `%LOCALAPPDATA%\dfabric` / `~/Library/Application Support/dfabric`）。
pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dfabric")
}

pub fn open_store() -> Result<df_core::stores::Store> {
    df_core::stores::Store::open(&data_dir())
}

/// MIME 猜测（常见类型；其余 application/octet-stream）。
pub fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" | "log" => "text/plain",
        "csv" => "text/csv",
        "html" => "text/html",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "apk" => "application/vnd.android.package-archive",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// 准备阶段（10.1 第 1 步）：把源文件复制到私有暂存区，复制时计算 SHA-256 与大小。
/// 暂存后任务与源文件解耦；返回 (元数据, 暂存路径)。
pub fn stage_file(store: &df_core::stores::Store, src: &Path) -> Result<(FileMeta, PathBuf)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| DfError::Protocol("源文件名不是 UTF-8".into()))?;
    if name.chars().count() > 128 {
        return Err(DfError::Protocol("文件名超过 128 字符".into()));
    }
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let staging_dir = store.staging_dir();
    std::fs::create_dir_all(&staging_dir)?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let staged = staging_dir.join(&transfer_id);
    let mut out = std::fs::File::create(&staged)?;
    let mut in_file = std::fs::File::open(src)?;
    let mut buf = vec![0u8; 1024 * 512];
    loop {
        let n = in_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
        std::io::Write::write_all(&mut out, &buf[..n])?;
    }
    df_core::fsutil::sync_file(&mut out)?;
    drop(out);

    if size > df_core::consts::MAX_FILE_SIZE {
        let _ = std::fs::remove_file(&staged);
        return Err(DfError::Protocol("文件超过 16 GiB 上限".into()));
    }
    let meta = FileMeta {
        transfer_id,
        name: name.to_string(),
        mime: guess_mime(name),
        size,
        chunk_size: df_core::consts::CHUNK_SIZE,
        sha256: hex::encode(hasher.finalize()),
    };
    Ok((meta, staged))
}

/// LAN 候选地址选择（8.1 节）：mDNS 新近候选 → 上次成功地址；最多试 4 个，每个 TLS 超时约 2 秒。
pub async fn lan_candidates(
    mdns: &mdns::MdnsBrowser,
    trust: &df_core::stores::Trust,
) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    for addr in mdns.snapshot().await {
        if let Ok(ip) = addr.parse() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    if let Some(last) = &trust.last_addr {
        if let Ok(ip) = last.parse() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out.truncate(4);
    out
}

/// 连接并 HELLO（核对 nodeId）。返回会话。
pub async fn connect_trust(
    trust: &df_core::stores::Trust,
    display_name: Option<&str>,
    mdns: &mdns::MdnsBrowser,
) -> Result<df_core::session::ControlSession> {
    df_core::tls::ensure_provider();
    let config = df_core::tls::client_config(&trust.ca_pem, &trust.cert_pem, &trust.key_pem)?;
    let candidates = lan_candidates(mdns, trust).await;
    if candidates.is_empty() {
        df_core::logging::warn(
            "connect",
            format!("设备 {}… 没有可用候选地址（mDNS 未发现且无上次地址）", &trust.node_id[..12.min(trust.node_id.len())]),
        );
        return Err(DfError::NotConnected);
    }
    df_core::logging::debug("connect", format!("候选地址 {candidates:?}"));
    let mut last_err = DfError::NotConnected;
    for ip in candidates {
        match df_core::session::ControlSession::connect(
            ip,
            if trust.control_port == 0 { df_core::consts::DEFAULT_CONTROL_PORT } else { trust.control_port },
            config.clone(),
            Duration::from_secs(2),
        )
        .await
        {
            Ok(mut s) => match s.hello(&client_id_of(trust), display_name).await {
                Ok(ack) => {
                    if ack.node_id != trust.node_id {
                        return Err(DfError::Protocol(format!(
                            "HELLO_ACK nodeId 不匹配: {} != {}",
                            ack.node_id, trust.node_id
                        )));
                    }
                    return Ok(s);
                }
                Err(e) => last_err = e,
            },
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn client_id_of(_trust: &df_core::stores::Trust) -> String {
    open_store().map(|s| s.client_id()).unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
}

/// 本机显示名称（用户设置 → 系统名称）。
pub fn display_name(store: &df_core::stores::Store) -> String {
    store
        .local_name()
        .unwrap_or_else(df_core::names::default_device_name)
}

/// 平台通知（尽力而为）。
pub fn notify(title: &str, body: &str) {
    df_core::logging::info("notify", format!("{title}: {body}"));
    println!("[通知] {title}: {body}");
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send").arg(title).arg(body).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!("display notification \"{}\" with title \"{}\"", body.replace('"', "'"), title.replace('"', "'"));
        let _ = std::process::Command::new("osascript").args(["-e", &script]).spawn();
    }
}

/// 根据前缀匹配已信任节点（CLI 友好）。
pub fn find_trust(store: &df_core::stores::Store, prefix: &str) -> Option<df_core::stores::Trust> {
    let list = store.trusts();
    if let Some(t) = list.iter().find(|t| t.node_id == prefix) {
        return Some(t.clone());
    }
    let matches: Vec<_> = list.iter().filter(|t| t.node_id.starts_with(prefix)).collect();
    if matches.len() == 1 {
        Some(matches[0].clone())
    } else {
        None
    }
}

/// 挑选唯一可用的信任节点（只有一个时免指定 --to）。
pub fn pick_trust(store: &df_core::stores::Store, to: Option<&str>) -> Result<df_core::stores::Trust> {
    let list: Vec<_> = store.trusts().into_iter().filter(|t| !t.revoked).collect();
    if let Some(prefix) = to {
        return find_trust(store, prefix).ok_or_else(|| DfError::Protocol(format!("没有匹配的信任设备: {prefix}")));
    }
    match list.len() {
        1 => Ok(list[0].clone()),
        0 => Err(DfError::Protocol("尚未配对任何设备，请先运行 dfctl pair".into())),
        n => Err(DfError::Protocol(format!("有 {n} 台已配对设备，请用 --to <nodeId前缀> 指定"))),
    }
}
