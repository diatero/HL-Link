//! 接收（从手机拉取）10.2 节：PULL_LIST → 用户接受 → PULL_ACCEPT → DATA_PULL_BIND →
//! 被动收块（每块校验 → 落盘 → fsync → 位图 → CHUNK_ACK）→ 校验整文件 → 原子提交 → PULL_COMPLETE。
//! 用户接受前不拉取任何字节。

use super::DataConn;
use crate::bitmap;
use crate::error::{DfError, Result};
use crate::msg::{new_request_id, Envelope, FileMeta};
use crate::session::ControlSession;
use crate::{fsutil, fields};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// PULL_LIST。
pub async fn pull_list(ctrl: &mut ControlSession) -> Result<crate::msg::PullList> {
    let env = ctrl
        .request("PULL_LIST", serde_json::json!({}), Duration::from_secs(15))
        .await?;
    if env.kind != "PULL_LIST_RESULT" {
        return Err(ControlSession::unexpected(&env.kind, "PULL_LIST_RESULT"));
    }
    let offers = env
        .body
        .get("offers")
        .and_then(|o| o.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|o| FileMeta::from_offer(o).ok().map(|meta| crate::msg::PullOffer { meta }))
                .collect()
        })
        .unwrap_or_default();
    let ended = env
        .body
        .get("ended")
        .and_then(|o| o.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|o| {
                    Some(crate::msg::EndedRecord {
                        transfer_id: fields::get_str(o, &["transferId"])?,
                        state: fields::get_str(o, &["state"]).unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(crate::msg::PullList { offers, ended })
}

/// 拒绝 = PULL_CANCEL。
pub async fn pull_cancel(ctrl: &mut ControlSession, transfer_id: &str) -> Result<()> {
    let env = ctrl
        .request(
            "PULL_CANCEL",
            serde_json::json!({ "transferId": transfer_id }),
            Duration::from_secs(15),
        )
        .await?;
    if env.kind != "PULL_CANCELLED" {
        return Err(ControlSession::unexpected(&env.kind, "PULL_CANCELLED"));
    }
    Ok(())
}

/// 完整接收一个 offer：
/// * `staging`：私有暂存文件（稀疏预分配由调用方完成）。
/// * `commit_to`：校验通过后的可见位置（原子移动）。
/// * `journal`：持久化位图回调（每块落盘 + fsync 之后调用；崩溃恢复用）。
/// * `on_progress`：进度回调（字节）。
#[allow(clippy::too_many_arguments)]
pub async fn pull_accept(
    ctrl: &mut ControlSession,
    config: Arc<rustls::ClientConfig>,
    session_id: &str,
    meta: &FileMeta,
    staging: &Path,
    commit_to: &Path,
    done: &mut BTreeSet<u64>,
    mut journal: Option<&mut (dyn FnMut(&BTreeSet<u64>) + Send)>,
    mut on_progress: Option<&mut (dyn FnMut(u64, u64) + Send)>,
) -> Result<()> {
    meta.validate()?;
    let total_chunks = meta.chunk_count();

    // 空间预检：暂存 + 最终副本峰值两份
    if let Some(parent) = staging.parent() {
        let need = meta.size.saturating_mul(2);
        if need > 0 {
            if let Ok(free) = fsutil::free_space(parent) {
                if free < need {
                    return Err(DfError::Protocol(format!(
                        "磁盘空间不足：需要约 {need} 字节，可用 {free} 字节"
                    )));
                }
            }
        }
    }

    // PULL_ACCEPT（haveBits 描述本地已持久化的块）
    let env = ctrl
        .request(
            "PULL_ACCEPT",
            serde_json::json!({
                "transferId": meta.transfer_id,
                "haveBits": bitmap::encode_bits(done),
            }),
            Duration::from_secs(30),
        )
        .await?;
    if env.kind != "PULL_READY" {
        return Err(ControlSession::unexpected(&env.kind, "PULL_READY"));
    }

    // PULL_READY 清单必须与 offer 完全一致；ticket 32 字节、120 秒内一次性
    for (k, a, b) in [
        ("transferId", fields::get_str(&env.body, &["transferId"]).unwrap_or_default(), meta.transfer_id.clone()),
        ("name", fields::get_str(&env.body, &["name"]).unwrap_or_default(), meta.name.clone()),
        ("mime", fields::get_str(&env.body, &["mime"]).unwrap_or_default(), meta.mime.clone()),
        ("sha256", fields::get_str(&env.body, &["sha256"]).unwrap_or_default(), meta.sha256.clone()),
    ] {
        if !a.is_empty() && a != b {
            return Err(DfError::Protocol(format!("PULL_READY {k} 与 offer 不一致: {a} != {b}")));
        }
    }
    for (k, a, b) in [
        ("size", fields::get_u64(&env.body, &["size"]).unwrap_or(meta.size), meta.size),
        ("chunkSize", fields::get_u64(&env.body, &["chunkSize"]).unwrap_or(meta.chunk_size), meta.chunk_size),
    ] {
        if a != b {
            return Err(DfError::Protocol(format!("PULL_READY {k} 与 offer 不一致: {a} != {b}")));
        }
    }
    let ticket = fields::need_str(&env.body, &["ticket"], "ticket")?;
    let ticket_bytes = crate::crypto::b64_decode(&ticket)?;
    if ticket_bytes.len() != 32 {
        return Err(DfError::Protocol(format!("ticket 不是 32 字节: {}", ticket_bytes.len())));
    }
    let data_port = ControlSession::data_port_from(&env.body)?;

    // 数据连接：DATA_PULL_BIND，之后没有 DATA_READY，对方直接按升序发缺失块
    let mut data = DataConn::connect(ctrl.peer_addr, data_port, config).await?;
    let bind_rid = new_request_id();
    data.send_json(&Envelope::new(
        "DATA_PULL_BIND",
        &bind_rid,
        serde_json::json!({
            "sessionId": session_id,
            "transferId": meta.transfer_id,
            "direction": "download",
            "ticket": ticket,
        }),
    ))
    .await?;

    // 打开暂存文件（随机写）
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(staging)
        .await?;
    file.set_len(meta.size).await?;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    let chunk_size = meta.chunk_size as usize;

    loop {
        // 数据读超时 30 秒
        match data.next_event_timeout(Duration::from_secs(30)).await? {
            super::DataEvent::Chunk { index, data: chunk } => {
                // 校验：索引范围、长度、块哈希（哈希已在 DataConn 内校验）
                if index >= total_chunks {
                    return Err(DfError::Protocol(format!("块索引越界: {index}/{total_chunks}")));
                }
                let expected_len = if index == total_chunks - 1 {
                    (meta.size - index * meta.chunk_size) as usize
                } else {
                    chunk_size
                };
                if chunk.len() != expected_len {
                    return Err(DfError::Protocol(format!(
                        "块 {index} 长度不符: 期望 {expected_len}, 收到 {}",
                        chunk.len()
                    )));
                }
                // 写到绝对偏移 → fsync 数据
                file.seek(std::io::SeekFrom::Start(index * meta.chunk_size)).await?;
                file.write_all(&chunk).await?;
                file.flush().await?;
                sync_staging(&file).await?;
                // 原子保存位图日志，然后才 ACK
                done.insert(index);
                if let Some(j) = journal.as_mut() {
                    j(done);
                }
                data.send_json(&Envelope::new(
                    "CHUNK_ACK",
                    &bind_rid, // requestId 与 bind 相同
                    serde_json::json!({ "chunkIndex": index }),
                ))
                .await?;
                if let Some(p) = on_progress.as_mut() {
                    let done_bytes = ((index + 1) * meta.chunk_size).min(meta.size);
                    p(done_bytes, meta.size);
                }
            }
            super::DataEvent::Error(e) => return Err(DfError::Remote { code: e.code, retryable: e.retryable }),
            super::DataEvent::Closed => break,
            other => return Err(DfError::Protocol(format!("下载通道收到意外帧: {other:?}"))),
        }
    }

    // 校验整文件长度与 SHA-256
    drop(file);
    let staged_len = tokio::fs::metadata(staging).await?.len();
    if staged_len != meta.size {
        return Err(DfError::Protocol(format!(
            "整文件长度不符: 期望 {}, 实际 {staged_len}",
            meta.size
        )));
    }
    let whole = tokio::fs::read(staging).await?;
    let whole_hash = hex::encode(crate::crypto::sha256(&whole));
    drop(whole);
    if whole_hash != meta.sha256 {
        return Err(DfError::Protocol(format!(
            "整文件 SHA-256 不符: 期望 {}, 实际 {whole_hash}",
            meta.sha256
        )));
    }

    // 原子提交到收件位置
    fsutil::atomic_move(staging, commit_to)?;

    // PULL_COMPLETE → PULL_COMPLETED
    let env = ctrl
        .request(
            "PULL_COMPLETE",
            serde_json::json!({
                "transferId": meta.transfer_id,
                "size": fields::dec(meta.size),
                "sha256": meta.sha256,
            }),
            Duration::from_secs(30),
        )
        .await?;
    if env.kind != "PULL_COMPLETED" {
        return Err(ControlSession::unexpected(&env.kind, "PULL_COMPLETED"));
    }
    Ok(())
}

/// 暂存块落盘：unix 走 fsync（macOS F_FULLFSYNC），Windows 走 `sync_all`。
/// 必须先把 `std::os::unix` 隔在这里，否则非 unix 目标无法编译。
#[allow(unused_variables)]
async fn sync_staging(file: &tokio::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        fsutil::sync_raw_fd(file.as_raw_fd())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        file.sync_all().await?;
        Ok(())
    }
}

/// 生成收件位置（不覆盖已有文件）。
pub fn commit_path(inbox: &Path, meta: &FileMeta) -> PathBuf {
    inbox.join(crate::names::unique_filename(inbox, &meta.name))
}

#[allow(dead_code)]
fn _unused(_: PathBuf) {}
