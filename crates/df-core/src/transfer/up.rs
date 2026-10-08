//! 发送（上传到手机）10.1 节：FILE_OFFER → ACCEPT → DATA_BIND → 块（窗口 1）→ COMPLETE。
//! 中断恢复：同一 transferId 与相同元数据发 RESUME / FILE_OFFER，按 haveBits 只补缺块。

use super::DataConn;
use crate::bitmap;
use crate::error::{DfError, Result};
use crate::msg::{new_request_id, Envelope, FileMeta};
use crate::session::ControlSession;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub enum Outcome {
    /// 正常完成（节点已保存）。
    Completed { uri: Option<String> },
    /// FILE_OFFER 返回 COMPLETE：之前已经完成（幂等）。
    AlreadyCompleted,
}

/// 上传一个已暂存的文件。
///
/// * `config`：与控制会话相同的 mTLS 客户端配置。
/// * `session_id`：HELLO_ACK 返回的 sessionId（DATA_BIND 需要）。
/// * `done`：本地已确认持久化的块集合（跨重启恢复）。
/// * `on_progress(done_bytes, total)`：可选进度回调。
/// * `persist_done(chunk_index)`：CHUNK_ACK 到达后调用（调用方持久化任务位图）。
#[allow(clippy::too_many_arguments)]
pub async fn upload(
    ctrl: &mut ControlSession,
    config: Arc<rustls::ClientConfig>,
    session_id: &str,
    meta: &FileMeta,
    staged: &Path,
    done: &mut BTreeSet<u64>,
    mut on_progress: Option<&mut (dyn FnMut(u64, u64) + Send)>,
    mut persist_done: Option<&mut (dyn FnMut(&BTreeSet<u64>) + Send)>,
) -> Result<Outcome> {
    meta.validate()?;
    let total_chunks = meta.chunk_count();

    // FILE_OFFER（首次）—— RESUME 也走同一入口（响应语义相同）
    let env = ctrl
        .request("FILE_OFFER", meta.offer_body(), Duration::from_secs(120))
        .await?;
    match env.kind.as_str() {
        "COMPLETE" => return Ok(Outcome::AlreadyCompleted),
        "ACCEPT" => {}
        other => return Err(ControlSession::unexpected(other, "ACCEPT/COMPLETE")),
    }

    let ticket = crate::fields::need_str(&env.body, &["ticket"], "ticket")?;
    let data_port = ControlSession::data_port_from(&env.body)?;
    let have = bitmap::decode_bits(
        &crate::fields::get_str(&env.body, &["haveBits"]).unwrap_or_default(),
        total_chunks,
    )?;
    done.extend(have);

    // 数据连接：mTLS + DATA_BIND（ticket 60 秒内一次性；控制连接必须保持）
    let mut data = DataConn::connect(ctrl.peer_addr, data_port, config).await?;
    let bind_rid = new_request_id();
    data.send_json(&Envelope::new(
        "DATA_BIND",
        &bind_rid,
        serde_json::json!({
            "sessionId": session_id,
            "transferId": meta.transfer_id,
            "ticket": ticket,
            "direction": "upload",
        }),
    ))
    .await?;

    // 等 DATA_READY
    match data.next_event_timeout(Duration::from_secs(30)).await? {
        super::DataEvent::Ready => {}
        super::DataEvent::Error(e) => return Err(DfError::Remote { code: e.code, retryable: e.retryable }),
        other => return Err(DfError::Protocol(format!("期望 DATA_READY，收到 {other:?}"))),
    }

    // 逐块发送（窗口 1：每发一块等 CHUNK_ACK）；跳过已有块；空文件不发块
    let chunk_size = meta.chunk_size as usize;
    for index in 0..total_chunks {
        if done.contains(&index) {
            continue;
        }
        let offset = index * meta.chunk_size;
        let len = ((meta.size - offset) as usize).min(chunk_size);
        let chunk = super::read_chunk_at(staged, offset, len).await?;
        if chunk.len() != len {
            return Err(DfError::Protocol(format!("暂存文件变短：期望块 {index} 有 {len} 字节")));
        }
        data.write_chunk(index, &chunk).await?;
        match data.next_event_timeout(Duration::from_secs(30)).await? {
            super::DataEvent::Ack { chunk_index, .. } => {
                if chunk_index != index {
                    return Err(DfError::Protocol(format!(
                        "CHUNK_ACK 序号不匹配: 期望 {index}, 收到 {chunk_index}"
                    )));
                }
                if let Some(p) = persist_done.as_mut() {
                    p(done);
                }
                if let Some(p) = on_progress.as_mut() {
                    let done_bytes = ((index + 1) * meta.chunk_size).min(meta.size);
                    p(done_bytes, meta.size);
                }
            }
            super::DataEvent::Error(e) => return Err(DfError::Remote { code: e.code, retryable: e.retryable }),
            other => return Err(DfError::Protocol(format!("期望 CHUNK_ACK，收到 {other:?}"))),
        }
    }

    // COMPLETE 在数据连接上返回
    let complete = match data.next_event_timeout(Duration::from_secs(30)).await? {
        super::DataEvent::Complete(v) => v,
        super::DataEvent::Error(e) => return Err(DfError::Remote { code: e.code, retryable: e.retryable }),
        other => return Err(DfError::Protocol(format!("期望 COMPLETE，收到 {other:?}"))),
    };
    data.shutdown().await;

    // 校验回执与元数据一致
    let back_id = crate::fields::get_str(&complete, &["transferId"]).unwrap_or_default();
    if !back_id.is_empty() && back_id != meta.transfer_id {
        return Err(DfError::Protocol("COMPLETE transferId 不匹配".into()));
    }
    Ok(Outcome::Completed { uri: crate::fields::get_str(&complete, &["uri"]) })
}

/// 用户取消：发 CANCEL，同时关闭数据连接。若手机已提交，响应为 COMPLETE 状态，以此为准。
pub async fn cancel(ctrl: &mut ControlSession, transfer_id: &str) -> Result<bool> {
    let env = ctrl
        .request(
            "CANCEL",
            serde_json::json!({ "transferId": transfer_id }),
            Duration::from_secs(15),
        )
        .await?;
    Ok(matches!(env.kind.as_str(), "CANCELLED" | "COMPLETE"))
}

/// 发送文本（UTF-8 ≤ 49152 字节且整帧 ≤ 65536）。
pub async fn send_text(ctrl: &mut ControlSession, transfer_id: &str, text: &str) -> Result<()> {
    if text.len() > crate::consts::MAX_TEXT {
        return Err(DfError::Protocol(format!(
            "文本超过 {} 字节上限（更长的文本请作为 .txt 文件发送）",
            crate::consts::MAX_TEXT
        )));
    }
    let env = ctrl
        .request(
            "TEXT_OFFER",
            serde_json::json!({ "transferId": transfer_id, "text": text }),
            Duration::from_secs(120),
        )
        .await?;
    if env.kind != "COMPLETE" {
        return Err(ControlSession::unexpected(&env.kind, "COMPLETE"));
    }
    Ok(())
}
