//! GATT 传输抽象与 BLE 分片（6.1 节）。
//!
//! 每个 ATT 值：`uint16 BE messageId | uint16 BE fragmentIndex | uint16 BE total | payload`，
//! payload ≤ ATT_MTU − 9（保守按 MTU 23：14 字节）。节点拒绝 prepared/long write，
//! 因此每次写入都必须单片放得下。

use crate::error::{DfError, Result};
use async_trait::async_trait;

/// 消息体上限。
pub const MAX_MESSAGE: usize = 16384;
/// 片数上限（含）。
pub const MAX_FRAGMENTS: u16 = 2048;

/// 平台 BLE 中心设备的传输抽象（agent 侧用 btleplug 实现）。
#[async_trait]
pub trait GattLink: Send {
    /// 发送一条完整消息（自动分片，逐片 write with response）。
    async fn send_message(&mut self, msg: &[u8]) -> Result<()>;
    /// 接收下一条完整消息（内部完成重组）。
    async fn recv_message(&mut self) -> Result<Vec<u8>>;
}

/// 计算给定 ATT MTU 下每片 payload 上限。
pub fn payload_len_for_mtu(mtu: u16) -> u16 {
    // ATT 值 ≤ MTU-3，头部 6 字节 → payload ≤ MTU-9
    (mtu.saturating_sub(9)).max(1)
}

/// 把一条消息切成 ATT 值序列。
pub fn fragment(message: &[u8], payload_len: u16) -> Result<Vec<Vec<u8>>> {
    if message.is_empty() || message.len() > MAX_MESSAGE {
        return Err(DfError::Protocol(format!("BLE 消息长度越界: {}", message.len())));
    }
    let pl = payload_len.max(1) as usize;
    let total = message.len().div_ceil(pl) as u16;
    if total > MAX_FRAGMENTS {
        return Err(DfError::Protocol(format!("BLE 片数越界: {total}")));
    }
    let mut out = Vec::with_capacity(total as usize);
    for (idx, chunk) in message.chunks(pl).enumerate() {
        let mut att = Vec::with_capacity(6 + chunk.len());
        att.extend_from_slice(&1u16.to_be_bytes()); // messageId（单消息串行，固定 1）
        att.extend_from_slice(&(idx as u16).to_be_bytes());
        att.extend_from_slice(&total.to_be_bytes());
        att.extend_from_slice(chunk);
        out.push(att);
    }
    Ok(out)
}

/// 分片重组器（喂入收到的 ATT 值，吐出完整消息）。
#[derive(Default)]
pub struct Reassembler {
    current: Option<Partial>,
    done: Vec<u8>,
}

struct Partial {
    message_id: u16,
    total: u16,
    next_index: u16,
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler { current: None, done: Vec::new() }
    }

    /// 喂入一个 ATT 值；返回 Some(消息) 表示一条完整消息就绪。
    pub fn feed(&mut self, att: &[u8]) -> Result<Option<Vec<u8>>> {
        if att.len() < 7 {
            return Err(DfError::Protocol("BLE 片过短（< 头 6 字节 + 1 载荷）".into()));
        }
        let message_id = u16::from_be_bytes([att[0], att[1]]);
        let index = u16::from_be_bytes([att[2], att[3]]);
        let total = u16::from_be_bytes([att[4], att[5]]);
        let payload = &att[6..];
        if total == 0 || total > MAX_FRAGMENTS {
            return Err(DfError::Protocol(format!("BLE total 越界: {total}")));
        }

        match &self.current {
            Some(p) if p.message_id != message_id => {
                return Err(DfError::Protocol("BLE 消息中途出现新 messageId".into()));
            }
            Some(p) if p.total != total => {
                return Err(DfError::Protocol("BLE total 不一致".into()));
            }
            _ => {}
        }

        if index == 0 {
            if self.current.is_some() {
                return Err(DfError::Protocol("BLE 上一条消息未完成就开始新消息".into()));
            }
            if payload.len() + 6 > MAX_MESSAGE {
                return Err(DfError::Protocol("BLE 消息超长".into()));
            }
            self.current = Some(Partial { message_id, total, next_index: 1, buf: payload.to_vec() });
        } else {
            let p = match &mut self.current {
                Some(p) => p,
                None => return Err(DfError::Protocol("BLE 中间片先于首片到达".into())),
            };
            if index != p.next_index {
                return Err(DfError::Protocol(format!(
                    "BLE 片乱序/重复: 期望 {}, 收到 {}",
                    p.next_index, index
                )));
            }
            if p.buf.len() + payload.len() > MAX_MESSAGE {
                return Err(DfError::Protocol("BLE 消息超长".into()));
            }
            p.buf.extend_from_slice(payload);
            p.next_index = index + 1;
        }

        let complete = match &self.current {
            Some(p) if p.next_index >= p.total => Some(p.buf.clone()),
            _ => None,
        };
        if let Some(msg) = complete {
            self.current = None;
            self.done = msg;
            return Ok(Some(std::mem::take(&mut self.done)));
        }
        Ok(None)
    }
}

/// 平台适配层（agent）为 btleplug 外设实现本 trait；
/// 构造时可参考 fragment/reassembler 组合。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_shapes() {
        let msg = vec![7u8; 40];
        let frags = fragment(&msg, 14).unwrap();
        assert_eq!(frags.len(), 3);
        assert_eq!(u16::from_be_bytes([frags[0][4], frags[0][5]]), 3);
        assert_eq!(frags[0].len(), 6 + 14);
        assert_eq!(frags[2].len(), 6 + 12);
        // MTU 23 → 14 字节 payload
        assert_eq!(payload_len_for_mtu(23), 14);
        assert_eq!(payload_len_for_mtu(517), 508);
    }

    #[test]
    fn reassembly_order_and_gaps() {
        let msg: Vec<u8> = (0..100u8).collect();
        let frags = fragment(&msg, 20).unwrap();
        assert_eq!(frags.len(), 5);
        let mut r = Reassembler::new();
        assert!(r.feed(&frags[0]).unwrap().is_none());
        assert!(r.feed(&frags[1]).unwrap().is_none());
        assert!(r.feed(&frags[2]).unwrap().is_none());
        assert!(r.feed(&frags[3]).unwrap().is_none());
        assert_eq!(r.feed(&frags[4]).unwrap().unwrap(), msg);
        // 乱序（出错后状态保留，连接应按协议重建）
        assert!(r.feed(&frags[0]).unwrap().is_none());
        assert!(r.feed(&frags[2]).is_err());
        // 重复首片（新重组器：消息未完成时再次收到首片应报错）
        let mut r2 = Reassembler::new();
        assert!(r2.feed(&frags[0]).unwrap().is_none());
        assert!(r2.feed(&frags[0]).is_err());
        // 空消息
        assert!(fragment(b"", 14).is_err());
        // 超长
        assert!(fragment(&vec![0u8; MAX_MESSAGE + 1], 508).is_err());
    }
}
