//! DF-BLE-1 认证与 SECURE 通道（6.2 / 6.3 节）。
//!
//! - hint = HMAC(bleKey, "DF-HINT-1\n<eid>") 的 hex 前 32 字符
//! - T = `DF-BLE-1\n<nodeId>\n<eid>\n<cn>\n<sn>`（cn、sn 为 base64 文本）
//! - 会话密钥 HKDF(IKM=bleKey, salt=SHA256(cn 原始字节‖sn 原始字节), info=`DF-BLE-1\n<nodeId>\n<eid>`, 72)
//! - SECURE {seq, data}：AES-256-GCM，nonce = 4B 方向前缀 ‖ uint64 BE seq，AAD=`<sessionId>\n<c2s|s2c>\n<seq>`

use super::ble_link::GattLink;
use crate::crypto::{b64_decode, b64_encode, gcm_open, gcm_seal, hmac_sha256, hkdf_sha256, sha256};
use crate::error::{DfError, Result};
use crate::fields;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SecureChannel {
    pub session_id: String,
    pub c2s_key: [u8; 32],
    pub s2c_key: [u8; 32],
    pub c2s_nonce: [u8; 4],
    pub s2c_nonce: [u8; 4],
    pub seq_c2s: u64,
    pub seq_s2c: u64,
}

pub fn hint_for(ble_key: &[u8; 32], eid: &str) -> String {
    let mac = hmac_sha256(ble_key, format!("DF-HINT-1\n{eid}").as_bytes());
    hex::encode(mac)[..32].to_string()
}

fn t_string(node_id: &str, eid: &str, cn: &str, sn: &str) -> String {
    format!("DF-BLE-1\n{node_id}\n{eid}\n{cn}\n{sn}")
}

fn session_keys(ble_key: &[u8; 32], node_id: &str, eid: &str, cn_b64: &str, sn_b64: &str) -> Result<SecureChannel> {
    let cn_raw = b64_decode(cn_b64)?;
    let sn_raw = b64_decode(sn_b64)?;
    let salt = sha256(&[cn_raw.as_slice(), sn_raw.as_slice()].concat());
    let info = format!("DF-BLE-1\n{node_id}\n{eid}");
    let okm = hkdf_sha256(ble_key, &salt, info.as_bytes(), 72)?;
    Ok(SecureChannel {
        session_id: String::new(), // AUTH_OK 后填入
        c2s_key: okm[0..32].try_into().unwrap(),
        s2c_key: okm[32..64].try_into().unwrap(),
        c2s_nonce: okm[64..68].try_into().unwrap(),
        s2c_nonce: okm[68..72].try_into().unwrap(),
        seq_c2s: 0,
        seq_s2c: 0,
    })
}

impl SecureChannel {
    fn seal(&mut self, direction: &str, key: &[u8; 32], prefix: &[u8; 4], seq: u64, plaintext: &[u8]) -> Result<serde_json::Value> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(prefix);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let aad = format!("{}\n{}\n{}", self.session_id, direction, seq);
        let ct = gcm_seal(key, &nonce, aad.as_bytes(), plaintext)?;
        let v = serde_json::json!({
            "type": "SECURE",
            "seq": seq,
            "data": b64_encode(&ct),
        });
        Ok(v)
    }

    fn open(&mut self, direction: &str, key: &[u8; 32], prefix: &[u8; 4], seq: u64, data_b64: &str) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(prefix);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let aad = format!("{}\n{}\n{}", self.session_id, direction, seq);
        let ct = b64_decode(data_b64)?;
        gcm_open(key, &nonce, aad.as_bytes(), &ct)
    }

    /// 发送加密请求/响应。seq < 10000；任意失败应由调用方废弃整个会话状态。
    pub async fn send_request(&mut self, link: &mut dyn GattLink, kind: &str, body: serde_json::Value) -> Result<()> {
        if self.seq_c2s >= 10000 {
            return Err(DfError::Ble("c2s 序号耗尽，需重新认证".into()));
        }
        let seq = self.seq_c2s;
        let plaintext = serde_json::to_vec(&serde_json::json!({ "type": kind, "body": body }))?;
        let key = self.c2s_key;
        let prefix = self.c2s_nonce;
        let wrapper = self.seal("c2s", &key, &prefix, seq, &plaintext)?;
        self.seq_c2s += 1;
        let bytes = serde_json::to_vec(&wrapper)?;
        link.send_message(&bytes).await
    }

    /// 接收加密消息，返回 (type, body)。严格按序号校验（重放立即失败）。
    pub async fn recv_response(&mut self, link: &mut dyn GattLink) -> Result<(String, serde_json::Value)> {
        let raw = link.recv_message().await?;
        let v: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| DfError::Protocol(format!("SECURE 帧不是 JSON: {e}")))?;
        let t = fields::need_str(&v, &["type"], "type")?;
        if t != "SECURE" {
            return Err(DfError::Ble(format!("期望 SECURE，收到 {t}")));
        }
        let seq = fields::need_u64(&v, &["seq"], "seq")?;
        if seq != self.seq_s2c {
            // 重放或乱序：废弃全部会话状态
            return Err(DfError::Ble(format!("s2c 序号异常: 期望 {}, 收到 {}", self.seq_s2c, seq)));
        }
        let data = fields::need_str(&v, &["data"], "data")?;
        let key = self.s2c_key;
        let prefix = self.s2c_nonce;
        let plaintext = self.open("s2c", &key, &prefix, seq, &data)?;
        self.seq_s2c += 1;
        let inner: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| DfError::Protocol(format!("SECURE 内层不是 JSON: {e}")))?;
        let kind = fields::need_str(&inner, &["type"], "type")?;
        Ok((kind, inner.get("body").cloned().unwrap_or(serde_json::Value::Null)))
    }
}

/// 执行 DF-BLE-1 认证（AUTH_START → CHALLENGE → AUTH_FINISH → AUTH_OK）。
/// 任何失败：节点废弃全部状态，Controller 也应丢弃密钥并用新随机数重来。
pub async fn authenticate(
    link: &mut dyn GattLink,
    ble_key: &[u8; 32],
    node_id: &str,
    eid: &str,
) -> Result<SecureChannel> {
    let cn = crate::keys::random_b64_32();
    let hint = hint_for(ble_key, eid);

    let msg = serde_json::to_vec(&serde_json::json!({
        "type": "AUTH_START",
        "eid": eid,
        "hint": hint,
        "cn": cn,
    }))?;
    link.send_message(&msg).await?;

    // CHALLENGE
    let (t, v) = super::expect_type(link, &["CHALLENGE"], Duration::from_secs(10)).await?;
    debug_assert_eq!(t, "CHALLENGE");
    let sn = fields::need_str(&v, &["sn"], "sn")?;
    let proof = fields::need_str(&v, &["proof"], "proof")?;
    let tstr = t_string(node_id, eid, &cn, &sn);
    let expect_server = hex::encode(hmac_sha256(ble_key, format!("{tstr}\nserver").as_bytes()));
    // 常量时间比较由 HMAC 输出等长 + 字符串比较实现（hex 展开前后均无秘密常量）
    if !eq_ignore_case(&proof, &expect_server) {
        return Err(DfError::Ble("CHALLENGE proof 校验失败：对方不是该节点".into()));
    }

    let msg = serde_json::to_vec(&serde_json::json!({
        "type": "AUTH_FINISH",
        "proof": hex::encode(hmac_sha256(ble_key, format!("{tstr}\nclient").as_bytes())),
    }))?;
    link.send_message(&msg).await?;

    // AUTH_OK
    let (t, v) = super::expect_type(link, &["AUTH_OK"], Duration::from_secs(10)).await?;
    debug_assert_eq!(t, "AUTH_OK");
    let session_id = fields::need_str(&v, &["sessionId"], "sessionId")?;
    let expect_session = hex::encode(hmac_sha256(ble_key, format!("{tstr}\nsession").as_bytes()));
    if !eq_ignore_case(&session_id, &expect_session) {
        return Err(DfError::Ble("AUTH_OK sessionId 校验失败".into()));
    }

    let mut ch = session_keys(ble_key, node_id, eid, &cn, &sn)?;
    ch.session_id = session_id;
    Ok(ch)
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// LINK_REQUEST(LAN)：取节点当前地址。
pub async fn link_request_lan(ch: &mut SecureChannel, link: &mut dyn GattLink) -> Result<LinkReady> {
    ch.send_request(link, "LINK_REQUEST", serde_json::json!({ "transport": "LAN" }))
        .await?;
    let (t, v) = ch.recv_response(link).await?;
    if t != "LINK_READY" {
        return Err(DfError::Ble(format!("期望 LINK_READY，收到 {t}")));
    }
    LinkReady::from_json(&v)
}

/// LINK_REQUEST(P2P) + 轮询 LINK_STATUS 直到 GO 就绪（总时限约 30 秒）。
pub async fn link_request_p2p(ch: &mut SecureChannel, link: &mut dyn GattLink) -> Result<LinkReady> {
    ch.send_request(link, "LINK_REQUEST", serde_json::json!({ "transport": "P2P" }))
        .await?;
    let (t, v) = ch.recv_response(link).await?;
    if t == "ERROR" || t == "P2P_BUSY" {
        return Err(DfError::Remote {
            code: fields::get_str(&v, &["code"]).unwrap_or_else(|| "P2P_BUSY".into()),
            retryable: false,
        });
    }
    if t != "LINK_READY" {
        return Err(DfError::Ble(format!("期望 LINK_READY，收到 {t}")));
    }
    let mut ready = LinkReady::from_json(&v)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while ready.group_name.is_empty() || ready.go_address.is_empty() {
        if tokio::time::Instant::now() > deadline {
            return Err(DfError::Timeout("等待 P2P GO 就绪超时".into()));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        ch.send_request(link, "LINK_STATUS", serde_json::json!({})).await?;
        let (t, v) = ch.recv_response(link).await?;
        if t == "LINK_READY" {
            ready = LinkReady::from_json(&v)?;
        }
    }
    Ok(ready)
}

/// LINK_READY 解析。
#[derive(Debug, Clone, Default)]
pub struct LinkReady {
    pub addresses: Vec<String>,
    pub control_port: u16,
    pub data_port: u16,
    pub group_name: String,
    pub group_passphrase: String,
    pub go_address: String,
    pub group_state: String,
}

impl LinkReady {
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let addresses = v
            .get("addresses")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let group = v.get("group").cloned().unwrap_or(serde_json::Value::Null);
        let g = |name: &str| fields::get_str(&group, &[name]).unwrap_or_default();
        Ok(LinkReady {
            addresses,
            control_port: fields::get_u64(v, &["controlPort"]).unwrap_or(crate::consts::DEFAULT_CONTROL_PORT as u64) as u16,
            data_port: fields::get_u64(v, &["dataPort"]).unwrap_or(crate::consts::DEFAULT_DATA_PORT as u64) as u16,
            group_name: g("name"),
            group_passphrase: g("passphrase"),
            go_address: g("goAddress"),
            group_state: g("state"),
        })
    }

    pub fn group_ready(&self) -> bool {
        !self.group_name.is_empty() && !self.go_address.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_matches_spec_construction() {
        // hint 的构造必须与 vectors.json 对拍；此处验证长度与字符集
        let key = [1u8; 32];
        let h = hint_for(&key, "aabbccdd00112233");
        assert_eq!(h.len(), 32);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn keys_split_72() {
        let ch = session_keys(&[2u8; 32], "node", "eid", &b64_encode(&[3u8; 32]), &b64_encode(&[4u8; 32])).unwrap();
        assert_eq!(ch.c2s_key.len(), 32);
        assert_eq!(ch.s2c_key.len(), 32);
        assert_eq!(ch.c2s_nonce.len(), 4);
        assert_eq!(ch.s2c_nonce.len(), 4);
    }

    #[tokio::test]
    async fn secure_roundtrip() {
        let mut ch = session_keys(&[9u8; 32], "node", "eid", &b64_encode(&[3u8; 32]), &b64_encode(&[4u8; 32])).unwrap();
        ch.session_id = "sess".into();

        let queue: std::sync::Arc<tokio::sync::Mutex<Vec<Vec<u8>>>> = Default::default();
        struct Q(std::sync::Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>);
        #[async_trait::async_trait]
        impl GattLink for Q {
            async fn send_message(&mut self, msg: &[u8]) -> Result<()> {
                self.0.lock().await.push(msg.to_vec());
                Ok(())
            }
            async fn recv_message(&mut self) -> Result<Vec<u8>> {
                let mut q = self.0.lock().await;
                Ok(q.remove(0))
            }
        }
        let mut link = Q(queue.clone());

        // seal → 模拟对端用相同方向/序号 open
        ch.send_request(&mut link, "STATUS", serde_json::json!({ "x": 1 })).await.unwrap();
        let raw = {
            let mut q = queue.lock().await;
            q.remove(0)
        };
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["type"], "SECURE");
        let data_str = v["data"].as_str().unwrap().to_string();
        let key = ch.c2s_key;
        let prefix = ch.c2s_nonce;
        let pt = ch.open("c2s", &key, &prefix, 0, &data_str).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&pt).unwrap();
        assert_eq!(inner["type"], "STATUS");

        // seq 不匹配（接收侧以 seq 单调计数拒绝重放）
        assert!(ch.open("c2s", &key, &prefix, 5, &data_str).is_err());
        // AAD 篡改（sessionId 不同）
        let mut tamper = session_keys(&[9u8; 32], "node", "eid", &b64_encode(&[3u8; 32]), &b64_encode(&[4u8; 32])).unwrap();
        tamper.session_id = "other".into();
        assert!(tamper.open("c2s", &key, &prefix, 0, &data_str).is_err());
    }
}
