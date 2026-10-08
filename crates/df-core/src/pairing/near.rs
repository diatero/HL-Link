//! DF-NEAR-1 附近配对（7.1 节，主要配对方式）。
//!
//! 前提：手机上点了「添加设备」（5 分钟窗口），INFO 的 `pairing` 为 true。
//! 验证码必须由人比对，不能自动确认：prepare 之后由 UI 展示 SAS，用户确认后才 confirm。

use super::ble_link::GattLink;
use super::{expect_type, PairResult};
use crate::crypto::{b64_encode, hmac_sha256, hkdf_sha256, sas_code, sha256};
use crate::error::{DfError, Result};
use crate::fields;
use crate::keys::{self, SigningIdentity};
use p256::SecretKey;
use std::time::Duration;

const PHONE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(90);

/// prepare 阶段产出的握手状态（不可跨进程序列化；包含临时私钥，丢弃即取消）。
pub struct NearHandshake {
    pub eid: String,
    #[allow(dead_code)] // 保留以备调试/扩展（派生已完成）
    ecdh: SecretKey,
    identity: SigningIdentity,
    c_str: String,
    s_str: String,
    node_id: String,
    ca_der: Vec<u8>,
    k: [u8; 72],
    digest_b64: String,
}

impl NearHandshake {
    /// 六位验证码，需用户与手机比对。
    pub fn sas(&self) -> String {
        let mut k32 = [0u8; 32];
        k32.copy_from_slice(&self.k[0..32]);
        sas_code(&k32, &self.digest_b64)
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// DF-NEAR-1 客户端揭示串 C（无结尾换行）。
/// 提交给节点的是 `base64(SHA256(C))`。
///
/// `DF-NEAR-C1\n<eid>\n<客户端 ECDH 公钥 SPKI base64>\n<nonce>\n<证书公钥 SPKI base64>\n<base64(UTF8(名称))>`
pub fn client_commit_string(eid: &str, ecdh_spki_b64: &str, nonce_b64: &str, cert_spki_b64: &str, name_b64: &str) -> String {
    format!("DF-NEAR-C1\n{eid}\n{ecdh_spki_b64}\n{nonce_b64}\n{cert_spki_b64}\n{name_b64}")
}

/// DF-NEAR-1 服务端揭示串 S 的格式（节点侧生成；这里供自检对拍字段数与顺序）。
///
/// `DF-NEAR-S1\n<eid>\n<节点 ECDH 公钥 SPKI base64>\n<节点 nonce base64>\n<nodeId>\n<CA DER base64>`
pub fn server_commit_string(eid: &str, node_spki_b64: &str, node_nonce_b64: &str, node_id: &str, ca_der_b64: &str) -> String {
    format!("DF-NEAR-S1\n{eid}\n{node_spki_b64}\n{node_nonce_b64}\n{node_id}\n{ca_der_b64}")
}

/// 第一阶段：commit + reveal。返回握手状态与 SAS 验证码。
///
/// `eid` 必须来自刚读到的 INFO 特征值（`parse_info`），不能从消息流里等：
/// DF-NEAR-1 由 Controller 先发 `NEAR_COMMIT`，节点在收到之前不会主动推送任何消息，
/// 在这里 recv 会一直阻塞到节点 60 秒空闲清理断开连接。
///
/// 调用方展示验证码；用户确认一致后调用 [`near_confirm`]，取消则调用 [`near_cancel`]。
pub async fn near_prepare(link: &mut dyn GattLink, eid: &str, display_name: &str) -> Result<NearHandshake> {
    let eid = eid.to_string();

    let ecdh = keys::new_ecdh_secret();
    let identity = SigningIdentity::generate();
    let nonce = crate::keys::random_b64_32();
    let name_b64 = b64_encode(display_name.as_bytes());
    let ecdh_spki_b64 = b64_encode(&keys::p256_spki(&keys::ecdh_public_key(&ecdh)));
    let cert_spki_b64 = b64_encode(&identity.spki_der());

    let c_str = client_commit_string(&eid, &ecdh_spki_b64, &nonce, &cert_spki_b64, &name_b64);
    let commit = b64_encode(&sha256(c_str.as_bytes()));

    let msg = serde_json::to_vec(&serde_json::json!({
        "type": "NEAR_COMMIT",
        "eid": eid,
        "commit": commit,
    }))?;
    crate::logging::info("near", &format!("NEAR_COMMIT 已发送（eid {eid}）"));
    link.send_message(&msg).await?;

    let (_, v) = expect_type(link, &["NEAR_COMMIT"], Duration::from_secs(15)).await?;
    let node_commit = fields::need_str(&v, &["commit"], "commit")?;

    let msg = serde_json::to_vec(&serde_json::json!({
        "type": "NEAR_REVEAL",
        "publicKey": ecdh_spki_b64,
        "nonce": nonce,
        "certificateKey": cert_spki_b64,
        "name": display_name,
    }))?;
    link.send_message(&msg).await?;

    let (_, v) = expect_type(link, &["NEAR_REVEAL"], Duration::from_secs(15)).await?;
    let s_str = fields::need_str(&v, &["reveal"], "reveal")?;

    // S = DF-NEAR-S1\n<eid>\n<节点 ECDH 公钥>\n<节点 nonce>\n<nodeId>\n<CA DER b64>
    let parts: Vec<&str> = s_str.split('\n').collect();
    if parts.len() != 6 || parts[0] != "DF-NEAR-S1" {
        return Err(DfError::Pairing("REVEAL 格式错误".into()));
    }
    if parts[1] != eid {
        return Err(DfError::Pairing("REVEAL eid 不一致".into()));
    }
    let node_ecdh_spki = crate::crypto::b64_decode(parts[2])?;
    let node_nonce = crate::crypto::b64_decode(parts[3])?;
    if node_nonce.len() != 32 {
        return Err(DfError::Pairing("节点 nonce 不是 32 字节".into()));
    }
    let node_id = parts[4].to_string();
    let ca_der = crate::crypto::b64_decode(parts[5])?;

    // 全部校验不可省略
    if b64_encode(&sha256(s_str.as_bytes())) != node_commit {
        return Err(DfError::Pairing("节点 commit 与 REVEAL 不一致".into()));
    }
    let derived_node_id = keys::node_id_from_ca_der(&ca_der)?;
    if derived_node_id != node_id {
        return Err(DfError::Pairing(format!("SHA256(CA SPKI) != nodeId: {derived_node_id}")));
    }

    let shared = keys::ecdh_shared(&ecdh, &node_ecdh_spki)?;
    let digest_preimage = format!("{c_str}\n{s_str}");
    let digest_b64 = b64_encode(&sha256(digest_preimage.as_bytes()));
    let k_vec = hkdf_sha256(
        shared.raw_secret_bytes(),
        &sha256(digest_preimage.as_bytes()),
        b"DF-NEAR-1",
        72,
    )?;
    let mut k = [0u8; 72];
    k.copy_from_slice(&k_vec);

    Ok(NearHandshake {
        eid,
        ecdh, // 保留防止被优化；实际派生已完成
        identity,
        c_str,
        s_str,
        node_id,
        ca_der,
        k,
        digest_b64,
    })
}

/// 第二阶段：用户确认验证码一致后发送 NEAR_CONFIRM，等待手机批准并解析 NEAR_RESULT。
pub async fn near_confirm(link: &mut dyn GattLink, hs: &NearHandshake) -> Result<PairResult> {
    let mut k32 = [0u8; 32];
    k32.copy_from_slice(&hs.k[0..32]);
    let proof = b64_encode(&hmac_sha256(&k32, format!("{}\nconfirm", hs.digest_b64).as_bytes()));

    let msg = serde_json::to_vec(&serde_json::json!({ "type": "NEAR_CONFIRM", "proof": proof }))?;
    link.send_message(&msg).await?;

    // 手机确认 ≤ 90 秒；等待 NEAR_RESULT
    let (_, v) = expect_type(link, &["NEAR_RESULT"], PHONE_CONFIRM_TIMEOUT).await?;
    let data = fields::need_str(&v, &["data"], "data")?;
    let ct = crate::crypto::b64_decode(&data)?;

    // AES-256-GCM：key = K[32:64]，nonce = K[68:72] ‖ 8×0，AAD = "<digest>\nresult"
    let mut key = [0u8; 32];
    key.copy_from_slice(&hs.k[32..64]);
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&hs.k[68..72]);
    let aad = format!("{}\nresult", hs.digest_b64);
    let plaintext = crate::crypto::gcm_open(&key, &nonce, aad.as_bytes(), &ct)
        .map_err(|e| DfError::Pairing(format!("NEAR_RESULT 解密失败: {e}")))?;
    let result: serde_json::Value = serde_json::from_slice(&plaintext)?;

    let mut pr = super::parse_pair_result(&result, Some(&hs.ca_der), &hs.identity)?;
    pr.key_pem = hs.identity.to_pkcs8_pem();
    Ok(pr)
}

/// 随时取消。
pub async fn near_cancel(link: &mut dyn GattLink) -> Result<()> {
    let msg = serde_json::to_vec(&serde_json::json!({ "type": "NEAR_CANCEL" }))?;
    link.send_message(&msg).await
}

/// 读取 INFO 特征值（UTF-8 JSON {v:1, eid, pairing}）。
pub fn parse_info(bytes: &[u8]) -> Result<(String, bool)> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| DfError::Protocol(format!("INFO 不是 JSON: {e}")))?;
    let eid = fields::need_str(&v, &["eid"], "eid")?;
    let pairing = v.get("pairing").and_then(|p| p.as_bool()).unwrap_or(false);
    Ok((eid, pairing))
}

#[allow(dead_code)]
fn _keep_ecdh(_s: &SecretKey) {}

#[allow(dead_code)]
fn _keep_c(h: &NearHandshake) -> (&str, &str) {
    (&h.c_str, &h.s_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_parse() {
        let (eid, pairing) = parse_info(br#"{"v":1,"eid":"0102030405060708","pairing":true}"#).unwrap();
        assert_eq!(eid, "0102030405060708");
        assert!(pairing);
        let (_, pairing) = parse_info(br#"{"v":1,"eid":"x"}"#).unwrap();
        assert!(!pairing);
    }
}
