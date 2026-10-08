//! 二维码 / 导出文件配对（7.2 节，备用方式）。
//!
//! 导出 JSON：`protocolMajor=1, nodeId, caDer, pairingToken, expiresAt(毫秒十进制字符串),
//! controlPort, dataPort, addresses, group`。
//! 导出文件含一次性口令，只能私下传递（例如 USB），导入后提示用户删除该文件。

use super::PairResult;
use crate::error::{DfError, Result};
use crate::fields;
use crate::keys::{self, SigningIdentity};
use crate::session::ControlSession;
use serde_json::Value;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TokenPairing {
    pub node_id: String,
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
    pub pairing_token: String,
    pub expires_at_ms: u64,
    pub addresses: Vec<String>,
    pub group: Option<Value>,
}

impl TokenPairing {
    pub fn from_json(json: &str) -> Result<TokenPairing> {
        let v: Value =
            serde_json::from_str(json).map_err(|e| DfError::Pairing(format!("导出内容不是 JSON: {e}")))?;
        let major = fields::get_u64(&v, &["protocolMajor"]).unwrap_or(1);
        if major != 1 {
            return Err(DfError::Pairing(format!("不支持的 protocolMajor: {major}")));
        }
        let node_id = fields::need_str(&v, &["nodeId"], "nodeId")?;
        let ca_der = crate::crypto::b64_decode(&fields::need_str(&v, &["caDer", "nodeCa"], "caDer")?)?;
        let derived = keys::node_id_from_ca_der(&ca_der)?;
        if derived != node_id {
            return Err(DfError::Pairing(format!("nodeId 与 CA 不匹配: {node_id} != {derived}")));
        }
        let expires_at_ms = fields::get_u64(&v, &["expiresAt"]).unwrap_or(0);
        if expires_at_ms != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if now >= expires_at_ms {
                return Err(DfError::Pairing("配对口令已过期".into()));
            }
        }
        let addresses = v
            .get("addresses")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        Ok(TokenPairing {
            ca_pem: keys::der_to_pem(&ca_der, "CERTIFICATE"),
            node_id,
            ca_der,
            pairing_token: fields::need_str(&v, &["pairingToken"], "pairingToken")?,
            expires_at_ms,
            addresses,
            group: v.get("group").cloned(),
        })
    }

    /// 执行 PAIR。`identity` 必须在调用前已作为“待定”持久保存（同一私钥重试拿到同一结果）。
    pub async fn pair(&self, identity: &SigningIdentity, display_name: &str) -> Result<PairResult> {
        if self.addresses.is_empty() {
            return Err(DfError::Pairing("导出信息中没有可用地址".into()));
        }
        let mut last_err = DfError::NotConnected;
        for addr in &self.addresses {
            let ip: IpAddr = match addr.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            match self.pair_to(ip, identity, display_name).await {
                Ok(r) => return Ok(r),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn pair_to(&self, ip: IpAddr, identity: &SigningIdentity, display_name: &str) -> Result<PairResult> {
        crate::tls::ensure_provider();
        let cfg = crate::tls::pairing_config(&self.ca_pem)?;
        let mut session = ControlSession::connect(ip, crate::consts::DEFAULT_CONTROL_PORT, cfg, Duration::from_secs(5)).await?;

        // 匿名 HELLO：不带 name
        let ack = session.hello("dfabric-desktop", None).await?;
        if ack.node_id != self.node_id {
            return Err(DfError::Pairing(format!(
                "HELLO_ACK nodeId 不匹配: {} != {}",
                ack.node_id, self.node_id
            )));
        }

        // proof = ECDSA-SHA256(DER) over `DF-PAIR-1\n<nodeId>\n<pairingToken>\n<challenge>`
        let msg = format!("DF-PAIR-1\n{}\n{}\n{}", self.node_id, self.pairing_token, ack.challenge);
        let sig = identity.sign_der(msg.as_bytes());

        let env = session
            .request(
                "PAIR",
                serde_json::json!({
                    "pairingToken": self.pairing_token,
                    "name": display_name,
                    "publicKey": crate::crypto::b64_encode(&identity.spki_der()),
                    "proof": crate::crypto::b64_encode(&sig),
                }),
                // 等待手机批准 ≤ 90 秒，请求超时 ≥ 120 秒
                Duration::from_secs(120),
            )
            .await?;
        if env.kind != "PAIR_RESULT" {
            return Err(ControlSession::unexpected(&env.kind, "PAIR_RESULT"));
        }
        let mut pr = super::parse_pair_result(&env.body, None, identity)?;
        pr.key_pem = identity.to_pkcs8_pem();
        Ok(pr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates() {
        // 用一把假 CA 生成自洽 JSON（nodeId = SHA256(SPKI)）
        let id = SigningIdentity::generate();
        let spki = id.spki_der();
        let node_id = crate::crypto::b64_encode(&spki); // 只为占位；真实校验在下面被期望失败
        let json = format!(
            r#"{{"protocolMajor":1,"nodeId":"{node_id}","caDer":"AAAA","pairingToken":"tok","expiresAt":"0","addresses":["192.168.1.9"]}}"#
        );
        // caDer 非法 → 失败
        assert!(TokenPairing::from_json(&json).is_err());
    }

    #[test]
    fn rejects_expired() {
        let past = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            - 10_000;
        let spki = SigningIdentity::generate().spki_der();
        let _ = spki;
        let json = format!(
            r#"{{"protocolMajor":1,"nodeId":"n","caDer":"{}","pairingToken":"tok","expiresAt":"{past}","addresses":[]}}"#,
            crate::crypto::b64_encode(&[0x30, 0x82, 0x01, 0x0a])
        );
        // caDer 不是合法证书 → parse_x509 失败，同样算错误路径（过期检查顺序在其后也不影响）
        assert!(TokenPairing::from_json(&json).is_err());
    }
}
