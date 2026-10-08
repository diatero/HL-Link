//! 配对与 BLE 控制通道。
//!
//! - `ble_link`: GATT 传输抽象与分片重组（6 字节头）
//! - `ble_auth`: DF-BLE-1 认证与 SECURE 通道、LINK_REQUEST/LINK_STATUS
//! - `near`: DF-NEAR-1 附近配对
//! - `token`: 二维码 / 导出文件配对（PAIR）

pub mod ble_auth;
pub mod ble_link;
pub mod near;
pub mod token;

use crate::error::{DfError, Result};
use crate::keys::{der_to_pem, peer_id_from_cert_der, pem_to_der, SigningIdentity};
use crate::{fields, keys};

/// 配对结果（NEAR_RESULT / PAIR_RESULT 解析 + 校验后的统一结构）。
#[derive(Debug, Clone)]
pub struct PairResult {
    pub node_id: String,
    pub ca_der: Vec<u8>,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub peer_id: String,
    pub ble_key: Option<[u8; 32]>,
    pub node_name: Option<String>,
    pub addresses: Vec<String>,
    pub control_port: u16,
    pub data_port: u16,
}

/// 解析并校验配对结果 JSON（第 7.1.6 / 7.2 节的校验不可省略）。
///
/// * `expected_ca_der`：附近配对时为 S 中拿到的 CA（必须一致）；导入配对时为 None。
/// * `identity`：本次配对使用的签名身份（客户端证书公钥必须等于它的 SPKI）。
pub fn parse_pair_result(
    v: &serde_json::Value,
    expected_ca_der: Option<&[u8]>,
    identity: &SigningIdentity,
) -> Result<PairResult> {
    let node_id = fields::need_str(v, &["nodeId"], "nodeId")?;
    let ca_b64 = fields::need_str(v, &["caDer", "nodeCa", "ca"], "caDer")?;
    let ca_der = crate::crypto::b64_decode(&ca_b64)?;

    // nodeId 必须等于 CA SPKI 的 SHA-256
    let derived = keys::node_id_from_ca_der(&ca_der)?;
    if derived != node_id {
        return Err(DfError::Pairing(format!("nodeId 与 CA 不匹配: {node_id} != {derived}")));
    }
    if let Some(exp) = expected_ca_der {
        if exp != ca_der.as_slice() {
            return Err(DfError::Pairing("配对结果中的 CA 与握手 CA 不一致".into()));
        }
    }

    let cert_pem = fields::need_str(
        v,
        &["clientCertificate", "clientCert", "certPem", "certificate"],
        "客户端证书",
    )?;
    let cert_der = pem_to_der(&cert_pem)?;

    // 客户端证书公钥必须等于第 1 步提交的证书公钥
    let cert_spki = keys::cert_spki_der(&cert_der)?;
    if cert_spki != identity.spki_der() {
        return Err(DfError::Pairing("客户端证书公钥与提交的公钥不一致".into()));
    }

    let ble_key = match fields::get_str(v, &["bleKey", "bleKeyB64"]) {
        Some(b) => {
            let raw = crate::crypto::b64_decode(&b)?;
            let arr: [u8; 32] = raw
                .try_into()
                .map_err(|_| DfError::Pairing("bleKey 不是 32 字节".into()))?;
            Some(arr)
        }
        None => None,
    };

    let addresses = v
        .get("addresses")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    Ok(PairResult {
        peer_id: peer_id_from_cert_der(&cert_der),
        ca_pem: der_to_pem(&ca_der, "CERTIFICATE"),
        node_name: fields::get_str(v, &["name"]),
        addresses,
        control_port: fields::get_u64(v, &["controlPort"]).unwrap_or(crate::consts::DEFAULT_CONTROL_PORT as u64) as u16,
        data_port: fields::get_u64(v, &["dataPort"]).unwrap_or(crate::consts::DEFAULT_DATA_PORT as u64) as u16,
        node_id,
        ca_der,
        cert_pem,
        key_pem: String::new(),
        ble_key,
    })
}

/// 读取一条 BLE 消息并按 type 分发的小工具（附近配对用）。
pub async fn expect_type(
    link: &mut dyn ble_link::GattLink,
    want: &[&str],
    deadline: std::time::Duration,
) -> Result<(String, serde_json::Value)> {
    let fut = async {
        loop {
            let raw = link.recv_message().await?;
            let v: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|e| DfError::Protocol(format!("BLE 消息不是 JSON: {e}")))?;
            let t = fields::need_str(&v, &["type"], "type")?;
            if want.contains(&t.as_str()) {
                return Ok((t, v));
            }
            if t == "NEAR_CANCEL" || t == "ERROR" {
                return Err(DfError::Pairing(format!("配对被节点终止: {t} {}", v)));
            }
            // 其他类型忽略
        }
    };
    tokio::time::timeout(deadline, fut)
        .await
        .map_err(|_| DfError::Timeout(format!("等待 {want:?} 超时")))?
}
