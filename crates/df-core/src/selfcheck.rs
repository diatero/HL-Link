//! 协议核心自检：全部是**确定性、离线**检查，不需要网络、蓝牙或已配对数据。
//!
//! 这些检查刻意贴在历史上出过问题的字节级约定上（字段名、编码、串格式），
//! 让「能编译、单测自洽」和「能和真实节点互通」之间的差距可以在本机先暴露出来。
//! 平台环境、已配对设备与连通性检查在 `dfabric::selfcheck`。

use crate::pairing::{ble_auth, near, parse_ca_field, token};
use crate::{bitmap, crypto, fields, keys, names, tls};
use crate::msg::Envelope;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    pub fn new(name: &str, status: Status, detail: impl Into<String>) -> Check {
        Check { name: name.to_string(), status, detail: detail.into() }
    }

    pub fn pass(name: &str, detail: impl Into<String>) -> Check {
        Check::new(name, Status::Pass, detail)
    }

    pub fn warn(name: &str, detail: impl Into<String>) -> Check {
        Check::new(name, Status::Warn, detail)
    }

    pub fn fail(name: &str, detail: impl Into<String>) -> Check {
        Check::new(name, Status::Fail, detail)
    }

    pub fn skip(name: &str, detail: impl Into<String>) -> Check {
        Check::new(name, Status::Skip, detail)
    }

    pub fn is_fail(&self) -> bool {
        self.status == Status::Fail
    }
}

/// 协议核心检查清单（顺序稳定，便于脚本比对）。
pub fn protocol_checks() -> Vec<Check> {
    vec![
        run("控制帧信封字段名（requestId）", envelope_field_names),
        run("配对结果 CA 字段（PEM / base64）", ca_field_encodings),
        run("BLE 认证 MAC 编码（base64）", ble_mac_encoding),
        run("DF-BLE-1 转录串", ble_transcript),
        run("DF-NEAR-1 揭示串与验证码", near_reveal_strings),
        run("PAIR 证明串", pair_proof_string),
        run("密码学已知向量（HKDF/HMAC/GCM）", crypto_vectors),
        run("PEM/DER 往返（含 CRLF）", pem_der_roundtrip),
        run("规范十进制与 haveBits 位图", decimal_and_bitmap),
        run("名称/文件名与协议上限", names_and_limits),
        run("TLS 配置（信任锚、provider）", tls_config),
    ]
}

/// 是否存在失败项（决定退出码）。
pub fn has_failure(checks: &[Check]) -> bool {
    checks.iter().any(Check::is_fail)
}

fn run(name: &str, f: fn() -> Result<String, String>) -> Check {
    match f() {
        Ok(detail) => Check::pass(name, detail),
        Err(detail) => Check::fail(name, detail),
    }
}

fn e<E: std::fmt::Display>(v: E) -> String {
    v.to_string()
}

/// 线上字段名必须是驼峰 `requestId`；节点 `Wire.read()` 缺字段即判 INVALID_FRAME。
fn envelope_field_names() -> Result<String, String> {
    let env = Envelope::new("HELLO", "rid-1", json!({ "clientId": "x" }));
    let s = String::from_utf8(env.to_json().map_err(e)?).map_err(e)?;
    if s.contains("request_id") {
        return Err(format!("仍在使用 snake_case 字段名：{s}"));
    }
    if !s.contains("\"requestId\":\"rid-1\"") {
        return Err(format!("缺少驼峰 requestId：{s}"));
    }
    let back = Envelope::parse(br#"{"v":1,"type":"HELLO_ACK","requestId":"r2","body":{}}"#).map_err(e)?;
    if back.request_id != "r2" {
        return Err("解析节点响应时 requestId 丢失（会被当成空字符串而跳过校验）".into());
    }
    Ok(s)
}

/// `PAIR_RESULT`/`NEAR_RESULT` 的 `nodeCa` 是 PEM，导出 JSON 的 `caDer` 是 base64。
fn ca_field_encodings() -> Result<String, String> {
    let der: Vec<u8> = (0u8..=255).collect();
    let pem = keys::der_to_pem(&der, "CERTIFICATE");
    let from_pem = parse_ca_field(&json!({ "nodeCa": pem })).map_err(e)?;
    let from_b64 = parse_ca_field(&json!({ "caDer": crypto::b64_encode(&der) })).map_err(e)?;
    if from_pem != der {
        return Err("PEM 形式的 nodeCa 解析结果不一致".into());
    }
    if from_b64 != der {
        return Err("base64 形式的 caDer 解析结果不一致".into());
    }
    Ok(format!("{} 字节 CA：PEM 与 base64 均可解析", der.len()))
}

/// 节点用 `Wire.b64` 传 MAC；用 hex 会导致 CHALLENGE/AUTH_OK 校验必然失败。
fn ble_mac_encoding() -> Result<String, String> {
    let mac = [7u8; 32];
    let enc = ble_auth::encode_mac(&mac);
    if enc != crypto::b64_encode(&mac) {
        return Err(format!("MAC 编码不是标准 base64：{enc}"));
    }
    if enc.len() != 44 || !enc.ends_with('=') {
        return Err(format!("base64 形态异常（长度 {}）", enc.len()));
    }
    if !ble_auth::verify_mac(&mac, &enc) {
        return Err("verify_mac 拒绝自身编码输出".into());
    }
    if !ble_auth::verify_mac(&mac, &hex::encode(mac)) {
        return Err("verify_mac 未兼容 hex 表示".into());
    }
    if ble_auth::verify_mac(&mac, &crypto::b64_encode(&[8u8; 32])) {
        return Err("verify_mac 接受了不匹配的 MAC".into());
    }
    let hint = ble_auth::hint_for(&mac, "0102030405060708");
    if hint.len() != 32 || !hint.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(format!("hint 不是 32 位小写 hex：{hint}"));
    }
    Ok(format!("证明用 base64（{enc}），hint 用 hex 前 32 字符"))
}

fn ble_transcript() -> Result<String, String> {
    let t = ble_auth::transcript("nodeid", "0102030405060708", "cn", "sn");
    let want = "DF-BLE-1\nnodeid\n0102030405060708\ncn\nsn";
    if t != want {
        return Err(format!("转录串不符：{t}"));
    }
    Ok(want.replace('\n', "\\n"))
}

/// DF-NEAR-1 的 C/S 都是六段、无结尾换行；验证码必须六位数字。
fn near_reveal_strings() -> Result<String, String> {
    let c = near::client_commit_string("eid", "PUB", "NONCE", "CERT", "bmFtZQ==");
    let want_c = "DF-NEAR-C1\neid\nPUB\nNONCE\nCERT\nbmFtZQ==";
    if c != want_c {
        return Err(format!("C 串不符：{c}"));
    }
    let s = near::server_commit_string("eid", "SPUB", "SNONCE", "node", "caDer");
    let want_s = "DF-NEAR-S1\neid\nSPUB\nSNONCE\nnode\ncaDer";
    if s != want_s || s.split('\n').count() != 6 {
        return Err(format!("S 串不符：{s}"));
    }
    let code = crypto::sas_code(&[9u8; 32], "digest");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("验证码格式异常：{code}"));
    }
    Ok(format!("C/S 六段格式正确，验证码示例 {code}"))
}

fn pair_proof_string() -> Result<String, String> {
    let m = token::pair_proof_message("node", "tok", "chal");
    let want = "DF-PAIR-1\nnode\ntok\nchal";
    if m != want {
        return Err(format!("PAIR 证明串不符：{m}"));
    }
    Ok(want.replace('\n', "\\n"))
}

fn crypto_vectors() -> Result<String, String> {
    // HKDF-SHA256 RFC 5869 Test Case 1
    let okm = crypto::hkdf_sha256(&[0x0bu8; 22], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9], 42).map_err(e)?;
    if hex::encode(&okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
        return Err("HKDF-SHA256 结果与 RFC 5869 TC1 不符".into());
    }
    // HMAC-SHA256 RFC 4231 Test Case 1
    if hex::encode(crypto::hmac_sha256(&[0x0bu8; 20], b"Hi There")) != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
        return Err("HMAC-SHA256 结果与 RFC 4231 TC1 不符".into());
    }
    // AES-256-GCM NIST 零向量
    if hex::encode(crypto::gcm_seal(&[0u8; 32], &[0u8; 12], b"", b"").map_err(e)?) != "530f8afbc74536b9a963b4f1c4cb738b" {
        return Err("AES-256-GCM 结果与 NIST 零向量不符".into());
    }
    Ok("HKDF(RFC5869 TC1) / HMAC(RFC4231 TC1) / GCM(NIST 零向量) 全部一致".into())
}

fn pem_der_roundtrip() -> Result<String, String> {
    let sk = keys::new_ecdh_secret();
    let der = keys::p256_spki(&keys::ecdh_public_key(&sk));
    let pem = keys::der_to_pem(&der, "PUBLIC KEY");
    if keys::pem_to_der(&pem).map_err(e)? != der {
        return Err("PEM→DER 往返不一致".into());
    }
    if keys::pem_to_der(&pem.replace('\n', "\r\n")).map_err(e)? != der {
        return Err("CRLF 形式的 PEM 无法解析（Windows/邮件转发常见）".into());
    }
    if keys::parse_p256_spki(&der).is_err() {
        return Err("生成的 P-256 SPKI 无法回读".into());
    }
    Ok(format!("{} 字节 SPKI 往返一致（含 CRLF）", der.len()))
}

fn decimal_and_bitmap() -> Result<String, String> {
    for bad in ["007", "-1", "1e3", "", " 1"] {
        if fields::parse_dec(bad).is_ok() {
            return Err(format!("非规范十进制被接受：{bad:?}"));
        }
    }
    if fields::dec(1_048_576) != "1048576" {
        return Err("十进制输出不符合规范".into());
    }
    let mut set = std::collections::BTreeSet::new();
    set.insert(0u64);
    set.insert(8);
    set.insert(9);
    let enc = bitmap::encode_bits(&set);
    if crypto::b64_decode(&enc).map_err(e)? != vec![0x01, 0x03] {
        return Err("haveBits 与 Java BitSet 字节序不符".into());
    }
    if bitmap::decode_bits(&enc, 0).map_err(e)? != set {
        return Err("haveBits 解码结果与原集合不一致".into());
    }
    Ok("十进制与 haveBits（Java BitSet 小端位序）一致".into())
}

fn names_and_limits() -> Result<String, String> {
    if names::sanitize_display_name("   ").is_some() {
        return Err("空白名称未被拒绝".into());
    }
    if names::truncate_display_name(&"a".repeat(100)).encode_utf16().count() != 64 {
        return Err("名称截断未按 UTF-16 码元限制".into());
    }
    if names::safe_filename("../x") != ".._x" {
        return Err(format!("路径分隔符未被替换：{}", names::safe_filename("../x")));
    }
    if crate::consts::CHUNK_SIZE != 1_048_576 || crate::consts::MAX_FRAME != 65_536 {
        return Err("分块/帧上限常量被改动".into());
    }
    if crate::consts::DEFAULT_CONTROL_PORT != 9527 || crate::consts::DEFAULT_DATA_PORT != 9528 {
        return Err("默认端口常量被改动".into());
    }
    Ok("名称规则与协议上限（1 MiB 块 / 64 KiB 帧 / 9527、9528）一致".into())
}

fn tls_config() -> Result<String, String> {
    tls::ensure_provider();
    if tls::client_config("", "", "").is_ok() {
        return Err("空信任锚未被拒绝（绝不能降级为不校验）".into());
    }
    if tls::pairing_config("").is_ok() {
        return Err("配对配置在空信任锚时未返回错误".into());
    }
    Ok("rustls(ring) provider 可用；空信任锚被拒绝".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_protocol_checks_pass() {
        let checks = protocol_checks();
        for c in &checks {
            assert!(!c.is_fail(), "自检失败：{} - {}", c.name, c.detail);
        }
        assert!(checks.len() >= 10);
    }
}
