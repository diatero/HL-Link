//! 节点侧的 DF/1 线上工具：带错误码的失败、控制帧读写、规范十进制。
//!
//! 语义以 LineageOS 节点（`Wire.java` / `NodeRuntime.java`）为准：
//! 信封 `{v:1,type,requestId,body}`，requestId ≤128，body 必须是对象；
//! 整数用 `0|[1-9][0-9]{0,18}` 的十进制字符串且不超过 2^63-1。

use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CONTROL_PORT: u16 = 9527;
pub const DATA_PORT: u16 = 9528;
pub const CHUNK: u64 = 1024 * 1024;
pub const MAX_FRAME: usize = 65536;

/// 协议失败：`code` 原样进入 ERROR 帧（AUTH_FAILED / INVALID_FRAME / ...）。
#[derive(Debug, Clone)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Failure {
        Failure { code, message: message.into() }
    }
    pub fn io(e: impl std::fmt::Display) -> Failure {
        Failure::new("IO_ERROR", e.to_string())
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Failure {}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Failure {
        Failure::io(e)
    }
}

impl From<serde_json::Error> for Failure {
    fn from(e: serde_json::Error) -> Failure {
        Failure::new("INVALID_FRAME", e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

/// 读取控制帧并校验信封；对端在帧边界关闭时返回 None。
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Value>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(Failure::new("INVALID_FRAME", "Control length"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    let text = std::str::from_utf8(&buf).map_err(|_| Failure::new("INVALID_FRAME", "UTF-8"))?;
    let v: Value = serde_json::from_str(text)?;
    let ok = v.get("v").and_then(Value::as_i64) == Some(1)
        && v.get("requestId").and_then(Value::as_str).is_some_and(|s| s.chars().count() <= 128)
        && v.get("type").and_then(Value::as_str).is_some()
        && v.get("body").is_some_and(Value::is_object);
    if !ok {
        return Err(Failure::new("INVALID_FRAME", "Protocol version or request ID"));
    }
    Ok(Some(v))
}

pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, message: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_FRAME {
        return Err(Failure::new("INVALID_FRAME", "Response too large"));
    }
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    w.write_all(&out).await?;
    w.flush().await?;
    Ok(())
}

pub fn message(kind: &str, request_id: &str, body: Value) -> Value {
    json!({ "v": 1, "type": kind, "requestId": request_id, "body": body })
}

pub fn error(request_id: &str, f: &Failure) -> Value {
    message("ERROR", request_id, json!({ "code": f.code, "retryable": f.code == "IO_ERROR" }))
}

pub fn kind(m: &Value) -> &str {
    m.get("type").and_then(Value::as_str).unwrap_or("")
}

pub fn request_id(m: &Value) -> String {
    m.get("requestId").and_then(Value::as_str).unwrap_or("").to_string()
}

pub fn body(m: &Value) -> &Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    m.get("body").and_then(Value::as_object).unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

pub fn string<'a>(o: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    o.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new("INVALID_FRAME", format!("Missing {field}")))
}

/// 规范十进制字符串（`Wire.decimal`）：无符号、无前导 0、最多 19 位且 ≤ 2^63-1。
pub fn decimal(o: &Map<String, Value>, field: &str) -> Result<u64> {
    let s = o.get(field).and_then(Value::as_str).unwrap_or("");
    let canonical = !s.is_empty()
        && s.len() <= 19
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(Failure::new("INVALID_FRAME", format!("Invalid decimal {field}")));
    }
    s.parse::<i64>()
        .map(|v| v as u64)
        .map_err(|_| Failure::new("INVALID_FRAME", "Integer overflow"))
}

pub fn b64(data: &[u8]) -> String {
    df_core::crypto::b64_encode(data)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    df_core::crypto::b64_decode(s).map_err(|_| Failure::new("INVALID_FRAME", "base64"))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(df_core::crypto::sha256(data))
}

pub fn random(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn now_ms() -> u64 {
    df_core::stores::now_ms()
}

/// 小写 UUID（`[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}`）。
pub fn valid_transfer_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12].iter().zip(&parts).all(|(n, p)| p.len() == *n)
        && id.bytes().all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=128).contains(&n)
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
        && !name.chars().any(char::is_control)
}

pub fn valid_mime(mime: &str) -> bool {
    let token = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b));
    mime.len() <= 128 && mime.split_once('/').is_some_and(|(a, b)| token(a) && token(b))
}

pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_rules() {
        let o = |s: &str| serde_json::from_value::<Map<String, Value>>(json!({ "n": s })).unwrap();
        assert_eq!(decimal(&o("0"), "n").unwrap(), 0);
        assert_eq!(decimal(&o("1048576"), "n").unwrap(), 1048576);
        assert!(decimal(&o("01"), "n").is_err());
        assert!(decimal(&o("-1"), "n").is_err());
        assert!(decimal(&o("9223372036854775808"), "n").is_err());
        let num = serde_json::from_value::<Map<String, Value>>(json!({ "n": 5 })).unwrap();
        assert!(decimal(&num, "n").is_err());
    }

    #[test]
    fn field_rules() {
        assert!(valid_transfer_id("0602ad31-b1a4-4134-8249-2120f747cb35"));
        assert!(!valid_transfer_id("0602AD31-b1a4-4134-8249-2120f747cb35"));
        assert!(!valid_name("../x") && !valid_name("") && valid_name("a b.txt"));
        assert!(valid_mime("application/vnd.android.package-archive") && !valid_mime("text"));
    }
}
