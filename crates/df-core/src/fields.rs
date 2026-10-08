//! JSON 字段提取工具。
//!
//! 参考实现（df_client.py / DF1.md）不在当前环境，个别响应字段名无法逐字核对；
//! 所有“按名字取字段”都经过这里，并对常见别名做容错，便于对拍后集中修正。

use crate::error::{DfError, Result};
use serde_json::Value;

/// 按候选名依次取字符串字段。
pub fn get_str(obj: &Value, names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(v) = obj.get(*n) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
            // 允许数字被写成字符串的情况（协议中端口/大小有明确类型，这里只兜底）
            if let Some(n2) = v.as_u64() {
                return Some(n2.to_string());
            }
        }
    }
    None
}

pub fn need_str(obj: &Value, names: &[&str], what: &str) -> Result<String> {
    get_str(obj, names).ok_or_else(|| DfError::Protocol(format!("响应缺少字段 {what}（候选: {names:?}）")))
}

pub fn get_u64(obj: &Value, names: &[&str]) -> Option<u64> {
    for n in names {
        if let Some(v) = obj.get(*n) {
            if let Some(n2) = v.as_u64() {
                return Some(n2);
            }
            if let Some(s) = v.as_str() {
                if let Ok(n2) = parse_dec(s) {
                    return Some(n2);
                }
            }
        }
    }
    None
}

pub fn need_u64(obj: &Value, names: &[&str], what: &str) -> Result<u64> {
    get_u64(obj, names).ok_or_else(|| DfError::Protocol(format!("响应缺少字段 {what}")))
}

/// 规范十进制字符串 → u64：无符号、无前导 0、无指数。
pub fn parse_dec(s: &str) -> Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DfError::Protocol(format!("非规范十进制字符串: {s:?}")));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(DfError::Protocol(format!("非规范十进制字符串（前导 0）: {s:?}")));
    }
    s.parse::<u64>()
        .map_err(|_| DfError::Protocol(format!("十进制超出范围: {s:?}")))
}

/// u64 → 规范十进制字符串。
pub fn dec(n: u64) -> String {
    format!("{n}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dec_rules() {
        assert_eq!(dec(0), "0");
        assert_eq!(dec(1048576), "1048576");
        assert!(parse_dec("0").is_ok());
        assert!(parse_dec("007").is_err());
        assert!(parse_dec("-1").is_err());
        assert!(parse_dec("1e3").is_err());
        assert!(parse_dec("").is_err());
        assert!(parse_dec("18446744073709551616").is_err());
    }

    #[test]
    fn aliases() {
        let v = json!({"certPem": "x", "size": "1024", "dataPort": 9528});
        assert_eq!(get_str(&v, &["clientCert", "certPem"]).unwrap(), "x");
        assert_eq!(get_u64(&v, &["size"]).unwrap(), 1024);
        assert_eq!(get_u64(&v, &["dataPort"]).unwrap(), 9528);
        assert!(need_str(&v, &["missing"], "missing").is_err());
    }
}
