//! 控制协议信封与消息类型（9.1 / 9.3 节）。
//! `{v:1, type, requestId, body}`；整数（size、chunkSize、index、received）用规范十进制字符串；
//! 未知字段忽略。

use crate::error::{DfError, Result};
use crate::fields;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_MAJOR: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub body: Value,
}

impl Envelope {
    pub fn new(kind: &str, request_id: &str, body: Value) -> Self {
        Envelope {
            v: PROTOCOL_MAJOR,
            kind: kind.to_string(),
            request_id: request_id.to_string(),
            body,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<Envelope> {
        let env: Envelope = serde_json::from_slice(bytes)?;
        if env.v != PROTOCOL_MAJOR {
            return Err(DfError::Protocol(format!("不支持的协议版本 v={}", env.v)));
        }
        Ok(env)
    }
}

/// 新的 requestId（≤128 字符）。
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 解析 ERROR 帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    #[serde(default)]
    pub retryable: bool,
}

impl ErrorBody {
    pub fn from_value(v: &Value) -> Result<Self> {
        let mut e: ErrorBody = serde_json::from_value(v.clone())
            .map_err(|_| DfError::Protocol("ERROR 帧格式错误".into()))?;
        if e.code.is_empty() {
            e.code = "UNKNOWN".into();
        }
        Ok(e)
    }
}

/// FILE_OFFER / RESUME 的元数据（10.1 节约束）。
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FileMeta {
    pub transfer_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunk_size: u64,
    pub sha256: String,
}

impl FileMeta {
    pub fn validate(&self) -> Result<()> {
        let n = self.name.chars().count();
        if n == 0 || n > 128 {
            return Err(DfError::Protocol("文件名长度必须为 1..128".into()));
        }
        if self.name.contains('/') || self.name.contains('\\') || self.name == "." || self.name == ".." {
            return Err(DfError::Protocol("文件名包含路径分隔符".into()));
        }
        if self.name.chars().any(|c| c.is_control()) {
            return Err(DfError::Protocol("文件名含控制字符".into()));
        }
        let m = self.mime.split('/').count();
        if m != 2 || self.mime.len() > 128 || self.mime.is_empty() {
            return Err(DfError::Protocol(format!("mime 不合规: {:?}", self.mime)));
        }
        if self.size > crate::consts::MAX_FILE_SIZE {
            return Err(DfError::Protocol("文件超过 16 GiB 上限".into()));
        }
        if self.chunk_size != crate::consts::CHUNK_SIZE {
            return Err(DfError::Protocol("chunkSize 必须为 1048576".into()));
        }
        if self.sha256.len() != 64 || self.sha256.bytes().any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase()) {
            return Err(DfError::Protocol("sha256 必须为 64 位小写 hex".into()));
        }
        Ok(())
    }

    pub fn chunk_count(&self) -> u64 {
        if self.size == 0 {
            0
        } else {
            self.size.div_ceil(self.chunk_size)
        }
    }

    pub fn offer_body(&self) -> Value {
        serde_json::json!({
            "transferId": self.transfer_id,
            "name": self.name,
            "mime": self.mime,
            "size": fields::dec(self.size),
            "chunkSize": fields::dec(self.chunk_size),
            "sha256": self.sha256,
        })
    }

    pub fn from_offer(v: &Value) -> Result<FileMeta> {
        let meta = FileMeta {
            transfer_id: fields::need_str(v, &["transferId"], "transferId")?,
            name: fields::need_str(v, &["name"], "name")?,
            mime: fields::get_str(v, &["mime"]).unwrap_or_else(|| "application/octet-stream".into()),
            size: fields::need_u64(v, &["size"], "size")?,
            chunk_size: fields::get_u64(v, &["chunkSize"]).unwrap_or(crate::consts::CHUNK_SIZE),
            sha256: fields::need_str(v, &["sha256"], "sha256")?,
        };
        meta.validate()?;
        Ok(meta)
    }
}

/// 从 JSON 提取的待接收 offer。
#[derive(Debug, Clone)]
pub struct PullOffer {
    pub meta: FileMeta,
}

/// PULL_LIST_RESULT 的 ended 记录。
#[derive(Debug, Clone)]
pub struct EndedRecord {
    pub transfer_id: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct PullList {
    pub offers: Vec<PullOffer>,
    pub ended: Vec<EndedRecord>,
}

/// HELLO_ACK 解析结果。
#[derive(Debug, Clone)]
pub struct HelloAck {
    pub node_id: String,
    pub session_id: String,
    pub challenge: String,
    pub capabilities: Vec<String>,
    pub chunk_size: u64,
    pub window: u64,
    pub name: Option<String>,
}

impl HelloAck {
    pub fn from_value(v: &Value) -> Result<HelloAck> {
        Ok(HelloAck {
            node_id: fields::need_str(v, &["nodeId"], "nodeId")?,
            session_id: fields::need_str(v, &["sessionId"], "sessionId")?,
            challenge: fields::need_str(v, &["challenge"], "challenge")?,
            capabilities: v
                .get("capabilities")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            chunk_size: fields::get_u64(v, &["chunkSize"]).unwrap_or(crate::consts::CHUNK_SIZE),
            window: fields::get_u64(v, &["window"]).unwrap_or(1),
            name: fields::get_str(v, &["name"]),
        })
    }

    pub fn has(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let e = Envelope::new("HELLO", "r1", serde_json::json!({"clientId": "c"}));
        let bytes = e.to_json().unwrap();
        let back = Envelope::parse(&bytes).unwrap();
        assert_eq!(back.kind, "HELLO");
        assert_eq!(back.request_id, "r1");
    }

    #[test]
    fn rejects_wrong_version() {
        let bad = serde_json::json!({"v": 2, "type": "X", "requestId": "", "body": {}});
        assert!(Envelope::parse(serde_json::to_vec(&bad).unwrap().as_slice()).is_err());
    }

    #[test]
    fn meta_validation() {
        let mut m = FileMeta {
            transfer_id: "t".into(),
            name: "a.png".into(),
            mime: "image/png".into(),
            size: 5,
            chunk_size: 1048576,
            sha256: "a".repeat(64),
        };
        assert!(m.validate().is_ok());
        m.name = "../x".into();
        assert!(m.validate().is_err());
        m.name = "ok".into();
        m.sha256 = "A".repeat(64);
        assert!(m.validate().is_err());
        m.sha256 = "a".repeat(63);
        assert!(m.validate().is_err());
        m.sha256 = "a".repeat(64);
        m.chunk_size = 4096;
        assert!(m.validate().is_err());
    }

    #[test]
    fn chunk_count() {
        let m = FileMeta {
            transfer_id: String::new(),
            name: String::new(),
            mime: String::new(),
            size: 1048577,
            chunk_size: 1048576,
            sha256: String::new(),
        };
        assert_eq!(m.chunk_count(), 2);
    }
}
