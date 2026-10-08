use thiserror::Error;

pub type Result<T> = std::result::Result<T, DfError>;

#[derive(Debug, Error)]
pub enum DfError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("协议错误: {0}")]
    Protocol(String),

    /// 节点返回的应用层 ERROR 帧。
    #[error("节点错误 {code}")]
    Remote {
        code: String,
        retryable: bool,
    },

    #[error("TLS: {0}")]
    Tls(String),

    #[error("密码学: {0}")]
    Crypto(String),

    #[error("BLE: {0}")]
    Ble(String),

    #[error("配对失败: {0}")]
    Pairing(String),

    #[error("未连接到设备")]
    NotConnected,

    #[error("超时: {0}")]
    Timeout(String),

    #[error("用户取消")]
    Cancelled,

    #[error("平台不支持: {0}")]
    Unsupported(String),
}

impl DfError {
    /// 错误码对应协议中的语义（本地分类），用于任务状态记录。
    pub fn kind(&self) -> &'static str {
        match self {
            DfError::Remote { code: _, .. } => "remote",
            DfError::NotConnected | DfError::Timeout(_) => "LINK_TIMEOUT",
            DfError::Cancelled => "CANCELLED",
            DfError::Unsupported(_) => "UNSUPPORTED",
            _ => "IO_ERROR",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, DfError::NotConnected | DfError::Timeout(_))
            || matches!(self, DfError::Remote { code, retryable } if code == "IO_ERROR" && *retryable)
    }
}

impl From<rustls::Error> for DfError {
    fn from(e: rustls::Error) -> Self {
        DfError::Tls(e.to_string())
    }
}
