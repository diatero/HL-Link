//! 控制会话：TLS 连接 + HELLO + 请求/响应（9.1–9.4 节）。
//! 控制连接是严格的一问一答；收到 ERROR 后连接必须关闭重连。

use crate::consts::HELLO_TIMEOUT;
use crate::error::{DfError, Result};
use crate::fields;
use crate::frame;
use crate::msg::{new_request_id, Envelope, ErrorBody, HelloAck};
use rustls::ClientConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream, TlsConnector};

pub struct ControlSession {
    pub stream: TlsStream<TcpStream>,
    pub peer_addr: IpAddr,
    pub control_port: u16,
    pub data_port: Option<u16>,
    /// 最近一次 HELLO_ACK 的 sessionId（DATA_BIND 需要）。
    pub hello_session_id: String,
}

impl ControlSession {
    /// 连接（服务器名 = 实际 IP，校验 IP SAN + nodeId 由 HELLO_ACK 再核对）。
    pub async fn connect(
        addr: IpAddr,
        control_port: u16,
        config: Arc<ClientConfig>,
        connect_timeout: Duration,
    ) -> Result<ControlSession> {
        let tcp = timeout(connect_timeout, TcpStream::connect((addr, control_port)))
            .await
            .map_err(|_| DfError::Timeout(format!("TCP 连接 {addr}:{control_port} 超时")))??;
        tcp.set_nodelay(true)?;
        let connector = TlsConnector::from(config);
        // 以实际连接的 IP 作为服务器名（要求 leaf 的 IP SAN 匹配）
        let server_name = rustls::pki_types::ServerName::IpAddress(addr.into());
        let stream = timeout(connect_timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| DfError::Timeout("TLS 握手超时".into()))?
            .map_err(|e| {
                crate::logging::warn("tls", format!("{addr}:{control_port} TLS 握手失败: {e}"));
                DfError::Tls(format!("TLS 握手失败: {e}"))
            })?;
        crate::logging::debug("tls", format!("{addr}:{control_port} TLS 握手完成（nid={:?}）", stream.get_ref().1.negotiated_cipher_suite().map(|c| c.suite())));
        Ok(ControlSession { stream, peer_addr: addr, control_port, data_port: None, hello_session_id: String::new() })
    }

    /// 发送一帧。
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        frame::write_frame(&mut self.stream, &env.to_json()?).await
    }

    /// 读取一帧。
    pub async fn recv(&mut self) -> Result<Option<Envelope>> {
        match frame::read_frame(&mut self.stream).await? {
            None => Ok(None),
            Some(bytes) => Ok(Some(Envelope::parse(&bytes)?)),
        }
    }

    /// 请求-响应（发送后读下一帧，校验 requestId；ERROR → Remote 错误）。
    pub async fn request(&mut self, kind: &str, body: serde_json::Value, resp_timeout: Duration) -> Result<Envelope> {
        let rid = new_request_id();
        self.send(&Envelope::new(kind, &rid, body)).await?;
        let inner = timeout(resp_timeout, self.recv())
            .await
            .map_err(|_| DfError::Timeout(format!("{kind} 响应超时")))?;
        let env = inner?.ok_or_else(|| DfError::Protocol(format!("{kind} 后连接被对端关闭")))?;
        if env.kind == "ERROR" {
            let e = ErrorBody::from_value(&env.body)?;
            return Err(DfError::Remote { code: e.code, retryable: e.retryable });
        }
        if !env.request_id.is_empty() && env.request_id != rid {
            return Err(DfError::Protocol(format!(
                "requestId 不匹配: 期望 {rid}, 收到 {}",
                env.request_id
            )));
        }
        Ok(env)
    }

    /// HELLO（连接后 15 秒内必须发送）。匿名（配对）连接不带 name。
    pub async fn hello(&mut self, client_id: &str, name: Option<&str>) -> Result<HelloAck> {
        let mut body = serde_json::json!({ "clientId": client_id });
        if let Some(n) = name {
            body["name"] = serde_json::Value::String(n.to_string());
        }
        let env = timeout(HELLO_TIMEOUT + Duration::from_secs(5), self.hello_raw(&body))
            .await
            .map_err(|_| DfError::Timeout("HELLO 超时".into()))??;
        if env.kind != "HELLO_ACK" {
            crate::logging::warn("session", format!("HELLO 未得到 HELLO_ACK：{}", env.kind));
            return Err(DfError::Protocol(format!("期望 HELLO_ACK，收到 {}", env.kind)));
        }
        let ack = HelloAck::from_value(&env.body)?;
        crate::logging::info(
            "session",
            format!(
                "HELLO_ACK: node {}… 能力 [{}] chunkSize={} window={}",
                &ack.node_id[..12.min(ack.node_id.len())],
                ack.capabilities.join(","),
                ack.chunk_size,
                ack.window
            ),
        );
        self.hello_session_id = ack.session_id.clone();
        Ok(ack)
    }

    async fn hello_raw(&mut self, body: &serde_json::Value) -> Result<Envelope> {
        self.send(&Envelope::new("HELLO", "", body.clone())).await?;
        self.recv()
            .await?
            .ok_or_else(|| DfError::Protocol("HELLO 后连接被关闭".into()))
    }

    /// STATUS。
    pub async fn status(&mut self) -> Result<serde_json::Value> {
        let env = self
            .request("STATUS", serde_json::json!({}), Duration::from_secs(10))
            .await?;
        if env.kind != "STATUS_RESULT" {
            return Err(DfError::Protocol(format!("期望 STATUS_RESULT，收到 {}", env.kind)));
        }
        Ok(env.body)
    }

    /// 转换响应类型错误。
    pub fn unexpected(kind: &str, want: &str) -> DfError {
        DfError::Protocol(format!("期望 {want}，收到 {kind}"))
    }

    /// 数据端口（以 HELLO_ACK/ACCEPT/PULL_READY 协商值为准，默认 9528）。
    pub fn set_data_port(&mut self, port: u16) {
        self.data_port = Some(port);
    }

    pub fn get_data_port(&self) -> u16 {
        self.data_port.unwrap_or(crate::consts::DEFAULT_DATA_PORT)
    }

    /// 从 body 中读取数据端口（兼容数字与规范字符串）。
    pub fn data_port_from(body: &serde_json::Value) -> Result<u16> {
        let p = fields::need_u64(body, &["dataPort"], "dataPort")?;
        u16::try_from(p).map_err(|_| DfError::Protocol(format!("dataPort 越界: {p}")))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_name_from_ip() {
        // IP 形式的服务器名必须可构造（4.2 节）
        let n = rustls::pki_types::ServerName::try_from("192.168.1.10".to_string());
        assert!(n.is_ok());
    }
}
