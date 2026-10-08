//! 文件传输（10.1 上传 / 10.2 接收）。

pub mod down;
pub mod up;

use crate::error::{DfError, Result};
use crate::msg::Envelope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// 数据连接事件。
#[derive(Debug)]
pub enum DataEvent {
    Ready,
    /// 原始块帧：index | len | 32B 块哈希 | 数据
    Chunk { index: u64, data: Vec<u8> },
    Ack { chunk_index: u64, received: Option<u64> },
    Complete(serde_json::Value),
    Error(crate::msg::ErrorBody),
    Closed,
}

pub struct DataConn {
    pub stream: TlsStream<TcpStream>,
}

impl DataConn {
    pub async fn connect(addr: std::net::IpAddr, port: u16, config: std::sync::Arc<rustls::ClientConfig>) -> Result<DataConn> {
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect((addr, port)),
        )
        .await
        .map_err(|_| DfError::Timeout("数据连接超时".into()))??;
        tcp.set_nodelay(true)?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let server_name = rustls::pki_types::ServerName::IpAddress(addr.into());
        let stream = tokio::time::timeout(std::time::Duration::from_secs(5), connector.connect(server_name, tcp))
            .await
            .map_err(|_| DfError::Timeout("数据 TLS 握手超时".into()))?
            .map_err(|e| DfError::Tls(format!("数据 TLS 握手失败: {e}")))?;
        Ok(DataConn { stream })
    }

    /// 读取下一个数据事件（JSON 帧或 44 字节块头的二进制块帧）。
    pub async fn next_event(&mut self) -> Result<DataEvent> {
        match crate::frame::read_frame(&mut self.stream).await? {
            None => Ok(DataEvent::Closed),
            Some(payload) => {
                if payload.first() == Some(&b'{') {
                    let env = Envelope::parse(&payload)?;
                    return match env.kind.as_str() {
                        "DATA_READY" => Ok(DataEvent::Ready),
                        "CHUNK_ACK" => Ok(DataEvent::Ack {
                            chunk_index: crate::fields::need_u64(&env.body, &["chunkIndex"], "chunkIndex")?,
                            received: crate::fields::get_u64(&env.body, &["received"]),
                        }),
                        "COMPLETE" => Ok(DataEvent::Complete(env.body)),
                        "ERROR" => Ok(DataEvent::Error(crate::msg::ErrorBody::from_value(&env.body)?)),
                        other => Err(crate::session::ControlSession::unexpected(other, "数据帧")),
                    };
                }
                // 二进制块帧：uint64 BE index | uint32 BE len | 32 字节块 SHA-256 | 数据
                if payload.len() < 44 {
                    return Err(DfError::Protocol(format!("块帧过短: {}", payload.len())));
                }
                let index = u64::from_be_bytes(payload[0..8].try_into().unwrap());
                let len = u32::from_be_bytes(payload[8..12].try_into().unwrap()) as usize;
                let hash: [u8; 32] = payload[12..44].try_into().unwrap();
                let data = &payload[44..];
                if data.len() != len {
                    return Err(DfError::Protocol(format!(
                        "块帧长度不一致: 声明 {len}, 实际 {}",
                        data.len()
                    )));
                }
                let actual = crate::crypto::sha256(data);
                if actual != hash {
                    return Err(DfError::Protocol(format!("块 {index} 哈希校验失败")));
                }
                Ok(DataEvent::Chunk { index, data: data.to_vec() })
            }
        }
    }

    /// 发送块帧（头 44 字节 + 数据）。
    pub async fn write_chunk(&mut self, index: u64, data: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(44 + data.len());
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crate::crypto::sha256(data));
        frame.extend_from_slice(data);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// 发送 JSON 帧（DATA_BIND / CHUNK_ACK）。
    pub async fn send_json(&mut self, env: &Envelope) -> Result<()> {
        crate::frame::write_frame(&mut self.stream, &env.to_json()?).await
    }

    /// 读取数据连接单帧，带超时（默认 30 秒）。
    pub async fn next_event_timeout(&mut self, dur: std::time::Duration) -> Result<DataEvent> {
        tokio::time::timeout(dur, self.next_event())
            .await
            .map_err(|_| DfError::Timeout("数据连接读取超时".into()))?
    }

    /// 关闭（发送 CANCEL 时同时关闭数据连接）。
    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

/// 流式读取暂存文件的一个块并计算整文件无需重读。
pub async fn read_chunk_at(path: &std::path::Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    use tokio::io::AsyncSeekExt;
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        let n = f.read(&mut buf[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok(buf)
}
