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
    ///
    /// 数据连接上两种帧并存，编码不同：
    /// * JSON 帧（DATA_READY / CHUNK_ACK / COMPLETE / ERROR）：`uint32 BE 长度 + JSON`
    ///   （节点用 `Wire.write`，带长度前缀）；
    /// * 二进制块帧（下载方向，节点 `DataOutputStream` 直接写，**无长度前缀**）：
    ///   `uint64 BE index | uint32 BE len | 32B SHA-256 | 数据`。
    ///
    /// 区分方法：JSON 帧载荷以 `{` 开头，即第 5 字节为 `{` 且首 4 字节是合法长度
    /// （1..=65536）；块帧第 5 字节是 8 字节 index 的第 4 字节，块数上限 16384
    /// （16 GiB / 1 MiB）下恒为 0x00，两者无歧义。
    pub async fn next_event(&mut self) -> Result<DataEvent> {
        let mut head = [0u8; 4];
        match self.stream.read_exact(&mut head).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(DataEvent::Closed),
            Err(e) => return Err(e.into()),
        }
        let mut fifth = [0u8; 1];
        self.stream.read_exact(&mut fifth).await?;
        let declared = u32::from_be_bytes(head) as usize;

        if fifth[0] == b'{' && (1..=crate::consts::MAX_FRAME).contains(&declared) {
            // 长度前缀 JSON 帧（fifth 是载荷首字节）
            let mut payload = vec![0u8; declared];
            payload[0] = b'{';
            self.stream.read_exact(&mut payload[1..]).await?;
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

        // 二进制块帧：head(4) + fifth(1) 是 8 字节 index 的前 5 字节
        let mut idx = [0u8; 8];
        idx[..4].copy_from_slice(&head);
        idx[4] = fifth[0];
        let mut rest = [0u8; 7];
        self.stream.read_exact(&mut rest).await?;
        idx[5..].copy_from_slice(&rest[..3]);
        let index = u64::from_be_bytes(idx);
        let len = u32::from_be_bytes(rest[3..7].try_into().unwrap()) as usize;
        if len == 0 || len > crate::consts::CHUNK_SIZE as usize {
            return Err(DfError::Protocol(format!("块帧长度越界: {len}")));
        }
        let mut hash = [0u8; 32];
        self.stream.read_exact(&mut hash).await?;
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        let actual = crate::crypto::sha256(&data);
        if actual != hash {
            return Err(DfError::Protocol(format!("块 {index} 哈希校验失败")));
        }
        Ok(DataEvent::Chunk { index, data })
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
