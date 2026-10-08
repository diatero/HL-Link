//! 控制帧编解码：`uint32 BE 长度 + UTF-8 JSON`，长度 1..=65536。
//! 读取时先校验长度再分配内存，天然处理 TCP 半包/粘包。

use crate::consts::MAX_FRAME;
use crate::error::{DfError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 读取一帧（长度前缀 + 载荷）。对端关闭连接返回 None。
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut lenbuf = [0u8; 4];
    // read_exact 在流关闭时返回 UnexpectedEof：区分“干净关闭”与半包
    match r.read_exact(&mut lenbuf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(lenbuf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(DfError::Protocol(format!("非法控制帧长度 {len}")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// 写出一帧。
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > MAX_FRAME {
        return Err(DfError::Protocol(format!("非法控制帧载荷长度 {}", data.len())));
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    w.write_all(&out).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip_boundaries() {
        for payload in [&b"x"[..], &vec![b'a'; 65536][..]] {
            let mut cur = Cursor::new(Vec::new());
            write_frame(&mut cur, payload).await.unwrap();
            let mut r = Cursor::new(cur.into_inner());
            let got = read_frame(&mut r).await.unwrap().unwrap();
            assert_eq!(got, payload);
        }
    }

    #[tokio::test]
    async fn rejects_bad_length() {
        // 长度 0
        let mut r = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_frame(&mut r).await.is_err());
        // 长度 65537
        let mut r = Cursor::new(65537u32.to_be_bytes().to_vec());
        assert!(read_frame(&mut r).await.is_err());
    }

    #[tokio::test]
    async fn clean_close_returns_none() {
        let mut r = Cursor::new(Vec::new());
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }
}
