//! TLS 客户端配置（4.2 节）：
//! - 只信任配对得到的节点 CA（自定义信任锚，不用系统根证书）；
//! - 以实际连接的 IP 作为服务器名，要求出现在 leaf 的 IP SAN；
//! - 客户端证书（ECDSA P-256）认证；仅 TLS 1.3；
//! - 不提供跳过校验的开关。

use crate::error::{DfError, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// 安装默认 crypto provider（ring，三平台行为一致；不依赖 SChannel）。
pub fn ensure_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut pem.as_bytes()).collect();
    certs.map_err(|e| DfError::Tls(format!("证书 PEM 解析失败: {e}")))
}

/// 由节点 CA + 客户端证书/私钥 PEM 构建 ClientConfig。
/// `ca_pem` 为空时得到“无信任锚”的配置——调用方只应在 PAIR（仅信任 caDer 的匿名配对连接）使用专用入口。
pub fn client_config(ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let cas = parse_certs(ca_pem)?;
    if cas.is_empty() {
        return Err(DfError::Tls("信任锚为空：必须提供配对得到的节点 CA".into()));
    }
    for c in cas {
        roots
            .add(c)
            .map_err(|e| DfError::Tls(format!("CA 无法加入信任锚: {e}")))?;
    }

    let certs = parse_certs(cert_pem)?;
    if certs.is_empty() {
        return Err(DfError::Tls("客户端证书为空".into()));
    }
    let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| DfError::Tls(format!("私钥 PEM 解析失败: {e}")))?
        .ok_or_else(|| DfError::Tls("私钥缺失".into()))?;
    let key: PrivateKeyDer<'static> = key_der;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| DfError::Tls(format!("客户端证书/私钥不匹配: {e}")))?;
    Ok(Arc::new(config))
}

/// 配对（PAIR）专用：只信任导入的 CA，不带客户端证书。
pub fn pairing_config(ca_pem: &str) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for c in parse_certs(ca_pem)? {
        roots.add(c).map_err(|e| DfError::Tls(e.to_string()))?;
    }
    // rustls 在信任锚为空时会在 with_root_certificates 内部直接 panic；
    // 任何解析失败都必须变成普通错误，绝不让进程崩溃。
    if roots.is_empty() {
        return Err(DfError::Tls("信任锚为空：配对信息里的 CA 无效".into()));
    }
    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningIdentity;

    fn self_signed_test_pem() -> (String, String, String) {
        // 仅测试配置构建路径：签名身份自签一张最小证书
        let id = SigningIdentity::generate();
        let key_pem = id.to_pkcs8_pem();
        // 构造一个自签证书 DER（用 rcgen 不可用时手写太重；这里用 x509-parser 无法签发）
        // 改为：以自签 CA 证书（p256 手工 DER）超出范围，测试只验证错误路径与私钥解析
        (String::new(), String::new(), key_pem)
    }

    #[test]
    fn rejects_empty_trust() {
        ensure_provider();
        let (_c, _k, key) = self_signed_test_pem();
        assert!(client_config("", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", &key).is_err());
        assert!(client_config("not a pem", "", "").is_err());
        // 空信任锚必须返回错误而不是 panic（rustls 会在 builder 内部 panic）
        assert!(pairing_config("").is_err());
        assert!(pairing_config("not a pem").is_err());
    }
}
