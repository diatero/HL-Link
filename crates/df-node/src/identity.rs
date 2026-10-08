//! 节点身份（对应 `Identity.java`）：私有 P-256 CA（10 年）、服务端证书（1 年，IP SAN = 当前监听地址）、
//! 给控制端签发客户端证书（clientAuth）。`nodeId` = SHA-256(CA SPKI DER)。
//!
//! 只持久化 CA 证书 DER（交给控制端的信任锚）与两把私钥（0600）。签发时用同一 DN 与同一把 CA 私钥
//! 在内存里重建签发者：签出证书的 issuer DN / AKI 与持久化的 CA 一致，链校验不受影响。

use crate::wire::{Failure, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CA_NAME: &str = "HL Link Desktop CA";

pub struct Identity {
    ca_key: KeyPair,
    ca_issuer: rcgen::Certificate,
    server_key: KeyPair,
    pub ca_der: Vec<u8>,
    pub node_id: String,
}

fn rc(e: rcgen::Error) -> Failure {
    Failure::io(format!("证书: {e}"))
}

fn serial() -> SerialNumber {
    let mut b = crate::wire::random(16);
    b[0] &= 0x7f;
    b[0] |= 0x01;
    SerialNumber::from(b)
}

fn params(cn: &str, valid_days: i64) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(valid_days);
    p.serial_number = Some(serial());
    p
}

fn ca_params() -> CertificateParams {
    let mut p = params(CA_NAME, 3650);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

fn load_key(path: &Path) -> Result<KeyPair> {
    let pem = std::fs::read_to_string(path)?;
    KeyPair::from_pem(&pem).map_err(rc)
}

fn save_private(path: &Path, data: &[u8]) -> Result<()> {
    df_core::fsutil::atomic_write(path, data).map_err(Failure::io)?;
    restrict(path);
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict(_path: &Path) {}

impl Identity {
    pub fn load_or_create(dir: &Path) -> Result<Identity> {
        std::fs::create_dir_all(dir)?;
        let p = |n: &str| -> PathBuf { dir.join(n) };
        let (ca_key, ca_der) = if p("ca.der").exists() && p("ca.key.pem").exists() {
            (load_key(&p("ca.key.pem"))?, std::fs::read(p("ca.der"))?)
        } else {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rc)?;
            let cert = ca_params().self_signed(&key).map_err(rc)?;
            save_private(&p("ca.key.pem"), key.serialize_pem().as_bytes())?;
            df_core::fsutil::atomic_write(&p("ca.der"), cert.der()).map_err(Failure::io)?;
            (key, cert.der().to_vec())
        };
        let server_key = if p("server.key.pem").exists() {
            load_key(&p("server.key.pem"))?
        } else {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rc)?;
            save_private(&p("server.key.pem"), key.serialize_pem().as_bytes())?;
            key
        };
        let node_id = df_core::keys::node_id_from_ca_der(&ca_der).map_err(Failure::io)?;
        // 内存中的签发者：DN 与密钥与持久化 CA 相同
        let ca_issuer = ca_params().self_signed(&ca_key).map_err(rc)?;
        if df_core::keys::cert_spki_der(&ca_der).map_err(Failure::io)? != ca_key.public_key_der() {
            return Err(Failure::io("节点 CA 证书与私钥不匹配"));
        }
        Ok(Identity { ca_key, ca_issuer, server_key, ca_der, node_id })
    }

    pub fn ca_pem(&self) -> String {
        pem(&self.ca_der)
    }

    /// 给控制端提交的 P-256 公钥签发客户端证书（1 年，clientAuth），返回 DER。
    pub fn issue_client(&self, spki_der: &[u8]) -> Result<Vec<u8>> {
        let spki = SubjectPublicKeyInfo::from_der(spki_der).map_err(rc)?;
        let mut p = params(&format!("peer-{}", &crate::wire::sha256_hex(spki_der)[..32]), 365);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.signed_by(&spki, &self.ca_issuer, &self.ca_key).map_err(rc)?;
        Ok(cert.der().to_vec())
    }

    fn server_chain(&self, ips: &[Ipv4Addr]) -> Result<Vec<CertificateDer<'static>>> {
        let mut p = params("HL Link Desktop", 365);
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.subject_alt_names = ips.iter().map(|ip| SanType::IpAddress((*ip).into())).collect();
        let leaf = p.signed_by(&self.server_key, &self.ca_issuer, &self.ca_key).map_err(rc)?;
        Ok(vec![leaf.der().clone(), CertificateDer::from(self.ca_der.clone())])
    }

    /// 两个 TLS 1.3 服务端配置：控制端口（配对窗口允许无证书，只能 HELLO/PAIR）与数据端口（必须客户端证书）。
    /// 客户端证书必须链到本节点 CA；是否仍受信任由每次请求查信任列表决定（撤销即时生效）。
    pub fn tls(&self, ips: &[Ipv4Addr]) -> Result<(Arc<rustls::ServerConfig>, Arc<rustls::ServerConfig>)> {
        df_core::tls::ensure_provider();
        let chain = self.server_chain(ips)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(self.ca_der.clone())).map_err(Failure::io)?;
        let roots = Arc::new(roots);
        let build = |optional: bool| -> Result<Arc<rustls::ServerConfig>> {
            let builder = rustls::server::WebPkiClientVerifier::builder(roots.clone());
            let verifier = if optional { builder.allow_unauthenticated().build() } else { builder.build() }
                .map_err(Failure::io)?;
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key.serialize_der()));
            let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(verifier)
                .with_single_cert(chain.clone(), key)
                .map_err(Failure::io)?;
            Ok(Arc::new(config))
        };
        Ok((build(true)?, build(false)?))
    }
}

pub fn pem(der: &[u8]) -> String {
    df_core::keys::der_to_pem(der, "CERTIFICATE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_identity_and_client_chain() {
        let dir = std::env::temp_dir().join(format!("df-node-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.ca_der, b.ca_der);

        // 重载后签发的客户端证书仍链到最初的 CA（客户端视角：rustls 用该 CA 校验）
        let client = df_core::keys::SigningIdentity::generate();
        let cert = b.issue_client(&client.spki_der()).unwrap();
        assert_eq!(df_core::keys::cert_spki_der(&cert).unwrap(), client.spki_der());
        let (control, data) = a.tls(&["192.168.1.19".parse().unwrap()]).unwrap();
        assert!(control.alpn_protocols.is_empty() && data.alpn_protocols.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
