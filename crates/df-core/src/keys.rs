//! P-256 密钥与 X.509 工具：SPKI 编解码、ECDH、ECDSA(P-256) 签名、证书 DER 解析。

use crate::crypto::{b64_encode, sha256};
use crate::error::{DfError, Result};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;


/// P-256 SPKI 的固定 ASN.1 前缀（EC public key, prime256v1）+ 65 字节非压缩点。
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// 编码 P-256 公钥为 SPKI DER。
pub fn p256_spki(pk: &PublicKey) -> Vec<u8> {
    let mut out = P256_SPKI_PREFIX.to_vec();
    out.extend_from_slice(pk.to_encoded_point(false).as_bytes());
    out
}

/// 解析 SPKI DER。
pub fn parse_p256_spki(der: &[u8]) -> Result<PublicKey> {
    if der.len() != 26 + 65 || der[..26] != P256_SPKI_PREFIX || der[26] != 0x04 {
        return Err(DfError::Protocol("不是 P-256 SPKI（非压缩点）".into()));
    }
    PublicKey::from_sec1_bytes(&der[26..]).map_err(|_| DfError::Protocol("P-256 点非法".into()))
}

/// 新的 ECDH 临时密钥。
pub fn new_ecdh_secret() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

pub fn ecdh_public_key(sk: &SecretKey) -> PublicKey {
    sk.public_key()
}

/// ECDH P-256 共享密钥。
pub fn ecdh_shared(
    sk: &SecretKey,
    peer_spki: &[u8],
) -> Result<p256::elliptic_curve::ecdh::SharedSecret<p256::NistP256>> {
    let peer = parse_p256_spki(peer_spki)?;
    Ok(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine()))
}

/// ECDSA P-256 签名密钥（长期客户端私钥，配对前生成并持久保存）。
#[derive(Clone)]
pub struct SigningIdentity {
    pub key: SigningKey,
}

impl SigningIdentity {
    pub fn generate() -> Self {
        SigningIdentity { key: SigningKey::random(&mut OsRng) }
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| DfError::Crypto(format!("读取签名私钥失败: {e}")))?;
        Ok(SigningIdentity { key })
    }

    pub fn to_pkcs8_pem(&self) -> String {
        use p256::pkcs8::EncodePrivateKey;
        self.key.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }

    /// 证书公钥 SPKI DER（发送给节点签发客户端证书）。
    pub fn spki_der(&self) -> Vec<u8> {
        let mut out = P256_SPKI_PREFIX.to_vec();
        out.extend_from_slice(self.key.verifying_key().to_encoded_point(false).as_bytes());
        out
    }

    /// ECDSA-SHA256 签名（DER 编码）。
    pub fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }
}

/// 32 字节随机数（base64）。
pub fn random_b64_32() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b64_encode(&b)
}

/// 从 X.509 DER 证书中提取 SubjectPublicKeyInfo 的 DER。
pub fn cert_spki_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| DfError::Protocol(format!("证书解析失败: {e}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// nodeId / peerId：证书 SPKI DER 的 SHA-256 小写 hex（peerId 是整张证书 DER 的 SHA-256）。
pub fn node_id_from_ca_der(ca_der: &[u8]) -> Result<String> {
    Ok(hex::encode(sha256(&cert_spki_der(ca_der)?)))
}

pub fn peer_id_from_cert_der(cert_der: &[u8]) -> String {
    hex::encode(sha256(cert_der))
}

/// DER → PEM。
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = b64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// PEM（单块）→ DER。
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    crate::crypto::b64_decode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_roundtrip() {
        let sk = new_ecdh_secret();
        let point = ecdh_public_key(&sk);
        let der = p256_spki(&point);
        assert_eq!(der.len(), 91);
        let back = parse_p256_spki(&der).unwrap();
        assert_eq!(
            back.to_encoded_point(false).as_bytes(),
            point.to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn ecdh_agreement() {
        let a = new_ecdh_secret();
        let b = new_ecdh_secret();
        let s1 = ecdh_shared(&a, &p256_spki(&ecdh_public_key(&b))).unwrap();
        let s2 = ecdh_shared(&b, &p256_spki(&ecdh_public_key(&a))).unwrap();
        assert_eq!(s1.raw_secret_bytes(), s2.raw_secret_bytes());
    }

    #[test]
    fn signing_identity_roundtrip() {
        let id = SigningIdentity::generate();
        let pem = id.to_pkcs8_pem();
        let id2 = SigningIdentity::from_pkcs8_pem(&pem).unwrap();
        let msg = b"DF-PAIR-1\nx";
        let sig = id2.sign_der(msg);
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::VerifyingKey;
        let vk = VerifyingKey::from(&id2.key);
        vk.verify(msg, &Signature::from_der(&sig).unwrap()).unwrap();
    }

    #[test]
    fn pem_roundtrip() {
        let sk = new_ecdh_secret();
        let der = p256_spki(&ecdh_public_key(&sk));
        let pem = der_to_pem(&der, "PUBLIC KEY");
        assert_eq!(pem_to_der(&pem).unwrap(), der);
    }
}
