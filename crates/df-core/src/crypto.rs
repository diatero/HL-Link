//! 密码学原语：SHA-256、HMAC-SHA256、HKDF-SHA256、AES-256-GCM（ct‖16B tag）。
//! 所有编码细节必须与 vectors.json 逐字节一致（对拍见 tests）。

use crate::error::{DfError, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869)。
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|e| DfError::Crypto(format!("HKDF expand 失败: {e}")))?;
    Ok(okm)
}

pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| DfError::Crypto(format!("base64 解码失败: {e}")))
}

/// AES-256-GCM 加密，输出 `密文 ‖ 16 字节 tag`。nonce 必须为 12 字节。
pub fn gcm_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| DfError::Crypto("GCM 加密失败".into()))
}

/// AES-256-GCM 解密（输入为 `密文 ‖ tag`）。
pub fn gcm_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_with_tag: &[u8]) -> Result<Vec<u8>> {
    if ct_with_tag.len() < 16 {
        return Err(DfError::Crypto("GCM 密文过短".into()));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ct_with_tag, aad })
        .map_err(|_| DfError::Crypto("GCM 校验失败（tag 或 AAD 不匹配）".into()))
}

/// SAS 六位验证码：HMAC(k, "sas\n<digest>") 前 4 字节（大端无符号）mod 1,000,000，补零到 6 位。
pub fn sas_code(k32: &[u8; 32], digest_b64: &str) -> String {
    let mac = hmac_sha256(k32, format!("sas\n{digest_b64}").as_bytes());
    let n = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]);
    format!("{:06}", (n as u64) % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 附录 A Test Case 1（HKDF-SHA256, L=42）。
    #[test]
    fn hkdf_rfc5869_tc1() {
        let ikm = [0x0bu8; 22];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        let expected = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();
        assert_eq!(okm, expected);
    }

    /// RFC 4231 Test Case 1（HMAC-SHA256）。
    #[test]
    fn hmac_rfc4231_tc1() {
        let key = [0x0bu8; 20];
        let out = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// NIST GCMVS：AES-256-GCM，零密钥/零 IV/空明文 → tag 530f8afbc74536b9a963b4f1c4cb738b。
    #[test]
    fn gcm_nist_zero_vector() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let out = gcm_seal(&key, &nonce, b"", b"").unwrap();
        assert_eq!(hex::encode(&out), "530f8afbc74536b9a963b4f1c4cb738b");
        let pt = gcm_open(&key, &nonce, b"", &out).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn gcm_aad_tamper_fails() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ct = gcm_seal(&key, &nonce, b"aad", b"hello").unwrap();
        assert!(gcm_open(&key, &nonce, b"bad", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(gcm_open(&key, &nonce, b"aad", &bad).is_err());
    }

    #[test]
    fn sas_format() {
        let k = [7u8; 32];
        let code = sas_code(&k, "abc");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
