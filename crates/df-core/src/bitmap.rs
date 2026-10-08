//! Java BitSet 兼容的 haveBits 编解码：
//! 字节 k 的位 j 表示块 8k+j；空位图为空字符串。base64(std)。

use crate::error::{DfError, Result};
use std::collections::BTreeSet;

/// 编码为 base64（空集合 → ""）。
pub fn encode_bits(set: &BTreeSet<u64>) -> String {
    if set.is_empty() {
        return String::new();
    }
    let max = *set.iter().max().unwrap();
    let mut bytes = vec![0u8; (max / 8) as usize + 1];
    for &bit in set {
        bytes[(bit / 8) as usize] |= 1u8 << (bit % 8);
    }
    crate::crypto::b64_encode(&bytes)
}

/// 解码 base64 位图。`max_bits` 用于拒绝越界位（0 = 不限制）。
pub fn decode_bits(s: &str, max_bits: u64) -> Result<BTreeSet<u64>> {
    let mut set = BTreeSet::new();
    if s.is_empty() {
        return Ok(set);
    }
    let bytes = crate::crypto::b64_decode(s)?;
    for (k, &b) in bytes.iter().enumerate() {
        for j in 0..8 {
            if b & (1u8 << j) != 0 {
                let bit = (k as u64) * 8 + j;
                if max_bits != 0 && bit >= max_bits {
                    return Err(DfError::Protocol(format!("haveBits 越界: 块 {bit} 超出总数")));
                }
                set.insert(bit);
            }
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(encode_bits(&BTreeSet::new()), "");
        assert!(decode_bits("", 10).unwrap().is_empty());
    }

    #[test]
    fn java_bitset_semantics() {
        // Java: BitSet bs; bs.set(0); bs.set(8); bs.set(9); → bytes 0x01 0x03
        let mut set = BTreeSet::new();
        set.insert(0);
        set.insert(8);
        set.insert(9);
        let enc = encode_bits(&set);
        assert_eq!(crate::crypto::b64_decode(&enc).unwrap(), vec![0x01, 0x03]);
        assert_eq!(decode_bits(&enc, 0).unwrap(), set);
    }

    #[test]
    fn last_byte_and_out_of_range() {
        let mut set = BTreeSet::new();
        set.insert(15);
        let enc = encode_bits(&set);
        // Java BitSet.toByteArray：bit 15 → 第 1 字节的 bit 7，前置零字节保留
        assert_eq!(crate::crypto::b64_decode(&enc).unwrap(), vec![0x00, 0x80]);
        assert!(decode_bits(&enc, 15).is_err());
        assert_eq!(decode_bits(&enc, 16).unwrap(), set);
    }

    #[test]
    fn roundtrip_sparse() {
        let mut set = BTreeSet::new();
        for i in [3u64, 7, 8, 23, 100, 513] {
            set.insert(i);
        }
        assert_eq!(decode_bits(&encode_bits(&set), 0).unwrap(), set);
    }
}
