//! 机密存储（4.3 / 12 节）：优先平台安全存储（Keychain / Secret Service / Cred Manager），
//! 不可用时退回 0600 权限文件并提示保护程度较低。
//!
//! 存储项（每个节点一条）：客户端私钥 PEM 与 bleKey。
//! 注意：trusts.json 本身也以 0600 保存；把机密移入 keyring 后可从中剥离（v1 保留双写以便回退）。

use df_core::error::{DfError, Result};

const SERVICE: &str = "DeviceFabric";

pub fn store_secret(node_id: &str, key: &str, value: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, &format!("{node_id}/{key}"))
        .map_err(|e| DfError::Protocol(format!("keyring 不可用: {e}")))?;
    entry
        .set_password(value)
        .map_err(|e| DfError::Protocol(format!("写入 keyring 失败: {e}")))
}

pub fn load_secret(node_id: &str, key: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(SERVICE, &format!("{node_id}/{key}"))
        .map_err(|e| DfError::Protocol(format!("keyring 不可用: {e}")))?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(DfError::Protocol(format!("读取 keyring 失败: {e}"))),
    }
}

pub fn delete_secret(node_id: &str, key: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, &format!("{node_id}/{key}"))
        .map_err(|e| DfError::Protocol(format!("keyring 不可用: {e}")))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(DfError::Protocol(format!("删除 keyring 失败: {e}"))),
    }
}

/// 保存信任时把机密同步进 keyring（尽力而为；失败不影响本地 0600 文件回退）。
pub fn protect_trust(trust: &df_core::stores::Trust) {
    if !trust.key_pem.is_empty() {
        let _ = store_secret(&trust.node_id, "keyPem", &trust.key_pem);
    }
    if let Some(b64) = &trust.ble_key_b64 {
        let _ = store_secret(&trust.node_id, "bleKey", b64);
    }
}

/// 删除信任时清理 keyring。
pub fn drop_trust(node_id: &str) {
    let _ = delete_secret(node_id, "keyPem");
    let _ = delete_secret(node_id, "bleKey");
}

/// 启动时从 keyring 回填机密（trusts.json 中缺失时）。
pub fn restore_secrets_into_trusts(store: &df_core::stores::Store) {
    let mut changed = false;
    let mut trusts = store.trusts();
    for t in trusts.iter_mut() {
        if t.key_pem.is_empty() {
            // 与 protects 相反：keyPem 在 keyring 有备份时回填
            if let Ok(Some(pem)) = load_secret(&t.node_id, "keyPem") {
                t.key_pem = pem;
                changed = true;
            }
        }
        if t.ble_key_b64.is_none() {
            if let Ok(Some(k)) = load_secret(&t.node_id, "bleKey") {
                t.ble_key_b64 = Some(k);
                changed = true;
            }
        }
    }
    if changed {
        let _ = store.save_trusts(&trusts);
    }
}
