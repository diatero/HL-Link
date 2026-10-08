//! 持久化：信任设备、本机名称、clientId、待定身份（pending.<nodeId>）与任务记录。
//! 含机密数据的文件以 0600 权限保存；生产部署应由平台 SecretStore 接管私钥与 bleKey。

use crate::error::{DfError, Result};
use crate::fsutil;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 一个已信任节点的全部数据（4.3 节）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Trust {
    pub node_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub paired_at_ms: u64,
    /// 节点 CA（PEM），信任锚。
    pub ca_pem: String,
    /// 客户端证书（PEM）。
    pub cert_pem: String,
    /// 客户端私钥（PKCS#8 PEM）。机密：生产中放入平台安全存储后此处留空。
    #[serde(default)]
    pub key_pem: String,
    /// 客户端证书 DER SHA-256 小写 hex。
    #[serde(default)]
    pub peer_id: String,
    /// BLE 控制认证密钥（base64）。机密。
    #[serde(default)]
    pub ble_key_b64: Option<String>,
    /// 最近地址 / 端口 / 能力：只是连接提示。
    #[serde(default)]
    pub last_addr: Option<String>,
    #[serde(default)]
    pub control_port: u16,
    #[serde(default)]
    pub data_port: u16,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// 信任已失效（收到 AUTH_FAILED 后标记；不自动删除收件箱）。
    #[serde(default)]
    pub revoked: bool,
}

impl Trust {
    pub fn from_pair_result(pr: &crate::pairing::PairResult) -> Trust {
        Trust {
            node_id: pr.node_id.clone(),
            name: pr.node_name.clone(),
            paired_at_ms: now_ms(),
            ca_pem: pr.ca_pem.clone(),
            cert_pem: pr.cert_pem.clone(),
            key_pem: pr.key_pem.clone(),
            peer_id: pr.peer_id.clone(),
            ble_key_b64: pr.ble_key.map(|k| crate::crypto::b64_encode(&k)),
            last_addr: pr.addresses.first().cloned(),
            control_port: pr.control_port,
            data_port: pr.data_port,
            capabilities: Vec::new(),
            revoked: false,
        }
    }
}

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir.join("inbox"))?;
        std::fs::create_dir_all(dir.join("staging"))?;
        Ok(Store { dir: dir.to_path_buf() })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let p = self.path(name);
        if !p.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&p)?;
        Ok(Some(serde_json::from_slice(&data)?))
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let data = serde_json::to_vec_pretty(value)?;
        fsutil::atomic_write(&self.path(name), &data)?;
        restrict(&self.path(name));
        Ok(())
    }

    // —— 信任设备 ——
    pub fn trusts(&self) -> Vec<Trust> {
        self.read_json::<Vec<Trust>>("trusts.json").ok().flatten().unwrap_or_default()
    }

    pub fn save_trusts(&self, list: &[Trust]) -> Result<()> {
        self.write_json("trusts.json", &list)
    }

    pub fn trust(&self, node_id: &str) -> Option<Trust> {
        self.trusts().into_iter().find(|t| t.node_id == node_id)
    }

    pub fn upsert_trust(&self, t: Trust) -> Result<()> {
        let mut list = self.trusts();
        if let Some(slot) = list.iter_mut().find(|x| x.node_id == t.node_id) {
            *slot = t;
        } else {
            list.push(t);
        }
        self.save_trusts(&list)
    }

    /// 记录最近一次连通的地址（只是连接提示；只改这一字段，按文件当前内容重写）。
    pub fn set_last_addr(&self, node_id: &str, addr: &str) -> Result<()> {
        let mut list = self.trusts();
        match list.iter_mut().find(|t| t.node_id == node_id) {
            Some(t) if t.last_addr.as_deref() != Some(addr) => {
                t.last_addr = Some(addr.to_string());
                self.save_trusts(&list)
            }
            _ => Ok(()),
        }
    }

    /// 标记信任已失效（节点对本机证书回 AUTH_FAILED：手机上已解除信任）。
    pub fn set_revoked(&self, node_id: &str) -> Result<()> {
        let mut list = self.trusts();
        match list.iter_mut().find(|t| t.node_id == node_id) {
            Some(t) if !t.revoked => {
                t.revoked = true;
                self.save_trusts(&list)
            }
            _ => Ok(()),
        }
    }

    /// 删除信任（UI 提醒用户在手机上解除信任）。
    pub fn remove_trust(&self, node_id: &str) -> Result<bool> {
        let mut list = self.trusts();
        let before = list.len();
        list.retain(|t| t.node_id != node_id);
        if list.len() != before {
            self.save_trusts(&list)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // —— 本机身份 ——
    pub fn client_id(&self) -> String {
        if let Some(v) = self.read_json::<serde_json::Value>("identity.json").ok().flatten() {
            if let Some(id) = v.get("clientId").and_then(|x| x.as_str()) {
                return id.to_string();
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let _ = self.write_json("identity.json", &serde_json::json!({ "clientId": id }));
        id
    }

    pub fn local_name(&self) -> Option<String> {
        self.read_json::<serde_json::Value>("identity.json")
            .ok()
            .flatten()
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
            .filter(|s| crate::names::sanitize_display_name(s).is_some())
    }

    /// None = 跟随系统名称。
    pub fn set_local_name(&self, name: Option<&str>) -> Result<()> {
        let mut v = self
            .read_json::<serde_json::Value>("identity.json")
            .ok()
            .flatten()
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(n) = name {
            let sanitized = crate::names::sanitize_display_name(n)
                .ok_or_else(|| DfError::Protocol("名称不合规（1..64，无控制字符）".into()))?;
            v["name"] = serde_json::Value::String(sanitized);
        } else {
            v.as_object_mut().unwrap().remove("name");
        }
        self.write_json("identity.json", &v)
    }

    // —— 待定身份（PAIR 重试用同一私钥，成功保存信任后删除）——
    pub fn set_pending_key(&self, node_id: &str, pem: &str) -> Result<()> {
        self.write_json(&format!("pending.{node_id}.json"), &serde_json::json!({ "keyPem": pem }))
    }

    pub fn take_pending_key(&self, node_id: &str) -> Option<String> {
        let p = self.path(&format!("pending.{node_id}.json"));
        let pem = self
            .read_json::<serde_json::Value>(&format!("pending.{node_id}.json"))
            .ok()
            .flatten()
            .and_then(|v| v.get("keyPem").and_then(|k| k.as_str()).map(String::from))?;
        let _ = std::fs::remove_file(&p);
        Some(pem)
    }

    // —— 目录 ——
    pub fn inbox_dir(&self) -> PathBuf {
        self.dir.join("inbox")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.dir.join("staging")
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(unix)]
fn restrict(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> Store {
        let dir = std::env::temp_dir().join(format!(
            "df-store-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        Store::open(&dir).unwrap()
    }

    #[test]
    fn trust_roundtrip() {
        let s = temp_store();
        let t = Trust { node_id: "abc".into(), ca_pem: "CA".into(), ..Default::default() };
        s.upsert_trust(t).unwrap();
        assert_eq!(s.trust("abc").unwrap().ca_pem, "CA");
        s.upsert_trust(Trust { node_id: "abc".into(), ca_pem: "CA2".into(), ..Default::default() }).unwrap();
        assert_eq!(s.trusts().len(), 1);
        assert!(s.remove_trust("abc").unwrap());
        assert!(s.trust("abc").is_none());
        let _ = std::fs::remove_dir_all(&s.dir);
    }

    #[test]
    fn identity_and_pending() {
        let s = temp_store();
        let id1 = s.client_id();
        assert_eq!(s.client_id(), id1);
        assert!(crate::names::sanitize_display_name(&id1).is_some());

        s.set_local_name(Some("工作机")).unwrap();
        assert_eq!(s.local_name().unwrap(), "工作机");
        s.set_local_name(Some("  ")).unwrap_err();
        s.set_local_name(None).unwrap();
        assert!(s.local_name().is_none());

        s.set_pending_key("n1", "PEM").unwrap();
        assert_eq!(s.take_pending_key("n1").unwrap(), "PEM");
        assert!(s.take_pending_key("n1").is_none());
        let _ = std::fs::remove_dir_all(&s.dir);
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let s = temp_store();
        s.set_local_name(Some("x")).unwrap();
        let mode = std::fs::metadata(s.path("identity.json")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&s.dir);
    }
}
