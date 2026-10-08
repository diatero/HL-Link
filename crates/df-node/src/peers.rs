//! 已信任的控制端（对应 `PeerStore.java`）。键 = 客户端证书 DER 的 SHA-256（peerId）。
//! 文件 0600；最多 32 个。名称只是标签，不参与任何信任判断。

use crate::wire::{Failure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    /// 客户端证书 DER（base64）。
    pub cert: String,
    /// DF-BLE-1 控制密钥（base64）。桌面节点暂不提供 BLE，仍按协议签发以兼容控制端校验。
    #[serde(rename = "bleKey")]
    pub ble_key: String,
    pub auto: bool,
    #[serde(default)]
    pub added: u64,
}

pub struct PeerStore {
    path: PathBuf,
    peers: Mutex<BTreeMap<String, Peer>>,
}

impl PeerStore {
    pub fn open(dir: &Path) -> Result<PeerStore> {
        let path = dir.join("peers.json");
        let peers = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(Failure::io)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(PeerStore { path, peers: Mutex::new(peers) })
    }

    fn save(&self, peers: &BTreeMap<String, Peer>) -> Result<()> {
        df_core::fsutil::atomic_write(&self.path, &serde_json::to_vec_pretty(peers).map_err(Failure::io)?)
            .map_err(Failure::io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn add(&self, name: &str, cert_der: &[u8], ble_key: &[u8], auto: bool) -> Result<String> {
        let mut peers = self.peers.lock().unwrap();
        let id = crate::wire::sha256_hex(cert_der);
        if peers.len() >= 32 && !peers.contains_key(&id) {
            return Err(Failure::new("NO_SPACE", "Trusted device limit"));
        }
        peers.insert(
            id.clone(),
            Peer {
                name: name.to_string(),
                cert: crate::wire::b64(cert_der),
                ble_key: crate::wire::b64(ble_key),
                auto,
                added: crate::wire::now_ms(),
            },
        );
        self.save(&peers)?;
        Ok(id)
    }

    /// 未知或已撤销 → AUTH_FAILED（每个已认证请求都调用，撤销即时生效）。
    pub fn get(&self, id: &str) -> Result<Peer> {
        self.peers
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| Failure::new("AUTH_FAILED", "Unknown or revoked peer"))
    }

    pub fn contains(&self, id: &str) -> bool {
        self.peers.lock().unwrap().contains_key(id)
    }

    pub fn list(&self) -> Vec<(String, Peer)> {
        self.peers.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        match peers.get_mut(id) {
            Some(p) if p.name != name => {
                p.name = name.to_string();
                self.save(&peers)
            }
            Some(_) => Ok(()),
            None => Err(Failure::new("AUTH_FAILED", "Unknown or revoked peer")),
        }
    }

    pub fn set_auto(&self, id: &str, auto: bool) -> Result<()> {
        let mut peers = self.peers.lock().unwrap();
        let p = peers.get_mut(id).ok_or_else(|| Failure::new("AUTH_FAILED", "Unknown peer"))?;
        p.auto = auto;
        self.save(&peers)
    }

    pub fn remove(&self, id: &str) -> Result<bool> {
        let mut peers = self.peers.lock().unwrap();
        let removed = peers.remove(id).is_some();
        if removed {
            self.save(&peers)?;
        }
        Ok(removed)
    }
}
