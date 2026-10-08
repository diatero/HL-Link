//! 接收记录（对应 `TransferStore.java`）：控制端 → 本节点的 FILE_OFFER / RESUME / TEXT_OFFER。
//!
//! 每块：校验索引/长度/哈希 → 写入暂存 `.part` 的绝对偏移 → fsync → 原子保存位图记录 → 才 ACK。
//! 已保存的重复块必须哈希一致。整文件 SHA-256 通过后才移动到收件目录（不覆盖同名文件），
//! 未完成或已取消的文件从不出现在收件目录。最多 64 条记录（已结束的记录在满额时自动清理最旧的）。

use crate::wire::{self, Failure, Result, CHUNK};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 64;

pub struct Transfer {
    pub id: String,
    pub peer: String,
    pub size: u64,
    pub count: u64,
    meta: Map<String, Value>,
    bits: BTreeSet<u64>,
    pub busy: bool,
    record: PathBuf,
    part: PathBuf,
}

pub type Shared = Arc<Mutex<Transfer>>;

pub struct Incoming {
    dir: PathBuf,
    inbox: PathBuf,
    transfers: Mutex<HashMap<String, Shared>>,
}

impl Incoming {
    pub fn open(dir: &Path, inbox: &Path) -> Result<Incoming> {
        std::fs::create_dir_all(dir)?;
        let mut transfers = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta: Map<String, Value> = match std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
                Some(m) => m,
                None => continue,
            };
            let t = Transfer::from_meta(dir, meta)?;
            transfers.insert(t.id.clone(), Arc::new(Mutex::new(t)));
        }
        Ok(Incoming { dir: dir.to_path_buf(), inbox: inbox.to_path_buf(), transfers: Mutex::new(transfers) })
    }

    pub fn inbox(&self) -> &Path {
        &self.inbox
    }

    pub fn offer(&self, peer: &str, b: &Map<String, Value>) -> Result<Shared> {
        let id = wire::string(b, "transferId")?;
        if !wire::valid_transfer_id(id) {
            return Err(Failure::new("INVALID_FRAME", "Transfer ID"));
        }
        let size = wire::decimal(b, "size")?;
        let chunk = wire::decimal(b, "chunkSize")?;
        let sha = wire::string(b, "sha256")?;
        if size > LIMIT || chunk != CHUNK || !wire::valid_sha256(sha) {
            return Err(Failure::new("INVALID_FRAME", "File size, chunk size or hash"));
        }
        let name = wire::string(b, "name")?;
        let mime = wire::string(b, "mime")?;
        if !wire::valid_name(name) {
            return Err(Failure::new("INVALID_FRAME", "Unsafe filename"));
        }
        if !wire::valid_mime(mime) {
            return Err(Failure::new("INVALID_FRAME", "MIME type"));
        }
        let mut transfers = self.transfers.lock().unwrap();
        if let Some(old) = transfers.get(id) {
            let t = old.lock().unwrap();
            if t.peer != peer {
                return Err(Failure::new("PERMISSION_DENIED", "Transfer owner"));
            }
            if t.size != size || t.meta_str("sha256") != sha || t.meta_str("name") != name || t.meta_str("mime") != mime {
                return Err(Failure::new("SOURCE_CHANGED", "Transfer metadata changed"));
            }
            return Ok(old.clone());
        }
        if transfers.len() >= MAX_RECORDS {
            Self::prune(&mut transfers);
            if transfers.len() >= MAX_RECORDS {
                return Err(Failure::new("NO_SPACE", "Remove old transfer records first"));
            }
        }
        let reserved: u64 = transfers
            .values()
            .map(|t| t.lock().unwrap())
            .filter(|t| !t.done() && !t.cancelled())
            .map(|t| t.size * 2)
            .sum();
        let free = df_core::fsutil::free_space(&self.dir).map_err(Failure::io)?;
        if reserved + size * 2 + 64 * 1024 * 1024 > free {
            return Err(Failure::new("NO_SPACE", "Insufficient staging and final copy space"));
        }
        let mut meta = Map::new();
        for k in ["transferId", "name", "mime", "size", "chunkSize", "sha256"] {
            meta.insert(k.into(), b[k].clone());
        }
        meta.insert("peer".into(), json!(peer));
        meta.insert("state".into(), json!("OFFERED"));
        meta.insert("bits".into(), json!(""));
        meta.insert("created".into(), json!(wire::now_ms().to_string()));
        let t = Transfer::from_meta(&self.dir, meta)?;
        t.save()?;
        let shared = Arc::new(Mutex::new(t));
        transfers.insert(id.to_string(), shared.clone());
        Ok(shared)
    }

    /// 满额时清理已结束（非活动）的记录，最旧的优先；不删除收件目录里的文件。
    fn prune(transfers: &mut HashMap<String, Shared>) {
        let mut finished: Vec<(String, String)> = transfers
            .iter()
            .filter_map(|(id, t)| {
                let t = t.lock().unwrap();
                (!t.busy && (t.done() || t.cancelled())).then(|| (t.meta_str("created").to_string(), id.clone()))
            })
            .collect();
        finished.sort();
        for (_, id) in finished.into_iter().take(transfers.len().saturating_sub(MAX_RECORDS - 1)) {
            if let Some(t) = transfers.remove(&id) {
                let t = t.lock().unwrap();
                let _ = std::fs::remove_file(&t.record);
                let _ = std::fs::remove_file(&t.part);
            }
        }
    }

    pub fn get(&self, peer: &str, id: &str) -> Result<Shared> {
        let transfers = self.transfers.lock().unwrap();
        match transfers.get(id) {
            Some(t) if t.lock().unwrap().peer == peer => Ok(t.clone()),
            _ => Err(Failure::new("PERMISSION_DENIED", "Unknown transfer or owner")),
        }
    }

    pub fn list(&self, peer: Option<&str>) -> Vec<Value> {
        let transfers = self.transfers.lock().unwrap();
        transfers
            .values()
            .filter_map(|t| {
                let t = t.lock().unwrap();
                peer.is_none_or(|p| t.peer == p).then(|| t.status())
            })
            .collect()
    }

    /// 本机界面视图：状态 + 发送方、MIME、本地路径、到达时间（不发给对端）。
    pub fn views(&self) -> Vec<Value> {
        let transfers = self.transfers.lock().unwrap();
        transfers
            .values()
            .map(|t| {
                let t = t.lock().unwrap();
                let mut v = t.status();
                v["peer"] = json!(t.peer);
                v["mime"] = json!(t.meta_str("mime"));
                v["created"] = json!(t.meta_str("created"));
                v["path"] = json!(t.meta_str("path"));
                v
            })
            .collect()
    }

    pub fn cancel_all(&self, peer: &str) {
        for t in self.transfers.lock().unwrap().values() {
            let mut t = t.lock().unwrap();
            if t.peer == peer && !t.done() {
                let _ = t.cancel();
            }
        }
    }

    pub fn forget_finished(&self) -> usize {
        let mut transfers = self.transfers.lock().unwrap();
        let before = transfers.len();
        transfers.retain(|_, t| {
            let t = t.lock().unwrap();
            let gone = !t.busy && (t.done() || t.cancelled());
            if gone {
                let _ = std::fs::remove_file(&t.record);
                let _ = std::fs::remove_file(&t.part);
            }
            !gone
        });
        before - transfers.len()
    }
}

impl Transfer {
    fn from_meta(dir: &Path, meta: Map<String, Value>) -> Result<Transfer> {
        let id = wire::string(&meta, "transferId")?.to_string();
        if !wire::valid_transfer_id(&id) {
            return Err(Failure::io("Invalid stored transfer ID"));
        }
        let peer = wire::string(&meta, "peer")?.to_string();
        let size = wire::decimal(&meta, "size")?;
        let count = size.div_ceil(CHUNK);
        let bits = df_core::bitmap::decode_bits(meta.get("bits").and_then(Value::as_str).unwrap_or(""), count)
            .map_err(Failure::io)?;
        Ok(Transfer {
            record: dir.join(format!("{id}.json")),
            part: dir.join(format!("{id}.part")),
            id,
            peer,
            size,
            count,
            meta,
            bits,
            busy: false,
        })
    }

    fn meta_str(&self, k: &str) -> &str {
        self.meta.get(k).and_then(Value::as_str).unwrap_or("")
    }

    fn set_state(&mut self, state: &str) -> Result<()> {
        self.meta.insert("state".into(), json!(state));
        self.save()
    }

    fn save(&self) -> Result<()> {
        let mut meta = self.meta.clone();
        meta.insert("bits".into(), json!(df_core::bitmap::encode_bits(&self.bits)));
        df_core::fsutil::atomic_write(&self.record, &serde_json::to_vec(&meta).map_err(Failure::io)?).map_err(Failure::io)
    }

    pub fn state(&self) -> &str {
        self.meta_str("state")
    }
    pub fn name(&self) -> &str {
        self.meta_str("name")
    }
    /// 收件目录中的本地路径（只给本机界面，不发给对端）。
    pub fn path(&self) -> &str {
        self.meta_str("path")
    }
    pub fn done(&self) -> bool {
        self.state() == "COMPLETE"
    }
    pub fn cancelled(&self) -> bool {
        self.state() == "CANCELLED"
    }
    pub fn accepted(&self) -> bool {
        self.state() != "OFFERED"
    }
    pub fn complete_bits(&self) -> bool {
        self.bits.len() as u64 == self.count
    }
    pub fn bitmap(&self) -> String {
        df_core::bitmap::encode_bits(&self.bits)
    }

    pub fn accept(&mut self) -> Result<()> {
        if !self.accepted() {
            self.set_state("RECEIVING")?;
        }
        Ok(())
    }

    pub fn begin(&mut self) -> Result<()> {
        if self.busy {
            return Err(Failure::new("P2P_BUSY", "Transfer already active"));
        }
        if !self.accepted() || self.cancelled() {
            return Err(Failure::new("PERMISSION_DENIED", "Transfer not accepted"));
        }
        self.busy = true;
        Ok(())
    }

    pub fn received(&self) -> u64 {
        let mut received = self.bits.len() as u64 * CHUNK;
        if self.count > 0 && self.bits.contains(&(self.count - 1)) {
            received -= self.count * CHUNK - self.size;
        }
        received
    }

    pub fn status(&self) -> Value {
        json!({
            "transferId": self.id,
            "name": self.name(),
            "state": self.state(),
            "size": self.size.to_string(),
            "received": self.received().to_string(),
            "uri": if self.done() { format!("content://hllink.desktop/received/{}", self.id) } else { String::new() },
        })
    }

    /// 写入一块（阻塞 I/O：调用方在 spawn_blocking 中执行）。
    pub fn chunk(&mut self, index: u64, data: &[u8], hash: &[u8; 32]) -> Result<()> {
        if self.cancelled() || self.done() {
            return Err(Failure::new("CANCELLED", "Transfer closed"));
        }
        if index >= self.count || data.len() as u64 != CHUNK.min(self.size - index * CHUNK) {
            return Err(Failure::new("INVALID_FRAME", "Chunk bounds"));
        }
        if df_core::crypto::sha256(data) != *hash {
            return Err(Failure::new("HASH_MISMATCH", "Chunk hash"));
        }
        let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&self.part)?;
        f.seek(SeekFrom::Start(index * CHUNK))?;
        if self.bits.contains(&index) {
            let mut old = vec![0u8; data.len()];
            f.read_exact(&mut old)?;
            if df_core::crypto::sha256(&old) != *hash {
                return Err(Failure::new("SOURCE_CHANGED", "Duplicate chunk differs"));
            }
            return self.save();
        }
        f.write_all(data)?;
        f.sync_all()?;
        self.bits.insert(index);
        self.save()
    }

    /// 整文件校验 → 移到收件目录（不覆盖）→ COMPLETE。阻塞 I/O。
    pub fn finish(&mut self, inbox: &Path) -> Result<Value> {
        if self.done() {
            return Ok(self.status());
        }
        if self.cancelled() {
            return Err(Failure::new("CANCELLED", "Transfer cancelled"));
        }
        if !self.complete_bits() {
            return Err(Failure::new("INVALID_FRAME", "Missing chunks"));
        }
        let mut path = PathBuf::from(self.meta_str("path"));
        if self.meta_str("path").is_empty() || self.part.exists() {
            if self.size == 0 && !self.part.exists() {
                std::fs::File::create(&self.part)?;
            }
            self.set_state("VERIFYING")?;
            if hash_file(&self.part)? != self.meta_str("sha256") {
                self.set_state("HASH_ERROR")?;
                return Err(Failure::new("HASH_MISMATCH", "Whole file hash"));
            }
            if self.meta_str("path").is_empty() {
                std::fs::create_dir_all(inbox)?;
                let local = if self.name() == "text.txt" && self.meta_str("mime") == "text/plain" {
                    format!("文本-{}.txt", &self.id[..8])
                } else {
                    self.name().to_string()
                };
                path = inbox.join(df_core::names::unique_filename(inbox, &local));
                self.meta.insert("path".into(), json!(path.to_string_lossy()));
                self.set_state("SAVING")?;
            }
            publish(&self.part, &path)?;
        }
        // 回执是节点本地的不透明标识（DF1.md：node-local content URI，不是下载地址）。
        // 不把本机路径（含用户名、目录）发给对端；本地路径只在本机视图的 path 字段里。
        // 现有 HL Link 只接受 content:// 回执。
        self.meta.insert("uri".into(), json!(format!("content://hllink.desktop/received/{}", self.id)));
        self.set_state("COMPLETE")?;
        Ok(self.status())
    }

    pub fn cancel(&mut self) -> Result<()> {
        if self.done() {
            return Ok(());
        }
        self.set_state("CANCELLED")?;
        let _ = std::fs::remove_file(&self.part);
        Ok(())
    }
}

/// 暂存文件 → 收件路径：同一文件系统直接 rename；否则复制到同目录临时名、fsync 后再 rename。
fn publish(part: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::rename(part, dest).is_err() {
        let tmp = dest.with_file_name(format!(".{}.hl-part", dest.file_name().and_then(|n| n.to_str()).unwrap_or("f")));
        {
            let mut out = std::fs::File::create(&tmp)?;
            std::io::copy(&mut std::fs::File::open(part)?, &mut out)?;
            out.sync_all()?;
        }
        std::fs::rename(&tmp, dest)?;
        let _ = std::fs::remove_file(part);
    }
    if let Some(parent) = dest.parent() {
        let _ = df_core::fsutil::sync_dir(parent);
    }
    Ok(())
}

pub fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
