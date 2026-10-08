//! 待对端拉取的发送记录（对应 `OutgoingStore.java`，DF1.md「Reverse file transfer extension」）。
//!
//! 选中的文件先复制到私有暂存（边复制边算 SHA-256），之后与源文件解耦，跨重启保留；
//! 只有暂存完成（WAITING）后才出现在该对端的 PULL_LIST 里。最多 64 条记录。

use crate::wire::{self, Failure, Result, CHUNK};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_RECORDS: usize = 64;

pub struct Send {
    pub id: String,
    pub peer: String,
    meta: Map<String, Value>,
    pub busy: bool,
    pub part: PathBuf,
    record: PathBuf,
}

pub type Shared = Arc<Mutex<Send>>;

pub struct Outgoing {
    dir: PathBuf,
    sends: Mutex<HashMap<String, Shared>>,
}

impl Outgoing {
    pub fn open(dir: &Path) -> Result<Outgoing> {
        std::fs::create_dir_all(dir)?;
        let mut sends = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(meta) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Map<String, Value>>(&b).ok())
            else {
                continue;
            };
            let mut s = Send::from_meta(dir, meta)?;
            match s.state() {
                "STAGING" => {
                    s.meta.insert("state".into(), json!("FAILED"));
                    s.meta.insert("error".into(), json!("文件准备被中断，请重新选择文件"));
                    let _ = std::fs::remove_file(&s.part);
                }
                "SENDING" => {
                    s.meta.insert("state".into(), json!("WAITING"));
                }
                _ => {}
            }
            s.save()?;
            sends.insert(s.id.clone(), Arc::new(Mutex::new(s)));
        }
        Ok(Outgoing { dir: dir.to_path_buf(), sends: Mutex::new(sends) })
    }

    pub fn create(&self, peer: &str) -> Result<Shared> {
        let mut sends = self.sends.lock().unwrap();
        if sends.len() >= MAX_RECORDS {
            Self::prune(&mut sends);
            if sends.len() >= MAX_RECORDS {
                return Err(Failure::new("NO_SPACE", "Remove completed send records first"));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut meta = Map::new();
        meta.insert("transferId".into(), json!(id));
        meta.insert("peer".into(), json!(peer));
        meta.insert("name".into(), json!("正在准备文件"));
        meta.insert("mime".into(), json!("application/octet-stream"));
        meta.insert("size".into(), json!("0"));
        meta.insert("chunkSize".into(), json!(CHUNK.to_string()));
        meta.insert("sha256".into(), json!(""));
        meta.insert("state".into(), json!("STAGING"));
        meta.insert("sent".into(), json!("0"));
        meta.insert("created".into(), json!(wire::now_ms().to_string()));
        let s = Send::from_meta(&self.dir, meta)?;
        s.save()?;
        let shared = Arc::new(Mutex::new(s));
        sends.insert(id, shared.clone());
        Ok(shared)
    }

    fn prune(sends: &mut HashMap<String, Shared>) {
        let mut finished: Vec<(String, String)> = sends
            .iter()
            .filter_map(|(id, s)| {
                let s = s.lock().unwrap();
                (!s.busy && s.terminal()).then(|| (s.meta_str("created").to_string(), id.clone()))
            })
            .collect();
        finished.sort();
        for (_, id) in finished.into_iter().take(sends.len().saturating_sub(MAX_RECORDS - 1)) {
            if let Some(s) = sends.remove(&id) {
                let s = s.lock().unwrap();
                let _ = std::fs::remove_file(&s.record);
                let _ = std::fs::remove_file(&s.part);
            }
        }
    }

    pub fn get(&self, peer: &str, id: &str) -> Result<Shared> {
        let sends = self.sends.lock().unwrap();
        match sends.get(id) {
            Some(s) if s.lock().unwrap().peer == peer => Ok(s.clone()),
            _ => Err(Failure::new("PERMISSION_DENIED", "Unknown send or owner")),
        }
    }

    pub fn find(&self, id: &str) -> Option<Shared> {
        self.sends.lock().unwrap().get(id).cloned()
    }

    /// PULL_LIST 的 offers：只含该对端已就绪（WAITING/SENDING）的不可变清单。
    pub fn offers(&self, peer: &str) -> Vec<Value> {
        self.sends
            .lock()
            .unwrap()
            .values()
            .filter_map(|s| {
                let s = s.lock().unwrap();
                (s.peer == peer && s.offered()).then(|| s.offer())
            })
            .collect()
    }

    /// PULL_LIST 的 ended：该对端已结束的记录状态（COMPLETE / CANCELLED / FAILED）。
    pub fn ended(&self, peer: &str) -> Vec<Value> {
        self.sends
            .lock()
            .unwrap()
            .values()
            .filter_map(|s| {
                let s = s.lock().unwrap();
                (s.peer == peer && s.terminal()).then(|| json!({ "transferId": s.id, "state": s.state() }))
            })
            .collect()
    }

    pub fn views(&self) -> Vec<Value> {
        self.sends.lock().unwrap().values().map(|s| Value::Object(s.lock().unwrap().meta.clone())).collect()
    }

    pub fn cancel_all(&self, peer: &str) {
        for s in self.sends.lock().unwrap().values() {
            let mut s = s.lock().unwrap();
            if s.peer == peer && !s.terminal() {
                let _ = s.cancel();
            }
        }
    }

    pub fn forget_finished(&self) -> usize {
        let mut sends = self.sends.lock().unwrap();
        let before = sends.len();
        sends.retain(|_, s| {
            let s = s.lock().unwrap();
            let gone = !s.busy && s.terminal();
            if gone {
                let _ = std::fs::remove_file(&s.record);
                let _ = std::fs::remove_file(&s.part);
            }
            !gone
        });
        before - sends.len()
    }
}

impl Send {
    fn from_meta(dir: &Path, meta: Map<String, Value>) -> Result<Send> {
        let id = wire::string(&meta, "transferId")?.to_string();
        if !wire::valid_transfer_id(&id) {
            return Err(Failure::io("Invalid stored transfer ID"));
        }
        let peer = wire::string(&meta, "peer")?.to_string();
        Ok(Send {
            part: dir.join(format!("{id}.part")),
            record: dir.join(format!("{id}.json")),
            id,
            peer,
            meta,
            busy: false,
        })
    }

    fn meta_str(&self, k: &str) -> &str {
        self.meta.get(k).and_then(Value::as_str).unwrap_or("")
    }

    fn save(&self) -> Result<()> {
        df_core::fsutil::atomic_write(&self.record, &serde_json::to_vec(&self.meta).map_err(Failure::io)?).map_err(Failure::io)
    }

    fn set(&mut self, k: &str, v: Value) {
        self.meta.insert(k.into(), v);
    }

    pub fn state(&self) -> &str {
        self.meta_str("state")
    }
    pub fn size(&self) -> u64 {
        self.meta_str("size").parse().unwrap_or(0)
    }
    pub fn terminal(&self) -> bool {
        matches!(self.state(), "COMPLETE" | "CANCELLED" | "FAILED")
    }
    pub fn offered(&self) -> bool {
        matches!(self.state(), "WAITING" | "SENDING")
    }

    /// 对端可见的状态（不含本地的 created）。
    pub fn status(&self) -> Value {
        let mut m = self.meta.clone();
        m.remove("created");
        m.remove("source");
        Value::Object(m)
    }

    pub fn offer(&self) -> Value {
        json!({
            "transferId": self.id,
            "name": self.meta_str("name"),
            "mime": self.meta_str("mime"),
            "size": self.meta_str("size"),
            "chunkSize": CHUNK.to_string(),
            "sha256": self.meta_str("sha256"),
        })
    }

    /// 从本地文件暂存（阻塞 I/O）。失败记为 FAILED 并删除暂存。
    pub fn stage(&mut self, source: &Path, mime: &str, stopped: &dyn Fn() -> bool) -> Result<()> {
        let result = (|| -> Result<()> {
            let raw = source.file_name().and_then(|n| n.to_str()).unwrap_or("shared-file");
            let mut name: String = raw.chars().map(|c| if c.is_control() || c == '/' || c == '\\' { '_' } else { c }).collect();
            if name.is_empty() || name == "." || name == ".." {
                name = "shared-file".into();
            }
            name = name.chars().take(128).collect();
            let mime = if wire::valid_mime(mime) { mime } else { "application/octet-stream" };
            self.set("name", json!(name));
            self.set("mime", json!(mime));
            self.set("source", json!(source.to_string_lossy()));
            self.save()?;
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            let mut size: u64 = 0;
            let mut input = std::fs::File::open(source)?;
            let mut out = std::fs::File::create(&self.part)?;
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if stopped() || self.terminal() {
                    return Err(Failure::new("CANCELLED", "Preparation ended"));
                }
                if size + n as u64 > crate::incoming::LIMIT {
                    return Err(Failure::new("NO_SPACE", "File exceeds storage limit"));
                }
                std::io::Write::write_all(&mut out, &buf[..n])?;
                hash.update(&buf[..n]);
                size += n as u64;
            }
            out.sync_all()?;
            if stopped() || self.terminal() {
                return Err(Failure::new("CANCELLED", "Preparation ended"));
            }
            self.set("size", json!(size.to_string()));
            self.set("sha256", json!(hex::encode(hash.finalize())));
            self.set("state", json!("WAITING"));
            self.save()
        })();
        if let Err(e) = &result {
            if self.state() != "CANCELLED" {
                self.set("state", json!("FAILED"));
                self.set("error", json!(e.code));
                let _ = self.save();
            }
            let _ = std::fs::remove_file(&self.part);
        }
        result
    }

    /// 校验 PULL_ACCEPT 的 haveBits（Java BitSet 小端，长度不超过块数）。
    pub fn bitmap(&self, encoded: &str) -> Result<BTreeSet<u64>> {
        if !self.offered() {
            return Err(Failure::new("CANCELLED", "Send ended"));
        }
        self.check_part()?;
        let count = self.size().div_ceil(CHUNK);
        let raw = wire::unb64(encoded)?;
        if raw.len() as u64 > count.div_ceil(8) {
            return Err(Failure::new("INVALID_FRAME", "Resume bitmap"));
        }
        df_core::bitmap::decode_bits(encoded, count).map_err(|_| Failure::new("INVALID_FRAME", "Resume bitmap"))
    }

    fn check_part(&self) -> Result<()> {
        match std::fs::metadata(&self.part) {
            Ok(m) if m.len() == self.size() => Ok(()),
            _ => Err(Failure::new("SOURCE_CHANGED", "Staged source unavailable")),
        }
    }

    pub fn begin(&mut self, bits: &BTreeSet<u64>) -> Result<()> {
        if !self.offered() {
            return Err(Failure::new("CANCELLED", "Send ended"));
        }
        if self.busy {
            return Err(Failure::new("P2P_BUSY", "Send active"));
        }
        self.check_part()?;
        self.set("state", json!("SENDING"));
        if let Err(e) = self.progress(bits) {
            self.set("state", json!("WAITING"));
            return Err(e);
        }
        self.busy = true;
        Ok(())
    }

    pub fn progress(&mut self, bits: &BTreeSet<u64>) -> Result<()> {
        if self.terminal() {
            return Err(Failure::new("CANCELLED", "Send ended"));
        }
        let size = self.size();
        let count = size.div_ceil(CHUNK);
        let mut sent = bits.len() as u64 * CHUNK;
        if count > 0 && bits.contains(&(count - 1)) {
            sent -= count * CHUNK - size;
        }
        self.set("sent", json!(sent.to_string()));
        self.save()
    }

    pub fn end(&mut self) {
        self.busy = false;
        if self.state() == "SENDING" {
            self.set("state", json!("WAITING"));
            let _ = self.save();
        }
        if self.terminal() {
            let _ = std::fs::remove_file(&self.part);
        }
    }

    pub fn complete(&mut self, b: &Map<String, Value>) -> Result<()> {
        if wire::decimal(b, "size")? != self.size() || wire::string(b, "sha256")? != self.meta_str("sha256") {
            return Err(Failure::new("HASH_MISMATCH", "Receiver completion mismatch"));
        }
        if self.state() == "COMPLETE" {
            return Ok(());
        }
        if !self.offered() {
            return Err(Failure::new("CANCELLED", "Send ended"));
        }
        let size = self.meta_str("size").to_string();
        self.set("state", json!("COMPLETE"));
        self.set("sent", json!(size));
        self.save()?;
        let _ = std::fs::remove_file(&self.part);
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<()> {
        if self.state() == "COMPLETE" {
            return Ok(());
        }
        self.set("state", json!("CANCELLED"));
        self.save()?;
        if !self.busy {
            let _ = std::fs::remove_file(&self.part);
        }
        Ok(())
    }
}
