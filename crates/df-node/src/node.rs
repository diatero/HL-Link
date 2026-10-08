//! 桌面 DF/1 节点运行时（对应 `NodeRuntime.java`）。
//!
//! 每个可用 IPv4 地址上监听控制端口 9527 与数据端口 9528（TLS 1.3）。控制连接先 HELLO；
//! 无客户端证书的连接只允许配对窗口内的 PAIR。地址变化时重签服务端证书、重建监听并断开现有连接
//! （控制端以同一 transferId 续传）。所有对已认证对端的请求都会重新检查信任列表。

use crate::identity::{pem, Identity};
use crate::incoming::{self, Incoming};
use crate::outgoing::{self, Outgoing};
use crate::peers::PeerStore;
use crate::wire::{self, Failure, Result, CHUNK, CONTROL_PORT, DATA_PORT};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot};
use tokio::task::AbortHandle;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

const PAIR_WINDOW: Duration = Duration::from_secs(300);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CONNECTIONS: usize = 16;

pub struct NodeConfig {
    /// 节点私有数据目录（证书私钥、信任列表、传输记录）。
    pub dir: PathBuf,
    /// 收件目录（校验完成的文件放这里）。
    pub inbox: PathBuf,
    /// 本机显示名称（每次读取，改名后下次 HELLO 生效）。
    pub name: Arc<dyn Fn() -> String + Send + Sync>,
}

/// 给本机界面/通知的事件。
#[derive(Debug, Clone)]
pub enum Event {
    Approval { id: String, kind: String, description: String },
    Paired { peer: String, name: String },
    Received { peer: String, name: String, path: String },
    Delivered { peer: String, name: String },
    Status(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApprovalView {
    pub id: String,
    pub kind: String,
    pub description: String,
    #[serde(rename = "allowAuto")]
    pub allow_auto: bool,
}

struct Approval {
    view: ApprovalView,
    answer: Option<oneshot::Sender<(bool, bool)>>,
}

struct Ticket {
    session: String,
    peer: String,
    transfer: incoming::Shared,
    expires: Instant,
}

struct PullTicket {
    session: String,
    peer: String,
    send: outgoing::Shared,
    bits: BTreeSet<u64>,
    expires: Instant,
}

#[derive(Default)]
struct Pairing {
    token: Option<String>,
    expires: Option<Instant>,
    expires_ms: u64,
    token_public: Option<String>,
    result: Option<Value>,
}

struct Net {
    addresses: Vec<Ipv4Addr>,
    listeners: Vec<AbortHandle>,
    mdns: Option<(mdns_sd::ServiceDaemon, String)>,
}

struct Inner {
    cfg: NodeConfig,
    identity: Identity,
    peers: PeerStore,
    incoming: Incoming,
    outgoing: Outgoing,
    enabled: AtomicBool,
    net: Mutex<Net>,
    sessions: Mutex<HashMap<String, String>>,
    tickets: Mutex<HashMap<String, Ticket>>,
    pull_tickets: Mutex<HashMap<String, PullTicket>>,
    /// 连接 ID → 中止句柄（撤销信任、换网、关闭节点时断开）。
    conns: Mutex<HashMap<u64, AbortHandle>>,
    /// 传输 ID → 正在使用的数据连接 ID（本机取消时断开）。
    active: Mutex<HashMap<String, u64>>,
    next_conn: AtomicU64,
    approval: Mutex<Option<Approval>>,
    pairing: Mutex<Pairing>,
    last_pair_auto: AtomicBool,
    seen: Mutex<HashMap<String, u64>>,
    events: broadcast::Sender<Event>,
    tasks: Mutex<Vec<AbortHandle>>,
}

#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

impl Node {
    /// 打开存储与身份（不监听）。
    pub fn open(cfg: NodeConfig) -> Result<Node> {
        let identity = Identity::load_or_create(&cfg.dir)?;
        let peers = PeerStore::open(&cfg.dir)?;
        let incoming = Incoming::open(&cfg.dir.join("transfers"), &cfg.inbox)?;
        let outgoing = Outgoing::open(&cfg.dir.join("outgoing"))?;
        let (events, _) = broadcast::channel(64);
        Ok(Node {
            inner: Arc::new(Inner {
                cfg,
                identity,
                peers,
                incoming,
                outgoing,
                enabled: AtomicBool::new(false),
                net: Mutex::new(Net { addresses: Vec::new(), listeners: Vec::new(), mdns: None }),
                sessions: Mutex::new(HashMap::new()),
                tickets: Mutex::new(HashMap::new()),
                pull_tickets: Mutex::new(HashMap::new()),
                conns: Mutex::new(HashMap::new()),
                active: Mutex::new(HashMap::new()),
                next_conn: AtomicU64::new(1),
                approval: Mutex::new(None),
                pairing: Mutex::new(Pairing::default()),
                last_pair_auto: AtomicBool::new(false),
                seen: Mutex::new(HashMap::new()),
                events,
                tasks: Mutex::new(Vec::new()),
            }),
        })
    }

    pub fn node_id(&self) -> &str {
        &self.inner.identity.node_id
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::SeqCst)
    }

    /// 开始监听，并每 10 秒检查一次地址变化。
    pub fn start(&self) {
        if self.inner.enabled.swap(true, Ordering::SeqCst) {
            return;
        }
        df_core::logging::info("node", format!("节点启动：nodeId {}…", &self.node_id()[..12]));
        let inner = self.inner.clone();
        let task = tokio::spawn(async move {
            loop {
                if !inner.enabled.load(Ordering::SeqCst) {
                    break;
                }
                refresh(&inner).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        self.inner.tasks.lock().unwrap().push(task.abort_handle());
    }

    /// 停止监听并断开所有连接；只清理本功能的状态，不删除信任与收件。
    pub fn stop(&self) {
        let inner = &self.inner;
        inner.enabled.store(false, Ordering::SeqCst);
        for t in inner.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        if let Some(a) = inner.approval.lock().unwrap().take() {
            if let Some(tx) = a.answer {
                let _ = tx.send((false, false));
            }
        }
        *inner.pairing.lock().unwrap() = Pairing::default();
        {
            let mut net = inner.net.lock().unwrap();
            for l in net.listeners.drain(..) {
                l.abort();
            }
            if let Some((daemon, fullname)) = net.mdns.take() {
                let _ = daemon.unregister(&fullname);
                let _ = daemon.shutdown();
            }
            net.addresses.clear();
        }
        close_all(inner);
        inner.tickets.lock().unwrap().clear();
        inner.pull_tickets.lock().unwrap().clear();
        inner.sessions.lock().unwrap().clear();
        df_core::logging::info("node", "节点已关闭");
    }

    pub fn addresses(&self) -> Vec<Ipv4Addr> {
        self.inner.net.lock().unwrap().addresses.clone()
    }

    /// 打开 5 分钟配对窗口，返回二维码 / 导出用 JSON（含一次性口令，只给要绑定的设备）。
    pub fn open_pairing(&self) -> Result<Value> {
        if !self.enabled() {
            return Err(Failure::new("PERMISSION_DENIED", "Node disabled"));
        }
        {
            let mut p = self.inner.pairing.lock().unwrap();
            *p = Pairing {
                token: Some(wire::b64(&wire::random(32))),
                expires: Some(Instant::now() + PAIR_WINDOW),
                expires_ms: wire::now_ms() + PAIR_WINDOW.as_millis() as u64,
                token_public: None,
                result: None,
            };
        }
        self.pairing_info().ok_or_else(|| Failure::new("PAIR_EXPIRED", "Window closed"))
    }

    pub fn close_pairing(&self) {
        *self.inner.pairing.lock().unwrap() = Pairing::default();
    }

    /// 当前配对窗口的 DF/1 二维码载荷（窗口关闭/已配对返回 None）。
    pub fn pairing_info(&self) -> Option<Value> {
        let p = self.inner.pairing.lock().unwrap();
        let token = p.token.as_ref()?;
        if p.result.is_some() || p.expires.is_none_or(|e| Instant::now() >= e) {
            return None;
        }
        let addresses: Vec<String> = self.addresses().iter().map(|a| a.to_string()).collect();
        Some(json!({
            "protocolMajor": 1,
            "nodeId": self.inner.identity.node_id,
            "caDer": wire::b64(&self.inner.identity.ca_der),
            "pairingToken": token,
            "expiresAt": p.expires_ms.to_string(),
            "controlPort": CONTROL_PORT,
            "dataPort": DATA_PORT,
            "addresses": addresses,
            // 桌面节点不建 Wi-Fi Direct 组：组字段留空（协议允许“未就绪”）
            "group": { "name": "", "passphrase": "", "goAddress": "", "peerAddress": "", "state": "" },
        }))
    }

    pub fn pending_approval(&self) -> Option<ApprovalView> {
        self.inner.approval.lock().unwrap().as_ref().map(|a| a.view.clone())
    }

    /// 本机用户的决定。`auto` 只对配对请求有意义（以后来自该设备的文件自动接收）。
    pub fn decide(&self, id: &str, accept: bool, auto: bool) -> bool {
        let mut slot = self.inner.approval.lock().unwrap();
        match slot.as_mut() {
            Some(a) if a.view.id == id => {
                if let Some(tx) = a.answer.take() {
                    let _ = tx.send((accept, auto && a.view.allow_auto));
                }
                true
            }
            _ => false,
        }
    }

    pub fn peers(&self) -> Vec<Value> {
        let seen = self.inner.seen.lock().unwrap().clone();
        self.inner
            .peers
            .list()
            .into_iter()
            .map(|(id, p)| json!({ "id": id, "name": p.name, "auto": p.auto, "added": p.added, "lastSeen": seen.get(&id).copied().unwrap_or(0) }))
            .collect()
    }

    pub fn find_peer(&self, query: &str) -> Option<String> {
        let list = self.inner.peers.list();
        let hits: Vec<&String> = list.iter().filter(|(id, p)| id.starts_with(query) || p.name == query).map(|(id, _)| id).collect();
        (hits.len() == 1).then(|| hits[0].clone())
    }

    pub fn set_auto(&self, peer: &str, auto: bool) -> Result<()> {
        self.inner.peers.set_auto(peer, auto)
    }

    /// 解除信任：删除信任记录、取消该对端未完成的收发，并断开所有连接（对端证书立即失效）。
    pub fn revoke(&self, peer: &str) -> Result<bool> {
        let removed = self.inner.peers.remove(peer)?;
        self.inner.incoming.cancel_all(peer);
        self.inner.outgoing.cancel_all(peer);
        close_all(&self.inner);
        Ok(removed)
    }

    /// 把本地文件排队给某个对端拉取（暂存在后台进行）。返回 transferId。
    pub async fn send_file(&self, peer: &str, path: &Path) -> Result<String> {
        self.inner.peers.get(peer)?;
        let send = self.inner.outgoing.create(peer)?;
        let id = send.lock().unwrap().id.clone();
        let mime = df_core_mime(path);
        let source = path.to_path_buf();
        tokio::task::spawn_blocking(move || send.lock().unwrap().stage(&source, &mime, &|| false))
        .await
        .map_err(Failure::io)??;
        df_core::logging::info("node", format!("已排队等待对端拉取：{}（{id}）", path.display()));
        Ok(id)
    }

    pub fn cancel_send(&self, id: &str) -> Result<()> {
        let send = self.inner.outgoing.find(id).ok_or_else(|| Failure::new("PERMISSION_DENIED", "Unknown send"))?;
        send.lock().unwrap().cancel()?;
        self.close_active(&format!("send:{id}"));
        self.inner.pull_tickets.lock().unwrap().retain(|_, t| t.send.lock().unwrap().id != id);
        Ok(())
    }

    pub fn cancel_incoming(&self, id: &str) -> Result<()> {
        for (peer, _) in self.inner.peers.list() {
            if let Ok(t) = self.inner.incoming.get(&peer, id) {
                self.close_active(id);
                return t.lock().unwrap().cancel();
            }
        }
        Err(Failure::new("PERMISSION_DENIED", "Unknown transfer"))
    }

    fn close_active(&self, key: &str) {
        if let Some(conn) = self.inner.active.lock().unwrap().remove(key) {
            if let Some(h) = self.inner.conns.lock().unwrap().remove(&conn) {
                h.abort();
            }
        }
    }

    pub fn transfers(&self) -> Value {
        json!({ "incoming": self.inner.incoming.views(), "outgoing": self.inner.outgoing.views() })
    }

    pub fn forget_finished(&self) -> usize {
        self.inner.incoming.forget_finished() + self.inner.outgoing.forget_finished()
    }

    pub fn status(&self) -> Value {
        json!({
            "enabled": self.enabled(),
            "nodeId": self.inner.identity.node_id,
            "addresses": self.addresses().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "pairing": self.pairing_info().is_some(),
            "approval": self.pending_approval(),
            "peers": self.inner.peers.list().len(),
            "inbox": self.inner.incoming.inbox().to_string_lossy(),
        })
    }
}

fn df_core_mime(path: &Path) -> String {
    // dfabric::guess_mime 在上层 crate；这里只需要一个保守值，由上层传入更好的 MIME 时可替换
    match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("txt" | "md" | "log") => "text/plain",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        Some("apk") => "application/vnd.android.package-archive",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn close_all(inner: &Inner) {
    for (_, h) in inner.conns.lock().unwrap().drain() {
        h.abort();
    }
    inner.active.lock().unwrap().clear();
}

fn emit(inner: &Inner, e: Event) {
    let _ = inner.events.send(e);
}

/// 地址变化：重签证书、重建监听、断开现有连接、更新 mDNS。
async fn refresh(inner: &Arc<Inner>) {
    let next = crate::net::addresses();
    if next == inner.net.lock().unwrap().addresses {
        return;
    }
    let configs = if next.is_empty() { None } else { inner.identity.tls(&next).ok() };
    let mut listeners = Vec::new();
    if let Some((control, data)) = &configs {
        for ip in &next {
            for (port, config, is_data) in [(CONTROL_PORT, control.clone(), false), (DATA_PORT, data.clone(), true)] {
                match TcpListener::bind((*ip, port)).await {
                    Ok(l) => {
                        let inner2 = inner.clone();
                        let task = tokio::spawn(accept_loop(inner2, l, TlsAcceptor::from(config), is_data));
                        listeners.push(task.abort_handle());
                    }
                    Err(e) => df_core::logging::warn("node", format!("监听 {ip}:{port} 失败：{e}")),
                }
            }
        }
    }
    let mdns = if next.is_empty() { None } else { publish_mdns(inner, &next) };
    {
        let mut net = inner.net.lock().unwrap();
        for l in net.listeners.drain(..) {
            l.abort();
        }
        if let Some((daemon, fullname)) = net.mdns.take() {
            let _ = daemon.unregister(&fullname);
            let _ = daemon.shutdown();
        }
        net.listeners = listeners;
        net.mdns = mdns;
        net.addresses = next.clone();
    }
    close_all(inner);
    let text = if next.is_empty() {
        "等待局域网地址".to_string()
    } else {
        format!("TLS：{}", next.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
    };
    df_core::logging::info("node", format!("监听地址更新：{text}"));
    emit(inner, Event::Status(text));
}

fn publish_mdns(inner: &Inner, ips: &[Ipv4Addr]) -> Option<(mdns_sd::ServiceDaemon, String)> {
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let host = format!("hllink-{}.local.", &inner.identity.node_id[..8]);
    let instance = format!("DF-{}", &inner.identity.node_id[..8]);
    let addrs: Vec<std::net::IpAddr> = ips.iter().map(|ip| (*ip).into()).collect();
    let info = mdns_sd::ServiceInfo::new(
        df_core::consts::MDNS_SERVICE,
        &instance,
        &host,
        &addrs[..],
        CONTROL_PORT,
        &[("v", "1")][..],
    )
    .ok()?;
    let fullname = info.get_fullname().to_string();
    match daemon.register(info) {
        Ok(()) => Some((daemon, fullname)),
        Err(e) => {
            df_core::logging::warn("node", format!("mDNS 发布失败：{e}"));
            let _ = daemon.shutdown();
            None
        }
    }
}

async fn accept_loop(inner: Arc<Inner>, listener: TcpListener, acceptor: TlsAcceptor, data: bool) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else { break };
        if !inner.enabled.load(Ordering::SeqCst) {
            break;
        }
        let _ = tcp.set_nodelay(true);
        let mut conns = inner.conns.lock().unwrap();
        if conns.len() >= MAX_CONNECTIONS {
            continue; // 丢弃 = 关闭
        }
        let id = inner.next_conn.fetch_add(1, Ordering::SeqCst);
        let inner2 = inner.clone();
        let acceptor = acceptor.clone();
        // 持有 conns 锁时 spawn：任务结束时的移除一定发生在登记之后
        let task = tokio::spawn(async move {
            serve(&inner2, id, tcp, acceptor, data).await;
            inner2.conns.lock().unwrap().remove(&id);
            inner2.active.lock().unwrap().retain(|_, c| *c != id);
        });
        conns.insert(id, task.abort_handle());
    }
}

/// 证书已链到本节点 CA 的连接：返回 peerId；对方未带证书返回 None；
/// 证书不在信任列表（已撤销）→ AUTH_FAILED。
fn authenticated(inner: &Inner, tls: &TlsStream<TcpStream>) -> Result<Option<String>> {
    let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
        return Ok(None);
    };
    let id = wire::sha256_hex(cert.as_ref());
    inner.peers.get(&id)?;
    Ok(Some(id))
}

async fn serve(inner: &Arc<Inner>, conn: u64, tcp: TcpStream, acceptor: TlsAcceptor, data: bool) {
    let mut tls = match tokio::time::timeout(Duration::from_secs(15), acceptor.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            df_core::logging::debug("node", format!("TLS 握手失败：{e}"));
            return;
        }
        Err(_) => return,
    };
    let mut session: Option<String> = None;
    let mut request_id = String::new();
    let result: Result<()> = async {
        let peer = authenticated(inner, &tls)?;
        if data {
            let peer = peer.ok_or_else(|| Failure::new("AUTH_FAILED", "Client certificate required"))?;
            let bind = read_timeout(&mut tls, 15).await?.ok_or_else(|| Failure::new("INVALID_FRAME", "Closed"))?;
            request_id = wire::request_id(&bind);
            return if wire::kind(&bind) == "DATA_PULL_BIND" {
                send_file(inner, conn, &mut tls, &peer, &bind).await
            } else {
                receive(inner, conn, &mut tls, &peer, &bind).await
            };
        }
        let Some(hello) = read_timeout(&mut tls, 15).await? else { return Ok(()) };
        request_id = wire::request_id(&hello);
        if wire::kind(&hello) != "HELLO" {
            return Err(Failure::new("INVALID_FRAME", "HELLO required"));
        }
        let sid = wire::b64(&wire::random(32));
        let challenge = wire::b64(&wire::random(32));
        let mut ack = json!({
            "nodeId": inner.identity.node_id,
            "sessionId": sid,
            "challenge": challenge,
            "capabilities": ["FILE_RECEIVE", "TEXT_RECEIVE", "RESUME", "STATUS", "FILE_SEND"],
            "chunkSize": CHUNK.to_string(),
            "window": 1,
            // 桌面节点只有局域网链路：控制端据此跳过 BLE / Wi-Fi Direct 回退（旧节点不发该字段）
            "links": ["LAN"],
        });
        if let Some(p) = &peer {
            inner.sessions.lock().unwrap().insert(sid.clone(), p.clone());
            session = Some(sid.clone());
            if let Some(name) = wire::body(&hello).get("name").and_then(Value::as_str) {
                if let Some(valid) = df_core::names::sanitize_display_name(name) {
                    if valid == name {
                        let _ = inner.peers.rename(p, name);
                    }
                }
            }
            ack["name"] = json!((inner.cfg.name)());
        }
        wire::write(&mut tls, &wire::message("HELLO_ACK", &request_id, ack)).await?;
        while inner.enabled.load(Ordering::SeqCst) {
            let Some(m) = read_timeout(&mut tls, 120).await? else { return Ok(()) };
            request_id = wire::request_id(&m);
            let (response, result) = dispatch(inner, peer.as_deref(), &sid, &challenge, &m).await?;
            wire::write(&mut tls, &wire::message(response, &request_id, result)).await?;
        }
        Ok(())
    }
    .await;
    if let Err(f) = result {
        if f.code != "IO_ERROR" || !f.message.contains("timed out") {
            df_core::logging::debug("node", format!("连接结束：{f}"));
        }
        let _ = wire::write(&mut tls, &wire::error(&request_id, &f)).await;
    }
    if let Some(sid) = session {
        inner.sessions.lock().unwrap().remove(&sid);
        inner.tickets.lock().unwrap().retain(|_, t| t.session != sid);
        inner.pull_tickets.lock().unwrap().retain(|_, t| t.session != sid);
    }
    let _ = tls.shutdown().await;
}

async fn read_timeout(tls: &mut TlsStream<TcpStream>, secs: u64) -> Result<Option<Value>> {
    match tokio::time::timeout(Duration::from_secs(secs), wire::read(tls)).await {
        Ok(r) => r,
        Err(_) => Ok(None), // 空闲超时：静默关闭（只保留已持久化的检查点）
    }
}

async fn dispatch(
    inner: &Arc<Inner>,
    peer: Option<&str>,
    session: &str,
    challenge: &str,
    m: &Value,
) -> Result<(&'static str, Value)> {
    let kind = wire::kind(m);
    let b = wire::body(m);
    if kind == "PAIR" && peer.is_none() {
        return Ok(("PAIR_RESULT", enroll(inner, b, challenge).await?));
    }
    let peer = peer.ok_or_else(|| Failure::new("AUTH_FAILED", "Pair before file operations"))?;
    let record = inner.peers.get(peer)?;
    match kind {
        "PULL_LIST" => {
            inner.seen.lock().unwrap().insert(peer.to_string(), wire::now_ms());
            Ok(("PULL_LIST_RESULT", json!({ "offers": inner.outgoing.offers(peer), "ended": inner.outgoing.ended(peer) })))
        }
        "PULL_ACCEPT" => {
            let send = inner.outgoing.get(peer, wire::string(b, "transferId")?)?;
            let (send_id, bits, offer) = {
                let s = send.lock().unwrap();
                (s.id.clone(), s.bitmap(wire::string(b, "haveBits")?)?, s.offer())
            };
            let mut pulls = inner.pull_tickets.lock().unwrap();
            pulls.retain(|_, t| t.expires > Instant::now() && t.send.lock().unwrap().id != send_id);
            if pulls.len() >= 64 {
                return Err(Failure::new("P2P_BUSY", "Too many pending downloads"));
            }
            let ticket = wire::b64(&wire::random(32));
            pulls.insert(
                ticket.clone(),
                PullTicket {
                    session: session.to_string(),
                    peer: peer.to_string(),
                    send,
                    bits,
                    expires: Instant::now() + Duration::from_secs(120),
                },
            );
            let mut r = offer;
            r["ticket"] = json!(ticket);
            r["dataPort"] = json!(DATA_PORT);
            r["window"] = json!(1);
            Ok(("PULL_READY", r))
        }
        "PULL_CANCEL" => {
            let id = wire::string(b, "transferId")?;
            let send = inner.outgoing.get(peer, id)?;
            send.lock().unwrap().cancel()?;
            Node { inner: inner.clone() }.close_active(&format!("send:{id}"));
            inner.pull_tickets.lock().unwrap().retain(|_, t| t.send.lock().unwrap().id != id);
            let status = send.lock().unwrap().status();
            Ok(("PULL_CANCELLED", status))
        }
        "PULL_COMPLETE" => {
            let send = inner.outgoing.get(peer, wire::string(b, "transferId")?)?;
            let mut s = send.lock().unwrap();
            let first = s.state() != "COMPLETE";
            s.complete(b)?;
            if first {
                emit(inner, Event::Delivered { peer: record.name.clone(), name: s.offer()["name"].as_str().unwrap_or("").into() });
            }
            Ok(("PULL_COMPLETED", s.status()))
        }
        "STATUS" => Ok(("STATUS_RESULT", json!({ "transfers": inner.incoming.list(Some(peer)), "state": "节点运行中" }))),
        "FILE_OFFER" | "RESUME" => {
            let t = inner.incoming.offer(peer, b)?;
            {
                let t = t.lock().unwrap();
                if t.cancelled() {
                    return Err(Failure::new("CANCELLED", "Transfer cancelled"));
                }
                if t.done() {
                    return Ok(("COMPLETE", t.status()));
                }
            }
            if !t.lock().unwrap().accepted() {
                let name = wire::string(b, "name")?;
                let accept = record.auto || approve(inner, "file", &format!("{} → {name}", record.name), false).await?.0;
                if !accept {
                    t.lock().unwrap().cancel()?;
                    return Err(Failure::new("PERMISSION_DENIED", "Reception declined"));
                }
                t.lock().unwrap().accept()?;
            }
            let ticket = wire::b64(&wire::random(32));
            let mut tickets = inner.tickets.lock().unwrap();
            tickets.retain(|_, t| t.expires > Instant::now());
            if tickets.len() >= 64 {
                return Err(Failure::new("P2P_BUSY", "Too many pending data connections"));
            }
            tickets.insert(
                ticket.clone(),
                Ticket {
                    session: session.to_string(),
                    peer: peer.to_string(),
                    transfer: t.clone(),
                    expires: Instant::now() + Duration::from_secs(60),
                },
            );
            let tr = t.lock().unwrap();
            let mut r = tr.status();
            r["chunkSize"] = json!(CHUNK.to_string());
            r["ticket"] = json!(ticket);
            r["dataPort"] = json!(DATA_PORT);
            r["haveBits"] = json!(tr.bitmap());
            r["window"] = json!(1);
            Ok(("ACCEPT", r))
        }
        "CANCEL" => {
            let id = wire::string(b, "transferId")?;
            let t = inner.incoming.get(peer, id)?;
            Node { inner: inner.clone() }.close_active(id);
            t.lock().unwrap().cancel()?;
            let status = t.lock().unwrap().status();
            Ok(("CANCELLED", status))
        }
        "TEXT_OFFER" => {
            let text = wire::string(b, "text")?;
            let bytes = text.as_bytes().to_vec();
            if bytes.len() > df_core::consts::MAX_TEXT {
                return Err(Failure::new("INVALID_FRAME", "Text too long"));
            }
            let offer: Map<String, Value> = serde_json::from_value(json!({
                "transferId": wire::string(b, "transferId")?,
                "name": "text.txt",
                "mime": "text/plain",
                "size": bytes.len().to_string(),
                "chunkSize": CHUNK.to_string(),
                "sha256": wire::sha256_hex(&bytes),
            }))
            .map_err(Failure::io)?;
            let t = inner.incoming.offer(peer, &offer)?;
            if !t.lock().unwrap().accepted() {
                if !record.auto && !approve(inner, "text", &format!("{} 发送文本", record.name), false).await?.0 {
                    t.lock().unwrap().cancel()?;
                    return Err(Failure::new("PERMISSION_DENIED", "Reception declined"));
                }
                t.lock().unwrap().accept()?;
            }
            t.lock().unwrap().begin()?;
            let _guard = Busy(t.clone());
            let inbox = inner.incoming.inbox().to_path_buf();
            let t2 = t.clone();
            let status = tokio::task::spawn_blocking(move || -> Result<Value> {
                let mut t = t2.lock().unwrap();
                if !t.done() && !bytes.is_empty() {
                    let hash = df_core::crypto::sha256(&bytes);
                    t.chunk(0, &bytes, &hash)?;
                }
                t.finish(&inbox)
            })
            .await
            .map_err(Failure::io)??;
            emit_received(inner, &record.name, &t);
            Ok(("COMPLETE", status))
        }
        _ => Err(Failure::new("INVALID_FRAME", "Unsupported operation")),
    }
}

fn emit_received(inner: &Inner, peer_name: &str, t: &incoming::Shared) {
    let v = {
        let t = t.lock().unwrap();
        (t.name().to_string(), t.path().to_string())
    };
    df_core::logging::info("node", format!("已接收：{}（来自 {peer_name}）", v.0));
    emit(inner, Event::Received { peer: peer_name.to_string(), name: v.0, path: v.1 });
}

/// 传输进行中标记（任务被中止时也会复位）。
struct Busy(incoming::Shared);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.lock().unwrap().busy = false;
    }
}

struct Sending(outgoing::Shared);
impl Drop for Sending {
    fn drop(&mut self) {
        self.0.lock().unwrap().end();
    }
}

/// 本机审批（一次只有一个；90 秒无人处理 = 拒绝）。返回 (accept, auto)。
async fn approve(inner: &Arc<Inner>, kind: &str, description: &str, allow_auto: bool) -> Result<(bool, bool)> {
    let (tx, rx) = oneshot::channel();
    let id = uuid::Uuid::new_v4().to_string();
    {
        let mut slot = inner.approval.lock().unwrap();
        if slot.is_some() {
            return Err(Failure::new("P2P_BUSY", "Another approval is pending"));
        }
        if !inner.enabled.load(Ordering::SeqCst) {
            return Err(Failure::new("PERMISSION_DENIED", "Node disabled"));
        }
        *slot = Some(Approval {
            view: ApprovalView { id: id.clone(), kind: kind.into(), description: description.into(), allow_auto },
            answer: Some(tx),
        });
    }
    emit(inner, Event::Approval { id: id.clone(), kind: kind.into(), description: description.into() });
    let answer = tokio::time::timeout(APPROVAL_TIMEOUT, rx).await.ok().and_then(|r| r.ok()).unwrap_or((false, false));
    let mut slot = inner.approval.lock().unwrap();
    if slot.as_ref().is_some_and(|a| a.view.id == id) {
        *slot = None;
    }
    Ok(answer)
}

/// PAIR（对应 `NodeRuntime.enroll`）：一次性口令 + P-256 持有证明 + 本机批准 → 签发客户端证书。
/// 口令绑定第一个提交的公钥；同一公钥在窗口内重试拿到同一结果（响应丢失可恢复）。
async fn enroll(inner: &Arc<Inner>, b: &Map<String, Value>, challenge: &str) -> Result<Value> {
    let supplied = wire::string(b, "pairingToken")?.to_string();
    let encoded = wire::string(b, "publicKey")?.to_string();
    let name = wire::string(b, "name")?.to_string();
    let n = name.encode_utf16().count();
    if !(1..=64).contains(&n) || encoded.len() > 2048 || supplied.len() > 128 {
        return Err(Failure::new("INVALID_FRAME", "Pairing fields"));
    }
    let spki = wire::unb64(&encoded)?;
    let public = df_core::keys::parse_p256_spki(&spki).map_err(|_| Failure::new("INVALID_FRAME", "P-256 required"))?;
    let proof = wire::unb64(wire::string(b, "proof")?)?;
    let message = format!("DF-PAIR-1\n{}\n{supplied}\n{challenge}", inner.identity.node_id);
    {
        use p256::ecdsa::signature::Verifier;
        let key = p256::ecdsa::VerifyingKey::from(&public);
        let sig = p256::ecdsa::Signature::from_der(&proof).map_err(|_| Failure::new("AUTH_FAILED", "Key possession proof"))?;
        key.verify(message.as_bytes(), &sig).map_err(|_| Failure::new("AUTH_FAILED", "Key possession proof"))?;
    }
    {
        let mut p = inner.pairing.lock().unwrap();
        let valid = p.token.as_deref().is_some_and(|t| constant_eq(t.as_bytes(), supplied.as_bytes()))
            && p.expires.is_some_and(|e| Instant::now() < e);
        if !valid {
            return Err(Failure::new("PAIR_EXPIRED", "Pairing window closed or token invalid"));
        }
        if p.token_public.as_deref().is_some_and(|k| k != encoded) {
            return Err(Failure::new("AUTH_FAILED", "Token already bound"));
        }
        if let Some(r) = &p.result {
            return Ok(r.clone());
        }
        if p.token_public.is_some() {
            return Err(Failure::new("P2P_BUSY", "Pairing approval pending"));
        }
        p.token_public = Some(encoded.clone());
    }
    let fingerprint = &wire::sha256_hex(&spki)[..16];
    let outcome = approve(inner, "pair", &format!("{name}\n公钥 {fingerprint}"), true).await;
    let mut p = inner.pairing.lock().unwrap();
    let still = p.token.as_deref() == Some(supplied.as_str())
        && p.token_public.as_deref() == Some(encoded.as_str())
        && p.expires.is_some_and(|e| Instant::now() < e);
    let result = match outcome {
        Ok((true, auto)) if still && inner.enabled.load(Ordering::SeqCst) => {
            let cert = inner.identity.issue_client(&spki)?;
            let ble_key = wire::random(32);
            let peer = inner.peers.add(&name, &cert, &ble_key, auto)?;
            inner.last_pair_auto.store(auto, Ordering::SeqCst);
            let r = json!({
                "peerId": peer,
                "clientCert": pem(&cert),
                "nodeCa": inner.identity.ca_pem(),
                "bleKey": wire::b64(&ble_key),
                "nodeId": inner.identity.node_id,
                "name": (inner.cfg.name)(),
            });
            p.result = Some(r.clone());
            df_core::logging::info("node", format!("配对成功：{name}（peerId {}…）", &peer[..12]));
            emit(inner, Event::Paired { peer, name: name.clone() });
            Ok(r)
        }
        Ok(_) => Err(Failure::new("PERMISSION_DENIED", "Pairing not approved")),
        Err(e) => Err(e),
    };
    if p.result.is_none() && p.token_public.as_deref() == Some(encoded.as_str()) {
        p.token_public = None;
    }
    result
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// 上传（控制端 → 本节点）：DATA_BIND → DATA_READY → 块 → CHUNK_ACK … → COMPLETE。
async fn receive(inner: &Arc<Inner>, conn: u64, tls: &mut TlsStream<TcpStream>, peer: &str, bind: &Value) -> Result<()> {
    let request_id = wire::request_id(bind);
    if wire::kind(bind) != "DATA_BIND" {
        return Err(Failure::new("INVALID_FRAME", "DATA_BIND required"));
    }
    let b = wire::body(bind);
    let ticket = inner.tickets.lock().unwrap().remove(wire::string(b, "ticket")?);
    let ticket = match ticket {
        Some(t)
            if t.expires >= Instant::now()
                && t.peer == peer
                && t.session == wire::string(b, "sessionId")?
                && inner.sessions.lock().unwrap().get(&t.session).map(String::as_str) == Some(peer)
                && t.transfer.lock().unwrap().id == wire::string(b, "transferId")?
                && wire::string(b, "direction")? == "upload" =>
        {
            t
        }
        _ => return Err(Failure::new("AUTH_FAILED", "Invalid data binding")),
    };
    let t = ticket.transfer;
    t.lock().unwrap().begin()?;
    let _busy = Busy(t.clone());
    let id = t.lock().unwrap().id.clone();
    inner.active.lock().unwrap().insert(id.clone(), conn);
    wire::write(tls, &wire::message("DATA_READY", &request_id, json!({}))).await?;
    loop {
        inner.peers.get(peer)?;
        let (done, count) = {
            let t = t.lock().unwrap();
            (t.done() || t.complete_bits(), t.count)
        };
        if done {
            break;
        }
        let mut head = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(30), tls.read_exact(&mut head))
            .await
            .map_err(|_| Failure::io("timed out"))??;
        let index = u64::from_be_bytes(head[0..8].try_into().unwrap());
        let size = u32::from_be_bytes(head[8..12].try_into().unwrap()) as u64;
        if size < 1 || size > CHUNK || index >= count {
            return Err(Failure::new("INVALID_FRAME", "Chunk bounds"));
        }
        let mut hash = [0u8; 32];
        let mut bytes = vec![0u8; size as usize];
        tokio::time::timeout(Duration::from_secs(30), async {
            tls.read_exact(&mut hash).await?;
            tls.read_exact(&mut bytes).await
        })
        .await
        .map_err(|_| Failure::io("timed out"))??;
        let t2 = t.clone();
        let received = tokio::task::spawn_blocking(move || -> Result<u64> {
            let mut t = t2.lock().unwrap();
            t.chunk(index, &bytes, &hash)?;
            Ok(t.received())
        })
        .await
        .map_err(Failure::io)??;
        wire::write(
            tls,
            &wire::message("CHUNK_ACK", &request_id, json!({ "chunkIndex": index.to_string(), "received": received.to_string() })),
        )
        .await?;
    }
    let peer_name = inner.peers.get(peer)?.name;
    let inbox = inner.incoming.inbox().to_path_buf();
    let t2 = t.clone();
    let status = tokio::task::spawn_blocking(move || t2.lock().unwrap().finish(&inbox)).await.map_err(Failure::io)??;
    emit_received(inner, &peer_name, &t);
    wire::write(tls, &wire::message("COMPLETE", &request_id, status)).await?;
    inner.active.lock().unwrap().remove(&id);
    Ok(())
}

/// 反向发送（本节点 → 控制端）：DATA_PULL_BIND 之后只发二进制块，按升序发缺失块并等数据连接上的 CHUNK_ACK；
/// 发完关闭连接，由控制端校验后在控制连接上 PULL_COMPLETE。
async fn send_file(inner: &Arc<Inner>, conn: u64, tls: &mut TlsStream<TcpStream>, peer: &str, bind: &Value) -> Result<()> {
    let b = wire::body(bind);
    let bind_rid = wire::request_id(bind);
    let ticket = inner.pull_tickets.lock().unwrap().remove(wire::string(b, "ticket")?);
    let ticket = match ticket {
        Some(t)
            if t.expires >= Instant::now()
                && t.peer == peer
                && t.session == wire::string(b, "sessionId")?
                && inner.sessions.lock().unwrap().get(&t.session).map(String::as_str) == Some(peer)
                && t.send.lock().unwrap().id == wire::string(b, "transferId")?
                && wire::string(b, "direction")? == "download" =>
        {
            t
        }
        _ => return Err(Failure::new("AUTH_FAILED", "Invalid download binding")),
    };
    let send = ticket.send;
    let mut bits = ticket.bits;
    send.lock().unwrap().begin(&bits)?;
    let _sending = Sending(send.clone());
    let (id, size, part) = {
        let s = send.lock().unwrap();
        (s.id.clone(), s.size(), s.part.clone())
    };
    inner.active.lock().unwrap().insert(format!("send:{id}"), conn);
    let count = size.div_ceil(CHUNK);
    let mut file = tokio::fs::File::open(&part).await?;
    for i in 0..count {
        if bits.contains(&i) {
            continue;
        }
        inner.peers.get(peer)?;
        if send.lock().unwrap().terminal() {
            return Err(Failure::new("CANCELLED", "Send ended"));
        }
        let len = CHUNK.min(size - i * CHUNK) as usize;
        let mut data = vec![0u8; len];
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(i * CHUNK)).await?;
        file.read_exact(&mut data).await?;
        let mut frame = Vec::with_capacity(44 + len);
        frame.extend_from_slice(&i.to_be_bytes());
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.extend_from_slice(&df_core::crypto::sha256(&data));
        frame.extend_from_slice(&data);
        tls.write_all(&frame).await?;
        tls.flush().await?;
        let ack = tokio::time::timeout(Duration::from_secs(30), wire::read(tls))
            .await
            .map_err(|_| Failure::io("timed out"))??
            .ok_or_else(|| Failure::io("closed"))?;
        let ok = wire::kind(&ack) == "CHUNK_ACK"
            && wire::request_id(&ack) == bind_rid
            && wire::decimal(wire::body(&ack), "chunkIndex")? == i;
        if !ok {
            return Err(Failure::new("INVALID_FRAME", "Download acknowledgement"));
        }
        bits.insert(i);
        send.lock().unwrap().progress(&bits)?;
    }
    inner.active.lock().unwrap().remove(&format!("send:{id}"));
    Ok(())
}
