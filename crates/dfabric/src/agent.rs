//! 后台 Agent：登录用户的常驻进程，持有全部状态（第 3 / 10.2 / 12 节）。
//!
//! - 在线时对每个可达节点保持独立接收轮询（约每 3 秒 PULL_LIST）；
//! - 新 offer 只通知用户，“用户接受前不拉取任何字节”；
//! - 串行发送队列：分享入口/CLI 通过 IPC 交接“发送请求 + 文件路径”后立即返回，
//!   入口进程退出不影响任务；
//! - IPC 只对当前用户开放（Unix socket 0700 目录 / 命名管道当前用户 ACL）。

use crate::{connect_trust, data_dir, display_name, find_trust, notify, open_store};
use df_core::error::{DfError, Result};
use df_core::stores::Trust;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

// —— 待接收清单（pulls.json）——

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRecord {
    pub node_id: String,
    pub node_name: Option<String>,
    pub transfer_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunk_size: u64,
    pub sha256: String,
    pub state: String, // pending | accepted | denied | completed | cancelled
    #[serde(default)]
    pub done_b64: String,
}

fn pulls_path() -> PathBuf {
    data_dir().join("pulls.json")
}

pub fn load_pulls() -> Vec<PullRecord> {
    std::fs::read_to_string(pulls_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_pulls(list: &[PullRecord]) -> Result<()> {
    df_core::fsutil::atomic_write(&pulls_path(), &serde_json::to_vec_pretty(list)?)
}

pub fn update_pull(rec: PullRecord) -> Result<()> {
    let mut list = load_pulls();
    if let Some(slot) = list.iter_mut().find(|p| p.transfer_id == rec.transfer_id) {
        *slot = rec;
    } else {
        list.push(rec);
    }
    save_pulls(&list)
}

// —— 发送记录（send_records.json，跨重启续传）——

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRecord {
    pub node_id: String,
    pub meta: df_core::msg::FileMeta,
    pub state: String, // queued | sending | completed | failed | cancelled
    #[serde(default)]
    pub done_b64: String,
    #[serde(default)]
    pub error: Option<String>,
}

fn sends_path() -> PathBuf {
    data_dir().join("send_records.json")
}

pub fn load_sends() -> Vec<SendRecord> {
    std::fs::read_to_string(sends_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_sends(list: &[SendRecord]) -> Result<()> {
    df_core::fsutil::atomic_write(&sends_path(), &serde_json::to_vec_pretty(list)?)
}

pub fn update_send(rec: SendRecord) -> Result<()> {
    let mut list = load_sends();
    if let Some(slot) = list.iter_mut().find(|p| p.meta.transfer_id == rec.meta.transfer_id) {
        *slot = rec;
    } else {
        list.push(rec);
    }
    save_sends(&list)
}

// —— IPC 命令 ——

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum IpcCommand {
    #[serde(rename = "send-files")]
    SendFiles { to: Option<String>, paths: Vec<String> },
    #[serde(rename = "send-text")]
    SendText { to: Option<String>, text: String },
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "pulls")]
    Pulls,
    #[serde(rename = "accept")]
    Accept { transfer_id: String },
    #[serde(rename = "deny")]
    Deny { transfer_id: String },
    #[serde(rename = "devices")]
    Devices,
    #[serde(rename = "set-name")]
    SetName { name: Option<String> },
    #[serde(rename = "remove")]
    Remove { node_id: String },
    #[serde(rename = "shutdown")]
    Shutdown,
    // —— 本机作为节点（df-node）——
    #[serde(rename = "node-status")]
    NodeStatus,
    #[serde(rename = "node-enable")]
    NodeEnable { on: bool },
    #[serde(rename = "node-pair")]
    NodePair,
    #[serde(rename = "node-pair-close")]
    NodePairClose,
    #[serde(rename = "node-decide")]
    NodeDecide { accept: bool, auto: bool },
    #[serde(rename = "node-peers")]
    NodePeers,
    #[serde(rename = "node-revoke")]
    NodeRevoke { peer: String },
    #[serde(rename = "node-auto")]
    NodeAuto { peer: String, on: bool },
    #[serde(rename = "node-send")]
    NodeSend { peer: String, paths: Vec<String> },
    #[serde(rename = "node-transfers")]
    NodeTransfers,
    #[serde(rename = "node-clean")]
    NodeClean,
    #[serde(rename = "node-cancel")]
    NodeCancel { transfer_id: String },
}

/// 向运行中的 Agent 发送一条 IPC 命令（未运行返回 None，调用方回退直连模式）。
pub async fn ipc_request(cmd: IpcCommand) -> Option<IpcReply> {
    #[cfg(unix)]
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(ipc_socket_path()).await.ok()?;
        let mut line = serde_json::to_string(&cmd).ok()?;
        line.push('\n');
        stream.write_all(line.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.ok()?;
        serde_json::from_slice(&buf).ok()
    }
    #[cfg(windows)]
    {
        let _ = cmd;
        None // Windows 命名管道 IPC 在后续版本接入
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcReply {
    fn ok(v: serde_json::Value) -> IpcReply {
        IpcReply { ok: true, data: Some(v), error: None }
    }
    fn err(e: String) -> IpcReply {
        IpcReply { ok: false, data: None, error: Some(e) }
    }
}

pub fn ipc_socket_path() -> PathBuf {
    data_dir().join("agent.sock")
}

// —— Agent 运行时 ——

pub struct Agent {
    pub store: df_core::stores::Store,
    pub mdns: crate::mdns::MdnsBrowser,
    pub queue_tx: tokio::sync::mpsc::UnboundedSender<()>,
    /// 本机作为节点（初始化失败时为 None，不影响控制端功能）。
    pub node: Option<df_node::Node>,
}

impl Agent {
    pub async fn start() -> Result<std::sync::Arc<Agent>> {
        let store = open_store()?;
        crate::secrets::restore_secrets_into_trusts(&store);
        df_core::logging::info(
            "agent",
            format!(
                "Agent 启动：数据目录 {}，已配对 {} 台设备",
                crate::data_dir().display(),
                store.trusts().len()
            ),
        );
        let mdns = crate::mdns::MdnsBrowser::new();
        if let Err(e) = mdns.start() {
            // mDNS 不可用时退回 BLE/上次地址，不致命
            df_core::logging::warn("agent", format!("mDNS 启动失败：{e}"));
        }

        // 上次退出时正在发送的任务：重新排队，按原 transferId/元数据续传（只补缺块）
        let mut sends = load_sends();
        let mut pending = 0;
        for r in sends.iter_mut() {
            if r.state == "sending" {
                r.state = "queued".into();
            }
            if r.state == "queued" || r.state == "queued-text" {
                pending += 1;
            }
        }
        if pending > 0 {
            save_sends(&sends).ok();
            df_core::logging::info("agent", format!("恢复 {pending} 个未完成的发送任务"));
        }

        let (queue_tx, queue_rx) = tokio::sync::mpsc::unbounded_channel();
        if pending > 0 {
            let _ = queue_tx.send(());
        }
        let node = match crate::node_host::open() {
            Ok(n) => {
                crate::node_host::spawn_notifications(&n);
                if crate::node_host::load_settings().enabled {
                    n.start();
                }
                Some(n)
            }
            Err(e) => {
                df_core::logging::warn("agent", format!("{e}"));
                None
            }
        };
        let agent = std::sync::Arc::new(Agent { store, mdns, queue_tx, node });
        let a2 = agent.clone();
        tokio::spawn(async move { send_worker(a2, queue_rx).await });
        let a3 = agent.clone();
        tokio::spawn(async move { receive_poller(a3).await });
        Ok(agent)
    }

    /// 交接发送任务（分享入口/CLI 调用后立即返回）。
    pub fn enqueue_files(&self, to: Option<String>, paths: Vec<String>) -> Result<usize> {
        let mut staged = 0;
        for p in &paths {
            let (meta, staged_path) = crate::stage_file(&self.store, std::path::Path::new(p))?;
            let trust = crate::pick_trust(&self.store, to.as_deref())?;
            update_send(SendRecord {
                node_id: trust.node_id,
                meta,
                state: "queued".into(),
                done_b64: String::new(),
                error: None,
            })
            .ok();
            let _ = staged_path; // 暂存路径由 transferId 决定，worker 重新拼接
            staged += 1;
        }
        let _ = self.queue_tx.send(());
        Ok(staged)
    }

    pub fn enqueue_text(&self, to: Option<String>, text: String) -> Result<()> {
        let trust = crate::pick_trust(&self.store, to.as_deref())?;
        let transfer_id = uuid::Uuid::new_v4().to_string();
        if text.len() > df_core::consts::MAX_TEXT {
            // 超长文本作为 .txt 文件发送
            let tmp = self.store.staging_dir().join(format!("text-{transfer_id}.txt"));
            df_core::fsutil::atomic_write(&tmp, text.as_bytes())?;
            let (meta, _) = crate::stage_file(&self.store, &tmp)?;
            let _ = std::fs::remove_file(&tmp);
            update_send(SendRecord { node_id: trust.node_id, meta, state: "queued".into(), done_b64: String::new(), error: None }).ok();
        } else {
            update_send(SendRecord {
                node_id: trust.node_id,
                meta: df_core::msg::FileMeta {
                    transfer_id,
                    name: String::new(),
                    mime: "text/plain".into(),
                    size: text.len() as u64,
                    chunk_size: df_core::consts::CHUNK_SIZE,
                    sha256: String::new(),
                },
                state: "queued-text".into(),
                done_b64: text,
                error: None,
            })
            .ok();
        }
        let _ = self.queue_tx.send(());
        Ok(())
    }
}

/// 串行发送 worker：一次只处理一个任务。
async fn send_worker(agent: std::sync::Arc<Agent>, mut rx: tokio::sync::mpsc::UnboundedReceiver<()>) {
    loop {
        if rx.recv().await.is_none() {
            return;
        }
        // 逐条处理 queued
        loop {
            let next = load_sends()
                .into_iter()
                .find(|r| r.state == "queued" || r.state == "queued-text");
            let Some(mut rec) = next else { break };
            match run_send_task(&agent, &mut rec).await {
                Ok(()) => {}
                Err(e) => {
                    rec.state = "failed".into();
                    rec.error = Some(e.to_string());
                    let label = if rec.meta.name.is_empty() { "文本".to_string() } else { rec.meta.name.clone() };
                    update_send(rec).ok();
                    df_core::logging::warn("send", format!("发送失败（{label}）：{e}"));
                    notify("发送失败", &e.to_string());
                }
            }
        }
    }
}

async fn run_send_task(agent: &Agent, rec: &mut SendRecord) -> Result<()> {
    let Some(trust) = find_trust(&agent.store, &rec.node_id) else {
        return Err(DfError::Protocol("节点已删除".into()));
    };
    let name = display_name(&agent.store);
    let mut ctrl = connect_trust(&trust, Some(&name), &agent.mdns).await?;
    let config = df_core::tls::client_config(&trust.ca_pem, &trust.cert_pem, &trust.key_pem)?;
    let ack_session = ctrl.hello_session_id.clone();

    if rec.state == "queued-text" {
        let text = rec.done_b64.clone();
        df_core::logging::info("send", format!("发送文本（{} 字节）", text.len()));
        df_core::transfer::up::send_text(&mut ctrl, &rec.meta.transfer_id, &text).await?;
        rec.state = "completed".into();
        update_send(rec.clone()).ok();
        return Ok(());
    }
    df_core::logging::info(
        "send",
        format!(
            "开始发送 {}（{} 字节，transferId {}）",
            rec.meta.name, rec.meta.size, rec.meta.transfer_id
        ),
    );

    let staged = agent.store.staging_dir().join(&rec.meta.transfer_id);
    let mut done = df_core::bitmap::decode_bits(&rec.done_b64, rec.meta.chunk_count()).unwrap_or_default();
    rec.state = "sending".into();
    update_send(rec.clone()).ok();

    let meta = rec.meta.clone();
    let mut persist = |set: &BTreeSet<u64>| {
        rec.done_b64 = df_core::bitmap::encode_bits(set);
        update_send(rec.clone()).ok();
    };
    let outcome = df_core::transfer::up::upload(
        &mut ctrl,
        config,
        &ack_session,
        &meta,
        &staged,
        &mut done,
        None,
        Some(&mut persist),
    )
    .await?;
    if matches!(outcome, df_core::transfer::up::Outcome::Completed { .. }) {
        rec.state = "completed".into();
        update_send(rec.clone()).ok();
        let _ = std::fs::remove_file(&staged);
        df_core::logging::info("send", format!("发送完成：{}（{}）", rec.meta.name, rec.meta.transfer_id));
        notify("发送完成", &rec.meta.name);
    } else {
        rec.state = "completed".into();
        update_send(rec.clone()).ok();
    }
    Ok(())
}

/// 接收轮询：每 3 秒 PULL_LIST（独立控制会话，不与发送共用）。
///
/// 每个节点保持一条已认证的控制连接反复 PULL_LIST（DF1.md FILE_SEND 扩展），
/// 不再每 3 秒重新 TLS 握手：手机端每次握手都要用 AndroidKeyStore 签名。
/// 连接出错（节点换网关闭了 socket、空闲超时、信任被撤销）时丢弃并在下一轮重连；
/// 本机显示名称改变时也重连，让新名称通过 HELLO 同步到手机。
async fn receive_poller(agent: std::sync::Arc<Agent>) {
    df_core::logging::info("agent", "接收轮询已启动（每 3 秒 PULL_LIST；接受前不拉取任何字节）");
    let mut last_err: Option<String> = None;
    let mut sessions: std::collections::HashMap<String, (df_core::session::ControlSession, String)> =
        std::collections::HashMap::new();
    loop {
        let trusts = agent.store.trusts();
        sessions.retain(|id, _| trusts.iter().any(|t| &t.node_id == id && !t.revoked));
        let mut errored: Option<String> = None;
        let mut polled = 0;
        for trust in trusts.iter().filter(|t| !t.revoked) {
            match poll_one(&agent, trust, &mut sessions).await {
                Ok(()) => polled += 1,
                Err(e) => errored = Some(e.to_string()),
            }
        }
        // 只在状态变化时记录，避免每 3 秒刷屏
        if errored != last_err {
            match &errored {
                Some(msg) => df_core::logging::debug("recv", format!("接收轮询未能连接：{msg}")),
                None if last_err.is_some() && polled > 0 => df_core::logging::info("recv", "接收轮询已恢复连接"),
                None => {}
            }
            last_err = errored;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn poll_one(
    agent: &Agent,
    trust: &Trust,
    sessions: &mut std::collections::HashMap<String, (df_core::session::ControlSession, String)>,
) -> Result<()> {
    let name = display_name(&agent.store);
    if sessions.get(&trust.node_id).is_some_and(|(_, n)| *n != name) {
        sessions.remove(&trust.node_id);
    }
    // 复用的连接可能已被节点关闭：失败一次就丢弃并用新连接重试一次
    let list = match sessions.get_mut(&trust.node_id) {
        Some((ctrl, _)) => match df_core::transfer::down::pull_list(ctrl).await {
            Ok(list) => Some(list),
            Err(_) => {
                sessions.remove(&trust.node_id);
                None
            }
        },
        None => None,
    };
    let list = match list {
        Some(list) => list,
        None => {
            let mut ctrl = connect_trust(trust, Some(&name), &agent.mdns).await?;
            let list = df_core::transfer::down::pull_list(&mut ctrl).await?;
            sessions.insert(trust.node_id.clone(), (ctrl, name));
            list
        }
    };

    let mut pulls = load_pulls();
    for offer in &list.offers {
        if pulls.iter().any(|p| p.transfer_id == offer.meta.transfer_id) {
            continue;
        }
        let rec = PullRecord {
            node_id: trust.node_id.clone(),
            node_name: trust.name.clone(),
            transfer_id: offer.meta.transfer_id.clone(),
            name: offer.meta.name.clone(),
            mime: offer.meta.mime.clone(),
            size: offer.meta.size,
            chunk_size: offer.meta.chunk_size,
            sha256: offer.meta.sha256.clone(),
            state: "pending".into(),
            done_b64: String::new(),
        };
        df_core::logging::info(
            "recv",
            format!(
                "收到发送请求：{}（{} 字节，transferId {}）来自 {}",
                offer.meta.name,
                offer.meta.size,
                offer.meta.transfer_id,
                trust.name.as_deref().unwrap_or("Lineage 设备")
            ),
        );
        update_pull(rec).ok();
        notify("收到文件请求", &format!("{} 想发送「{}」", trust.name.as_deref().unwrap_or("Lineage 设备"), offer.meta.name));
    }
    // 手机端取消了尚未完成的发送；只在状态真正变化时写盘（ended 每轮都会带上全部历史记录）
    for ended in &list.ended {
        if let Some(p) = pulls.iter_mut().find(|p| p.transfer_id == ended.transfer_id) {
            if ended.state.contains("CANCEL") && (p.state == "pending" || p.state == "accepted") {
                p.state = "cancelled".into();
                update_pull(p.clone()).ok();
            }
        }
    }
    Ok(())
}

// —— IPC 服务器 ——

pub async fn run_ipc_server(agent: std::sync::Arc<Agent>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    #[cfg(unix)]
    {
        let path = ipc_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = match tokio::net::UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                df_core::logging::error("ipc", format!("IPC 绑定失败 {}: {e}", path.display()));
                eprintln!("IPC 绑定失败: {e}");
                return;
            }
        };
        df_core::logging::info("ipc", format!("IPC 已监听 {}", path.display()));
        // 只对当前用户开放（目录 0700 + socket 0600）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    if let Ok((stream, _)) = accepted {
                        handle_ipc_conn(agent.clone(), stream).await;
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&path);
    }
    #[cfg(windows)]
    {
        let _ = shutdown;
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}

#[cfg(unix)]
async fn handle_ipc_conn(agent: std::sync::Arc<Agent>, mut stream: tokio::net::UnixStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.iter().any(|&b| b == b'\n') {
            break;
        }
        if buf.len() > 1024 * 1024 {
            break;
        }
    }
    let line = String::from_utf8_lossy(&buf);
    let reply = match serde_json::from_str::<IpcCommand>(line.trim()) {
        Ok(cmd) => execute_ipc(&agent, cmd).await,
        Err(e) => IpcReply::err(format!("IPC 命令解析失败: {e}")),
    };
    let mut out = serde_json::to_vec(&reply).unwrap_or_default();
    out.push(b'\n');
    let _ = stream.write_all(&out).await;
}

async fn execute_ipc(agent: &Agent, cmd: IpcCommand) -> IpcReply {
    match cmd {
        IpcCommand::SendFiles { to, paths } => match agent.enqueue_files(to, paths) {
            Ok(n) => IpcReply::ok(serde_json::json!({ "queued": n })),
            Err(e) => IpcReply::err(e.to_string()),
        },
        IpcCommand::SendText { to, text } => match agent.enqueue_text(to, text) {
            Ok(()) => IpcReply::ok(serde_json::json!({ "queued": 1 })),
            Err(e) => IpcReply::err(e.to_string()),
        },
        IpcCommand::Status => {
            let sends = load_sends();
            IpcReply::ok(serde_json::json!(sends))
        }
        IpcCommand::Pulls => IpcReply::ok(serde_json::json!(load_pulls())),
        IpcCommand::Accept { transfer_id } => match accept_pull(&agent.store, &agent.mdns, &transfer_id).await {
            Ok(path) => IpcReply::ok(serde_json::json!({ "path": path })),
            Err(e) => IpcReply::err(e.to_string()),
        },
        IpcCommand::Deny { transfer_id } => {
            let pulls = load_pulls();
            let Some(rec) = pulls.iter().find(|p| p.transfer_id == transfer_id) else {
                return IpcReply::err("没有该待接收项".into());
            };
            let Some(trust) = find_trust(&agent.store, &rec.node_id) else {
                return IpcReply::err("节点不存在".into());
            };
            let mut rec2 = rec.clone();
            rec2.state = "denied".into();
            update_pull(rec2).ok();
            let result = async {
                let name = display_name(&agent.store);
                let mut ctrl = connect_trust(&trust, Some(&name), &agent.mdns).await?;
                df_core::transfer::down::pull_cancel(&mut ctrl, &transfer_id).await
            }
            .await;
            match result {
                Ok(()) => IpcReply::ok(serde_json::json!({})),
                Err(e) => IpcReply::err(e.to_string()),
            }
        }
        IpcCommand::Devices => IpcReply::ok(serde_json::json!(agent.store.trusts())),
        IpcCommand::SetName { name } => match agent.store.set_local_name(name.as_deref()) {
            Ok(()) => IpcReply::ok(serde_json::json!({})),
            Err(e) => IpcReply::err(e.to_string()),
        },
        IpcCommand::Remove { node_id } => {
            let Some(t) = find_trust(&agent.store, &node_id) else {
                return IpcReply::err("没有匹配的信任设备".into());
            };
            crate::secrets::drop_trust(&t.node_id);
            match agent.store.remove_trust(&t.node_id) {
                Ok(_) => IpcReply::ok(serde_json::json!({})),
                Err(e) => IpcReply::err(e.to_string()),
            }
        }
        IpcCommand::Shutdown => IpcReply::ok(serde_json::json!({})),
        cmd => match &agent.node {
            Some(node) => match execute_node(node, cmd).await {
                Ok(v) => IpcReply::ok(v),
                Err(e) => IpcReply::err(e),
            },
            None => IpcReply::err("本机节点未能初始化，见日志".into()),
        },
    }
}

async fn execute_node(node: &df_node::Node, cmd: IpcCommand) -> std::result::Result<serde_json::Value, String> {
    use serde_json::json;
    let peer_of = |q: &str| node.find_peer(q).ok_or_else(|| format!("没有唯一匹配的已配对设备：{q}"));
    match cmd {
        IpcCommand::NodeStatus => Ok(node.status()),
        IpcCommand::NodeEnable { on } => {
            if on {
                node.start();
            } else {
                node.stop();
            }
            crate::node_host::save_settings(&crate::node_host::NodeSettings { enabled: on }).map_err(|e| e.to_string())?;
            Ok(node.status())
        }
        IpcCommand::NodePair => {
            // 刚开启时地址刷新是异步的，最多等 3 秒拿到监听地址
            for _ in 0..30 {
                if !node.enabled() || !node.addresses().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if node.addresses().is_empty() {
                return Err("没有可用的局域网地址（请连接 Wi-Fi 或有线网络）".into());
            }
            node.open_pairing().map_err(|e| format!("{e}（请先 dfctl node on）"))
        }
        IpcCommand::NodePairClose => {
            node.close_pairing();
            Ok(json!({}))
        }
        IpcCommand::NodeDecide { accept, auto } => {
            let pending = node.pending_approval().ok_or("当前没有待审批的请求")?;
            node.decide(&pending.id, accept, auto);
            Ok(json!({ "decided": pending }))
        }
        IpcCommand::NodePeers => Ok(json!(node.peers())),
        IpcCommand::NodeRevoke { peer } => {
            let id = peer_of(&peer)?;
            node.revoke(&id).map_err(|e| e.to_string())?;
            Ok(json!({ "revoked": id }))
        }
        IpcCommand::NodeAuto { peer, on } => {
            let id = peer_of(&peer)?;
            node.set_auto(&id, on).map_err(|e| e.to_string())?;
            Ok(json!({ "peer": id, "auto": on }))
        }
        IpcCommand::NodeSend { peer, paths } => {
            let id = peer_of(&peer)?;
            for p in &paths {
                if !std::path::Path::new(p).is_file() {
                    return Err(format!("不是可读文件：{p}"));
                }
            }
            // 暂存（复制 + 哈希）在后台进行，入口进程立即返回
            for p in paths.clone() {
                let node = node.clone();
                let id = id.clone();
                tokio::spawn(async move {
                    if let Err(e) = node.send_file(&id, std::path::Path::new(&p)).await {
                        df_core::logging::warn("node", format!("排队发送失败（{p}）：{e}"));
                        notify("发送失败", &format!("{p}：{e}"));
                    }
                });
            }
            Ok(json!({ "queued": paths.len(), "peer": id }))
        }
        IpcCommand::NodeTransfers => Ok(node.transfers()),
        IpcCommand::NodeClean => Ok(json!({ "removed": node.forget_finished() })),
        IpcCommand::NodeCancel { transfer_id } => node
            .cancel_send(&transfer_id)
            .or_else(|_| node.cancel_incoming(&transfer_id))
            .map(|_| json!({}))
            .map_err(|e| e.to_string()),
        _ => Err("不支持的节点命令".into()),
    }
}

/// 接受并下载一个待接收项（用户接受前绝不拉取字节）。
pub async fn accept_pull(
    store: &df_core::stores::Store,
    mdns: &crate::mdns::MdnsBrowser,
    transfer_id: &str,
) -> Result<String> {
    let pulls = load_pulls();
    // accepted = 上次接收中断（位图记录已落盘的块），允许再次接受以续传
    let Some(rec) = pulls
        .iter()
        .find(|p| p.transfer_id == transfer_id && (p.state == "pending" || p.state == "accepted"))
    else {
        return Err(DfError::Protocol("没有该待接收项（或状态不是 pending / accepted）".into()));
    };
    let Some(trust) = find_trust(store, &rec.node_id) else {
        return Err(DfError::Protocol("节点不存在".into()));
    };
    let meta = df_core::msg::FileMeta {
        transfer_id: rec.transfer_id.clone(),
        name: rec.name.clone(),
        mime: rec.mime.clone(),
        size: rec.size,
        chunk_size: rec.chunk_size,
        sha256: rec.sha256.clone(),
    };
    meta.validate()?;

    let staging = store.staging_dir().join(&meta.transfer_id);
    let commit_to = store.inbox_dir().join(df_core::names::unique_filename(&store.inbox_dir(), &meta.name));
    let mut done = df_core::bitmap::decode_bits(&rec.done_b64, meta.chunk_count()).unwrap_or_default();

    let config = df_core::tls::client_config(&trust.ca_pem, &trust.cert_pem, &trust.key_pem)?;
    let name = display_name(store);
    let mut ctrl = connect_trust(&trust, Some(&name), mdns).await?;
    let ack_session = ctrl.hello_session_id.clone();

    // 稀疏预分配 + 崩溃恢复由 journal（pulls.json 位图）支撑。不能截断：
    // 续传时暂存文件里是位图记录的已确认块。暂存文件丢失则位图作废，从头接收。
    std::fs::create_dir_all(store.staging_dir())?;
    if !staging.exists() {
        done.clear();
    }
    std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&staging)?.set_len(meta.size)?;

    let mut rec_mut = rec.clone();
    rec_mut.state = "accepted".into();
    update_pull(rec_mut.clone()).ok();
    df_core::logging::info(
        "recv",
        format!("开始接收 {}（{} 字节，transferId {}）", meta.name, meta.size, meta.transfer_id),
    );

    let mut journal = |set: &BTreeSet<u64>| {
        rec_mut.done_b64 = df_core::bitmap::encode_bits(set);
        update_pull(rec_mut.clone()).ok();
    };
    let mut progress = |done_bytes: u64, total: u64| {
        if total > 0 && done_bytes % (16 * 1024 * 1024) < 1024 * 1024 {
            println!("  接收进度: {done_bytes}/{total}");
        }
    };
    df_core::transfer::down::pull_accept(
        &mut ctrl,
        config,
        &ack_session,
        &meta,
        &staging,
        &commit_to,
        &mut done,
        Some(&mut journal),
        Some(&mut progress),
    )
    .await?;

    let mut rec_final = rec_mut.clone();
    rec_final.state = "completed".into();
    update_pull(rec_final).ok();
    let _ = std::fs::remove_file(&staging);
    let path = commit_to.to_string_lossy().to_string();
    notify("接收完成", &path);
    Ok(path)
}
