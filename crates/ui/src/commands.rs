//! Tauri 命令：UI ↔ Agent。
//! 优先走 dfabricd IPC（任务交给后台队列），Agent 未运行时回退直连模式。

use df_core::error::{DfError, Result};
use dfabric::agent::{self, IpcCommand, IpcReply};
use serde::Serialize;

fn reply_to_result(reply: Option<IpcReply>) -> Option<Result<serde_json::Value>> {
    reply.map(|r| {
        if r.ok {
            Ok(r.data.unwrap_or(serde_json::Value::Null))
        } else {
            Err(DfError::Protocol(r.error.unwrap_or_else(|| "未知错误".into())))
        }
    })
}

async fn try_ipc(cmd: IpcCommand) -> Option<Result<serde_json::Value>> {
    reply_to_result(agent::ipc_request(cmd).await)
}

fn err_to_string(e: DfError) -> String {
    e.to_string()
}

// —— 数据模型（前端展示）——

#[derive(Serialize)]
pub struct Device {
    pub node_id: String,
    pub name: String,
    pub last_addr: String,
    pub revoked: bool,
    pub paired_at_ms: u64,
}

#[derive(Serialize)]
pub struct Pull {
    pub transfer_id: String,
    pub node_name: String,
    pub name: String,
    pub size: u64,
    pub state: String,
}

#[derive(Serialize)]
pub struct SendItem {
    pub transfer_id: String,
    pub name: String,
    pub size: u64,
    pub state: String,
    pub error: Option<String>,
}

fn trust_to_device(t: &df_core::stores::Trust) -> Device {
    Device {
        node_id: t.node_id.clone(),
        name: t.name.clone().unwrap_or_else(|| "Lineage 设备".into()),
        last_addr: t.last_addr.clone().unwrap_or_else(|| "-".into()),
        revoked: t.revoked,
        paired_at_ms: t.paired_at_ms,
    }
}

fn pull_to_view(p: &agent::PullRecord) -> Pull {
    Pull {
        transfer_id: p.transfer_id.clone(),
        node_name: p.node_name.clone().unwrap_or_else(|| "Lineage 设备".into()),
        name: p.name.clone(),
        size: p.size,
        state: p.state.clone(),
    }
}

// —— 命令 ——

#[tauri::command]
pub async fn get_devices() -> std::result::Result<Vec<Device>, String> {
    if let Some(Ok(v)) = try_ipc(IpcCommand::Devices).await {
        let list: Vec<df_core::stores::Trust> = serde_json::from_value(v)
            .map_err(|e| format!("解析设备列表失败: {e}"))?;
        return Ok(list.iter().map(trust_to_device).collect());
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    Ok(store.trusts().iter().map(trust_to_device).collect())
}

#[tauri::command]
pub async fn get_pulls() -> std::result::Result<Vec<Pull>, String> {
    if let Some(Ok(v)) = try_ipc(IpcCommand::Pulls).await {
        let list: Vec<agent::PullRecord> =
            serde_json::from_value(v).map_err(|e| format!("解析待接收失败: {e}"))?;
        return Ok(list.iter().map(pull_to_view).collect());
    }
    Ok(agent::load_pulls().iter().map(pull_to_view).collect())
}

#[tauri::command]
pub async fn get_sends() -> std::result::Result<Vec<SendItem>, String> {
    if let Some(Ok(v)) = try_ipc(IpcCommand::Status).await {
        let list: Vec<agent::SendRecord> =
            serde_json::from_value(v).map_err(|e| format!("解析发送记录失败: {e}"))?;
        return Ok(list
            .iter()
            .map(|r| SendItem {
                transfer_id: r.meta.transfer_id.clone(),
                name: if r.meta.name.is_empty() { "(文本)".into() } else { r.meta.name.clone() },
                size: r.meta.size,
                state: r.state.clone(),
                error: r.error.clone(),
            })
            .collect());
    }
    Ok(agent::load_sends()
        .iter()
        .map(|r| SendItem {
            transfer_id: r.meta.transfer_id.clone(),
            name: if r.meta.name.is_empty() { "(文本)".into() } else { r.meta.name.clone() },
            size: r.meta.size,
            state: r.state.clone(),
            error: r.error.clone(),
        })
        .collect())
}

#[tauri::command]
pub async fn accept_pull(transfer_id: String) -> std::result::Result<serde_json::Value, String> {
    if let Some(r) = try_ipc(IpcCommand::Accept { transfer_id: transfer_id.clone() }).await {
        return r.map_err(err_to_string);
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let path = agent::accept_pull(&store, &mdns, &transfer_id)
        .await
        .map_err(err_to_string)?;
    Ok(serde_json::json!({ "path": path }))
}

#[tauri::command]
pub async fn deny_pull(transfer_id: String) -> std::result::Result<(), String> {
    if let Some(r) = try_ipc(IpcCommand::Deny { transfer_id: transfer_id.clone() }).await {
        return r.map(|_| ()).map_err(err_to_string);
    }
    let mut pulls = agent::load_pulls();
    let Some(rec) = pulls.iter_mut().find(|p| p.transfer_id == transfer_id) else {
        return Err("没有该待接收项".into());
    };
    rec.state = "denied".into();
    agent::save_pulls(&pulls).map_err(err_to_string)?;
    Ok(())
}

#[tauri::command]
pub async fn send_files(paths: Vec<String>) -> std::result::Result<serde_json::Value, String> {
    if let Some(r) = try_ipc(IpcCommand::SendFiles { to: None, paths: paths.clone() }).await {
        return r.map_err(err_to_string);
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    let trust = dfabric::pick_trust(&store, None).map_err(err_to_string)?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let config = df_core::tls::client_config(&trust.ca_pem, &trust.cert_pem, &trust.key_pem)
        .map_err(err_to_string)?;
    let name = dfabric::display_name(&store);
    for f in &paths {
        let (meta, staged) = dfabric::stage_file(&store, std::path::Path::new(f))
            .map_err(err_to_string)?;
        let mut ctrl = dfabric::connect_trust(&trust, Some(&name), &mdns)
            .await
            .map_err(err_to_string)?;
        let session_id = ctrl.hello_session_id.clone();
        let mut done = std::collections::BTreeSet::new();
        df_core::transfer::up::upload(
            &mut ctrl, config.clone(), &session_id, &meta, &staged, &mut done, None, None,
        )
        .await
        .map_err(err_to_string)?;
        let _ = std::fs::remove_file(&staged);
    }
    Ok(serde_json::json!({ "queued": paths.len() }))
}

#[tauri::command]
pub async fn send_text(text: String) -> std::result::Result<(), String> {
    if let Some(r) = try_ipc(IpcCommand::SendText { to: None, text: text.clone() }).await {
        return r.map(|_| ()).map_err(err_to_string);
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    let trust = dfabric::pick_trust(&store, None).map_err(err_to_string)?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let name = dfabric::display_name(&store);
    let mut ctrl = dfabric::connect_trust(&trust, Some(&name), &mdns)
        .await
        .map_err(err_to_string)?;
    df_core::transfer::up::send_text(&mut ctrl, &uuid::Uuid::new_v4().to_string(), &text)
        .await
        .map_err(err_to_string)?;
    Ok(())
}

#[tauri::command]
pub async fn remove_device(node_id: String) -> std::result::Result<(), String> {
    if let Some(r) = try_ipc(IpcCommand::Remove { node_id: node_id.clone() }).await {
        return r.map(|_| ()).map_err(err_to_string);
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    dfabric::secrets::drop_trust(&node_id);
    store.remove_trust(&node_id).map_err(err_to_string)?;
    Ok(())
}

#[tauri::command]
pub async fn set_name(name: Option<String>) -> std::result::Result<(), String> {
    if let Some(r) = try_ipc(IpcCommand::SetName { name: name.clone() }).await {
        return r.map(|_| ()).map_err(err_to_string);
    }
    let store = dfabric::open_store().map_err(err_to_string)?;
    store.set_local_name(name.as_deref()).map_err(err_to_string)?;
    Ok(())
}

#[tauri::command]
pub async fn get_name() -> std::result::Result<serde_json::Value, String> {
    let store = dfabric::open_store().map_err(err_to_string)?;
    Ok(serde_json::json!({
        "name": dfabric::display_name(&store),
        "custom": store.local_name().is_some(),
    }))
}

#[tauri::command]
pub async fn import_pairing(json: String) -> std::result::Result<String, String> {
    let tp = df_core::pairing::token::TokenPairing::from_json(&json).map_err(err_to_string)?;
    let store = dfabric::open_store().map_err(err_to_string)?;
    // 同一 token 绑定第一次提交的公钥：私钥先保存为「待定」
    let identity = match store.take_pending_key(&tp.node_id) {
        Some(pem) => df_core::keys::SigningIdentity::from_pkcs8_pem(&pem).map_err(err_to_string)?,
        None => df_core::keys::SigningIdentity::generate(),
    };
    store
        .set_pending_key(&tp.node_id, &identity.to_pkcs8_pem())
        .map_err(err_to_string)?;
    let name = dfabric::display_name(&store);
    let pr = tp.pair(&identity, &name).await.map_err(err_to_string)?;
    let trust = df_core::stores::Trust::from_pair_result(&pr);
    dfabric::secrets::protect_trust(&trust);
    store.upsert_trust(trust.clone()).map_err(err_to_string)?;
    let _ = store.take_pending_key(&tp.node_id);
    Ok(trust.name.unwrap_or_else(|| "Lineage 设备".into()))
}

// —— 附近配对（两阶段：start 显示验证码 → confirm/cancel）——

pub struct PairState {
    session: tokio::sync::Mutex<Option<dfabric::ble::BleSession>>,
    handshake: tokio::sync::Mutex<Option<df_core::pairing::near::NearHandshake>>,
}

impl Default for PairState {
    fn default() -> Self {
        PairState { session: tokio::sync::Mutex::new(None), handshake: tokio::sync::Mutex::new(None) }
    }
}

#[tauri::command]
pub async fn pair_near_start(
    state: tauri::State<'_, PairState>,
    scan_secs: u64,
) -> std::result::Result<serde_json::Value, String> {
    use dfabric::ble::BleSession;

    let found = dfabric::ble::scan(std::time::Duration::from_secs(scan_secs.max(5)))
        .await
        .map_err(err_to_string)?;
    for p in found {
        let label = dfabric::ble::device_label(&p).await;
        let (mut session, eid, pairing) = match BleSession::connect(p).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        if !pairing {
            continue;
        }
        let store = dfabric::open_store().map_err(err_to_string)?;
        let name = dfabric::display_name(&store);
        // eid 取自 INFO；DF-NEAR-1 必须由本端先发 NEAR_COMMIT，这里再等节点说话会一直等到
        // 节点判空闲断开（约 60 秒）。加超时保证命令不会无限挂起。
        let hs = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            df_core::pairing::near::near_prepare(&mut session, &eid, &name),
        )
        .await
        .map_err(|_| "附近配对握手超时（请确认手机仍停在「添加设备」窗口）".to_string())?
        .map_err(err_to_string)?;
        let sas = hs.sas();
        let node_id = hs.node_id().to_string();
        *state.handshake.lock().await = Some(hs);
        *state.session.lock().await = Some(session);
        return Ok(serde_json::json!({ "sas": sas, "label": label, "nodeId": node_id }));
    }
    Err("没有处于「添加设备」窗口的设备（请先在手机上点「添加设备」）".into())
}

#[tauri::command]
pub async fn pair_near_confirm(
    app: tauri::AppHandle,
    state: tauri::State<'_, PairState>,
) -> std::result::Result<String, String> {
    use tauri::Emitter;
    let hs = state.handshake.lock().await.take();
    let session = state.session.lock().await.take();
    let (Some(hs), Some(mut session)) = (hs, session) else {
        return Err("没有进行中的配对".into());
    };
    let pr = df_core::pairing::near::near_confirm(&mut session, &hs)
        .await
        .map_err(err_to_string)?;
    let trust = df_core::stores::Trust::from_pair_result(&pr);
    dfabric::secrets::protect_trust(&trust);
    let store = dfabric::open_store().map_err(err_to_string)?;
    store.upsert_trust(trust.clone()).map_err(err_to_string)?;
    let name = trust.name.unwrap_or_else(|| "Lineage 设备".into());
    let _ = app.emit("pair-done", &name);
    Ok(name)
}

#[tauri::command]
pub async fn pair_near_cancel(state: tauri::State<'_, PairState>) -> std::result::Result<(), String> {
    let hs = state.handshake.lock().await.take();
    let session = state.session.lock().await.take();
    if let (Some(_), Some(mut session)) = (hs, session) {
        let _ = df_core::pairing::near::near_cancel(&mut session).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn daemon_running() -> bool {
    try_ipc(IpcCommand::Status).await.is_some()
}

/// 读取配对导出文件（前端 WebView 无法直接读任意路径）。
#[tauri::command]
pub async fn read_pairing_file(path: String) -> std::result::Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("读取文件失败: {e}"))
}

// —— 诊断：自检与日志 ——

/// 运行自检（只读，不修改任何数据）。返回检查项列表与统计。
#[tauri::command]
pub async fn run_selftest(
    no_ble: bool,
    no_mdns: bool,
    connect: bool,
) -> std::result::Result<serde_json::Value, String> {
    let opts = dfabric::selfcheck::Options {
        ble: !no_ble,
        mdns: !no_mdns,
        connect,
        timeout: std::time::Duration::from_secs(6),
    };
    df_core::logging::info("selftest", format!("GUI 触发自检（{opts:?}）"));
    let checks = dfabric::selfcheck::run(&opts).await;
    let (pass, warn, fail, skip) = dfabric::selfcheck::summary(&checks);
    Ok(serde_json::json!({
        "checks": checks,
        "pass": pass,
        "warn": warn,
        "fail": fail,
        "skip": skip,
    }))
}

/// 日志与数据目录位置。
#[tauri::command]
pub async fn log_info() -> std::result::Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "path": df_core::logging::log_path().map(|p| p.display().to_string()),
        "dir": dfabric::logging::log_dir().display().to_string(),
        "dataDir": dfabric::data_dir().display().to_string(),
    }))
}

/// 最近日志（含轮转文件）。
#[tauri::command]
pub async fn read_logs(tail: usize) -> std::result::Result<String, String> {
    let lines = df_core::logging::recent(tail.clamp(1, 2000));
    if lines.is_empty() {
        return Ok("（暂无日志内容）".into());
    }
    Ok(lines.join("\n"))
}

/// 用系统文件管理器打开日志目录。
#[tauri::command]
pub async fn open_log_dir() -> std::result::Result<(), String> {
    let dir = dfabric::logging::log_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("无法创建日志目录: {e}"))?;
    let target = dir.to_string_lossy().to_string();
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(&target);
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = std::process::Command::new("explorer");
        c.arg(&target);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(&target);
        c
    };
    cmd.spawn().map_err(|e| format!("无法打开日志目录: {e}"))?;
    Ok(())
}
