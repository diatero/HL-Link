//! dfctl：命令行 Controller（可直接操作，也可经 IPC 交接给运行中的 dfabricd）。

use clap::{Parser, Subcommand};
use df_core::error::{DfError, Result};
use dfabric::agent::{self, IpcCommand, IpcReply};
use dfabric::selfcheck;
use std::io::Write as _;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "dfctl", about = "DeviceFabric 桌面端命令行（Controller）", version)]
struct Cli {
    /// 日志级别：error / warn / info / debug（也可用环境变量 DFABRIC_LOG）
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,
    /// 不写日志文件，只输出到终端
    #[arg(long, global = true)]
    no_log: bool,
    /// 同时把日志镜像到 stderr（便于把终端输出和日志对照）
    #[arg(long, global = true)]
    log_stderr: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 附近配对（DF-NEAR-1，需要手机先点「添加设备」）
    PairNear {
        /// 扫描时长（秒）
        #[arg(long, default_value_t = 15)]
        scan_secs: u64,
    },
    /// 导入「导出配对信息」JSON 文件（含一次性口令，导入后请删除该文件）
    PairImport { file: String },
    /// 从标准输入粘贴导出配对 JSON
    PairPaste,
    /// 发送文件（可多个；有 dfabricd 在运行时交接给后台队列）
    Send {
        /// 目标节点 nodeId 前缀（只有一台已配对设备时可省略）
        #[arg(long)]
        to: Option<String>,
        files: Vec<String>,
    },
    /// 发送文本（≤49152 字节；更长的请作为 .txt 文件）
    SendText {
        #[arg(long)]
        to: Option<String>,
        text: String,
    },
    /// 列出已信任设备
    Devices,
    /// 查看节点状态（STATUS）
    Status {
        #[arg(long)]
        to: Option<String>,
    },
    /// 列出待接收（手机发来的文件请求）
    Pulls,
    /// 接受并下载
    Accept { transfer_id: String },
    /// 拒绝
    Deny { transfer_id: String },
    /// 查看/设置本机显示名称（无参数=跟随系统名称需传 --reset）
    Name {
        name: Option<String>,
        #[arg(long)]
        reset: bool,
    },
    /// 删除信任设备（同时提醒在手机上解除信任）
    Remove { node_id: String },
    /// 自检：协议核心 + 本机环境 + 已配对设备（不修改任何数据）
    Selftest {
        /// 以 JSON 输出（便于附到问题报告）
        #[arg(long)]
        json: bool,
        /// 跳过蓝牙检查（macOS 上不会触发蓝牙权限询问）
        #[arg(long)]
        no_ble: bool,
        /// 跳过 mDNS 检查
        #[arg(long)]
        no_mdns: bool,
        /// 额外对每个已配对设备做 TLS + HELLO + STATUS（需要手机在线）
        #[arg(long)]
        connect: bool,
        /// 单台设备连通超时（秒）
        #[arg(long, default_value_t = 6)]
        timeout: u64,
    },
    /// 查看日志：默认打印最后若干行与日志目录
    Logs {
        /// 打印的行数
        #[arg(long, default_value_t = 40)]
        tail: usize,
        /// 只打印日志文件路径
        #[arg(long)]
        path: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let level = cli
        .log_level
        .as_deref()
        .and_then(df_core::logging::Level::parse)
        .or_else(dfabric::logging::level_from_env)
        .unwrap_or(df_core::logging::Level::Info);
    if cli.no_log {
        df_core::logging::set_level(level);
        df_core::logging::set_stderr(true);
    } else {
        dfabric::logging::init_or_stderr(Some(level), cli.log_stderr);
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = match rt.block_on(run(cli.cmd)) {
        Ok(()) => 0,
        Err(e) => {
            df_core::logging::error("dfctl", format!("命令失败：{e}"));
            eprintln!("错误: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cmd: Cmd) -> Result<()> {
    df_core::tls::ensure_provider();
    match cmd {
        Cmd::PairNear { scan_secs } => pair_near(Duration::from_secs(scan_secs)).await,
        Cmd::PairImport { file } => {
            let json = std::fs::read_to_string(&file)
                .map_err(|e| DfError::Protocol(format!("读取导出文件失败: {e}")))?;
            pair_token(&json).await
        }
        Cmd::PairPaste => {
            let mut json = String::new();
            std::io::stdin().read_line(&mut json)?;
            pair_token(json.trim()).await
        }
        Cmd::Send { to, files } => send_files(to, files).await,
        Cmd::SendText { to, text } => send_text(to, text).await,
        Cmd::Devices => devices(),
        Cmd::Status { to } => status(to).await,
        Cmd::Pulls => {
            let pulls = agent::load_pulls();
            println!("{0:<40} {1:<10} {2:<10} {3}", "transferId", "状态", "大小", "名称");
            for p in &pulls {
                println!(
                    "{0:<40} {1:<10} {2:<10} {3}",
                    p.transfer_id,
                    p.state,
                    format_size(p.size),
                    p.name
                );
            }
            if pulls.is_empty() {
                println!("（空）");
            }
            Ok(())
        }
        Cmd::Accept { transfer_id } => {
            if let Some(reply) = try_ipc(IpcCommand::Accept { transfer_id: transfer_id.clone() }).await {
                return print_reply(reply);
            }
            let store = dfabric::open_store()?;
            let mdns = dfabric::mdns::MdnsBrowser::new();
            let path = agent::accept_pull(&store, &mdns, &transfer_id).await?;
            println!("已保存到 {path}");
            Ok(())
        }
        Cmd::Deny { transfer_id } => {
            if let Some(reply) = try_ipc(IpcCommand::Deny { transfer_id: transfer_id.clone() }).await {
                return print_reply(reply);
            }
            let mut pulls = agent::load_pulls();
            let Some(rec) = pulls.iter_mut().find(|p| p.transfer_id == transfer_id) else {
                return Err(DfError::Protocol("没有该待接收项".into()));
            };
            rec.state = "denied".into();
            agent::save_pulls(&pulls)?;
            println!("已拒绝");
            Ok(())
        }
        Cmd::Name { name, reset } => {
            let store = dfabric::open_store()?;
            if name.is_none() && reset {
                store.set_local_name(None)?;
                println!("已恢复跟随系统名称");
                return Ok(());
            }
            match name {
                Some(n) => {
                    store.set_local_name(Some(&n))?;
                    println!("已设置");
                }
                None => {
                    let current = dfabric::display_name(&store);
                    let custom = store.local_name();
                    println!("当前名称: {current}{}", if custom.is_some() { "（自定义）" } else { "（跟随系统）" });
                }
            }
            Ok(())
        }
        Cmd::Remove { node_id } => {
            if let Some(reply) = try_ipc(IpcCommand::Remove { node_id: node_id.clone() }).await {
                return print_reply(reply);
            }
            let store = dfabric::open_store()?;
            let Some(t) = dfabric::find_trust(&store, &node_id) else {
                return Err(DfError::Protocol("没有匹配的信任设备".into()));
            };
            dfabric::secrets::drop_trust(&t.node_id);
            store.remove_trust(&t.node_id)?;
            println!("已删除。请同时在手机上解除对这台电脑的信任。");
            Ok(())
        }
        Cmd::Selftest { json, no_ble, no_mdns, connect, timeout } => {
            selftest(json, no_ble, no_mdns, connect, timeout).await
        }
        Cmd::Logs { tail, path } => {
            if path {
                match df_core::logging::log_path() {
                    Some(p) => println!("{}", p.display()),
                    None => println!("（日志未初始化：日志目录 {}）", dfabric::logging::log_dir().display()),
                }
                return Ok(());
            }
            let lines = df_core::logging::recent(tail);
            if lines.is_empty() {
                println!("（暂无日志内容）");
            } else {
                for l in &lines {
                    println!("{l}");
                }
            }
            println!("\n日志目录: {}", dfabric::logging::log_dir().display());
            println!("提示: `dfctl selftest` 会把自检结果写入同一份日志");
            Ok(())
        }
    }
}

/// 自检报告：文本或 JSON；有 FAIL 时以退出码 2 结束（0 = 全部通过，1 = 命令本身出错）。
async fn selftest(json: bool, no_ble: bool, no_mdns: bool, connect: bool, timeout: u64) -> Result<()> {
    let opts = selfcheck::Options {
        ble: !no_ble,
        mdns: !no_mdns,
        connect,
        timeout: Duration::from_secs(timeout.max(1)),
    };
    df_core::logging::info("selftest", format!("开始自检（{opts:?}）"));
    let checks = selfcheck::run(&opts).await;
    let (pass, warn, fail, skip) = selfcheck::summary(&checks);
    if json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for c in &checks {
            println!("[{:<4}] {}: {}", c.status.as_str(), c.name, c.detail);
        }
    }
    let tail = format!("自检结果：PASS {pass} / WARN {warn} / FAIL {fail} / SKIP {skip}");
    println!("{tail}");
    df_core::logging::info("selftest", &tail);
    if selfcheck::has_failure(&checks) {
        // 直接以退出码 2 结束：所有输出与日志都已落盘（日志每次写入即落盘）
        std::process::exit(2);
    }
    Ok(())
}

fn print_reply(reply: IpcReply) -> Result<()> {
    if reply.ok {
        if let Some(d) = reply.data {
            println!("{d}");
        }
        Ok(())
    } else {
        Err(DfError::Protocol(reply.error.unwrap_or_else(|| "未知错误".into())))
    }
}

/// 若 dfabricd 在运行则走 IPC（入口进程退出后任务仍在 Agent 队列中）。
async fn try_ipc(cmd: IpcCommand) -> Option<IpcReply> {
    agent::ipc_request(cmd).await
}

async fn pair_near(scan: Duration) -> Result<()> {
    use dfabric::ble::BleSession;
    println!("正在扫描附近的 DeviceFabric 设备（请先在手机上点「添加设备」）…");
    let found = dfabric::ble::scan(scan).await?;
    if found.is_empty() {
        return Err(DfError::Ble("未发现设备：确认手机蓝牙已开且处于配对窗口内".into()));
    }
    for p in found {
        use btleplug::api::Peripheral as _;
        let props = p.properties().await.ok().flatten();
        let label = props
            .as_ref()
            .and_then(|pr| pr.local_name.clone())
            .unwrap_or_else(|| "附近的 Lineage 设备".into());
        println!("尝试连接: {label}");
        let (mut session, eid, pairing) = match BleSession::connect(p).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("  跳过（{e}）");
                continue;
            }
        };
        if !pairing {
            eprintln!("  跳过（该设备未处于添加设备窗口）");
            continue;
        }
        let store = dfabric::open_store()?;
        let name = dfabric::display_name(&store);
        // eid 必须取自刚才读到的 INFO：DF-NEAR-1 由本端先发 NEAR_COMMIT，
        // 在这里等节点先说话会一直等到节点判空闲断开。
        let hs = tokio::time::timeout(
            Duration::from_secs(20),
            df_core::pairing::near::near_prepare(&mut session, &eid, &name),
        )
        .await
        .map_err(|_| DfError::Timeout("附近配对握手超时（请确认手机仍停在「添加设备」窗口）".into()))??;
        println!();
        println!("  ╔══════════════════════╗");
        println!("  ║  验证码: {}         ║", hs.sas());
        println!("  ╚══════════════════════╝");
        println!("请在手机上确认显示相同的 6 位验证码，确认后在这里输入 y 继续（其他键取消）：");
        let mut line = String::new();
        std::io::stdout().flush().ok();
        std::io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            df_core::pairing::near::near_cancel(&mut session).await?;
            println!("已取消");
            return Ok(());
        }
        let pr = df_core::pairing::near::near_confirm(&mut session, &hs).await?;
        let trust = df_core::stores::Trust::from_pair_result(&pr);
        dfabric::secrets::protect_trust(&trust);
        store.upsert_trust(trust.clone())?;
        df_core::logging::info(
            "pair",
            format!("附近配对成功：{}（nodeId {}…）", trust.name.as_deref().unwrap_or("Lineage 设备"), &trust.node_id[..12.min(trust.node_id.len())]),
        );
        println!("配对成功：{}（nodeId {}…）", trust.name.as_deref().unwrap_or("Lineage 设备"), &trust.node_id[..12.min(trust.node_id.len())]);
        return Ok(());
    }
    Err(DfError::Pairing("没有设备处于配对窗口".into()))
}

async fn pair_token(json: &str) -> Result<()> {
    let tp = df_core::pairing::token::TokenPairing::from_json(json)?;
    let store = dfabric::open_store()?;
    // 同一 token 绑定第一次提交的公钥：私钥先保存为「待定」，重试拿到同一结果
    let identity = match store.take_pending_key(&tp.node_id) {
        Some(pem) => df_core::keys::SigningIdentity::from_pkcs8_pem(&pem)?,
        None => df_core::keys::SigningIdentity::generate(),
    };
    store.set_pending_key(&tp.node_id, &identity.to_pkcs8_pem())?;

    let name = dfabric::display_name(&store);
    println!("正在配对 {}…（手机上需要批准）", &tp.node_id[..12.min(tp.node_id.len())]);
    let pr = tp.pair(&identity, &name).await?;
    let trust = df_core::stores::Trust::from_pair_result(&pr);
    dfabric::secrets::protect_trust(&trust);
    store.upsert_trust(trust.clone())?;
    let _ = store.take_pending_key(&tp.node_id); // 成功后删除待定
    println!("配对成功。导入文件含一次性口令，请尽快删除该文件。");
    Ok(())
}

async fn send_files(to: Option<String>, files: Vec<String>) -> Result<()> {
    if files.is_empty() {
        return Err(DfError::Protocol("没有要发送的文件".into()));
    }
    if let Some(reply) = try_ipc(IpcCommand::SendFiles { to: to.clone(), paths: files.clone() }).await {
        return print_reply(reply);
    }
    // 直接模式：临时充当 Agent，串行发送
    let store = dfabric::open_store()?;
    let trust = dfabric::pick_trust(&store, to.as_deref())?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let config = df_core::tls::client_config(&trust.ca_pem, &trust.cert_pem, &trust.key_pem)?;
    let name = dfabric::display_name(&store);
    for f in files {
        let (meta, staged) = dfabric::stage_file(&store, std::path::Path::new(&f))?;
        println!("发送 {}（{}）→ {}", meta.name, format_size(meta.size), &trust.node_id[..12]);
        let mut ctrl = dfabric::connect_trust(&trust, Some(&name), &mdns).await?;
        let session_id = ctrl.hello_session_id.clone();
        let mut done = std::collections::BTreeSet::new();
        let result = df_core::transfer::up::upload(
            &mut ctrl,
            config.clone(),
            &session_id,
            &meta,
            &staged,
            &mut done,
            Some(&mut |d, t| {
                let pct = if t > 0 { d * 100 / t } else { 100 };
                print!("\r  进度 {pct}%  ");
                std::io::stdout().flush().ok();
            }),
            None,
        )
        .await;
        println!();
        match result {
            Ok(_) => {
                let _ = std::fs::remove_file(&staged);
                println!("  完成");
            }
            Err(e) => {
                eprintln!("  失败: {e}（任务与暂存已保留，重试同一文件将续传）");
                return Err(e);
            }
        }
    }
    Ok(())
}

async fn send_text(to: Option<String>, text: String) -> Result<()> {
    if let Some(reply) = try_ipc(IpcCommand::SendText { to: to.clone(), text: text.clone() }).await {
        return print_reply(reply);
    }
    let store = dfabric::open_store()?;
    let trust = dfabric::pick_trust(&store, to.as_deref())?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let name = dfabric::display_name(&store);
    let mut ctrl = dfabric::connect_trust(&trust, Some(&name), &mdns).await?;
    df_core::transfer::up::send_text(&mut ctrl, &uuid::Uuid::new_v4().to_string(), &text).await?;
    println!("已发送");
    Ok(())
}

fn devices() -> Result<()> {
    let store = dfabric::open_store()?;
    let trusts = store.trusts();
    if trusts.is_empty() {
        println!("（尚未配对任何设备）");
        return Ok(());
    }
    for t in &trusts {
        println!(
            "{}  {}  {}{}",
            &t.node_id[..12.min(t.node_id.len())],
            t.name.as_deref().unwrap_or("Lineage 设备"),
            t.last_addr.as_deref().unwrap_or("-"),
            if t.revoked { "  [信任已失效，请重新配对]" } else { "" }
        );
    }
    Ok(())
}

async fn status(to: Option<String>) -> Result<()> {
    let store = dfabric::open_store()?;
    let trust = dfabric::pick_trust(&store, to.as_deref())?;
    let mdns = dfabric::mdns::MdnsBrowser::new();
    let name = dfabric::display_name(&store);
    let mut ctrl = dfabric::connect_trust(&trust, Some(&name), &mdns).await?;
    let st = ctrl.status().await?;
    println!("{}", serde_json::to_string_pretty(&st)?);
    Ok(())
}

fn format_size(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
