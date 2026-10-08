//! 后台 Agent 守护进程（M5）：mDNS 浏览、接收轮询、IPC、串行发送队列。
//! 登录自启动可在各平台注册（Linux: systemd --user / .desktop；macOS: Login Item；Windows: 启动项）。
//!
//! 选项：
//! - 日志级别取自 `DFABRIC_LOG`（或 `RUST_LOG`），默认 info；
//! - 日志文件位于平台日志目录，`dfctl logs` 可查看路径与最近内容。

use dfabric::agent::{run_ipc_server, Agent};

#[tokio::main]
async fn main() {
    df_core::tls::ensure_provider();
    let log_path = dfabric::logging::init_or_stderr(dfabric::logging::level_from_env(), false);
    df_core::logging::info(
        "daemon",
        format!(
            "dfabricd 启动：数据目录 {}，日志 {}",
            dfabric::data_dir().display(),
            log_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "（仅 stderr）".into())
        ),
    );

    let agent = match Agent::start().await {
        Ok(a) => a,
        Err(e) => {
            df_core::logging::error("daemon", format!("Agent 启动失败：{e}"));
            eprintln!("Agent 启动失败: {e}");
            std::process::exit(1);
        }
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    eprintln!(
        "dfabricd 已启动：数据目录 {:?}，IPC {:?}",
        dfabric::data_dir(),
        dfabric::agent::ipc_socket_path()
    );

    // Ctrl+C 优雅退出
    let shutdown_rx2 = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    run_ipc_server(agent, shutdown_rx2).await;
    df_core::logging::info("daemon", "dfabricd 已退出");
    eprintln!("dfabricd 已退出");
}
