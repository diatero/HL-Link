//! 后台 Agent 守护进程（M5）：mDNS 浏览、接收轮询、IPC、串行发送队列。
//! 登录自启动可在各平台注册（Linux: systemd --user / .desktop；macOS: Login Item；Windows: 启动项）。

use dfabric::agent::{run_ipc_server, Agent};

#[tokio::main]
async fn main() {
    df_core::tls::ensure_provider();
    let agent = match Agent::start().await {
        Ok(a) => a,
        Err(e) => {
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
    eprintln!("dfabricd 已退出");
}
