//! 无路由器连接（8.2 节）：以“传统客户端”身份凭 SSID+口令加入节点的 Wi-Fi Direct GO。
//!
//! 平台实现：
//! - Linux：NetworkManager（nmcli）临时连接（不自动连接、结束后删除并恢复原网络）；
//! - macOS / Windows：v1 未实现（需 CoreWLAN / Native Wifi 适配），界面说明原因。
//!
//! 安全要求：入组前必须征得用户同意；使用 BLE 认证通道拿到的 SSID/口令；
//! 传输结束、取消或失败后删除临时配置并恢复原网络；不长期保存组口令。

use df_core::error::{DfError, Result};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GoJoin {
    pub iface: Option<String>,
    pub ssid: String,
    pub passphrase: String,
}

/// 加入前的系统状态记录（用于恢复）。
pub struct PrevState {
    conn_name: Option<String>,
}

pub async fn join_go(join: &GoJoin) -> Result<PrevState> {
    #[cfg(target_os = "linux")]
    {
        linux_join(join).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = join;
        Err(DfError::Unsupported(
            "该平台的无路由器连接（加入 Wi-Fi Direct GO）尚未实现，请使用局域网连接".into(),
        ))
    }
}

/// 传输结束 / 取消 / 失败后恢复原网络并删除临时配置。
pub async fn restore(prev: PrevState) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_restore(prev).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = prev;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn nmcli(args: &[&str]) -> Result<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("nmcli").args(args).output(),
    )
    .await
    .map_err(|_| DfError::Timeout("nmcli 超时".into()))?
    .map_err(|e| DfError::Unsupported(format!("nmcli 不可用: {e}")))?;
    if !out.status.success() {
        return Err(DfError::Protocol(format!(
            "nmcli {} 失败: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(target_os = "linux")]
async fn linux_join(join: &GoJoin) -> Result<PrevState> {
    // 记录当前活动的 Wi-Fi 连接，结束后恢复
    let active = nmcli(&["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]).await?;
    let conn_name = active
        .lines()
        .find(|l| l.contains(":802-11-wireless:") || l.contains(":wifi:"))
        .and_then(|l| l.split(':').next().map(String::from));

    // 临时连接（绝不自动连接；由 BLE 认证通道拿到的 SSID/口令）
    let ssid = &join.ssid;
    let pass = &join.passphrase;
    let name = format!("dfabric-temp-{ssid}");
    nmcli(&[
        "connection", "add", "type", "wifi", "con-name", &name, "ifname",
        join.iface.as_deref().unwrap_or("*"), "ssid", ssid, "wifi-sec.key-mgmt", "wpa-psk",
        "wifi-sec.psk", pass, "connection.autoconnect", "no",
    ])
    .await?;
    let up = nmcli(&["connection", "up", &name]).await;
    if let Err(e) = up {
        let _ = nmcli(&["connection", "delete", &name]).await;
        return Err(DfError::Protocol(format!("加入 GO 失败: {e}")));
    }
    Ok(PrevState { conn_name })
}

#[cfg(target_os = "linux")]
async fn linux_restore(prev: PrevState) -> Result<()> {
    // 删除临时配置
    let list = nmcli(&["-t", "-f", "NAME", "connection", "show"]).await?;
    for name in list.lines().filter(|n| n.starts_with("dfabric-temp-")) {
        let _ = nmcli(&["connection", "delete", name]).await;
    }
    // 恢复原网络
    if let Some(name) = prev.conn_name {
        let _ = nmcli(&["connection", "up", &name]).await;
    }
    Ok(())
}
