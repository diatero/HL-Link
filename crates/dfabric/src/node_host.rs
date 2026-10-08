//! 本机作为 DF/1 节点（df-node）的宿主：目录、开关设置、事件通知。
//!
//! 节点默认关闭，由用户 `dfctl node on` 开启；开启后在局域网监听 9527/9528，
//! 让 HL Link（鸿蒙）等控制端配对并互传。需要防火墙放行这两个 TCP 端口。

use crate::{data_dir, display_name, notify, open_store};
use df_core::error::{DfError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

pub fn node_dir() -> PathBuf {
    data_dir().join("node")
}

/// 收件目录：`~/Downloads/HL Link`（无下载目录时放在数据目录下）。
pub fn inbox_dir() -> PathBuf {
    dirs::download_dir().unwrap_or_else(data_dir).join("HL Link")
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NodeSettings {
    #[serde(default)]
    pub enabled: bool,
}

fn settings_path() -> PathBuf {
    data_dir().join("node.json")
}

pub fn load_settings() -> NodeSettings {
    std::fs::read(settings_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_settings(s: &NodeSettings) -> Result<()> {
    df_core::fsutil::atomic_write(&settings_path(), &serde_json::to_vec_pretty(s)?)
}

pub fn open() -> Result<df_node::Node> {
    let cfg = df_node::NodeConfig {
        dir: node_dir(),
        inbox: inbox_dir(),
        name: Arc::new(|| open_store().map(|s| display_name(&s)).unwrap_or_else(|_| df_core::names::default_device_name())),
    };
    df_node::Node::open(cfg).map_err(|e| DfError::Protocol(format!("节点初始化失败：{e}")))
}

/// 把节点事件转成桌面通知（审批请求提示用 dfctl / 界面处理）。
pub fn spawn_notifications(node: &df_node::Node) {
    let mut rx = node.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(df_node::Event::Approval { kind, description, .. }) => {
                    let title = match kind.as_str() {
                        "pair" => "设备请求配对",
                        "text" => "设备想发送文本",
                        _ => "设备想发送文件",
                    };
                    notify(title, &format!("{description}\n运行 dfctl node approve 允许，dfctl node deny 拒绝（90 秒内）"));
                }
                Ok(df_node::Event::Paired { name, .. }) => notify("配对成功", &name),
                Ok(df_node::Event::Received { peer, path, .. }) => notify(&format!("已接收（来自 {peer}）"), &path),
                Ok(df_node::Event::Delivered { peer, name }) => notify("发送完成", &format!("{name} → {peer}")),
                Ok(df_node::Event::Status(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
    });
}
