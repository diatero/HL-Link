//! 桌面端 DF/1 节点（Node 角色）：让 HL Link（鸿蒙）等控制端配对、发送与拉取。
//!
//! 协议与 LineageOS 节点（`vendor/diater/apps/DeviceFabric`）相同，见 DF1.md；
//! 桌面节点只提供局域网链路（HELLO_ACK `links: ["LAN"]`），不做 BLE 外设与 Wi-Fi Direct GO。

pub mod identity;
pub mod incoming;
pub mod net;
pub mod node;
pub mod outgoing;
pub mod peers;
pub mod wire;

pub use node::{ApprovalView, Event, Node, NodeConfig};
