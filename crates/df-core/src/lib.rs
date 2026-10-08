//! DF/1 桌面端协议核心（跨平台共享）。
//!
//! 字节格式与语义以 `vendor/diater/apps/DeviceFabric/protocol/DF1.md` 为准；
//! 本 crate 的字段名集中定义，便于与参考实现对拍修正。

pub mod bitmap;
pub mod crypto;
pub mod error;
pub mod fields;
pub mod frame;
pub mod fsutil;
pub mod keys;
pub mod msg;
pub mod names;
pub mod pairing;
pub mod session;
pub mod stores;
pub mod tls;
pub mod transfer;

/// BLE 服务 UUID（主广播）与 GATT 特征 UUID（尾号 e211/e212/e213）。
pub mod consts {
    /// DF-1 控制端口默认值（实际以配对/LINK_READY 为准）。
    pub const DEFAULT_CONTROL_PORT: u16 = 9527;
    /// DF-1 数据端口默认值。
    pub const DEFAULT_DATA_PORT: u16 = 9528;
    /// BLE 主广播 service UUID。
    pub const BLE_SERVICE_UUID: &str = "38e96d70-1342-4bc8-8f02-924127b5e210";
    /// GATT RX（Controller → 节点，write with response）。
    pub const BLE_CHAR_RX: &str = "38e96d70-1342-4bc8-8f02-924127b5e211";
    /// GATT TX（节点 → Controller，notify）。
    pub const BLE_CHAR_TX: &str = "38e96d70-1342-4bc8-8f02-924127b5e212";
    /// GATT INFO（read，UTF-8 JSON {v, eid, pairing}）。
    pub const BLE_CHAR_INFO: &str = "38e96d70-1342-4bc8-8f02-924127b5e213";
    /// mDNS 服务类型。
    pub const MDNS_SERVICE: &str = "_dfabric._tcp.local.";
    /// 控制帧长度上限（含）。
    pub const MAX_FRAME: usize = 65536;
    /// 块大小（字节）。
    pub const CHUNK_SIZE: u64 = 1048576;
    /// 单文件上限。
    pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;
    /// 文本上限（UTF-8 字节）。
    pub const MAX_TEXT: usize = 49152;
    /// 控制帧读取上限校验。
    pub const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
}
