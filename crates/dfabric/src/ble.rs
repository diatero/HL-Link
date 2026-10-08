//! BLE 平台适配：btleplug（Linux=BlueZ D-Bus，Windows=WinRT，macOS=CoreBluetooth）。
//!
//! 对应开发说明 5.2 / 6.1 节：
//! - 必须使用主动扫描（btleplug 默认主动）才能拿到 scan response 中的 eid；
//! - 以 service UUID 过滤；INFO 中的 eid 为准（扫描看到的可能已轮换）；
//! - 先订阅 TX（notify），再读 INFO，再写 RX；
//! - 写入按 MTU 切片（保守按 ATT MTU 23 → payload 14），避免平台自动 long write 被节点拒绝。
//!
//! 平台差异：Linux 用 BlueZ（需 bluetoothd）、macOS 用 CoreBluetooth（**必须有
//! `NSBluetoothAlwaysUsageDescription`，否则进程拿不到适配器**）、Windows 用 WinRT。
//! macOS 上适配器信息与广播地址由系统再映射一次，均不可当身份使用。

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::StreamExt;
use df_core::error::{DfError, Result};
use df_core::pairing::ble_link::GattLink;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

pub fn service_uuid() -> Uuid {
    Uuid::from_str(df_core::consts::BLE_SERVICE_UUID).unwrap()
}

/// 设备显示名（附近配对没有广播名 → “附近的 Lineage 设备”）。
pub async fn device_label(peripheral: &Peripheral) -> String {
    use btleplug::api::Peripheral as _;
    peripheral
        .properties()
        .await
        .ok()
        .flatten()
        .and_then(|p| p.local_name)
        .unwrap_or_else(|| "附近的 Lineage 设备".into())
}

/// 取第一个可用适配器（macOS 走 CoreBluetooth，Linux 走 BlueZ）。
async fn first_adapter() -> Result<Adapter> {
    let manager = Manager::new().await.map_err(|e| DfError::Ble(format!("BLE 管理器: {e}")))?;
    let adapters = manager.adapters().await.map_err(|e| DfError::Ble(format!("获取适配器: {e}")))?;
    adapters
        .into_iter()
        .next()
        .ok_or_else(|| DfError::Ble("没有可用的蓝牙适配器".into()))
}

/// 适配器可用性（自检用：不扫描、不连接、不申请额外权限）。
pub async fn adapter_available() -> Result<String> {
    let adapter = first_adapter().await?;
    let info = adapter
        .adapter_info()
        .await
        .unwrap_or_else(|_| "蓝牙适配器".into());
    Ok(format!("{info}（BLE 中心设备就绪）"))
}

/// 扫描发现（有超时，找到即返回；桌面端不要常驻扫描）。
pub async fn scan(timeout: Duration) -> Result<Vec<Peripheral>> {
    let adapter: Adapter = first_adapter().await?;
    df_core::logging::debug("ble", format!("开始扫描 _dfabric 服务（{timeout:?}）"));

    adapter
        .start_scan(ScanFilter { services: vec![service_uuid()] })
        .await
        .map_err(|e| DfError::Ble(format!("启动扫描: {e}")))?;

    let deadline = tokio::time::Instant::now() + timeout;
    let mut found: Vec<Peripheral> = Vec::new();
    while tokio::time::Instant::now() < deadline {
        for p in adapter.peripherals().await.map_err(|e| DfError::Ble(e.to_string()))? {
            if p.is_connected().await.unwrap_or(false) {
                continue;
            }
            if let Ok(Some(props)) = p.properties().await {
                if props.services.contains(&service_uuid()) && !found.iter().any(|f| f.id() == p.id()) {
                    found.push(p);
                }
            }
        }
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = adapter.stop_scan().await;
    df_core::logging::info("ble", format!("扫描结束：{} 个候选设备", found.len()));
    Ok(found)
}

/// 已连接的 BLE 会话（实现了 GattLink，可跑 DF-BLE-1 认证与附近配对）。
pub struct BleSession {
    peripheral: Peripheral,
    rx: Characteristic,
    tx: Characteristic,
    notifications: std::pin::Pin<Box<dyn futures::Stream<Item = btleplug::api::ValueNotification> + Send>>,
    mtu: u16,
    pending: df_core::pairing::ble_link::Reassembler,
}

impl BleSession {
    /// 连接 + 服务发现 + 订阅 TX + 读 INFO（6.1 节顺序）。
    pub async fn connect(peripheral: Peripheral) -> Result<(BleSession, String, bool)> {
        peripheral
            .connect()
            .await
            .map_err(|e| DfError::Ble(format!("连接失败: {e}")))?;
        peripheral
            .discover_services()
            .await
            .map_err(|e| DfError::Ble(format!("服务发现: {e}")))?;

        let suid = service_uuid();
        let chars: Vec<Characteristic> = peripheral.characteristics().into_iter().collect();
        let rx = chars
            .iter()
            .find(|c| c.service_uuid == suid && c.uuid == uuid_of(df_core::consts::BLE_CHAR_RX))
            .cloned()
            .ok_or_else(|| DfError::Ble("找不到 RX 特征".into()))?;
        let tx = chars
            .iter()
            .find(|c| c.service_uuid == suid && c.uuid == uuid_of(df_core::consts::BLE_CHAR_TX))
            .cloned()
            .ok_or_else(|| DfError::Ble("找不到 TX 特征".into()))?;
        let info = chars
            .iter()
            .find(|c| c.service_uuid == suid && c.uuid == uuid_of(df_core::consts::BLE_CHAR_INFO))
            .cloned()
            .ok_or_else(|| DfError::Ble("找不到 INFO 特征".into()))?;

        // 先订阅 TX
        peripheral
            .subscribe(&tx)
            .await
            .map_err(|e| DfError::Ble(format!("订阅 TX: {e}")))?;
        let notifications = peripheral
            .notifications()
            .await
            .map_err(|e| DfError::Ble(format!("通知流: {e}")))?;

        // 再读 INFO（以 INFO 中的 eid 为准）
        let info_bytes = peripheral
            .read(&info)
            .await
            .map_err(|e| DfError::Ble(format!("读 INFO: {e}")))?;
        let (eid, pairing) = df_core::pairing::near::parse_info(&info_bytes)?;
        df_core::logging::info(
            "ble",
            format!("GATT 就绪：eid {eid}，添加设备窗口 {}（此 eid 用于 DF-NEAR-1 与 DF-BLE-1，不要从消息流里等）", if pairing { "开启" } else { "关闭" }),
        );

        let mtu = detect_mtu(&peripheral).await;
        Ok((
            BleSession { peripheral, rx, tx, notifications, mtu, pending: Default::default() },
            eid,
            pairing,
        ))
    }

    /// MTU（默认保守 23；平台能查到则用真实值）。
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

fn uuid_of(s: &str) -> Uuid {
    Uuid::from_str(s).unwrap()
}

async fn detect_mtu(_p: &Peripheral) -> u16 {
    // btleplug 尚未统一暴露协商 MTU：保守按 ATT 默认 23（payload 14），
    // 协议允许任何 MTU ≥ 23，只是慢一点；macOS 的 maximumWriteValueLength /
    // Linux 的 AcquireWrite MTU 可在后续版本接入。
    23
}

#[async_trait::async_trait]
impl GattLink for BleSession {
    async fn send_message(&mut self, msg: &[u8]) -> Result<()> {
        let payload_len = df_core::pairing::ble_link::payload_len_for_mtu(self.mtu);
        for att in df_core::pairing::ble_link::fragment(msg, payload_len)? {
            // write with response；单片放得下，避免 long write 被节点拒绝
            self.peripheral
                .write(&self.rx, &att, WriteType::WithResponse)
                .await
                .map_err(|e| DfError::Ble(format!("写 RX: {e}")))?;
        }
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Vec<u8>> {
        loop {
            let note = self
                .notifications
                .next()
                .await
                .ok_or_else(|| DfError::Ble("通知流已结束（设备断开）".into()))?;
            if note.uuid != self.tx.uuid {
                continue;
            }
            if let Some(msg) = self.pending.feed(&note.value)? {
                return Ok(msg);
            }
        }
    }
}
