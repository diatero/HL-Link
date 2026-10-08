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
///
/// 返回的 [`ScanHandle`] 持有适配器：**调用方必须在连接尝试结束后调用
/// `stop()`**。不要在返回前停止扫描——BlueZ 在停止 discovery 后会移除刚发现的
/// 设备对象，随后的 GATT connect 会以 `le-connection-abort-by-local` 失败。
pub async fn scan(timeout: Duration) -> Result<(ScanHandle, Vec<Peripheral>)> {
    use btleplug::api::CentralEvent;
    let adapter: Adapter = first_adapter().await?;
    df_core::logging::debug("ble", format!("开始扫描 _dfabric 服务（{timeout:?}）"));

    // 先订阅事件再开始扫描：只接受本次扫描期间真正收到广播的设备。
    // BlueZ 会缓存已消失的设备对象，而节点每次重启广播（约 2 分钟轮换 eid）都换随机地址，
    // 直接列 peripherals() 会拿到连不上的旧对象（Connect 报 "doesn't exist" 或超时）。
    let mut events = adapter
        .events()
        .await
        .map_err(|e| DfError::Ble(format!("订阅扫描事件: {e}")))?;
    adapter
        .start_scan(ScanFilter { services: vec![service_uuid()] })
        .await
        .map_err(|e| DfError::Ble(format!("启动扫描: {e}")))?;

    let mut deadline = tokio::time::Instant::now() + timeout;
    let mut found: Vec<Peripheral> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let event = match tokio::time::timeout(remaining, events.next()).await {
            Ok(Some(ev)) => ev,
            _ => break,
        };
        let (id, kind) = match event {
            CentralEvent::DeviceDiscovered(id) => (id, "discovered"),
            CentralEvent::DeviceUpdated(id) => (id, "updated"),
            CentralEvent::ServiceDataAdvertisement { id, .. } => (id, "service-data"),
            CentralEvent::ServicesAdvertisement { id, .. } => (id, "services"),
            _ => continue,
        };
        if found.iter().any(|f| f.id() == id) {
            continue;
        }
        let Ok(p) = adapter.peripheral(&id).await else { continue };
        if p.is_connected().await.unwrap_or(false) {
            continue;
        }
        if let Ok(Some(props)) = p.properties().await {
            // RSSI 只在本次 discovery 收到广播后才有：订阅事件时 btleplug 会把 BlueZ 缓存的旧对象
            // 当作 discovered（RSSI None）重放，节点轮换广播地址后这些对象连接会挂 30 秒再失败。
            if props.rssi.is_none() {
                continue;
            }
            // RSSI 只在本次 discovery 收到广播后才有：订阅事件时 btleplug 会把 BlueZ 缓存的旧对象
            // 当作 discovered（RSSI None）重放，节点轮换广播地址后这些对象连接会挂 30 秒再失败。
            if props.rssi.is_none() {
                continue;
            }
            if props.services.contains(&service_uuid()) || props.service_data.contains_key(&service_uuid()) {
                df_core::logging::debug(
                    "ble",
                    format!("候选 {}（事件 {kind}，RSSI {:?}，eid {:?}）", props.address, props.rssi,
                        props.service_data.get(&service_uuid()).map(hex::encode)),
                );
                found.push(p);
                // 发现第一台后再收集 1.5 秒，附近有多台节点时一并尝试
                deadline = deadline.min(tokio::time::Instant::now() + Duration::from_millis(1500));
            }
        }
    }
    df_core::logging::info("ble", format!("扫描结束：{} 个候选设备", found.len()));
    Ok((ScanHandle(adapter), found))
}

/// 扫描停止句柄：显式结束 discovery（避免 BlueZ 移除待连接的设备对象）。
pub struct ScanHandle(Adapter);

impl ScanHandle {
    pub async fn stop(&self) {
        let _ = self.0.stop_scan().await;
    }
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
    ///
    /// Linux BlueZ 上 connect 偶发 `le-connection-abort-by-local`（HCI 本地中止，
    /// 常见于连接建立期间 discovery 竞争），这里做最多 3 次重试。
    pub async fn connect(peripheral: Peripheral) -> Result<(BleSession, String, bool)> {
        let mut last_err = None;
        for attempt in 0..3 {
            match Self::connect_once(&peripheral).await {
                Ok(x) => return Ok(x),
                Err(e) => {
                    // 通知流/特征缺失等非瞬时错误不重试；设备对象已被 BlueZ 移除（地址已轮换）也不重试
                    let transient = matches!(e, DfError::Ble(ref m)
                        if (m.contains("连接失败") || m.contains("服务发现")) && !m.contains("doesn't exist") && !m.contains("UnknownObject"));
                    if !transient {
                        return Err(e);
                    }
                    df_core::logging::warn("ble", format!("连接失败（第 {} 次）：{e}", attempt + 1));
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(800)).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| DfError::Ble("连接失败".into())))
    }

    async fn connect_once(peripheral: &Peripheral) -> Result<(BleSession, String, bool)> {
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
            BleSession { peripheral: peripheral.clone(), rx, tx, notifications, mtu, pending: Default::default() },
            eid,
            pairing,
        ))
    }

    /// MTU（默认保守 23；平台能查到则用真实值）。
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// 断开 GATT 连接（不常驻占用 BLE 连接；节点侧会话也随之失效）。
    pub async fn disconnect(&mut self) {
        let _ = self.peripheral.disconnect().await;
    }
}

/// 已配对设备的 BLE 控制链路（DF1.md「BLE framing and authentication」）：
/// 扫描 → GATT → 用该设备的 bleKey 完成 DF-BLE-1 认证 → 加密 LINK_REQUEST。
/// 用于 LAN 地址失效（手机换网/DHCP 换址、mDNS 不通）时向节点要当前地址，
/// `p2p` 为 true 时请求节点建立 Wi-Fi Direct GO 并等到组就绪。
///
/// 广播里没有身份：附近可能有多台节点，逐个尝试，认证失败（hint 不匹配，节点回 AUTH_FAILED）
/// 即换下一个。结果只是连接提示，身份仍以 TLS（节点 CA）+ HELLO_ACK nodeId 为准。
pub async fn link_request(
    trust: &df_core::stores::Trust,
    p2p: bool,
    scan_timeout: Duration,
) -> Result<df_core::pairing::ble_auth::LinkReady> {
    let key_b64 = trust
        .ble_key_b64
        .as_deref()
        .ok_or_else(|| DfError::Ble("该设备没有 bleKey（导入的配对结果不含 BLE 密钥）".into()))?;
    let key: [u8; 32] = df_core::crypto::b64_decode(key_b64)?
        .try_into()
        .map_err(|_| DfError::Ble("bleKey 不是 32 字节".into()))?;

    let (mut scan_handle, mut found) = scan(scan_timeout).await?;
    if found.is_empty() {
        // 节点约每 2 分钟换地址重启广播，偶有整轮扫描都错过的情况：再扫一轮
        scan_handle.stop().await;
        (scan_handle, found) = scan(scan_timeout).await?;
    }
    let mut last_err = DfError::Ble("附近没有发现 DeviceFabric 节点（手机蓝牙关闭或节点未开启）".into());
    for p in found {
        let (mut session, eid, _) = match BleSession::connect(p).await {
            Ok(x) => x,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let result = async {
            let mut ch = df_core::pairing::ble_auth::authenticate(&mut session, &key, &trust.node_id, &eid).await?;
            if p2p {
                df_core::pairing::ble_auth::link_request_p2p(&mut ch, &mut session).await
            } else {
                df_core::pairing::ble_auth::link_request_lan(&mut ch, &mut session).await
            }
        }
        .await;
        session.disconnect().await;
        match result {
            Ok(ready) => {
                scan_handle.stop().await;
                df_core::logging::info(
                    "ble",
                    format!("BLE 链路就绪：地址 {:?}，P2P 组 {}", ready.addresses, if ready.group_ready() { "就绪" } else { "未建立" }),
                );
                return Ok(ready);
            }
            Err(e) => {
                df_core::logging::debug("ble", format!("BLE 认证/链路请求失败：{e}"));
                last_err = e;
            }
        }
    }
    scan_handle.stop().await;
    Err(last_err)
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
