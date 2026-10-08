//! mDNS / DNS-SD 发现（5.1 节）：浏览 `_dfabric._tcp.local.`，候选 15 秒时效。
//! 地址只是候选：必须 TLS + HELLO 核对 nodeId 后才算命中。

use df_core::consts::MDNS_SERVICE;
use df_core::error::{DfError, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// 候选时效：mdns-sd 只在服务首次解析/记录变化时发 ServiceResolved，之后靠缓存刷新，
/// 不会每 15 秒重发；时效太短会让 Agent 在首次解析之后就丢掉手机地址。
/// 服务下线（ServiceRemoved）时立即清除。
const CANDIDATE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone)]
pub struct MdnsBrowser {
    candidates: Arc<RwLock<HashMap<IpAddr, (Instant, String)>>>,
}

impl MdnsBrowser {
    pub fn new() -> MdnsBrowser {
        MdnsBrowser { candidates: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// 开始浏览（后台线程收集候选）。
    pub fn start(&self) -> Result<()> {
        let daemon = ServiceDaemon::new().map_err(|e| DfError::Protocol(format!("mDNS 启动失败: {e}")))?;
        let receiver = daemon
            .browse(MDNS_SERVICE)
            .map_err(|e| DfError::Protocol(format!("浏览 {MDNS_SERVICE} 失败: {e}")))?;
        let candidates = self.candidates.clone();
        tokio::task::spawn_blocking(move || {
            df_core::logging::info("mdns", format!("开始浏览 {MDNS_SERVICE}"));
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let fullname = info.get_fullname().to_string();
                        let mut m = candidates.blocking_write();
                        // 同一服务的旧地址作废（手机换网后只保留新地址）
                        m.retain(|_, (_, name)| *name != fullname);
                        for ip in info.get_addresses() {
                            df_core::logging::debug("mdns", format!("候选地址 {ip}（{fullname}）"));
                            m.insert(*ip, (Instant::now(), fullname.clone()));
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        df_core::logging::debug("mdns", format!("服务下线 {fullname}"));
                        candidates.blocking_write().retain(|_, (_, name)| *name != fullname);
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }

    /// 当前新鲜候选（≤15 秒）。
    pub async fn snapshot(&self) -> Vec<String> {
        let mut m = self.candidates.write().await;
        m.retain(|_, (t, _)| t.elapsed() < CANDIDATE_TTL);
        let mut ips: Vec<IpAddr> = m.keys().copied().collect();
        // 优先私网地址
        ips.sort_by_key(|ip| match ip {
            IpAddr::V4(v4) => match v4.octets() {
                [192, 168, ..] | [10, ..] | [172, 16..=31, ..] => 0,
                [127, ..] => 3,
                _ => 1,
            },
            IpAddr::V6(_) => 2,
        });
        ips.into_iter().map(|i| i.to_string()).collect()
    }
}

impl Default for MdnsBrowser {
    fn default() -> Self {
        Self::new()
    }
}
