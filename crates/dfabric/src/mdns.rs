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

const CANDIDATE_TTL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct MdnsBrowser {
    candidates: Arc<RwLock<HashMap<IpAddr, Instant>>>,
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
            while let Ok(event) = receiver.recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    for ip in info.get_addresses() {
                        if let Ok(mut m) = candidates.try_write() {
                            m.insert(*ip, Instant::now());
                        }
                    }
                }
            }
        });
        Ok(())
    }

    /// 当前新鲜候选（≤15 秒）。
    pub async fn snapshot(&self) -> Vec<String> {
        let mut m = self.candidates.write().await;
        m.retain(|_, t| t.elapsed() < CANDIDATE_TTL);
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
