//! 监听地址选择：只用物理以太网 / Wi-Fi 的私网 IPv4（DF1.md：不监听蜂窝、VPN 与未指定地址，不支持 IPv6）。
//!
//! 排除 VPN/隧道/容器/虚拟网桥（tun、tap、wg、docker、br-、veth、virbr …）以及代理软件常用的
//! 198.18.0.0/15 “fake-ip” 网段：把这些地址写进证书和配对二维码只会让对端去连不可达的地址。

use std::net::Ipv4Addr;

const VIRTUAL_PREFIXES: [&str; 16] = [
    "lo", "tun", "tap", "wg", "utun", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "zt", "tailscale", "ham",
    "cni", "flannel",
];

pub fn usable(name: &str, ip: Ipv4Addr) -> bool {
    let virtual_iface = VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p));
    !virtual_iface && ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
}

/// 当前可监听地址（排序、去重）。
pub fn addresses() -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if usable(&i.name, v4.ip) => Some(v4.ip),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_virtual_and_proxy_interfaces() {
        assert!(usable("enp1s0", "192.168.1.19".parse().unwrap()));
        assert!(usable("wlp2s0", "10.1.2.3".parse().unwrap()));
        assert!(!usable("tun0", "10.0.0.4".parse().unwrap()));
        assert!(!usable("Meta", "198.18.0.1".parse().unwrap()));
        assert!(!usable("docker0", "172.17.0.1".parse().unwrap()));
        assert!(!usable("enp1s0", "8.8.8.8".parse().unwrap()));
    }
}
