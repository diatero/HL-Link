//! 自检：把「协议核心确定性检查 + 本机环境 + 已配对设备 + 可选连通性」汇总成一份报告。
//!
//! 设计目标：在没有手机、没有蓝牙的情况下，用户也能先在本机判断客户端是否处于
//! 可用状态（协议约定、目录权限、密钥材料、时钟、可选链路），并在出问题时给出
//! 具体到文件/字段的说明。所有检查都不得 panic、不得修改用户数据。

use df_core::error::{DfError, Result};
use df_core::selfcheck::{Check, Status};
use df_core::stores::Trust;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 自检选项（默认只做无副作用检查）。
#[derive(Debug, Clone)]
pub struct Options {
    /// 检查蓝牙适配器可用性（macOS 首次会触发系统权限询问）。
    pub ble: bool,
    /// 启动 mDNS 浏览（只验证能否启动，不做配对）。
    pub mdns: bool,
    /// 对每个已配对设备做 TLS + HELLO + STATUS（需要手机在线，只读）。
    pub connect: bool,
    /// 单台设备的连通超时。
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options { ble: true, mdns: true, connect: false, timeout: Duration::from_secs(6) }
    }
}

/// 执行全部自检，按固定顺序返回结果。
pub async fn run(opts: &Options) -> Vec<Check> {
    let mut out = Vec::new();
    out.push(platform_check());
    out.push(data_dir_check());
    out.push(log_dir_check());
    out.push(space_check());
    out.push(clock_check());
    out.push(keyring_check());
    out.extend(df_core::selfcheck::protocol_checks());
    out.push(if opts.mdns { mdns_check() } else { Check::skip("mDNS 浏览器", "已按参数跳过（--no-mdns）") });
    out.push(if opts.ble { ble_check().await } else { Check::skip("蓝牙适配器", "已按参数跳过（--no-ble）") });
    out.extend(trust_checks());
    if opts.connect {
        out.extend(connect_checks(opts).await);
    } else {
        out.push(Check::skip("设备连通性", "未启用（加 --connect 且手机节点在线时执行）"));
    }
    out
}

/// 是否存在 FAIL。
pub fn has_failure(checks: &[Check]) -> bool {
    checks.iter().any(Check::is_fail)
}

/// 统计各状态数量。
pub fn summary(checks: &[Check]) -> (usize, usize, usize, usize) {
    let mut s = (0, 0, 0, 0);
    for c in checks {
        match c.status {
            Status::Pass => s.0 += 1,
            Status::Warn => s.1 += 1,
            Status::Fail => s.2 += 1,
            Status::Skip => s.3 += 1,
        }
    }
    s
}

fn short(id: &str) -> String {
    let n = 12.min(id.len());
    format!("{}…", &id[..n])
}

fn platform_check() -> Check {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let mut hints: Vec<String> = Vec::new();
    if os == "macos" {
        hints.push("macOS：首次使用请允许「蓝牙」与「本地网络」访问".into());
    }
    if os == "linux" {
        hints.push("Linux：BLE 需要 BlueZ，无路由器连接需要 NetworkManager（nmcli）".into());
    }
    if os == "windows" {
        hints.push("Windows：无路由器连接加入 GO 尚未实现".into());
    }
    Check::pass(
        "运行平台",
        format!(
            "{} {} · dfabric {} · {}",
            os,
            arch,
            env!("CARGO_PKG_VERSION"),
            hints.join("；")
        ),
    )
}

fn data_dir_check() -> Check {
    match probe_write(&crate::data_dir(), "数据目录") {
        Ok(detail) => Check::pass("数据目录", detail),
        Err(e) => Check::fail("数据目录", format!("{e}（无法保存配对信息与收件箱）")),
    }
}

fn log_dir_check() -> Check {
    let dir = crate::logging::log_dir();
    match probe_write(&dir, "日志目录") {
        Ok(_) => match df_core::logging::log_path() {
            Some(p) if p.exists() => Check::pass("日志目录", format!("{}（当前日志 {}）", dir.display(), p.display())),
            _ => Check::warn("日志目录", format!("{} 可写，但日志尚未初始化（本进程未开启文件日志）", dir.display())),
        },
        Err(e) => Check::fail("日志目录", format!("{e}（排查问题时将没有日志文件）")),
    }
}

/// 在目录里写一个探针文件并删除；返回可读的说明。
fn probe_write(dir: &std::path::Path, what: &str) -> Result<String> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(".dfabric-selftest");
    std::fs::write(&probe, b"ok")?;
    let back = std::fs::read(&probe)?;
    let _ = std::fs::remove_file(&probe);
    if back != b"ok" {
        return Err(DfError::Protocol(format!("{what}写入后读回不一致")));
    }
    Ok(format!("{} 可读写", dir.display()))
}

fn space_check() -> Check {
    let dir = crate::data_dir();
    match df_core::fsutil::free_space(&dir) {
        Ok(free) => {
            let gib = free as f64 / (1024.0 * 1024.0 * 1024.0);
            if free < 256 * 1024 * 1024 {
                Check::fail("可用磁盘空间", format!("仅剩 {gib:.2} GiB，接收文件会失败（协议上限 16 GiB）"))
            } else if free < 2 * 1024 * 1024 * 1024 {
                Check::warn("可用磁盘空间", format!("仅剩 {gib:.2} GiB"))
            } else {
                Check::pass("可用磁盘空间", format!("{gib:.1} GiB"))
            }
        }
        Err(e) => Check::warn("可用磁盘空间", format!("无法读取：{e}")),
    }
}

/// 时钟偏差会直接破坏配对窗口（`expiresAt`）、证书有效期与 SAS 之外的超时判断。
fn clock_check() -> Check {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // 2020-01-01 之后才算合理
    if now < 1_577_836_800 {
        return Check::fail(
            "系统时钟",
            format!("当前时间戳 {now}（早于 2020-01-01）：请先校准时间，否则配对与证书校验会失败"),
        );
    }
    Check::pass("系统时钟", df_core::logging::timestamp(SystemTime::now()))
}

fn keyring_check() -> Check {
    const PROBE: &str = "selftest-probe";
    let entry = match keyring::Entry::new("DeviceFabric", PROBE) {
        Ok(e) => e,
        Err(e) => return Check::warn("平台安全存储", format!("不可用（{e}）：机密将保存为 0600 文件")),
    };
    // keyring 3.x 未启用任何平台后端时会退化成内存 mock：读写「成功」但不持久化。
    // 必须识别出来，否则自检会给出假阳性。
    if entry
        .get_credential()
        .downcast_ref::<keyring::mock::MockCredential>()
        .is_some()
    {
        return Check::warn(
            "平台安全存储",
            "当前构建没有平台后端（只编译了 keyring 的内存 mock）：机密实际保存在 0600 文件里。\
             请用 `features = [\"apple-native\", \"windows-native\", \"sync-secret-service\"]` 重新构建",
        );
    }
    let wrote = entry.set_password("ok").is_ok();
    let read = matches!(entry.get_password(), Ok(v) if v == "ok");
    let _ = entry.delete_credential();
    if wrote && read {
        Check::pass("平台安全存储", "读/写/删除正常（macOS 钥匙串、Linux Secret Service、Windows 凭据管理器）")
    } else {
        Check::warn(
            "平台安全存储",
            "读写探测失败（例如 Linux 上没有可用的 Secret Service）：机密将保存在 0600 文件（可用但保护较弱）",
        )
    }
}

fn mdns_check() -> Check {
    let browser = crate::mdns::MdnsBrowser::new();
    match browser.start() {
        Ok(()) => Check::pass("mDNS 浏览器", "已启动 _dfabric._tcp 浏览（local.）"),
        Err(e) => Check::warn(
            "mDNS 浏览器",
            format!("{e}；将退回 BLE 取地址或上次成功地址（不影响已配对设备的 BLE 链路）"),
        ),
    }
}

async fn ble_check() -> Check {
    match crate::ble::adapter_available().await {
        Ok(info) => Check::pass("蓝牙适配器", info),
        Err(e) => Check::warn(
            "蓝牙适配器",
            format!(
                "{e}；附近配对与「无路由器」建链不可用（局域网传输不受影响）{}",
                if cfg!(target_os = "macos") { "。macOS 需在「系统设置 › 隐私与安全性 › 蓝牙」允许本应用" } else { "" }
            ),
        ),
    }
}

fn trust_checks() -> Vec<Check> {
    let store = match crate::open_store() {
        Ok(s) => s,
        Err(e) => return vec![Check::fail("已配对设备", format!("无法打开数据目录：{e}"))],
    };
    let trusts = store.trusts();
    if trusts.is_empty() {
        return vec![Check::skip("已配对设备", "尚未配对：先运行 `dfctl pair-near` 或 `dfctl pair-import <file>`")];
    }
    trusts.iter().map(trust_check).collect()
}

fn trust_check(t: &Trust) -> Check {
    let name = format!("设备 {}", short(&t.node_id));
    match validate_trust(t) {
        Ok(detail) => {
            if t.revoked {
                Check::warn(&name, format!("{detail}；本地已标记「信任已失效」，需在手机上删除旧记录后重新配对"))
            } else {
                Check::pass(&name, detail)
            }
        }
        Err(e) => Check::fail(&name, format!("{e}；该设备需要重新配对")),
    }
}

/// 校验一台设备的本机信任材料是否自洽（不联网）。
fn validate_trust(t: &Trust) -> Result<String> {
    let ca_der = df_core::keys::pem_to_der(&t.ca_pem)?;
    let derived = df_core::keys::node_id_from_ca_der(&ca_der)?;
    if derived != t.node_id {
        return Err(DfError::Protocol(format!("nodeId 与 CA 不匹配: {} != {derived}", t.node_id)));
    }
    let cert_der = df_core::keys::pem_to_der(&t.cert_pem)?;
    let peer = df_core::keys::peer_id_from_cert_der(&cert_der);
    if !t.peer_id.is_empty() && !t.peer_id.eq_ignore_ascii_case(&peer) {
        return Err(DfError::Protocol(format!("peerId 与客户端证书不匹配: {} != {peer}", t.peer_id)));
    }
    // 私钥：优先 trusts.json，其次平台 keyring（只读，不写入）
    let key_pem = if t.key_pem.is_empty() {
        crate::secrets::load_secret(&t.node_id, "keyPem").ok().flatten()
    } else {
        Some(t.key_pem.clone())
    };
    let Some(key_pem) = key_pem else {
        return Err(DfError::Protocol("客户端私钥缺失（trusts.json 与平台安全存储都没有）".into()));
    };
    let identity = df_core::keys::SigningIdentity::from_pkcs8_pem(&key_pem)?;
    if df_core::keys::cert_spki_der(&cert_der)? != identity.spki_der() {
        return Err(DfError::Protocol("客户端私钥与客户端证书公钥不匹配".into()));
    }
    // 最终以「能不能构造出 mTLS 配置」为准（覆盖证书链/私钥格式问题）
    df_core::tls::client_config(&t.ca_pem, &t.cert_pem, &key_pem)?;

    let mut notes = vec![format!("信任材料自洽（peerId {}…）", &peer[..12.min(peer.len())])];
    if t.ble_key_b64.is_none() {
        notes.push("缺少 bleKey（BLE 认证与无路由器建链不可用，可重新配对修复）".into());
    }
    if t.last_addr.as_deref().unwrap_or("").is_empty() {
        notes.push("没有上次地址，连接将依赖 mDNS 发现".into());
    }
    if t.control_port != 0 && t.control_port != df_core::consts::DEFAULT_CONTROL_PORT {
        notes.push(format!("使用非默认控制端口 {}", t.control_port));
    }
    Ok(notes.join("；"))
}

async fn connect_checks(opts: &Options) -> Vec<Check> {
    let store = match crate::open_store() {
        Ok(s) => s,
        Err(e) => return vec![Check::fail("设备连通性", format!("无法打开数据目录：{e}"))],
    };
    let targets: Vec<Trust> = store.trusts().into_iter().filter(|t| !t.revoked).collect();
    if targets.is_empty() {
        return vec![Check::skip("设备连通性", "没有未失效的已配对设备")];
    }
    let mdns = crate::mdns::MdnsBrowser::new();
    let _ = mdns.start();
    let name = crate::display_name(&store);
    let mut out = Vec::new();
    for t in &targets {
        let label = format!("连通性 {}", short(&t.node_id));
        let attempt = tokio::time::timeout(opts.timeout, async {
            let mut ctrl = crate::connect_trust(t, Some(&name), &mdns).await?;
            let status = ctrl.status().await?;
            Ok::<serde_json::Value, DfError>(status)
        })
        .await;
        match attempt {
            Ok(Ok(status)) => out.push(Check::pass(
                &label,
                format!(
                    "TLS+HELLO+STATUS 正常（节点状态：{}）",
                    status.get("state").and_then(|v| v.as_str()).unwrap_or("-")
                ),
            )),
            Ok(Err(e)) => out.push(Check::fail(&label, format!("{e}"))),
            Err(_) => out.push(Check::fail(
                &label,
                "连接超时：确认手机节点已开启、与电脑在同一局域网、桌面防火墙未拦截 9527/9528",
            )),
        }
    }
    out
}
