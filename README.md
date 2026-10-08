# DeviceFabric 桌面端（Linux / macOS / Windows）

Rust 实现的 DF/1 Controller（桌面端）。协议逻辑全部在共享核心 `df-core` 中，三平台复用同一份实现；
平台差异通过适配层隔离。开发依据：`docs/device-fabric-desktop-adaptation.md`。

## 结构

```text
crates/df-core      协议核心（跨平台，无平台依赖）
  ├─ frame.rs          控制帧编解码（u32 BE 长度 + JSON，1..65536，半包/粘包）
  ├─ msg.rs            信封 {v,type,requestId,body}、十进制字符串、文件元数据校验
  ├─ crypto.rs         SHA-256 / HMAC / HKDF(RFC5869) / AES-256-GCM / SAS 验证码
  ├─ keys.rs           P-256 SPKI、ECDH、ECDSA(DER)、nodeId/peerId、DER/PEM
  ├─ tls.rs            rustls：只信任配对 CA、IP SAN、客户端证书、仅 TLS 1.3（不依赖 SChannel）
  ├─ session.rs        控制会话：连接、HELLO/HELLO_ACK、请求响应、ERROR 处理
  ├─ pairing/
  │   ├─ ble_link.rs   BLE 分片（6 字节头）与重组（乱序/重复/越界拒绝）
  │   ├─ ble_auth.rs   DF-BLE-1 认证、SECURE 通道（GCM+方向前缀 nonce+AAD）、LINK_REQUEST/P2P 轮询
  │   ├─ near.rs       DF-NEAR-1 附近配对（commit→reveal→SAS→confirm→result，全部校验）
  │   └─ token.rs      导出文件/二维码配对（PAIR + ECDSA proof + 待定私钥重试）
  ├─ transfer/         上传（FILE_OFFER/RESUME/窗口1/CHUNK_ACK/COMPLETE/取消/文本）
  │                    与接收（PULL_LIST/ACCEPT/PULL_BIND/收块/fsync/位图日志/原子提交/回执）
  ├─ bitmap.rs         Java BitSet 兼容 haveBits
  ├─ names.rs          显示名称规则（1..64 UTF-16、不拆代理对）与平台安全文件名
  ├─ fsutil.rs         fsync（macOS 用 F_FULLFSYNC）、目录 fsync、原子写入/移动、空间预检
  └─ stores.rs         信任设备 / 本机名称 / clientId / 待定私钥（0600）

crates/dfabric      平台适配层 + 可执行
  ├─ ble.rs            btleplug BLE 中心设备（Linux=BlueZ，Windows=WinRT，macOS=CoreBluetooth）
  ├─ mdns.rs           mDNS 浏览 _dfabric._tcp，候选 15 秒时效
  ├─ wifi.rs           无路由器：Linux NetworkManager 临时入组 + 事后恢复（macOS/Windows 未实现）
  ├─ secrets.rs        keyring（Keychain/Secret Service/Cred Manager）+ 0600 文件回退
  ├─ agent.rs          后台 Agent：3 秒接收轮询、待接收清单、串行发送队列、IPC
  ├─ bin/dfctl.rs      命令行 Controller
  └─ bin/dfabricd.rs   守护进程（登录自启动入口）

crates/ui           Tauri 2 桌面应用（窗口 + 托盘）
  ├─ src/commands.rs   UI 后端命令（IPC 优先，Agent 未运行回退直连）
  ├─ src/lib.rs        窗口、托盘（显示/退出）、关闭即隐藏
  └─ dist/             前端（纯 HTML/JS/CSS，无 Node 构建链）
```

## 构建

```bash
# 协议核心 + CLI + 守护进程
cargo build --release
# 产物：target/release/{dfctl,dfabricd}

# GUI（Linux 需要：libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev librsvg2-dev）
cargo build -p df-ui
# 产物：target/debug/df-ui（release: target/release/df-ui）
```

依赖 rustls（ring），不使用系统 TLS；Windows 10 亦可运行。

## 使用

### GUI（推荐入口）
`df-ui` 启动后：**设备**页附近配对（显示 6 位验证码 → 与手机比对 → 确认）或导入配对文件；
**接收**页确认手机发来的文件请求（接受前不传输任何字节）；**发送**页选文件/发文本；
**设置**页修改本机名称。关闭窗口即隐藏到托盘。
建议同时运行 `dfabricd`（顶栏徽标显示 Agent 状态）：GUI 关闭时后台仍在轮询接收。

### CLI
```bash
dfctl pair-near                    # 附近配对（验证码确认）
dfctl pair-import pairing.json     # 导入配对文件（导入后请删除）
dfabricd &                         # 后台接收轮询
dfctl send a.png b.pdf             # 发送文件
dfctl send-text "hello"            # 发送文本
dfctl pulls && dfctl accept <id>   # 接收
dfctl devices / status / name / remove
```

CLI 与 GUI 都在 `dfabricd` 运行时通过本地 IPC 交接任务，否则直接执行。

## 安全实现要点（对照开发说明第 14 节）

- 只信任配对得到的节点 CA；服务器名 = 实际 IP（校验 IP SAN）；HELLO_ACK `nodeId` 必须匹配；无跳过校验开关
- 附近配对验证码由人工比对；commit/reveal 顺序与全部校验不可省略；`SHA256(CA SPKI)==nodeId`、
  客户端证书公钥 == 提交公钥、`peerId==SHA256(cert DER)`、bleKey 32 字节
- BLE 认证 seq 严格单调，重放/tag 失败即废弃会话
- 接收：用户接受前不拉取任何字节；每块校验索引/长度/哈希 → 写入 → fsync → 位图日志 → 才回 CHUNK_ACK；
  整文件大小+SHA-256 校验通过后原子移动到收件箱；不覆盖同名文件
- 发送：暂存（复制时计算哈希）→ 与源文件解耦，跨重启以同一 transferId/元数据 RESUME 只补缺块
- 机密（私钥、bleKey）入平台 keyring，回退 0600 文件；信任文件 0600；IPC socket 0600
- AUTH_FAILED 撤销：节点侧由协议处理；删除设备需用户同时在手机上解除信任
- 日志不输出 token、口令、密钥

## 测试

```bash
cargo test --workspace   # 39 项
```

覆盖：HKDF（RFC 5869 TC1）、HMAC（RFC 4231 TC1）、AES-256-GCM（NIST 零向量）对拍；
控制帧边界（1/65536/65537/0）；规范十进制字符串；BLE 分片重组（乱序/重复/超长/片数越界/MTU→payload）；
Java BitSet 兼容（空位图、跨字节、越界位）；44 字节块头编解码；SAS 格式；名称/文件名规则；
fsync/原子写/移动；存储权限（0600）；P-256 SPKI/ECDH/签名回环；TLS 配置拒绝空信任锚。

## 与真实节点（Mi 10）验收

自动化测试之外，按开发说明 15.2 节逐项验收（LAN 配对/发送/续传/接收、附近配对、BLE 建链、
负向用例、无路由器入组等）。**所有桌面端结论必须以实际观察为准**。

已知边界（与说明 17 节一致）：
- 无路由器连接仅 Linux（NetworkManager）有实现，且“传统客户端加入 Android GO”未实测，需单独验收；
  未通过的平台不展示该能力。
- 分享入口（Windows「发送到」/ macOS Share Extension / Linux 文件管理器动作）与各平台安装包
  签名/公证属于 M5 剩余项；GUI 的 Windows 命名管道 IPC 待接入（当前 Windows 直连模式可用）。
- 响应字段名（如 PAIR_RESULT/NEAR_RESULT 内部字段）按文档实现并对常见别名容错
  （`df-core/src/fields.rs`），与 DF1.md/vectors.json 对拍后如有出入只需改这一处。
- mDNS 候选时效 15 秒；BLE MTU 保守按 23（payload 14），正确但偏慢，后续可接平台协商 MTU。
