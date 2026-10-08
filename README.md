# DeviceFabric 桌面端（Linux / macOS / Windows）

Rust 实现的 DF/1 Controller（桌面端）。协议逻辑全部在共享核心 `df-core` 中，三平台复用同一份实现；
平台差异通过适配层隔离。开发依据：`docs/device-fabric-desktop-adaptation.md`。

## 结构

```text
crates/df-core      协议核心（跨平台，无平台依赖）
  ├─ logging.rs        日志：分级/轮转/0600/UTC 时间戳（无外部依赖）
  ├─ selfcheck.rs      协议核心自检（字段名、编码、串格式、已知向量）
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
  ├─ logging.rs        平台日志目录 + 初始化（macOS ~/Library/Logs/DeviceFabric）
  ├─ selfcheck.rs      自检：本机环境、keyring、已配对设备、可选链路连通性
  ├─ ble.rs            btleplug BLE 中心设备（Linux=BlueZ，Windows=WinRT，macOS=CoreBluetooth）
  ├─ mdns.rs           mDNS 浏览 _dfabric._tcp，候选 15 秒时效
  ├─ wifi.rs           无路由器：仅 Linux（NetworkManager 临时入组 + 事后恢复）
  ├─ secrets.rs        keyring（Keychain/Secret Service/Cred Manager）+ 0600 文件回退
  ├─ agent.rs          后台 Agent：3 秒接收轮询、待接收清单、串行发送队列、IPC
  ├─ bin/dfctl.rs      命令行 Controller（pair / send / pulls / selftest / logs）
  └─ bin/dfabricd.rs   守护进程（登录自启动入口）

crates/ui           Tauri 2 桌面应用（窗口 + 托盘）
  ├─ Info.plist        macOS 权限声明（蓝牙、本地网络、Bonjour）
  ├─ entitlements.plist macOS 签名用（蓝牙、网络客户端）
  ├─ src/commands.rs   UI 后端命令（IPC 优先，Agent 未运行回退直连；含自检与日志）
  ├─ src/lib.rs        窗口、托盘（显示/退出）、关闭即隐藏、启动时初始化日志
  └─ dist/             前端（纯 HTML/JS/CSS，无 Node 构建链；含「诊断」页）
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

### macOS

- 构建：`cargo build --release` / `cargo tauri build`（需要 Xcode Command Line Tools）。
- 权限：`crates/ui/Info.plist` 已声明**蓝牙**（CoreBluetooth）与**本地网络 + Bonjour**；
  `crates/ui/entitlements.plist` 供签名使用。缺这两项时 BLE 拿不到适配器、mDNS 也收不到组播
  （`dfctl selftest` 会给出对应提示）。首次运行需要在「系统设置 › 隐私与安全性」里允许。
- 数据与日志：`~/Library/Application Support/dfabric`、`~/Library/Logs/DeviceFabric`。
- `keyring` 走 macOS 钥匙串（`apple-native`）；未启用时会退化成内存 mock，自检会直接报出来。
- 无路由器连接（加入 Wi-Fi Direct GO）**macOS 未实现**：CoreWLAN 无法关联 P2P 组，
  不做假成功；请改用局域网或手机热点。

## 使用

### GUI（推荐入口）
`df-ui` 启动后：**设备**页附近配对（显示 6 位验证码 → 与手机比对 → 确认）或导入配对文件；
**接收**页确认手机发来的文件请求（接受前不传输任何字节）；**发送**页选文件/发文本；
**设置**页修改本机名称；**诊断**页运行自检并查看日志。关闭窗口即隐藏到托盘。
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
dfctl selftest --json              # 自检（协议 + 环境 + 已配对设备；有 FAIL 时退出码 2）
dfctl selftest --connect           # 额外做 TLS + HELLO + STATUS 连通性检查
dfctl logs --tail 80               # 查看最近日志与日志目录
```

CLI 与 GUI 都在 `dfabricd` 运行时通过本地 IPC 交接任务，否则直接执行。

所有命令都支持 `--log-level error|warn|info|debug`、`--no-log`（只输出终端）、
`--log-stderr`（同时镜像到终端）；级别也可用 `DFABRIC_LOG` 环境变量设置。

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

## 日志与自检

**日志**（`df-core/logging.rs` + `dfabric/logging.rs`）

- 位置：macOS `~/Library/Logs/DeviceFabric/dfabric.log`；
  Linux `$XDG_STATE_HOME/dfabric/logs/dfabric.log`（缺省 `~/.local/state/...`）；
  Windows `%LOCALAPPDATA%\dfabric\logs\dfabric.log`。
- 单文件 4 MiB，轮转保留 3 份（`dfabric.log.1..3`），文件权限 0600；GUI 与 Agent 共用同一份。
- 记录：连接候选、TLS 握手结果、HELLO_ACK 能力、配对（PAIR/NEAR）阶段、发送/接收任务与
  每一条 offer、IPC 启停、错误分类。**不记录** token、口令、私钥、bleKey、配对导出内容。
- 查看：`dfctl logs [--tail N] [--path]`，或 GUI「诊断」页。

**自检**（`dfctl selftest`，或 GUI「诊断」页）覆盖三类：

1. 协议核心（离线确定性）：控制帧 `requestId` 字段名、`nodeCa` 的 PEM/base64 兼容、
   BLE 证明 base64 与 hex hint、DF-BLE-1 转录串、DF-NEAR-1 揭示串与验证码、PAIR 证明串、
   HKDF/HMAC/GCM 已知向量、PEM/DER 往返（含 CRLF）、规范十进制、haveBits 位图、
   名称规则与协议上限、TLS 信任锚；
2. 本机环境：数据/日志目录可写、磁盘空间、系统时钟、平台安全存储（含 keyring 退化检测）、
   mDNS 可启动、蓝牙适配器可用；
3. 已配对设备：CA/证书/私钥自洽（nodeId、peerId、私钥与证书公钥匹配、mTLS 配置可构造）；
   加 `--connect` 时再做 TLS + HELLO + STATUS。

退出码：0 全部通过（可有 WARN/SKIP），2 存在 FAIL，1 命令本身出错。`--json` 便于附到问题报告。

## 测试

```bash
cargo test --workspace   # 45 项
```

覆盖：HKDF（RFC 5869 TC1）、HMAC（RFC 4231 TC1）、AES-256-GCM（NIST 零向量）对拍；
控制帧边界（1/65536/65537/0）；规范十进制字符串；BLE 分片重组（乱序/重复/超长/片数越界/MTU→payload）；
Java BitSet 兼容（空位图、跨字节、越界位）；44 字节块头编解码；SAS 格式；名称/文件名规则；
fsync/原子写/移动；存储权限（0600）；P-256 SPKI/ECDH/签名回环；TLS 配置拒绝空信任锚；
日志时间戳（UTC/闰年）、轮转与 0600；协议核心自检 11 项全绿（`cargo test -p df-core` 会直接在
`selfcheck::tests::all_protocol_checks_pass` 里断言）。

单测只能证明**本端自洽**：字段名、编码、串格式一旦与节点不一致，单测一样全绿而配对照样失败，
所以另有 `dfctl selftest` 与真机验收；两者都不能互相替代。

## 与真实节点（Mi 10）验收

自动化测试之外，按开发说明 15.2 节逐项验收（LAN 配对/发送/续传/接收、附近配对、BLE 建链、
负向用例、无路由器入组等）。**所有桌面端结论必须以实际观察为准**。

### 早前已修缺陷（2026-10-08，联调前）

此前两条配对路径都在第一步就失败，原因是 4 处互相独立的实现错误：

1. `Envelope.request_id` 缺 `#[serde(rename = "requestId")]`，线上发的是 `request_id`；
   节点 `Wire.read()` 取不到该字段就把**每一帧**判为 INVALID_FRAME（连 HELLO 都过不去）。
2. `parse_pair_result` 把 PEM 形态的 `nodeCa` 当 base64 解码（`Invalid symbol 45`）；
   导入 JSON 的 `caDer` 才是 base64，两者必须分开处理。
3. BLE 认证链路的 CHALLENGE proof / AUTH_FINISH proof / AUTH_OK sessionId 用 hex，
   而协议与节点（`Wire.b64`）用 base64 —— 已配对设备的建链全部失败。
4. `near_prepare` 开头阻塞等待节点先说话（DF-NEAR-1 应由客户端先发 `NEAR_COMMIT`），
   同时把 INFO 里的 eid 丢掉了；现在 eid 作为参数传入并加了握手超时。

附带修复：`pairing_config` 空信任锚会让 rustls 直接 panic；`PAIR_RESULT` 未回填 addresses
导致导入配对后没有可连地址；`pem_to_der` 对 CRLF 不健壮；接收落盘使用了未按平台隔离的
`std::os::unix`（Windows 编译失败）；`keyring` 未启用任何平台后端而退化成内存 mock。

**这些修复只经过单元测试与 `dfctl selftest`，尚未与真实节点联调。**

验收前先跑 `dfctl selftest`：它能提前区分「本端材料/环境问题」和「与节点互通问题」，
避免拿真机试配置错误。`--connect` 会直接给出 TLS/HELLO/STATUS 结果。

### 真机联调（2026-10-08，Mi 10 / LineageOS DeviceFabric，LAN + BLE）

已在真机上实际通过（两端 SHA-256 一致、手机端记录 COMPLETE）：

- LAN 发送：空文件、25 B、3 MiB+7 B、400 MiB；文本（TEXT_OFFER）；
- 手机 → 电脑（FILE_SEND / PULL_*）：分享文本、3 MiB+7 B、184 MiB；
- 续传：上传中途杀掉 dfabricd，重启后自动按原 transferId 补发缺块，手机只保存一次；
  下载中途中断后再次 `accept` 只拉缺块；
- BLE：DF-BLE-1 认证 + 加密 LINK_REQUEST(LAN)（`dfctl link`）；LAN 地址失效时自动经 BLE 取回当前地址；
- 显示名称经 HELLO 同步到手机（改名与恢复）；`dfctl selftest --connect` 全部 PASS。

本轮修复：

1. 下载续传：`accept` 用 `File::create` 截断了暂存文件，且只接受 pending 状态 → 中断后无法续传
   （位图说已有的块被清零，整文件校验必然失败）；
2. 下载结束整文件读入内存算哈希（大文件 OOM）→ 流式计算；数据连接提前关闭时保留进度并提示续传；
3. 上传 CHUNK_ACK 后没有把块记入本地位图；dfabricd 重启后未完成/排队的发送任务不会再被处理；
4. 收件文件名套用了 64 码元的显示名称规则，超过 64 字符的文件名丢扩展名（手机发来的名字带 36 位 UUID 前缀）；
5. 接收轮询每 3 秒重新 TLS 握手（手机每次都要 AndroidKeyStore 签名）→ 复用一条已认证控制连接；
   `ended` 记录每 3 秒重写 pulls.json，且可能把已完成项改成已取消；
6. 连接地址：成功地址从不回写 `last_addr`，mDNS 候选 15 秒就过期 → 手机换 IP 后 Agent 找不到手机。
   现在优先上次成功地址，并在 LAN 都不通时经 BLE 认证链路取回地址（同一设备 2 分钟最多一次）；
7. BLE 扫描会拿到 BlueZ 缓存的旧设备对象（节点约 2 分钟换一次广播地址），连接挂 30 秒后失败
   → 只接受本次扫描收到广播（有 RSSI）的设备；附近配对中未处于配对窗口的设备、确认/取消后的会话主动断开；
8. 手机解除信任后 HELLO 收到 AUTH_FAILED 时标记信任失效、停止轮询（此前每 3 秒重连）；TLS 握手单独给 8 秒；
9. 新增与 `protocol/vectors.json` 逐项对拍的单测（hint、三种 proof、HKDF 72 字节、SECURE 密文）。

同日追加验证：手机端解除信任后 Agent 收到 AUTH_FAILED，标记「信任已失效」并停止轮询；`dfctl pair-near`
附近配对（两端验证码 715368 人工核对一致）成功，新证书下 mTLS 收发与 BLE 链路正常。附近配对此前在手机端崩溃：
节点按 MTU-9 切 BLE 通知，BlueZ 协商 MTU 517 时单片 514 字节超过 512 字节属性上限，
已在 LineageOS 端修复（vendor/diater 4bd670f），需要该版本以上的 DeviceFabric。

仍未在真机验证：无路由器 P2P（本机没有 Wi-Fi 网卡）、Tauri 界面交互（含界面里的附近配对）、导入配对文件。本网络中手机的 mDNS 响应到不了电脑
（电脑能收到其他主机的 mDNS），因此日常依赖上次成功地址 + BLE 回退。

已知边界（与说明 17 节一致）：
- 无路由器连接仅 Linux（NetworkManager）有实现，且“传统客户端加入 Android GO”未实测，需单独验收；
  macOS 因 CoreWLAN 无法关联 P2P 组而明确不做（见上文 macOS 一节），不提供假成功；
  未通过的平台不展示该能力。
- 分享入口（Windows「发送到」/ macOS Share Extension / Linux 文件管理器动作）与各平台安装包
  签名/公证属于 M5 剩余项；GUI 的 Windows 命名管道 IPC 待接入（当前 Windows 直连模式可用）。
- 响应字段名（如 PAIR_RESULT/NEAR_RESULT 内部字段）按文档实现并对常见别名容错
  （`df-core/src/fields.rs`），与 DF1.md/vectors.json 对拍后如有出入只需改这一处。
- mDNS 候选时效 15 秒；BLE MTU 保守按 23（payload 14），正确但偏慢，后续可接平台协商 MTU。
