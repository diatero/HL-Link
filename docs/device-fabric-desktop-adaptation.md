# Device Fabric 桌面端（Linux / macOS / Windows）开发说明

日期：2026-10-07（2026-10-08 补注）。状态：**桌面端已实现**（Rust，`/home/diater/CodeBuddy/HL Link-linux`），
本文保留为开发依据；2026-10-08 修复了 4 处导致配对失败协议缺陷，但**仍未与真机联调**，
所以本文不是验证记录。实现侧新增能力：文件日志（分级/轮转/0600）、`dfctl selftest` 自检、
macOS 打包权限声明（蓝牙/本地网络）。
配套文档：[LineageOS 实施方案](device-fabric.md)、[HarmonyOS 适配说明](device-fabric-harmonyos-adaptation.md)、
[自定义设备名称](device-fabric-name.md)。

## 0. 文档定位与权威来源

本文说明桌面 Controller 需要实现什么、为什么这样做、每个平台用什么能力实现，以及怎样验收。
本文不规定代码结构或具体 API 调用写法。线上字节格式以以下材料为准，与本文冲突时以它们为准：

| 材料 | 作用 |
| --- | --- |
| `vendor/diater/apps/DeviceFabric/protocol/DF1.md` | DF/1 规范：TLS、控制帧、配对、上传、反向下载、BLE 认证、DF-NEAR-1、显示名称 |
| `vendor/diater/apps/DeviceFabric/protocol/vectors.json` | BLE 认证/HKDF/AEAD 的公开确定性测试向量（测试密钥，不是实际凭据） |
| `vendor/diater/apps/DeviceFabric/tools/df_client.py` | Python 参考 Controller：QR/导出配对、上传、文本、状态、取消、BLE 建链 |
| `vendor/diater/apps/DeviceFabric/tools/test_*.py` | 参考客户端上的协议与负向用例 |
| HL Link（`/home/diater/harmonyos/projects/HlLink`） | 已与 Lineage 真机互通的完整 Controller，含附近配对、P2P、反向接收、分享入口、名称同步 |

已有证据边界：Python 参考客户端已在 Linux PC 上与 Mi 10 完成 BLE 发现/认证/建链描述读取、
LAN TLS 配对、文件与文本上传、断点续传和负向用例；HL Link 已完成附近配对、无路由器 P2P 传输与反向接收。
**任何桌面 OS 上的 P2P（无路由器）入组、系统分享入口、后台常驻都没有验证过**，下文涉及处均为设计要求。

## 1. 系统概览

### 1.1 角色

- **Node（节点）**：LineageOS 手机上的 DeviceFabric App。它是 TLS 服务端、BLE GATT 外设、mDNS 发布者、Wi-Fi Direct GO 创建者，
  持有私有 CA，给每个 Controller 签发客户端证书。节点默认关闭，由手机用户开启。
- **Controller（控制端）**：HL Link 和将来的桌面端。它是 TLS 客户端、BLE 中心设备，主动连接节点。
  桌面端沿用 Controller 角色，**不需要实现任何服务端监听**，所以无需在防火墙开放入站端口。

所有连接都由 Controller 发起，节点发给 Controller 的文件也由 Controller 轮询拉取（`FILE_SEND` 能力）。

### 1.2 桌面端功能范围

| 功能 | 协议能力 | 首版要求 |
| --- | --- | --- |
| 附近配对（BLE + 六位验证码） | DF-NEAR-1 | 主要配对方式（需要 BLE） |
| 备用配对（二维码 / 导出 JSON） | PAIR | 必须支持；桌面通常没有摄像头，以导入文件/粘贴为主 |
| 发送文件、发送文本 | FILE_OFFER/RESUME/TEXT_OFFER | 必须 |
| 接收手机发来的文件 | PULL_*（FILE_SEND） | 必须；在线时轮询 |
| 断点续传、取消 | RESUME / CANCEL / PULL_CANCEL | 必须 |
| 局域网连接 | mDNS + TLS | 必须 |
| 无路由器连接 | BLE LINK_REQUEST(P2P) + 加入节点 GO | 平台条件允许时实现，单独验收 |
| 显示名称 | HELLO/HELLO_ACK `name` | 必须；默认电脑名称，可修改 |
| 系统集成 | 分享/发送到/右键菜单、托盘 | 按平台实现 |

不在范围：剪贴板同步、远程 Shell、OCR/AI、桌面作为 Node、多节点调度、IPv6、云中继。
节点会拒绝不支持的操作，Controller 也不能宣称这些能力。

### 1.3 连接全景

```text
发现 ──┬─ mDNS _dfabric._tcp.（匿名候选：IP+端口）
       └─ BLE 扫描 service UUID（匿名候选：随机 eid）
          │
建链 ──┬─ LAN：对候选地址做 TLS + HELLO，nodeId 一致才算找到节点
       └─ BLE 认证 → LINK_REQUEST(LAN) 取最新地址；仍不可达 → LINK_REQUEST(P2P)
          → 轮询 LINK_STATUS 到 GO 就绪 → 用 SSID/PSK 加入 GO → TLS 到 goAddress
          │
业务 ── 控制连接（9527，mTLS，JSON 帧）+ 数据连接（9528，mTLS，DATA_BIND 后二进制块）
```

身份只由 TLS 确认：mDNS 名称、BLE 地址、eid、SSID、IP 都只是候选线索。

## 2. 开发者需要的背景知识

满足开发即可，无需更深：

1. **TLS 1.3 客户端编程**：自定义信任锚（只信任配对得到的 CA，不用系统根证书）、IP 地址形式的服务器名校验、
   客户端证书（ECDSA P-256）认证、TLS 握手失败的分类处理。
2. **X.509 基础**：证书链、SPKI、SubjectAltName(IP)、EKU、PEM/DER 转换、证书 SHA-256 指纹。
3. **密码学原语使用**：SHA-256、HMAC-SHA256、HKDF-SHA256（RFC 5869）、AES-256-GCM（含 AAD、12 字节 nonce）、
   ECDH P-256、ECDSA P-256 签名（DER 编码）；能用测试向量逐字节对拍。
4. **BLE 中心设备**：主动扫描（需要 scan response）、按 service UUID 过滤、GATT 连接、服务发现、
   write-with-response、订阅 notify（CCCD）、ATT MTU 与分片、断线处理。
5. **网络编程**：TCP 流式读取（处理半包/粘包）、超时、按源地址/接口绑定 socket、mDNS/DNS-SD 浏览与解析。
6. **Wi-Fi 管理**：用 SSID + WPA2-PSK 以普通客户端身份临时加入网络、DHCP 获取地址、事后恢复原网络。
7. **可靠文件 I/O**：大文件流式哈希、按偏移随机写、fsync/原子替换、稀疏文件、磁盘空间预检、跨平台文件名限制。
8. **并发与状态机**：一个持久化的串行发送队列、一个接收轮询循环、取消与重试、进程重启后恢复。
9. **各平台的安全存储与权限模型**（第 12 节）：Keychain/DPAPI/Secret Service、蓝牙与本地网络权限、打包与签名。

## 3. 推荐软件结构

建议“共享协议核心 + 平台适配层 + 平台 UI”。三个平台的协议逻辑完全相同，重复实现三次会产生互通差异。

```text
平台 UI（托盘/窗口、分享入口、通知）
        │  本地 IPC（命令：发送、接收确认、配对；事件：进度、状态）
后台 Agent（每个登录用户一个进程，持有全部状态）
  ├─ 协议核心（跨平台）
  │   ├─ FrameCodec：控制帧、数据块帧、BLE 分片
  │   ├─ Crypto：HMAC/HKDF/GCM/ECDH/ECDSA、SAS 验证码
  │   ├─ Pairing：DF-NEAR-1、QR PAIR
  │   ├─ Session：TLS 会话、HELLO、请求/响应匹配
  │   ├─ LinkSelector：LAN → BLE → P2P 决策
  │   ├─ SendQueue / Receiver：持久任务、续传、校验
  │   └─ Stores：信任设备、任务日志、本机名称
  └─ 平台适配接口
      ├─ BleCentral、MdnsBrowser、WifiJoiner
      ├─ TlsProvider（若核心不自带 TLS）
      ├─ SecretStore、FileSystem、DeviceName
      └─ Notifier、ShareIntake
```

选型原则（不强制具体语言）：

- 核心需要一个在三平台行为一致、支持 TLS 1.3 + 客户端证书 + 自定义校验的 TLS 实现。
  **不要依赖 Windows 10 的 SChannel**（客户端 TLS 1.3 从 Windows 11 / Server 2022 才可用）。
  可选：随程序携带 rustls、OpenSSL 或 BoringSSL；macOS 的 Network.framework 也支持 TLS 1.3，但客户端身份需要导入 Keychain，适配成本较高。
- Rust、Go、C++、.NET 都可行。项目首版设计里提过可以用 Rust 做共享协议核心，这只是参考，不是限制。
- Python 参考客户端适合原型和对拍，不建议直接作为发行版（打包、BLE 后台和系统集成都不理想）。
- UI 与 Agent 分进程：分享入口、右键菜单只把“发送请求 + 文件路径/书签”交给 Agent，立即返回；
  这与 HL Link 的教训一致（分享扩展生命周期短，必须交接给主进程的持久队列）。

## 4. 身份、信任与凭据

### 4.1 节点身份与证书剖面

- `nodeId` = 节点 CA 证书 SPKI DER 的 SHA-256，小写 hex（64 字符）。它是节点唯一的长期身份。
- 节点 CA：自签，CN `DeviceFabric-CA`，P-256/ECDSA-SHA256，10 年；BasicConstraints CA:true（关键）；KeyUsage keyCertSign、cRLSign（关键）。
- 节点服务器证书：CN `DeviceFabric`，由 CA 签发，1 年；BasicConstraints CA:false（关键）；KeyUsage digitalSignature（关键）；
  EKU serverAuth；**SAN 只有当前监听的 IPv4 地址**，没有 DNS 名称。握手时节点发送 `[leaf, CA]` 链。
  地址变化时节点会重新签发 leaf，CA 不变。
- Controller 客户端证书：由节点 CA 在配对批准后签发，CN `peer-<32 hex>`，EKU clientAuth，无 SAN；
  私钥由 Controller 生成且从不离开 Controller。`peerId` = 客户端证书 DER 的 SHA-256 小写 hex。

### 4.2 Controller 侧 TLS 校验（必须全部满足）

1. 只把配对时获得的节点 CA 作为信任锚，不信任系统根证书，也不信任其他已配对节点的 CA。
2. 以**实际连接的 IP 地址**作为服务器名，要求它出现在 leaf 的 IP SAN 中。
3. 检查有效期与 EKU；协议只用 TLS 1.3。
4. 握手后 HELLO_ACK 的 `nodeId` 必须等于该信任记录的 nodeId，否则立即断开。
5. 不提供“跳过证书校验”的开关，包括调试版。证书校验失败不能降级到别的链路绕过。

不同 TLS 库对“IP 作为服务器名”“叶子证书没有 DNS SAN”“自签 CA 的扩展”要求不一，
**实现第一步就要用真实节点或参考证书做互操作实验**，确认库接受上述剖面且拒绝错误的 CA 和错误 IP。

### 4.3 每个信任节点需要保存的数据

| 数据 | 敏感性 | 说明 |
| --- | --- | --- |
| nodeId、节点显示名称、配对时间 | 普通 | 名称会随连接更新 |
| 节点 CA（PEM） | 普通（完整性重要） | 信任锚；被篡改等于信任了别人 |
| 客户端证书（PEM）、peerId | 普通 | |
| 客户端私钥（P-256） | **机密** | 放平台安全存储；优先不可导出 |
| bleKey（32 字节） | **机密** | BLE 控制认证密钥 |
| 最近地址、端口、能力列表 | 普通 | 只是连接提示 |

另有本机 `clientId`（随机 UUID，HELLO 中发送，仅作信息）和本机显示名称。
配对过程中的临时私钥、二维码里的 `pairingToken`、P2P 组口令都不长期保存，也不写日志。
私钥丢失即身份丢失，只能重新配对，并提示用户在手机上删除旧的信任记录。

### 4.4 撤销

手机上解除信任后，旧证书的控制/数据连接和旧 bleKey 的 BLE 认证都会得到 `AUTH_FAILED`（TLS 也可能直接断开）。
桌面端收到后应标记该节点“信任已失效”，停止自动重连与轮询，提示重新配对；不要自动删除本地收件箱数据。

## 5. 发现

### 5.1 mDNS / DNS-SD

- 服务类型 `_dfabric._tcp.`（`local.` 域），实例名为随机 `DF-xxxxxxxx`，端口为控制端口，TXT 只有 `v=1`。
- 节点只发布 IPv4、只在 Wi-Fi/以太网/自身 P2P 接口监听。解析出的地址只是候选：对它做 TLS + HELLO 并核对 nodeId 后才算命中。
- 候选需有时效（HL Link 用 15 秒），Wi-Fi 网络变化时清空并重新浏览。
- 常见失败：路由器 AP 隔离、访客网络、组播过滤、桌面防火墙拦截 UDP 5353 组播。此时退回 BLE 获取地址，不要求用户输入 IP。

### 5.2 BLE 扫描

- 服务 UUID `38e96d70-1342-4bc8-8f02-924127b5e210`，位于主广播（legacy，可连接）。
- scan response 中 service data（同一 UUID）为 `0x01 | 8 字节随机 eid`；**必须使用主动扫描**才能拿到 scan response。
- eid 每 2 分钟轮换（有 GATT 客户端连着时不轮换），不能当身份；广播中没有设备名称，也没有持久标识。
- BLE 地址是随机/私有地址，桌面系统还可能再映射一次（macOS 只给本机生成的 UUID），不能把它当身份或 P2P 地址。
- 扫描要有超时（HL Link 为 15 秒），找到即可停止；桌面端不要常驻扫描。

## 6. BLE GATT 控制通道

作用只有两类：已配对设备的认证与建链协商（LINK_REQUEST/LINK_STATUS），以及附近配对（DF-NEAR-1）。
**文件和文本永远不走 BLE。**

### 6.1 GATT 结构与分片

| 特征 | UUID 尾号 | 属性 | 用途 |
| --- | --- | --- | --- |
| RX | …e211 | write with response | Controller → 节点 |
| TX | …e212 | notify（标准 CCCD） | 节点 → Controller |
| INFO | …e213 | read | UTF-8 JSON `{v:1, eid, pairing}` |

流程：连接 → 发现服务 → **先订阅 TX** → 读 INFO（以 INFO 中的 eid 为准，扫描时看到的 eid 可能已轮换）→ 写 RX。

- 每个 ATT 值：`uint16 BE messageId | uint16 BE fragmentIndex | uint16 BE total | payload`，6 字节头。
- 每片总长 ≤ ATT_MTU − 3，即 payload ≤ ATT_MTU − 9；默认 MTU 23 时 payload 14 字节。按实际协商出的 MTU 计算，不要写死 517。
- fragmentIndex 从 0 连续；total 1..2048；整条消息 ≤ 16384 字节；消息体是不带 TCP 长度头的 UTF-8 JSON。
- **节点拒绝 prepared/long write**：每次写入都必须单片放得下。部分平台在值超过上限时会自动改用 long write，必须自己按 MTU 切片。
- 每台节点最多 2 个 GATT 客户端；未认证或不活动的会话 1 分钟过期（每 30 秒检查），过期后需重新连接认证。

### 6.2 已配对设备认证（DF-BLE-1）

1. Controller 发 `AUTH_START {eid, hint, cn}`：cn 为新随机 32 字节（base64）；
   hint = HMAC-SHA256(bleKey, `DF-HINT-1\n<eid>`) 的 hex 前 32 字符，让节点在不暴露固定 ID 的情况下找到对应密钥。
2. 节点回 `CHALLENGE {sn, proof}`。定义 T = `DF-BLE-1\n<nodeId>\n<eid>\n<cn>\n<sn>`（cn、sn 为 base64 文本）。
   Controller 校验 proof = HMAC(bleKey, T + `\nserver`)，失败即断开（对方不是该节点）。
3. Controller 发 `AUTH_FINISH {proof = HMAC(bleKey, T + "\nclient")}`，节点回 `AUTH_OK {sessionId = HMAC(bleKey, T + "\nsession")}`，
   Controller 自行计算并比对。
4. 会话密钥：HKDF-SHA256(IKM=bleKey, salt=SHA256(cn 原始字节 ‖ sn 原始字节), info=`DF-BLE-1\n<nodeId>\n<eid>`, L=72)：
   [0:32] c2s 密钥、[32:64] s2c 密钥、[64:68] c2s nonce 前缀、[68:72] s2c nonce 前缀。
5. 之后的请求封装为 `SECURE {seq, data}`：AES-256-GCM，nonce = 4 字节方向前缀 ‖ uint64 BE seq，
   AAD = `<sessionId>\n<c2s|s2c>\n<seq 十进制>`，data = base64(密文‖16 字节 tag)。两个方向各自从 0 计数，< 10000。
6. 任意重放、tag 失败或认证失败，节点废弃全部状态；Controller 也应丢弃密钥，用新随机数重新开始。
   这个通道没有前向保密，这是设计已知取舍：它只用于协商，不承载文件。

所有 HMAC/HKDF/GCM 输入的换行、base64、十进制编码都必须与 `vectors.json` 逐字节一致。

### 6.3 建链请求

- 加密请求 `{type:"LINK_REQUEST", transport:"LAN"|"P2P"}` 或 `{type:"LINK_STATUS"}`。
- 加密响应 `LINK_READY {addresses, controlPort, dataPort, group}`；
  group = `{name, passphrase, goAddress, peerAddress, state}`，字段为空表示未就绪。
- `transport:"P2P"` 会让节点按需创建 GO；Controller 随后轮询 LINK_STATUS 直到 `name` 与 `goAddress` 都非空（总时限约 30 秒）。
- 节点的 P2P 已被投屏等其他功能占用时，group 为空且 state 说明占用，Controller 显示“对方 Wi-Fi 直连忙”，不重试抢占。

## 7. 配对

### 7.1 附近配对（主要方式，DF-NEAR-1）

前提：手机上点了「添加设备」（5 分钟窗口），INFO 的 `pairing` 为 true。

1. Controller 为本次尝试生成：临时 ECDH P-256 密钥、**长期证书用 P-256 签名密钥**（将来的客户端私钥）、32 字节 nonce。
2. 构造 C = `DF-NEAR-C1\n<eid>\n<ECDH 公钥 SPKI b64>\n<nonce b64>\n<证书公钥 SPKI b64>\n<base64(UTF-8 本机名称)>`，
   发 `NEAR_COMMIT {eid, commit=b64(SHA256(C))}`，收到节点的 commit。
3. 发 `NEAR_REVEAL {publicKey, nonce, certificateKey, name}`，收到 `NEAR_REVEAL {reveal=S}`。
   S = `DF-NEAR-S1\n<eid>\n<节点 ECDH 公钥>\n<节点 nonce>\n<nodeId>\n<CA DER b64>`。
   校验：SHA256(S) 等于先前 commit、eid 一致、nonce 32 字节、**SHA256(CA 的 SPKI) == nodeId**。
4. digest = b64(SHA256(C + "\n" + S))；HKDF(IKM=ECDH 共享密钥, salt=SHA256(C\nS), info=`DF-NEAR-1`, 72 字节)。
   验证码 = HMAC(K[0:32], `sas\n<digest>`) 前 4 字节（大端无符号）mod 1,000,000，补零到 6 位。
5. 桌面显示 6 位验证码并要求用户与手机比对；**只有用户确认一致后**才发 `NEAR_CONFIRM {proof=b64(HMAC(K[0:32], digest+"\nconfirm"))}`。
   手机侧用户也要确认。
6. 收到 `NEAR_RESULT {data}`：AES-256-GCM 解密，key = K[32:64]，nonce = K[68:72] ‖ 8 个 0 字节，AAD = `<digest>\nresult`。
   明文为 PAIR_RESULT 字段 + `addresses, controlPort, dataPort`（+ 节点 `name`）。
   校验 nodeId、nodeCa 与 S 中的 CA 相同、客户端证书公钥等于第 1 步的证书公钥、peerId = SHA256(证书 DER)、bleKey 32 字节。
7. 先持久保存信任，再尝试 mTLS + STATUS 验证；链路失败不影响已保存的信任（下次发送时再连）。

时限与限流：待处理配对 ≤ 120 秒，手机确认 ≤ 90 秒，每个窗口最多 5 次尝试。随时可发 `NEAR_CANCEL`。
验证码必须由人比对，不能自动确认。

### 7.2 二维码 / 导出文件（备用）

- 内容为 JSON：`protocolMajor=1, nodeId, caDer, pairingToken, expiresAt(毫秒十进制字符串), controlPort, dataPort, addresses, group`。
- 桌面入口：导入手机「导出配对信息」生成的文件、粘贴 JSON、或从截图/摄像头识别二维码。
  导出文件含一次性口令，只能私下传递（例如 USB），导入后提示用户删除该文件。
- 流程：校验 SHA256(caDer 的 SPKI) == nodeId 与有效期 → 依次尝试 addresses；都不可达且 group 就绪时，按第 8.2 节加入 GO →
  TLS（只信任 caDer，此时不带客户端证书）→ HELLO → `PAIR {pairingToken, name, publicKey, proof}`，
  proof 是对 `DF-PAIR-1\n<nodeId>\n<pairingToken>\n<HELLO_ACK.challenge>` 的 ECDSA-SHA256（DER）签名 → 等待手机用户批准 → PAIR_RESULT。
- 同一 token 绑定第一次提交的公钥；响应丢失时，用**同一私钥**在原窗口内重试会拿到同一结果。
  因此生成的私钥要在 PAIR 之前就安全保存为“待定”状态（HL Link 的 `pending.<nodeId>`），成功保存信任后删除。
- 拿到 PAIR_RESULT 后用新证书重新连接并 STATUS 验证。

### 7.3 配对 UI 要求

显示正在配对的设备（附近候选无名称，显示“附近的 Lineage 设备”），显示验证码与确认/取消，显示手机端需要确认的提示；
已配对的节点不重复添加；提供“删除此设备”（同时提醒在手机上解除信任）。

## 8. 链路选择

### 8.1 每次需要连接时的顺序（与 HL Link 一致）

1. 已有会话：发 STATUS（短超时）确认仍可用。
2. LAN：新近 mDNS 候选 → 上次成功地址 → 配对/LINK_READY 记录的地址；最多试 4 个，每个 TLS 超时约 2 秒。
3. BLE：扫描 → 认证 → `LINK_REQUEST(LAN)` 取节点当前地址再试 LAN。
4. 仍失败且平台支持无路由器连接：`LINK_REQUEST(P2P)` → 轮询到 GO 就绪 → 加入 GO → TLS 到 goAddress。
5. 全部失败：明确报“未连接到设备”，保留任务等待重试，不切到蜂窝/VPN 等其他网络。

每条路径最后都要 TLS + HELLO 核对 nodeId。连接成功后记住地址作为下次提示。

### 8.2 无路由器（加入节点的 Wi-Fi Direct GO）

节点用显式 SSID（`DIRECT-DF-<8 hex>`）和随机口令（24 个 hex 字符）创建 GO，频段自动，非持久组，空闲 5 分钟或关闭节点时移除。
GO 对外表现为 WPA2-PSK 接入点，地址由 GO 的 DHCP 分配（常见 192.168.49.x，但**不能写死**，以 goAddress 与实际获得的地址为准）。

桌面端推荐做法：**以“传统客户端（legacy client）”身份，用 SSID + 口令像加入普通 Wi-Fi 一样加入**，而不是实现 Wi-Fi Direct 协商。理由：

- macOS 没有公开的 Wi-Fi Direct API；
- Windows 的公开 Wi-Fi Direct API 面向设备发现与配对协商，未见用已知 SSID/口令加入现有组的接口（实现前再核查）；
- Linux wpa_supplicant 以 P2P 方式加入现有组走 WPS 流程，而节点不提供 WPS。

HL Link 也是凭已认证的 SSID/PSK 加入（鸿蒙 Hid2d 凭据分支），原理相同；但**桌面以普通客户端加入 Android GO 尚未实测**，必须作为独立验收项。

实现要求：

- 只使用通过 BLE 认证通道或本机二维码拿到的 SSID/口令；不扫描并加入任意 `DIRECT-` 网络。
- 加入前记录当前 Wi-Fi 状态。单网卡电脑加入 GO 会断开原 Wi-Fi，**必须先征得用户同意**（或在设置中给出明确的“允许为传输临时切换 Wi-Fi”选项）；
  有线 + Wi-Fi 的电脑最适合这条路径。
- 用临时、不自动连接的网络配置；传输结束、取消或失败后移除该配置并恢复原网络。不长期保存组口令。
- 获得地址后，控制和数据 socket 绑定到该接口的本机地址，确保流量走直连；不改系统默认路由。
- GO 在空闲 5 分钟后会被节点移除；入组后应尽快建立 TLS，长时间空闲后重新走 BLE 请求。

## 9. TLS 控制协议

### 9.1 连接与帧

- 控制端口默认 9527，数据端口默认 9528；实际值以配对结果/LINK_READY 为准。
- 控制帧：`uint32 BE 长度 + UTF-8 JSON`，长度 1..65536。读取时先校验长度再分配内存，处理 TCP 半包与粘包。
- 信封：`{v:1, type, requestId, body}`。requestId ≤ 128 字符，响应原样带回；连接建立前的错误 requestId 为空。
- 整数（size、chunkSize、index、received）用**规范十进制字符串**：无符号、无前导 0、无指数，范围 0..2^63−1。端口、window 为 JSON 数字。
- 未知字段忽略；未知类型或 major 版本拒绝。

### 9.2 HELLO

连接后 15 秒内必须发送第一条消息 HELLO：body `{clientId, name?}`（已鉴权连接才带 `name`，见第 11 节）。
HELLO_ACK：`nodeId, sessionId, challenge, capabilities, chunkSize="1048576", window=1`，已鉴权时还有 `name`。
sessionId 与 challenge 为 32 字节 base64。当前能力：FILE_RECEIVE、TEXT_RECEIVE、RESUME、STATUS、FILE_SEND。
只使用对方声明的能力；忽略未知能力。

控制端点允许不带客户端证书，但此时只能 HELLO 和 PAIR；数据端点必须带证书。

### 9.3 操作一览

| 请求 | 主要字段 | 响应 |
| --- | --- | --- |
| STATUS | `{}` | STATUS_RESULT `{transfers, state}`：只含本 Controller 的上传记录 |
| FILE_OFFER / RESUME | transferId, name, mime, size, chunkSize, sha256 | ACCEPT 或 COMPLETE |
| CANCEL | transferId | CANCELLED（已提交的返回 COMPLETE 状态） |
| TEXT_OFFER | transferId, text | COMPLETE（手机保存为 text.txt） |
| PULL_LIST | `{}` | PULL_LIST_RESULT `{offers, ended}` |
| PULL_ACCEPT | transferId, haveBits | PULL_READY（清单 + ticket, dataPort, window） |
| PULL_CANCEL | transferId | PULL_CANCELLED |
| PULL_COMPLETE | transferId, size, sha256 | PULL_COMPLETED |
| PAIR | 见 7.2 | PAIR_RESULT |

### 9.4 错误与超时

- `ERROR {code, retryable}`；收到 ERROR 后该连接即关闭，需重连，不能在同一流上继续。TLS 层失败可能没有应用层 ERROR。
- 错误码：AUTH_FAILED、PAIR_EXPIRED、PERMISSION_DENIED、INVALID_FRAME、SOURCE_CHANGED、NO_SPACE、HASH_MISMATCH、
  CANCELLED、P2P_BUSY、IO_ERROR。只有 IO_ERROR 标记 retryable；LINK_TIMEOUT 等是 Controller 本地错误分类。
- 节点控制连接空闲 120 秒超时：在线会话需每 < 120 秒有请求（接收轮询每约 3 秒天然满足）。
- 数据连接单次读超时 30 秒。
- FILE_OFFER/TEXT_OFFER 可能等待手机用户批准最长 90 秒；请求超时应 ≥ 120 秒。手机同一时间只显示一个批准请求，
  其他请求会得到 P2P_BUSY，需要排队重试。
- 节点 TLS 工作线程为 8 个、排队 16 个：每个节点同时最多保持 1 个发送控制会话、1 个接收轮询会话和当前的 1 条数据连接。

## 10. 文件传输

### 10.1 发送（上传到手机）

1. **准备**：把源文件复制到 Agent 私有暂存区，复制时计算 SHA-256 和大小；生成小写 UUID 作为 transferId。
   暂存后任务与源文件解耦，可跨重启续传；源文件被修改不影响已暂存的内容。
   （对超大文件可以选择不复制，但必须保证内容不变：记录大小/修改时间/文件 ID，续传前复核，变化即放弃该 ID 重新发送；
   节点最终会校验整文件哈希，内容变化会以 HASH_MISMATCH 失败。）
2. **元数据约束**：name 1..128 字符，无路径分隔符/控制字符，不能是 `.`/`..`；mime 形如 type/subtype，≤ 128；
   size ≤ 16 GiB；chunkSize 固定 `"1048576"`；sha256 小写 64 hex。同一 transferId 的元数据不可改变。
3. **FILE_OFFER**：首次发送；手机可能弹出批准。返回 COMPLETE 表示之前已经完成（幂等），直接标记成功。
4. **ACCEPT**：`ticket`（60 秒内一次性）、`dataPort`、`window=1`、`haveBits`。
   haveBits 是 Java BitSet 兼容的小端字节数组 base64：字节 k 的位 j 表示块 8k+j 已保存；空字符串表示一块都没有。
5. **数据连接**：mTLS 连接数据端口，先发 `DATA_BIND {sessionId, transferId, ticket, direction:"upload"}`（控制帧格式），
   等 DATA_READY。ticket 绑定当前控制会话、客户端证书和该传输，**控制连接必须保持**。
6. **块**：`uint64 BE index | uint32 BE 长度 | 32 字节该块 SHA-256 | 数据`（头 44 字节）。只有最后一块可短于 1 MiB。
   跳过 haveBits 中已有的块；窗口为 1：每发一块等待数据连接上的 CHUNK_ACK `{chunkIndex, received}` 再发下一块。
   ACK 表示手机已落盘并持久化检查点。空文件不发块。
7. **完成**：所有块确认后，手机校验整文件、保存到 `Download/DeviceFabric`，数据连接上返回 COMPLETE `{transferId,name,state,size,received,uri}`。
   uri 是手机本地 URI，仅作回执。此后删除暂存源。
8. **中断恢复**：网络中断、进程退出后用**同一 transferId 与相同元数据**发 RESUME（或 FILE_OFFER），按新的 haveBits 只补缺块。
   已批准的传输重连后不会再次询问。用户取消的任务不自动恢复。
9. **取消**：发 CANCEL；同时关闭数据连接。若手机已提交，响应为 COMPLETE 状态，以此为准。
10. **多文件**：串行队列，一次一个文件；不要为并行开多条数据连接。

文本：UTF-8 ≤ 49152 字节，且整帧 ≤ 65536，用 TEXT_OFFER；更长的文本作为 .txt 文件发送。不写对方剪贴板。

### 10.2 接收（从手机拉取）

前提：HELLO_ACK 含 `FILE_SEND`。

1. Agent 在线时对每个可达节点保持一个独立的控制会话（不与发送会话共用，避免批准等待阻塞轮询），约每 3 秒 `PULL_LIST`。
   `offers` 是待接收的清单（transferId, name, mime, size, chunkSize, sha256），`ended` 是对方已结束（取消/完成）的记录状态。
2. 新 offer：按 10.1 的规则校验元数据，持久记录，通知用户“接收/拒绝”。**用户接受前不拉取任何字节。**
   拒绝 = `PULL_CANCEL`。在 ended 中看到 CANCELLED 的，标记为对方已取消。
3. 接受：检查空间（文件大小 + 余量），`PULL_ACCEPT {transferId, haveBits}`，haveBits 描述本地**已持久化**的块。
   收到 PULL_READY：核对清单与 offer 完全一致，`ticket` 32 字节，120 秒内一次性。
4. 数据连接发 `DATA_PULL_BIND {sessionId, transferId, direction:"download", ticket}`。之后**没有 DATA_READY**，对方直接按升序发缺失块
   （同样 44 字节头）。每块：校验索引范围、长度、块哈希 → 写到绝对偏移 → fsync 数据 → 原子保存日志（位图）→ 在数据连接上回
   `CHUNK_ACK {chunkIndex}`（requestId 与 bind 相同）。所有缺块发完后对方关闭连接；接收方根据大小自行计算应收块数。
5. 校验整文件长度与 SHA-256 → 原子提交到收件位置 → 持久化 COMPLETE → `PULL_COMPLETE {transferId, size, sha256}` → PULL_COMPLETED。
   对方只有收到这一步才标记送达并删除源；回执丢失就用同一 ID 重发 PULL_COMPLETE，不重新下载。
6. 中断：保留已持久化的块，重新 PULL_ACCEPT 续传；同一 transferId 已完成的不再下载。

### 10.3 本地文件系统要求

- 写入顺序永远是“私有暂存 → 校验 → 原子移动到可见位置”；未完成或校验失败的文件不能出现在用户目录。
- 持久化：Linux 用 fsync，重命名后再 fsync 目录；**macOS 的 fsync 不保证落盘，需要 F_FULLFSYNC**；Windows 用 FlushFileBuffers，
  替换用带 write-through 的移动/替换。ACK 必须在持久化之后发出。
- 文件名：协议中的 name 只作元数据。保存时按本地规则生成安全文件名，不覆盖已有文件（加序号或 transferId 前缀）：
  - Windows：去除 `<>:"/\|?*` 与控制字符、末尾的点和空格，避开 CON/PRN/AUX/NUL/COM1–9/LPT1–9 等保留名，注意路径长度和大小写不敏感；
  - macOS：`/` 不可用，`:` 在 Finder 中显示异常，注意 Unicode 规范化；
  - Linux：`/` 与 NUL 不可用，其余按 UTF-8 保存。
- 空间：暂存 + 最终复制可能同时占两份，预检按峰值计；大文件可用稀疏文件预分配。
- 来自另一设备的文件，建议按平台惯例标记来源（Windows 的 Mark-of-the-Web、macOS 的 quarantine 属性），至少对可执行文件这样做。
- 记录上限对齐节点：每个方向最多 64 条记录，可清理已结束记录；单文件 16 GiB。

## 11. 显示名称

- 本机名称：1..64 个 UTF-16 码元，去控制字符、去首尾空白，截断时不拆开代理对（与 Lineage/HL Link 规则一致）。
- 默认值为电脑名称，用户可自定义；清空或设为与系统名称相同时恢复“跟随系统名称”。来源建议：
  - Windows：系统“设备名称”（即计算机名）；
  - macOS：系统设置中的“电脑名称”（ComputerName，不是主机名）；
  - Linux：systemd-hostnamed 的 pretty hostname，没有则用静态主机名。
- 交换：PAIR / NEAR_REVEAL 的 `name` 发送本机名称；PAIR_RESULT / NEAR_RESULT 的 `name` 是节点名称（旧节点没有时显示“Lineage 设备”）；
  每次**已鉴权**连接的 HELLO 带 `name`，HELLO_ACK 的 `name` 与本地记录不同时更新信任记录。
  匿名（配对）HELLO 不带名称。名称只是标签，不参与任何信任判断；不合规的名称忽略。

## 12. 平台适配

### 12.1 能力对照

| 能力 | Windows 10 / 11 | macOS（13+） | Linux（桌面发行版） |
| --- | --- | --- | --- |
| BLE 中心 | WinRT 蓝牙 LE（广播监听需设为主动扫描、GATT 客户端、GattSession 获取 MTU） | CoreBluetooth（广播数据已合并 scan response；按 maximumWriteValueLength 切片） | BlueZ D-Bus（默认主动扫描，ServiceData 属性；MTU 来自 AcquireWrite 或连接参数） |
| 跨平台 BLE 参考 | bleak 在三平台分别封装上述后端，参考客户端已在 Linux 用它与节点互通 | 同左 | 同左 |
| mDNS 浏览 | 设备枚举 API 的 DNS-SD 协议或 dnsapi 的 DNS-SD 浏览函数（按目标最低版本核查），也可自带 mDNS 实现 | Network.framework NWBrowser / dns_sd | Avahi（D-Bus）；或程序自带 mDNS 实现 |
| 临时加入 GO | Native Wifi（wlanapi）临时配置文件连接，完成后删除配置并恢复原网络 | CoreWLAN 关联指定网络（需定位权限才能看到 SSID） | NetworkManager D-Bus 临时连接（不自动连接、可指定网卡） |
| TLS 1.3 + 客户端证书 | 自带 TLS 库（SChannel 仅 Win11+ 支持 TLS 1.3 客户端） | 自带 TLS 库或 Network.framework（身份需 Keychain） | OpenSSL 1.1.1+/3.x 或 rustls |
| 私钥/bleKey 存储 | CNG 密钥存储（可选 TPM 提供程序，不可导出）或 DPAPI 加密文件 | Keychain（可设为本机专用、不可导出） | Secret Service（libsecret/KWallet）；不可用时 0600 文件并提示用户 |
| 电脑名称 | 计算机名 | ComputerName | pretty hostname |
| 分享/发送入口 | “发送到”菜单（无需打包身份）、右键菜单（Win11 新菜单需包身份）、分享目标（需 MSIX 包身份） | Share Extension（需 App Group 交接给主程序）、Finder 快速操作、服务菜单、拖到 Dock | .desktop 的“打开方式”、文件管理器扩展（Nautilus 脚本/扩展、Dolphin ServiceMenu、Thunar 自定义动作） |
| 常驻与通知 | 登录启动的托盘程序；Toast 通知 | 菜单栏程序 + Login Item；UserNotifications | 自启动 .desktop 或 systemd --user；StatusNotifierItem 托盘；freedesktop 通知 |
| 打包 | MSIX 或传统安装包（代码签名） | 签名并公证的 .app（可沙盒） | Flatpak / deb / rpm / AppImage |

### 12.2 Windows 注意事项

- 需要支持 BLE 的蓝牙 4.0+ 适配器；监听广播必须设为主动扫描，否则拿不到 eid。
- Windows 10 SChannel 不支持客户端 TLS 1.3，统一使用随程序携带的 TLS 库。
- 加入 GO 会替换当前 Wi-Fi 连接（单网卡），要征得用户同意并在结束后恢复；完成后删除临时配置文件。
- 防火墙：Controller 只有出站 TCP，不需要入站规则；mDNS 浏览可能触发防火墙提示，被拒时退回 BLE。
- 分享目标与新右键菜单需要包身份（MSIX 或稀疏包）；“发送到”最简单，首版可先做。
- 文件名保留字与路径长度见 10.3。

### 12.3 macOS 注意事项

- Info.plist 必须声明蓝牙使用说明；macOS 15 起访问本地网络需要“本地网络”授权，需声明用途说明和 Bonjour 服务类型 `_dfabric._tcp`。
- 沙盒应用需要网络客户端、蓝牙和用户选择文件的权限；Share Extension 与主程序通过 App Group 共享交接目录，扩展只负责交接。
- CoreBluetooth 只提供本机生成的外设 UUID，不提供 MAC，这符合协议（本来就不依赖地址）。
- 写入特征值时用“带响应”的最大长度切片，否则系统会尝试 long write 而被节点拒绝。
- 没有公开的 Wi-Fi Direct API；加入 GO 只能以普通 Wi-Fi 客户端方式（CoreWLAN），读取 SSID 列表需要定位授权，且会断开当前 Wi-Fi。
- 持久化需 F_FULLFSYNC。
- 分发需要 Developer ID 签名与公证。

### 12.4 Linux 注意事项

- BlueZ 5.5x+；用户需在本地活动会话中（polkit 允许 BlueZ 与 NetworkManager 操作）。
- 没有 NetworkManager 的系统（只有 wpa_supplicant/iwd）需另行适配或不提供无路由器连接，界面说明原因。
- Flatpak 需要系统总线访问 BlueZ（`org.bluez`）和 NetworkManager、网络权限；文件通过 portal 或文件管理器入口进入。
- 托盘在 GNOME 需要扩展支持；无托盘时提供普通窗口与通知。
- Secret Service 不可用（无桌面钥匙环）时退回 0600 权限文件，并在界面提示保护程度较低。

## 13. 常量与限制

| 项目 | 值 |
| --- | --- |
| 协议 | DF/1，信封 v=1，TLS 1.3，IPv4 |
| 端口 | 控制 9527，数据 9528（以协商值为准） |
| 控制帧 | 1..65536 字节 |
| 块 | 1 MiB，窗口 1，块头 44 字节 |
| 单文件 | ≤ 16 GiB；文本 ≤ 49152 UTF-8 字节 |
| 名称 | 文件名 1..128；设备名 1..64 |
| 节点容量 | 32 个信任设备；每方向 64 条记录；8 个 TLS 工作线程 |
| 票据 | 上传 60 秒，下载 120 秒，一次性 |
| 批准 | 手机确认 ≤ 90 秒，同时只处理一个 |
| 配对窗口 | 5 分钟；附近配对 ≤ 120 秒，每窗口 5 次 |
| BLE | MTU 按协商（默认 23）；消息 ≤ 16384；片数 ≤ 2048；序号 < 10000；会话 1 分钟不活动过期；最多 2 个客户端 |
| eid | 8 字节，2 分钟轮换 |
| GO | 空闲 5 分钟移除；口令 24 hex；SSID `DIRECT-DF-<8 hex>` |
| 超时（节点侧） | HELLO 15 秒内；控制空闲 120 秒；数据读 30 秒 |

## 14. 安全要求清单

- [ ] 只信任配对得到的 CA；校验 IP SAN；HELLO_ACK nodeId 必须匹配；没有跳过校验的选项。
- [ ] 私钥与 bleKey 存入平台安全存储；日志、崩溃报告、诊断导出中不出现 token、口令、密钥、证书私钥、组口令。
- [ ] 发现结果（mDNS、BLE、SSID、IP）都只作候选；任何信任决定都来自 TLS 或已认证的 BLE。
- [ ] 附近配对必须由人比对验证码；先 commit 后 reveal 的顺序和全部校验不可省略。
- [ ] BLE 认证失败、重放、tag 错误时废弃全部会话状态。
- [ ] 接收端用户接受前不拉取数据；文件名不当作路径；位图、索引、长度、块哈希与整文件哈希全部校验。
- [ ] 不自动执行、不自动打开收到的文件；按平台惯例标记来源。
- [ ] 加入 GO 前取得用户同意，结束后恢复网络、删除临时配置。
- [ ] 本地 IPC（UI ↔ Agent）只对当前用户开放（Unix socket 权限 / 命名管道 ACL / XPC）。
- [ ] 撤销后停止自动连接；不能因 AUTH_FAILED 自动重新配对。

## 15. 测试与验收

### 15.1 自动化（不需要手机）

1. 用 `vectors.json` 对拍 hint、服务端/客户端 proof、sessionId、HKDF 72 字节、首条 c2s 明文/密文。
2. 编解码单测：控制帧边界（0、1、65536、65537）、十进制字符串规则、BLE 分片重组（乱序、重复、超长、片数越界）、44 字节块头。
3. SAS 验证码与 DF-PAIR-1 签名串格式。
4. 位图编解码与 Java BitSet 兼容（含空位图、最后一字节、超出块数的位）。
5. 文件存储：中途杀进程后恢复、fsync 前后状态、同名文件不覆盖、非法文件名。

### 15.2 与真实节点（Mi 10）互操作

以 Python 参考客户端的已通过用例为基线，桌面端逐项通过：

1. LAN：mDNS 发现 → 导入导出文件配对 → 手机批准 → 新证书 mTLS + STATUS。
2. 附近配对：两端验证码一致、拒绝/超时/取消、窗口关闭后失败。
3. 发送：空文件、小文件、非 1 MiB 整数倍、> 4 GiB、同名文件、文本；两端 SHA-256 一致。
4. 续传：上传/下载中途断网、杀 Agent、重启电脑后只补缺块且只保存一次。
5. 接收：手机发起 → 桌面接受/拒绝 → 完成回执 → 手机显示已送达；手机取消后桌面状态正确。
6. 负向：错误 CA、错误 IP、已撤销证书、伪造 BLE proof、重放 SECURE、越界块、错误块哈希、错误 ticket。
7. BLE 建链：LINK_REQUEST(LAN) 获取新地址；节点 IP 变化后仍能连接。
8. 无路由器：两端断开 AP、Wi-Fi 开关保持开启，桌面以传统客户端加入 GO 完成传输；传输后恢复原网络；
   GO 被投屏占用时显示忙且投屏不受影响。（各 OS 分别验收）
9. 名称：默认电脑名称、自定义、恢复系统名称，手机端显示随下次连接更新；手机改名后桌面更新。
10. 系统集成：从文件管理器/分享入口发送多文件，入口进程退出后任务仍在 Agent 中完成。

### 15.3 证据要求

每项记录：桌面 OS 版本与硬件（蓝牙/Wi-Fi 网卡）、程序版本、手机 build、网络角色与实际地址/接口、耗时、结果、日志摘要（去除机密）。
只有实际观察到的结果才能标记通过；Python 参考客户端或 HL Link 的结果不能代替桌面端结论。
Lineage 侧版本仍按项目规则记录为 code-baseline，除非另有 ROM/设备验证证据。

## 16. 建议实施顺序

| 阶段 | 内容 | 进入下一阶段的条件 |
| --- | --- | --- |
| M1 | 协议核心：帧、密码学、向量对拍；TLS 库互操作实验（证书剖面、IP SAN、客户端证书） | 向量全部一致；能对真实节点完成 TLS + HELLO 并拒绝错误 CA/IP |
| M2 | 导入文件配对、LAN 发送/续传/取消/文本、凭据安全存储 | 15.2 第 1、3、4、6 项（LAN 部分）通过 |
| M3 | 接收（PULL）、收件箱、通知 | 第 5 项通过 |
| M4 | BLE：扫描、DF-BLE-1、LINK_REQUEST(LAN)、附近配对 | 第 2、7 项通过 |
| M5 | 平台集成：托盘/Agent、分享入口、开机自启、名称设置 | 第 9、10 项通过 |
| M6 | 无路由器：按平台实现临时加入 GO | 第 8 项在该平台通过；未通过的平台不展示此能力 |

建议先做一个平台（Linux 最接近已验证的参考客户端环境）走完 M1–M4，再移植平台适配层。

## 17. 已知边界与后续扩展

- 桌面以传统客户端加入 Android GO 未实测；如果某些网卡/驱动无法加入，该平台只提供 LAN + BLE 协商。
- 当前协议中节点不会主动连接 Controller，手机发文件依赖桌面在线轮询；桌面离线时文件留在手机发件箱等待。
- 桌面作为 Node（让手机主动推送、或桌面之间互传）需要在 Lineage App 中实现 Controller 角色，属于协议扩展，需要先更新 DF/1 规范。
- 剪贴板、IPv6、多文件并行、QUIC、云中继均未定义，不能自行加入私有消息；需要时先改规范并保持旧版本互通（可选字段 + 能力声明）。
- 服务类型 `_dfabric._tcp` 与 BLE 服务 UUID 为项目私有标识，未做公共注册。
