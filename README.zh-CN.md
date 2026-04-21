# ByeByeVPN

VPN / DPI / Reality / ТСПУ 可检测性扫描器。单个静态 `byebyevpn.exe`，
Windows 原生（Linux 和 macOS 可通过 Wine 运行），无需管理员权限，
无 DLL 依赖。

```
 ____             ____           __     ______  _   _
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/
   Full TSPU/DPI/VPN detectability scanner   v2.5.5
```

**语言:** [English](README.md) · [Русский](README.md#русский) · [简体中文](#简体中文) · [فارسی](README.fa.md)

**讨论 / 反馈:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues)

---

## 简体中文

### 用途

输入一个 IP 或主机名，工具作为第三方观察者对目标执行完整的俄罗斯
OCR 方法论（§5-10）加上 2026 年现代隧道指纹检测。输出：检测分数、
识别出的协议栈、以及 TSPU 级别分类器会做出的裁决。**无需**连接到
目标的 VPN——扫描器以外部视角看待目标，就像 ISP 或 DPI 中间盒
看到的一样。

### 流水线

| # | 模块                        | 功能                                                                     |
|---|-----------------------------|--------------------------------------------------------------------------|
| 1 | DNS 解析                    | A + AAAA，优先 IPv4                                                      |
| 2 | GeoIP 聚合                  | 并行查询 9 个提供商（3 欧 / 3 俄 / 3 全球），ASN + 标志                  |
| 3 | TCP 端口扫描                | Connect 扫描 1-65535（默认）或 205 个精选端口，500 线程                  |
| 4 | UDP 探测                    | 真实握手：DNS / IKE / OpenVPN / QUIC / WG / Tailscale / L2TP / Hysteria2 / TUIC / AmneziaWG |
| 5 | 服务指纹 + CT               | SSH、HTTP、TLS + SNI 一致性、SOCKS5、CONNECT、Shadowsocks、crt.sh、代理头泄漏 |
| 6 | J3 / TSPU 主动探测          | 每个 TLS 端口 8 种探测（Reality 鉴别器）                                 |
| 7 | SNITCH + traceroute + SSTP  | RTT vs GeoIP (方法论 §10.1)、ICMP 跳数、Microsoft SSTP                   |
| 8 | 裁决 + TSPU 模拟            | 0-100 分数、协议栈识别、3 级 TSPU 裁决、加固建议                         |

### UDP 握手

| 端口       | 协议              | 载荷                                                  |
|------------|-------------------|-------------------------------------------------------|
| 53         | DNS               | `example.com` 的 A 查询（事务 ID 随机化）             |
| 500, 4500  | IKEv2             | ISAKMP SA_INIT 头                                     |
| 1194       | OpenVPN           | HARD_RESET_CLIENT_V2                                  |
| 443        | QUIC v1           | 1200 字节 Initial（随机 DCID）                        |
| 51820      | WireGuard         | 148 字节 MessageInitiation                            |
| 41641      | Tailscale         | WG 风格握手                                           |
| 1701       | L2TP              | 带必需 AVP 的 SCCRQ，随机 tunnel-id                   |
| 36712      | Hysteria2         | QUIC v1 Initial，随机 DCID                            |
| 8443       | TUIC v5           | QUIC v1 Initial                                       |
| 55555      | AmneziaWG Sx=8    | 8 字节垃圾前缀 + WG init                              |
| 51820      | AmneziaWG Sx=8    | 对比探测：原版 WG 被拒，Sx=8 被接受                   |

### J3 探测

每个支持 TLS 的端口发送 8 种探测：

1. 空 TCP 连接（不发字节）
2. 带真实 Host 头的 `GET /`
3. `CONNECT example.com:443`
4. 合理的 OpenSSH banner
5. 512 字节随机数据（`RAND_bytes`）
6. 随机 `.invalid` SNI 的 TLS ClientHello
7. 绝对 URI 的 HTTP 代理风格 `GET`
8. `0xFF × 128`

Reality / XTLS 静默丢弃所有 8 种；常规 HTTP 返回 400/403。
**模式本身**就是诊断信号。

### 裁决等级

| 分数   | 标签            | 含义                                              |
|--------|-----------------|---------------------------------------------------|
| 85-100 | `CLEAN`         | 看起来像普通 Web 服务器                           |
| 70-84  | `NOISY`         | 有可疑痕迹，但不一定是 VPN                        |
| 50-69  | `SUSPICIOUS`    | 多个红旗                                          |
| < 50   | `OBVIOUSLY VPN` | 明显可检测——需要混淆/更换协议栈                    |

### TSPU 模拟

| 等级 | 裁决             | 含义                                                   |
|------|------------------|--------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| 命中已知协议签名——SYN/握手被丢弃                       |
| B≥2  | `BLOCK` (累计)   | ≥2 条软异常——分类器触发阻断阈值                        |
| B=1  | `THROTTLE / QoS` | 1 条软异常——标记监控/限速                              |
| 0    | `PASS / ALLOW`   | 无签名                                                 |

### 线缆上的行为

工具**不会**伪装成浏览器。每个向外发出的 HTTP 请求（到 IP-intel
服务、在 HTTP-over-TLS 审计中到目标、到 crt.sh）都**不带**任何
工具特定的头。

对于 `http_get()`（用于 IP-intel 和 crt.sh），请求逐字节如下：

```
GET /path HTTP/1.1
Host: <host>
```

**不**发送 `User-Agent`、`Accept`、`Accept-Language`、
`Accept-Encoding`、`Sec-Fetch-*`、`Upgrade-Insecure-Requests`。
这些端点接受裸 GET——就像 `curl -sS https://ipwho.is/8.8.8.8`
不带任何 flag 就能工作一样。若服务器自己选择 gzip，WinHTTP
仍会透明解压，但我们不宣传支持。

对于 `https_probe()`（目标 HTTP-over-TLS 审计），头也是最小集
（`Host`、`Accept: */*`、`Connection: close`）。

先前版本（v2.5 - v2.5.4）发送 Chrome-131 头块，试图「看起来像
浏览器」。这本身就是一个**唯一的静态指纹**，已被移除（见
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)）。

协议探测（UDP 握手、TLS ClientHello、ICMP）中，任何真实客户端会
随机化的字段都通过 OpenSSL `RAND_bytes` 填充：OpenVPN session-id
+ 时间戳偏移、WG 临时密钥、QUIC / Hysteria2 DCID、TLS
ClientRandom、invalid-SNI 前缀、DNS 事务 ID、L2TP tunnel-id。

ICMP traceroute 载荷是标准 Windows `ping.exe` 字符串
（`abcdefghi...`，32 字节）——与任何 Windows 主机发送的字节完全相同。

### 审计

grep 源码查找工具标识字符串。预期只有三个非网络匹配：

```
$ grep -nE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' src/byebyevpn.cpp
1:     // ByeByeVPN - full VPN / proxy / Reality detectability analyzer
...    // http_get 中关于 scrub 的注释
...    // --help 的 printf
```

没有任何一条会到达套接字。CI 工作流
(`.github/workflows/release.yml`) 会在出现任何额外匹配时使构建失败。

### 安装

Windows：从 [Releases](../../releases) 下载
`byebyevpn-v2.5.5-win64.zip`，解压，运行 `byebyevpn.exe`（双击
=交互菜单，或从终端传入 IP/主机名）。

运行要求：Windows 10 1803+ / 11 / Server 2019+。无需管理员，
无 DLL，无 .NET，无 VC++ Redistributable。需要互联网（GeoIP、CT-log）。

Linux / macOS：通过 Wine 运行。除 `local`（主机适配器枚举）外，
所有功能行为完全一致。

### 命令行

```bash
byebyevpn                        # 交互菜单
byebyevpn <host>                 # 完整扫描
byebyevpn scan 1.2.3.4           # 同上，显式
byebyevpn ports my.server.ru     # 仅 TCP
byebyevpn udp my.server.ru       # 仅 UDP
byebyevpn tls my.server.ru 443   # TLS + SNI 一致性
byebyevpn j3 my.server.ru 443    # J3 主动探测
byebyevpn geoip 8.8.8.8          # GeoIP
byebyevpn snitch my.server.ru    # RTT vs geo (§10.1)
byebyevpn trace my.server.ru     # ICMP 跳数
byebyevpn local                  # 扫描本机
```

主机名通过 `getaddrinfo` 解析；**总是**优先选择 IPv4，
所选 IP 在阶段 [1/8] 中打印。在纯 IPv4 链路上（俄罗斯 / 独联体
家用网络），这避免了 happy-eyeballs AAAA 陷阱——不可达的 v6
会静默耗尽每个超时。

### 端口扫描模式

```
--full                    所有端口 1-65535（默认）
--fast                    205 个精选 VPN / 代理 / TLS / 管理端口
--range 8000-9000 ports   端口范围
--ports 80,443,8443       明确列表
```

### 调优

```
--threads N       并行 TCP 连接数  (默认 500)
--tcp-to MS       TCP 连接超时     (默认 800)
--udp-to MS       UDP 接收超时     (默认 900)
--no-color        禁用 ANSI 颜色
-v / --verbose    详细输出
```

### 隐身 / 隐私

```
--stealth         同时启用 --no-geoip + --no-ct + --udp-jitter
--no-geoip        跳过所有 9 个 IP-intel 查找
--no-ct           跳过 crt.sh CT-log 查询
--udp-jitter      UDP 探测之间 50-300ms 随机延迟
```

全部默认关闭。扫描自己的 VPS 且不希望第三方服务记录该事件时启用。

### 构建

详见 [BUILD.md](BUILD.md) 完整说明、OpenSSL 溯源、SHA256。简要：

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

发布 zip 由
[`.github/workflows/release.yml`](.github/workflows/release.yml)
在 pinned msys2 镜像中生成。每次发布的 release notes 都会打印
exe 和 zip 的 SHA256 供验证。

### 限制

- Connect 扫描，非 SYN 扫描。目标会看到完整的 TCP 握手。
- Cloudflare WARP / CGNAT / 企业代理可能以相同 RTT ACK 每个端口。
  工具会检测此情况（>60 个端口 RTT 方差 <80ms）并警告。
- TLS JA3 是 OpenSSL 默认值，非 uTLS-Chrome。严格 uTLS 强制
  模式的 Reality 服务器会拒绝握手。输出中标注为 advisory。
- QUIC 探测仅进行版本协商——无派生密钥握手。足以验证端口可用性，
  不足以识别具体 QUIC 协议栈。
- GeoIP 提供商意见不一致；`ipapi.is` 将任何托管 IP 标记为 VPN。
  分数基于行为，不是基于单一来源标签。

### 许可证

MIT。见 [LICENSE](LICENSE)。
