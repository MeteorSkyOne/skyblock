# skyblock

自用的游戏加速器。Windows 客户端把游戏流量装进加密的 UDP 隧道，送到你自己的 Linux 节点（VPS），节点再转发给游戏服务器：

```
Windows 游戏机 ──(家宽)──> 节点（Linux VPS）──> 游戏服务器
```

- 游戏包默认发 2 份，分走 2 个 UDP 端口，丢一份不影响；丢包多时自动加到 3 份，还丢就按 NACK 立刻补发。
- 只接管游戏进程的流量（WinDivert 模式），其他程序照常直连；也可以用虚拟网卡（Wintun 模式）。
- TCP、UDP、ICMP 都能走；节点的 UDP 是 Full Cone NAT，P2P 游戏里 NAT 类型为开放。
- 节点对没通过认证的包一律不回应。

## 依赖

节点和客户端要用同一版代码构建，协议变了就一起升级（例如 M3 和 M4 不能互通）。

### 节点

x86_64 Linux VPS，root 权限，云厂商的安全组里能放行 UDP 端口。要 KVM 这类有独立内核的虚拟机：OpenVZ、LXC 容器通常没有 `/dev/net/tun`，也不让改 nftables。

`skyblock-server` 是静态链接的，不需要额外的库，但运行时要调用这几个系统命令：

| 依赖 | 包名（Debian / Ubuntu） | 包名（CentOS / Rocky / Alma） | 用途 |
|---|---|---|---|
| `nft` | `nftables` | `nftables` | 每次启动装转发和 NAT 规则 |
| `ip` | `iproute2` | `iproute` | 配置 TUN 网卡；`init` 靠它检测出口网卡 |
| `sysctl` | `procps` | `procps-ng` | 打开 `ip_forward` |
| `/dev/net/tun` | （内核自带） | （内核自带） | 节点的 TUN 网卡 |
| systemd | （系统自带） | （系统自带） | `init` 装服务；没有 systemd 时 `init` 只写配置，自己用 `skyblock-server run` 跑 |

精简的云镜像常常不带 `nftables`（例如 Debian 11），先装上：

```sh
apt install -y nftables iproute2 procps          # Debian / Ubuntu
dnf install -y nftables iproute procps-ng        # CentOS / Rocky / Alma

nft --version && ip -V && ls -l /dev/net/tun     # 三样都在就行
```

缺了哪个，节点都会启动失败、被 systemd 反复重启：

- 缺命令时，日志（`journalctl -u skyblock-server`）里是 `<命令>: No such file or directory`；缺 `nft` 时前面还有一行 `installing nftables rules (is nftables installed?)`。
- 没有 `/dev/net/tun` 时是 `creating TUN device`。

### 客户端

- Windows 10/11 x64，管理员权限。
- WinDivert 模式（默认）：[WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) 发布包里 `x64` 目录下的 `WinDivert.dll` 和 `WinDivert64.sys`。
- Wintun 模式：[Wintun 0.14](https://www.wintun.net) 发布包里 `bin/amd64` 目录下的 `wintun.dll`。
- 以上文件都放在 `skyblock.exe` 旁边，运行时加载。
- `skyblock games --ranges` 要用 `curl`，Windows 10 1803 起自带。

### 构建

- Rust 1.85 以上。
- 节点在 Linux 或 WSL 里构建：要 `x86_64-unknown-linux-musl` target 和系统的 `cc`（gcc 或 clang，当链接器用）。项目没有 C 依赖，不需要 musl-gcc。

## 构建

客户端，在 Windows 上：

```powershell
cargo build --release -p skyblock
# 产物：target\release\skyblock.exe
```

把 `WinDivert.dll`、`WinDivert64.sys`（以及要用 Wintun 模式时的 `wintun.dll`）放到 `skyblock.exe` 旁边。

节点，在 Linux 或 WSL 里构建一个静态二进制，哪台 VPS 都能直接跑：

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release -p skyblock-server --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/skyblock-server
```

## 第一步：客户端生成密钥

```powershell
.\skyblock.exe keygen
```

输出两行：`private_key = "..."` 是私钥，留在自己的配置里；`# public_key = "..."` 是公钥，下一步交给节点。每台电脑用一把密钥：两台电脑用同一把，连同一个节点时会互相顶掉。

## 第二步：部署节点

以 root 在 VPS 上操作：

```sh
# 先装依赖（见上文"依赖 → 节点"）
apt install -y nftables iproute2 procps

# 把二进制放到固定位置：init 会把这个路径写进 systemd 单元
install -m 755 skyblock-server /usr/local/bin/

# 生成 /etc/skyblock/server.toml（含节点密钥）和 systemd 单元
skyblock-server init                       # 默认监听 UDP 40001、40002；--ports 可改

# 添加用户：名字随意，公钥是第一步打印的那个
skyblock-server adduser me <客户端公钥>

systemctl daemon-reload
systemctl enable --now skyblock-server
skyblock-server status                     # 看会话、路径、NAT 映射和各项计数
```

`adduser` 会打印一段 `[[node]]` 配置，原样贴进客户端配置。注意：

- 片段里的 `addr` 取自节点网卡的地址。有些云主机网卡上只有内网地址，这时要改成公网 IP。
- 云厂商的安全组（以及 ufw、firewalld 之类）要放行 `ports` 里的 UDP 端口。
- 节点在运行时 `adduser`，要 `systemctl restart skyblock-server` 才生效。
- 日志用 `journalctl -u skyblock-server` 看。
- 节点对游戏的 TCP 和 ICMP 走内核转发，`run` 每次启动时会自己打开 `ip_forward`、装 nftables 规则。如果开了 ufw，它默认禁止转发，还要放行（例如 `ufw route allow in on sb0 out on eth0`；这种环境没实测过）。
- 装了 `nftables` 包，但它的系统服务（`nftables.service`）不用启用。启用了也行，不过重启它会清空所有规则，因为 Debian 默认的 `/etc/nftables.conf` 开头就是 `flush ruleset`。节点的规则被清掉后，要再 `systemctl restart skyblock-server`。

多台节点就在每台上各做一遍，把每段 `[[node]]` 都贴进客户端配置。

节点配置（`/etc/skyblock/server.toml`）一般不用改，改了要重启服务。可选项见 `init` 生成的文件里的注释，常用的有：

| 键 | 说明 |
|---|---|
| `ports` | 监听的 UDP 端口 |
| `egress` / `egress_ip` | 出口网卡和地址，`init` 会自动检测 |
| `dns_upstream` | 节点替客户端解析 DNS 时用的上游，例如 `["1.1.1.1"]`；空则用 `/etc/resolv.conf` |
| `subnet` | 分给用户的内部地址段，默认 `10.77.0.0/16` |
| `cpu` / `busy_poll` | 把节点绑在某个核上；`busy_poll = true` 让它不睡眠（占满一个核，唤醒延迟更低） |

## 第三步：客户端配置

把 [examples/skyblock.toml](examples/skyblock.toml) 复制成 `skyblock.toml`，放在 `skyblock.exe` 旁边（程序默认读**当前目录**下的 `skyblock.toml`，在别处运行时用 `-c 路径` 指定）。最少要填这些：

```toml
private_key = "<第一步的私钥>"

# adduser 打印的片段
[[node]]
name = "tokyo-1"
addr = "203.0.113.10"
ports = [40001, 40002]
public_key = "<节点公钥>"

# 要加速的游戏
[[game]]
name = "valorant"
```

`skyblock games` 列出内置的游戏模板（Valorant、LoL、CS2、Dota 2、守望先锋、Apex、PUBG、堡垒之夜、彩虹六号、塔科夫、THE FINALS、永劫无间、Rust）。`[[game]]` 的 `name` 和模板同名时，进程名和域名自动带上。不在模板里的游戏自己写：

```toml
[[game]]
name = "mygame"
process = ["MyGame-Win64-Shipping.exe"]   # 任务管理器"详细信息"页里的名字
domains = ["mygame.com"]                  # 可选：这些域名（含子域名）经节点解析
```

配置里写错键名会直接报错，不会被悄悄忽略。

## 第四步：使用

以**管理员**身份打开终端，进入 `skyblock.exe` 所在目录。

**选节点**（有多个节点时）：在 `up` 之前运行，让每个节点测一下到游戏服的延迟，按"你到节点 + 节点到游戏服"的总延迟排序：

```powershell
.\skyblock.exe ping --target <游戏服 IP>
.\skyblock.exe ping --target <游戏服 IP> --probe tcp:443   # 游戏服不回 ping 时改用 TCP 探测
```

游戏服 IP 可以在对局中打开资源监视器（`resmon`）→"网络"，看游戏进程连接的远程地址。`ping` 和 `bench` 会顶掉同一把密钥在该节点上正在运行的 `up`，所以先测再开。

**开始加速**：

```powershell
.\skyblock.exe up                              # 只有一个节点、加速配置里所有游戏
.\skyblock.exe up --node tokyo-1 --game valorant
```

- 要在**进游戏之前**开。已经连上的连接中途改走隧道，源 IP 会变，游戏服会断开你。
- 对局中不要换节点，理由同上。
- 按 Ctrl+C 退出，隧道和路由都会清理掉。

`up` 每秒打印一行状态：

```
[tokyo-1] up | rtt 42.1ms ±0.3 | loss up 0.8%/0.00% down 0.5%/0.00% rescued 3/2 | up 128pps 0.2Mbps down 128pps 0.3Mbps | paths 2/2 [42.1 43.0] | copies 2/3 | flows 3 bulk 1
```

| 字段 | 含义 |
|---|---|
| `rtt` | 到节点的往返延迟（最好的那条路径） |
| `loss up a/b` | a：线路上原始丢包率；b：冗余补救后实际丢掉的比例。`down` 同理，是节点到你的方向 |
| `rescued` | 靠副本或重传救回的包数（上行/下行） |
| `paths 2/2 [...]` | 可用路径数 / 总数，以及每条路径的延迟 |
| `copies 2/3` | 当前每个游戏包发几份（上行/下行），丢包多时自动变多 |
| `flows` / `bulk` | 正在走隧道的连接数，其中被识别为下载的有几个（下载只发一份） |

## 两种抓包模式

**WinDivert 模式**（默认）：按进程名接管，只有配置里的游戏进程走隧道。DNS 按域名处理：查询游戏 `domains` 的走节点解析，其他照常（`[dns] mode = "rules"`；`all` 全部走节点，`off` 不管 DNS）。

**Wintun 模式**：建一块名为 `skyblock` 的虚拟网卡，按路由决定什么走隧道，不认进程。适合 WinDivert 用不了的情况。

```toml
mode = "tun"            # 或者命令行 --mode tun

[tun]
global = false          # true：所有 IPv4 流量都走隧道，DNS 也走节点
routes = []             # 额外要走隧道的网段

[[game]]
name = "valorant"
ip_ranges = [...]       # 游戏服网段，见下
```

- 规则模式（`global = false`）要有网段。有自己网络的游戏可以现查：`skyblock games --ranges valorant` 从 RIPEstat 查该游戏 ASN 当前宣告的网段，打印成可以直接粘贴的 `ip_ranges = [...]`。游戏服放在公有云上的查不到，只能用 WinDivert 模式或全局模式。
- IPv6 不走隧道。
- 全局模式开启前已经建立的连接要重连。
- 节点地址会自动加一条走原网关的路由，局域网不受影响。程序被强制结束后留下的路由，下次启动时会清掉。

## 调参

`[tunnel]` 里的选项（默认值就是实测下来的推荐值）：

| 键 | 默认 | 说明 |
|---|---|---|
| `copies` | 2 | 每个游戏包发几份，两个方向都是；1 = 不冗余 |
| `copies_max` | 3 | 丢包时自动加到的上限；设成和 `copies` 一样就是固定份数 |
| `copy_delay_ms` | 2.0 | 副本之间隔多久，防止一次短暂断流把几份一起丢掉 |
| `paths` | 2 | 开几个 UDP socket（分别用节点的各个端口），副本分散到不同路径上 |
| `nack` | true | 发现缺包就请对方立刻重发 |
| `piggyback` | 0 | 每个包顺带捎上最近几个游戏包（0–8）；对付几十毫秒的断流，代价是流量变大 |
| `bulk_rate_mbps` | 0 | 节点给下载限速（Mbps），让边下载边玩时游戏包不用排在下载后面；0 = 关 |

**找适合自己线路的参数**：在晚高峰跑一次 `bench`，比较不同组合的丢包和延迟（每组测 60s，会顶掉正在运行的 `up`）：

```powershell
.\skyblock.exe bench --duration 60s --copies 1,2,3 --paths 1,2 --delay-ms 0,2,4
```

副本数上去后单条路径的丢包反而变多，说明多倍发包触发了运营商限速，这时要少发几份。

**边下载边玩**：`bulk_rate_mbps` 要设得比你的下载速度低不少才有效果。作者的线路上限到实测下载速度的约 55%，边下载边玩时游戏延迟的 p99 只多 2ms（不限速时多 10ms），代价是下载速度减半，所以默认关闭，按需自己取舍。

**系统设置**（程序不会替你改）：电源计划选"高性能"，关掉网卡的节能选项，能插网线就别用 Wi-Fi。

## 常见问题

**`WinDivertOpen ... error 1450`**：驱动被安全软件拦了。火绒会把 WinDivert 当作"可被滥用的驱动"拦下：到"系统防护 → 漏洞驱动拦截 → 例外驱动"里添加 `WinDivert64.sys`。加到"信任区"没用，信任区只管病毒扫描。其他安全软件找类似的驱动拦截设置；实在不行就用 Wintun 模式。

**`access denied`、`creating the Wintun adapter`**：没用管理员身份运行。

**`cannot load wintun.dll`**：`wintun.dll` 没放在 `skyblock.exe` 旁边。

**节点上 `skyblock-server status` 报 `connecting to /run/skyblock-server.sock ... No such file or directory`**：节点没在运行，多半是启动失败、正被 systemd 反复重启。用 `journalctl -u skyblock-server -n 20` 看原因，最常见的是缺依赖，见上文"依赖 → 节点"。装好后执行 `systemctl restart skyblock-server`。

**一直显示 `connecting`**：节点对认证不过的包不回应，所以连不上时没有报错，逐项检查：

- 节点在运行吗？在节点上执行 `skyblock-server status`。
- 客户端公钥 `adduser` 过吗？加完后节点重启过吗？
- 客户端配置里的 `addr` 是公网 IP 吗？`public_key` 是节点的公钥（不是你自己的）吗？
- 安全组和防火墙放行了 UDP 端口吗？
- 电脑时钟往回调过吗？节点要求同一用户的握手时间戳一直递增，时钟往回跳后要重启节点。

**开了加速后游戏掉线**：在对局中途开的。先开 `up`，再进游戏。

**进程没被接管**：`process` 要和任务管理器"详细信息"页里的名字一致。用 `--log-level debug` 运行 `up`，每 10s 会输出接管情况的计数。

## 开发

```sh
cargo test                   # 单元测试
cargo clippy --all-targets
cargo +nightly fuzz run frames   # Linux 上；目标还有 packet、handshake、inner
```

集成测试床用 Linux 网络命名空间和 `tc netem` 模拟丢包、抖动、断流，WSL2 里也能跑，见 [tools/testbed/README.md](tools/testbed/README.md)。
