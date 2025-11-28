# TL-Rustscan - 高性能异步端口扫描工具

> **此工具由天禄实验室开发**

`TL-Rustscan` 是一款基于 Rust 编写的高性能、高并发端口扫描命令行工具。专为攻防演练、资产摸排和渗透测试设计，旨在提供快速、稳定且易于集成的端口探测能力。

## 安全与合规警告

**严禁未授权扫描！**

本工具仅允许在**取得明确授权**的前提下，用于内部资产管理、安全自查、攻防演练等合法场景。
*   禁止对互联网上非授权目标进行扫描。
*   使用者需自行承担因违规使用本工具而产生的一切法律责任。

---

## 核心特性

*   **极速扫描**: 基于 Tokio 异步运行时，支持数千并发连接，秒级完成常见端口探测。
*   **实时反馈**: 发现开放端口立即输出，无需等待扫描结束。
*   **全端口覆盖**: 默认扫描 1-65535 全端口，不放过任何隐蔽服务。
*   **红队模式**: 提供 `--rscan` 参数，集成弱口令爆破（SSH, SMB, RDP 等）与高危漏洞检测（MS17-010, WebLogic 等），实现一键式内网打点。
*   **智能协议识别**: 支持 RTSP, SOCKS5, MQTT, AMQP 等协议的主动探测，在无 Banner 时自动识别。
*   **上下文感知爆破**: Web 目录扫描会根据识别到的指纹（如 Spring, PHP）自动加载特定敏感路径。
*   **TLS 深度解析**: 自动提取 HTTPS 证书中的 SANs (多域名) 信息，辅助发现隐藏资产。
*   **多目标支持**: 完美支持单 IP、域名、CIDR 网段（如 `192.168.1.0/24`）及文件导入。
*   **结构化输出**: 支持标准 JSON 输出，方便对接资产管理平台或后续自动化脚本。
*   **IPv6 Ready**: 完美支持 IPv6 环境下的扫描与插件探测，自动处理地址格式兼容性。
*   **跨平台**: 单一可执行文件，无依赖运行于 Windows, Linux, macOS。

## 精准度保障机制

作为一款安全工具，我们深知“误报”和“漏报”是最大的痛点。TL-Rustscan 在设计之初就将**精准度**作为核心指标，通过以下底层机制保障扫描结果的可靠性：

1.  **智能碎片重组 (Smart Fragmentation Reassembly)**:
    *   针对 SSH, MySQL 等协议，自动处理 TCP 数据包分片问题。
    *   引入动态缓冲区与超时窗口，确保在网络抖动或高延迟环境下也能完整读取 Banner，避免因数据截断导致的识别失败。

2.  **无连接 UDP 探测 (Connectionless UDP)**:
    *   摒弃传统的 `connect()` 调用，采用 `send_to/recv_from` 原生套接字模型。
    *   能够捕获中间网关返回的 ICMP (Port Unreachable) 消息，精准区分 `Closed` (有响应) 和 `Filtered` (无响应/被拦截) 状态，解决多宿主环境下的漏报问题。

3.  **Web 目录 Soft 404 动态基线**:
    *   在扫描前自动探测目标的 404 响应特征（状态码、页面长度、重定向行为）。
    *   支持 **Chunked Encoding** 流式读取，即使服务器不返回 `Content-Length` 也能通过计算实际包体大小来精准过滤伪造的 200 OK 页面。

4.  **Windows 异步 IO 优化**:
    *   针对 Windows 操作系统内核的 Socket 限制，实现了基于 `Blocking Task` 的连接池模型。
    *   彻底解决了在 Windows 下高并发扫描导致的 `OS Error 10055` (缓冲区空间不足) 和连接假死问题。

## 获取与安装

### 方式一：直接使用（如果你已有编译好的文件）
直接运行 `dist/TL-Rustscan.exe` 即可。

### 方式二：源码编译
如果你只有源代码，请确保已安装 [Rust 环境](https://rustup.rs/)，然后运行：

**Windows:**
双击运行项目根目录下的 `build.bat`。

**Linux/macOS:**
```bash
cargo build --release
```
编译产物位于 `target/release/TL-Rustscan`。

---

## 使用指南

### 1. 基础扫描（最常用）
只输入目标 IP 或域名，默认扫描 **1-65535** 所有端口，并实时显示结果。

```powershell
TL-Rustscan 192.168.1.10
TL-Rustscan example.com
```

### 2. 指定端口范围
如果你只想扫描特定端口，可以使用 `-p` 参数。

*   **单端口**: `-p 80`
*   **多端口**: `-p 22,80,443`
*   **端口范围**: `-p 1-1000`
*   **混合使用**: `-p 80,8000-8100,3389`

```powershell
TL-Rustscan 192.168.1.10 -p 22,80,443,3389
```

### 3. 扫描网段 (CIDR)
支持自动解析 CIDR 格式，批量扫描网段内的主机。

```powershell
# 扫描整个 C 段的 Web 端口
TL-Rustscan 192.168.1.0/24 -p 80,443
```

### 4. 从文件导入目标
当目标较多时，可以将目标写入文本文件（每行一个 IP、域名或网段），使用 `-L` 加载。

**targets.txt 内容示例:**
```text
192.168.1.10
10.0.0.0/24
db-server.local
```

**命令:**
```powershell
TL-Rustscan -L targets.txt -p 1-1000
```

### 5. JSON 输出 (自动化集成)
使用 `--json` 参数将结果以 JSON 格式输出，适合程序解析。

```powershell
TL-Rustscan 192.168.1.10 -p 80 --json
```
或者直接保存到文件：
```powershell
TL-Rustscan 192.168.1.10 -o result.json
```

### 6. 性能调优
*   **并发数 (`-C`)**: 默认为 200。网络状况好时可调高至 1000-2000 以加快速度。
*   **超时时间 (`-t`)**: 默认为 500ms。内网环境可调低（如 200ms），公网或高延迟环境建议调高（如 1000ms）。
*   **跳过复查 (`-x`)**: 默认情况下，工具会对超时端口进行智能复查以防止漏报。如果你追求极致速度，可以使用 `-x` 关闭此功能。

```powershell
# 高并发极速扫描 (关闭复查)
TL-Rustscan 10.0.0.0/16 -p 80 -C 2000 -t 200 -x
```

### 7. 服务指纹与 Web 标题识别
使用 `-b` 或 `--banner` 参数，工具会：
1.  尝试读取服务欢迎语（如 SSH, FTP, MySQL, PostgreSQL, RDP）。
2.  如果是 Web 服务，会自动发送请求并提取 **网页标题 (Title)** 以及 **Web 框架指纹** (如 Spring Boot, Laravel, Vue 等)。

```powershell
TL-Rustscan 192.168.1.10 -p 80,8080,22,3306 -b
```

输出示例：
```text
192.168.1.10:80 is open (Title: 某某公司OA系统 | Frameworks: Spring Boot)
192.168.1.10:22 is open (SSH-2.0-OpenSSH_8.2p1)
192.168.1.10:3306 is open (MySQL 5.7.33-log)
```

### 8. 生成 Markdown 报告
使用 `--output-markdown <FILE>` 参数，可以将扫描结果保存为美观的 Markdown 格式，方便直接复制到笔记或报告中。

```powershell
TL-Rustscan 192.168.1.0/24 -p 80,443 -b --output-markdown report.md
```

### 9. UDP 扫描
使用 `--udp` 参数开启 UDP 扫描模式。
注意：UDP 扫描速度较慢且不可靠，建议只针对特定端口（如 DNS 53, NTP 123, SNMP 161）使用。

```powershell
TL-Rustscan 192.168.1.1 -p 53,123,161 --udp
```

### 10. 主机存活检测 (Host Discovery)
使用 `--check` 参数，在扫描端口前先对目标进行存活检测（Ping/Connect）。
这对于扫描大网段非常有用，可以自动跳过不在线的主机，大幅节省时间。

```powershell
# 扫描整个 B 段，但只扫描在线的主机
TL-Rustscan 10.0.0.0/16 -p 80 --check
```

### 11. Web 目录爆破
使用 `--dir` 参数开启 Web 目录爆破功能。
当扫描到 Web 端口 (80, 443, 8080 等) 时，会自动尝试探测常见路径（内置 300,000+ 条高价值字典，涵盖 `/admin`, `/login`, `/backup` 及各类备份文件）。

```powershell
TL-Rustscan 192.168.1.10 -p 80,8080 --dir
```

你也可以使用 `--paths` 指定自定义字典文件：
```powershell
TL-Rustscan 192.168.1.10 -p 80 --dir --paths my_dict.txt
```

如果你想在非标准端口（如 12345）上启用目录爆破，可以使用 `--dir-ports`：
```powershell
TL-Rustscan 192.168.1.10 -p 12345 --dir --dir-ports 12345
```

### 12. 深度扫描 (Deep Scan)
使用 `--deep` 参数开启深度扫描模式。
在此模式下，如果扫描器识别出特定的前端框架（如 Vue.js, RuoYi），会尝试主动探测后端 API 接口以获取更详细的系统信息（如系统标题）。
**注意**：此模式会发送额外的 HTTP 请求，可能会增加被防火墙拦截的风险。

```powershell
TL-Rustscan 192.168.1.10 -p 80 -b --deep
```

### 13. 红队模式 / 内网渗透 (Red Team Mode)
使用 `--rscan` (或 `-r`) 参数开启红队全功能模式。此模式专为内网渗透设计，集成了类似 `fscan` 的强力功能。
开启此模式后，工具将在端口扫描和服务识别的基础上，自动执行：
1.  **弱口令爆破**: 对 SSH, SMB, FTP, MySQL, MSSQL, Postgres, Redis, MongoDB, Telnet 等服务进行弱口令尝试。
2.  **高危漏洞扫描**: 检测 MS17-010 (永恒之蓝), SMBGhost, WebLogic, SpringBoot, Docker Registry, PHPMyAdmin 等高危漏洞。
3.  **敏感信息泄露**: 检测 NetBIOS 主机名, SNMP 团体名, Oracle TNS 等信息。

**注意**: 此模式具有攻击性，请务必在授权范围内使用！

```powershell
# 开启红队模式，扫描 C 段
TL-Rustscan 192.168.1.0/24 -r

# 开启红队模式，但不进行暴力破解 (只扫漏洞)
TL-Rustscan 192.168.1.10 -r --no-brute

# 开启红队模式，但不进行漏洞验证 (只爆破)
TL-Rustscan 192.168.1.10 -r --no-poc
```

### 14. 支持的协议与漏洞列表
目前 `TL-Rustscan` 在红队模式下支持以下协议和漏洞的深度检测：

**弱口令爆破 (Brute-force):**
*   **SSH**: 22 端口
*   **SMB**: 445 端口
*   **FTP**: 21 端口
*   **Telnet**: 23 端口
*   **MySQL**: 3306 端口
*   **MSSQL**: 1433 端口
*   **PostgreSQL**: 5432 端口
*   **Redis**: 6379 端口
*   **MongoDB**: 27017 端口
*   **Tomcat**: 8080 端口 (Web 管理后台)

**漏洞与POC (Vulnerabilities):**
*   **Windows**: MS17-010 (永恒之蓝)
*   **WebLogic**: CVE-2017-10271, CVE-2019-2725, Console 弱口令
*   **SpringBoot**: Actuator 未授权访问
*   **Nacos**: 未授权访问
*   **Docker Registry**: 未授权访问
*   **PHPMyAdmin**: 弱口令/未授权
*   **Hikvision**: 海康威视摄像头弱口令/漏洞
*   **Prometheus**: 未授权访问
*   **CouchDB**: 未授权访问
*   **JDWP**: Java 远程调试漏洞
*   **FCGI**: FastCGI 未授权访问
*   **VNC**: 5900 端口未授权/弱口令
*   **LDAP**: 389 端口匿名访问
*   **Zookeeper**: 未授权访问
*   **Elasticsearch**: 未授权访问

**基础指纹识别 (原有功能):**
**基础服务:**
*   **SSH** (Port 22): 识别版本号 (e.g., OpenSSH 8.2p1)
*   **MySQL** (Port 3306): 识别版本号 (e.g., MySQL 5.7.33)
*   **PostgreSQL** (Port 5432): 识别服务存在
*   **MSSQL** (Port 1433): 识别 Microsoft SQL Server
*   **Oracle** (Port 1521): 识别 Oracle TNS Listener
*   **MongoDB** (Port 27017): 识别 MongoDB 版本
*   **Redis** (Port 6379): 识别 Redis 及是否需要认证
*   **Memcached** (Port 11211): 识别 Memcached 服务
*   **ElasticSearch** (Port 9200): 识别集群名和版本号
*   **SMB** (Port 445): 识别 Windows SMB 服务版本

**远程管理:**
*   **RDP** (Port 3389): 识别 Microsoft RDP 服务
*   **VNC** (Port 5900): 识别 RFB 协议版本
*   **Telnet** (Port 23): 识别 Telnet 服务

**Web 技术指纹 (16000+):**
TL-Rustscan 集成了 Wappalyzer, Nuclei 和 Recog 的指纹库，支持识别超过 16000 种 Web 技术，涵盖：
*   **Web 框架**: Spring Boot, Laravel, Django, Flask, ThinkPHP, ASP.NET, Ruby on Rails, Gin, Beego 等。
*   **前端技术**: Vue.js, React, Angular, jQuery, Bootstrap, Webpack 等。
*   **CMS & OA**: WordPress, Drupal, Joomla, Discuz!, 泛微 OA, 致远 OA, 用友 NC, 通达 OA, 蓝凌 OA 等。
*   **Favicon 识别**: 支持计算并匹配网站图标 Hash (Murmur3)，精准识别特定应用 (如 Seeyon OA)。
*   **智能净化**: 自动过滤通用噪音指纹 (如 "Nginx", "Wappalyzer")，只展示高价值结果。
*   **中间件**: Tomcat, Nginx, Apache, IIS, Jetty, WebLogic, WebSphere, JBoss 等。
*   **安全设备**: 识别 100+ 种 WAF (Cloudflare, AWS WAF, 阿里云 WAF, 长亭雷池等) 及防火墙设备。
*   **DevOps**: Kubernetes, Docker, Jenkins, Grafana, Prometheus, GitLab 等。
*   **其他**: 各种数据库管理后台、VPN 入口、虚拟化平台等。

**深度探测 (主动识别):**
*   **RuoYi / Vue Admin**: 配合 `--deep` 参数，主动探测后端 API 获取系统标题。

---

### 15. 指纹库管理与规避
TL-Rustscan 内置了丰富的指纹库，同时也支持用户自定义和规避检测。

*   **随机 User-Agent**: 使用 `--random-ua` 参数，工具会在发送 HTTP 请求时随机选择 User-Agent，以规避基于 UA 的特征检测。
*   **自动加载**: 如果当前运行目录下存在 `fingerprints.json` 文件，工具会自动加载它并替代内置指纹库。
*   **手动指定**: 使用 `--fingerprints <FILE>` 参数可以指定任意路径的指纹文件。
*   **导出内置**: 使用 `--dump-json` 参数可以将内置的指纹库导出到当前目录下的 `fingerprints.json` 文件中，方便您在此基础上进行修改和扩充。
*   **合并导入**: 使用 `scripts/import_fingerprints.py` 脚本可以将外部指纹数据（如 Ehole/Finger 格式）合并到内置指纹库中。

```powershell
# 使用随机 UA 进行扫描
TL-Rustscan 192.168.1.10 -p 80 -b --random-ua

# 导出内置指纹库
TL-Rustscan --dump-json
```

---

## 参数列表

| 参数 | 简写 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `TARGET` | - | 目标 IP、域名或 CIDR | - |
| `--target-list` | `-L` | 从文件读取目标列表 | - |
| `--ports` | `-p` | 扫描端口范围 | `1-65535` |
| `--concurrency` | `-C` | 最大并发连接数 | `200` |
| `--timeout` | `-t` | 连接超时时间 (毫秒) | `500` |
| `--banner` | `-b` | 开启服务指纹识别 | `false` |
| `--rscan` | `-r` | 开启红队模式 (爆破+漏洞) | `false` |
| `--no-brute` | - | 红队模式下禁用爆破 | `false` |
| `--no-poc` | - | 红队模式下禁用漏洞验证 | `false` |
| `--deep` | - | 开启深度扫描 (API 探测) | `false` |
| `--udp` | - | 使用 UDP 扫描模式 | `false` |
| `--check` | - | 扫描前进行主机存活检测 | `false` |
| `--dir` | - | 开启 Web 目录爆破 | `false` |
| `--paths` | - | 指定目录爆破字典文件 | 内置字典 |
| `--dir-ports` | - | 指定进行 Web 探测的端口 | `80,443...` |
| `--random-ua` | - | 使用随机 User-Agent | `false` |
| `--fingerprints` | - | 指定外部指纹库文件 (JSON) | - |
| `--dump-json` | - | 导出内置指纹库到文件 | `false` |
| `--json` | - | 输出 JSON 格式结果 | `false` |
| `--output-json` | `-o` | 将 JSON 结果保存到文件 | - |
| `--output-markdown` | - | 将结果输出为 Markdown 文件 | - |
| `--output-csv` | - | 将结果输出为 CSV 文件 | - |
| `--output-html` | - | 将结果输出为 HTML 文件 | - |
| `--show-closed` | - | 显示关闭/过滤的端口 | `false` |
| `--retry` | - | 失败重试次数 | `1` |
| `--rate` | - | 扫描速率限制 (请求/秒) | `0` (无限制) |
| `--random` | - | 随机化目标和端口顺序 | `false` |
| `--exclude-hosts` | - | 排除特定主机 | - |
| `--exclude-ports` | - | 排除特定端口 | - |
| `--help` | `-h` | 显示帮助信息 | - |

## 项目结构

```text
TL-Rustscan/
├── src/                    # Rust 源代码目录
│   ├── scanner/            # 核心扫描模块
│   │   ├── tcp_connect.rs  # TCP 端口扫描实现
│   │   ├── udp_scan.rs     # UDP 端口扫描实现
│   │   ├── probes.rs       # 服务指纹探测与识别
│   │   ├── web_dir.rs      # Web 目录爆破
│   │   └── ...
│   ├── config.rs           # 命令行参数解析与配置管理
│   ├── main.rs             # 程序入口
│   ├── output.rs           # 多格式结果输出 (JSON, CSV, HTML 等)
│   └── target.rs           # 目标解析逻辑 (CIDR, 域名, IP范围)
├── scripts/                # 辅助工具脚本
│   ├── update_fingerprints.py # 指纹库更新脚本 (Wappalyzer/Nuclei/Recog)
│   └── import_fingerprints.py # 自定义指纹导入脚本 (支持 Finger/Ehole 格式)
├── tests/                  # 测试用例
├── Cargo.toml              # 项目依赖配置
├── build.bat               # Windows 快速构建脚本
├── build.sh                # Linux/macOS 快速构建脚本
└── Dockerfile              # Docker 部署文件
```

## 常见问题

**Q: 扫描速度太慢怎么办？**
A: 尝试增加并发数 `-C 1000`，或者如果是在内网，减小超时时间 `-t 200`。

**Q: 为什么扫不到某些端口？**
A: 目标可能开启了防火墙。本工具目前仅支持 TCP Connect 扫描，会被防火墙记录或拦截。

**Q: 扫描结果太多刷屏怎么办？**
A: 建议使用 `--json` 或 `-o result.json` 将结果保存到文件查看。

**Q: Windows 下扫描大量端口时报错？**
A: 本工具已针对 Windows 做了优化，但如果并发过高仍可能受限于系统 TCP 连接数限制。尝试降低并发数 `-C 500`。

