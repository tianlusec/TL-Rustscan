# TL-Rustscan 架构设计

## 概述

TL-Rustscan 是一个基于 Rust 和 Tokio 异步运行时构建的高性能端口扫描器。本文档描述了项目的整体架构、核心模块和设计决策。

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│(clap + config.rs)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                     Main Orchestrator                        │
│                      (main.rs)                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Target Parse │  │ Config Init  │  │ Output Setup │     │
│  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    Scanner Module                            │
│                   (scanner/mod.rs)                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Scan Orchestration                       │  │
│  │  • Task Generation                                    │  │
│  │  • Concurrency Control (Semaphore)                   │  │
│  │  • Rate Limiting (Token Bucket)                      │  │
│  │  • Retry Logic                                        │  │
│  └──────────────────────────────────────────────────────┘  │
││                │
│  ┌──────────────┬──────┴──────┬──────────────┐            │
│  │              │              │              │            │
│  ▼              ▼              ▼              ▼            │
│ ┌────────┐  ┌────────┐          │
│ │  TCP   │  │  UDP   │  │  Host  │  │  Web   │          │
│ │ Scan   │  │ Scan   │  │Discovery│  │  Dir   │          │
│ └────────┘  └────────┘  └────────┘  └────────┘          │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Service Detection│
│                   (probes.rs)                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Protocol   │  │  Fingerprint │  │     HTTP     │     │
│  │    Probes    │  │   Matching   │  │   Analysis   │     │
│  └──────────────┘  └──────────────┘     │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Plugin System                             │
│                  (plugins/mod.rs)                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Brute   │  │   POC    │  │   Info   │  │  Custom  │  │
│  │  Force   │  │  Checks  │  │ Gathering│  │ Plugins  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Output Layer                              │
│                    (output.rs)                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   JSON   │  │ Markdown │  │   CSV    │  │   HTML   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块

### 1. CLI 层 (`config.rs`)

**职责**:
- 解析命令行参数
- 验证配置
- 提供默认值

**关键组件**:
```rust
pub struct Cli { ... }          // CLI 参数定义
pub struct ScanConfig { ... }   // 内部配置结构
fn parse_ports() -> Vec<u16>    // 端口解析
```

**设计决策**:
- 使用 `clap` 的 derive 宏简化参数定义
- 分离 CLI 结构和内部配置结构
- 提供智能默认值（如根据端口数量调整并发）

### 2. 目标解析 (`target.rs`)

**职责**:
- 解析多种目标格式（IP、CIDR、域名、范围）
- DNS 解析和缓存
- 目标去重

**支持的格式**:
```
192.168.1.1              # 单个 IP
192.168.1.0/24           # CIDR 网段
192.168.1.1-192.168.1.10 # IP 范围
192.168.1.1-10# 简写范围
example.com              # 域名
[::1]                    # IPv6
```

**DNS 缓存**:
```rust
static DNS_CACHE: OnceLock<Mutex<HashMap<String, DnsCacheEntry>>> = ...;
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
```

### 3. 扫描器核心 (`scanner/mod.rs`)

**职责**:
- 任务生成和调度
- 并发控制
- 速率限制
- 重试逻辑
- 插件集成

**并发模型**:
```rust
// 使用 futures::stream 实现并发
stream::iter(tasks)
    .map(|task| async move { scan_task(task).await })
    .buffer_unordered(concurrency)
    .collect().await
```

**速率限制**:
```rust
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_update: Instant,
}
```

**重试策略**:
- 只重试 `Filtered` 状态的端口
- 降低并发数（1/5）
- 增加超时时间（2x）
- 最大重试队列：100,000

### 4. TCP 扫描 (`scanner/tcp_connect.rs`)

**扫描流程**:
```
1. connect_with_backoff()
   ├─ Windows: spawn_blocking + std::net::TcpStream
   └─ Linux: Tokio async connect

2. Banner 抓取
   ├─ 被动读取（等待服务器发送）
   └─ 主动探测（发送协议特定请求）

3. 服务识别
   ├─ 协议探测（Redis, MySQL, SSH, etc.）
   ├─ HTTP/HTTPS 分析
   └─ 指纹匹配

4. 深度扫描（可选）
   ├─ 多协议尝试
   ├─ TLS 证书提取
   └─ API 探测
```

**Windows 优化**:
```rust
#[cfg(target_os = "windows")]
let connect_result = tokio::task::spawn_blocking(move || {
    std::net::TcpStream::connect_timeout(&addr, remaining)
}).await?;
```

### 5. UDP 扫描 (`scanner/udp_scan.rs`)

**挑战**:
- 无连接协议
- 需要协议特定的 payload
- 响应可能来自不同端口（如 TFTP）
- 需要区分 Closed 和 Filtered

**解决方案**:
```rust
// 使用 send_to/recv_from 而非 connect
socket.send_to(payload, addr).await?;

// 捕获 ICMP Port Unreachable
match socket.recv_from(&mut buf).await {
    Ok((n, src)) => PortState::Open,
    Err(e) if e.kind() == ConnectionRefused => PortState::Closed,
    Err(_) => PortState::Filtered,
}
```

### 6. 服务探测 (`scanner/probes.rs`)

**探测方法**:

1. **被动 Banner 抓取**
   ```rust
   stream.read(&mut buffer).await
   ```

2. **主动协议探测**
   ```rust
   // Redis
   stream.write_all(b"PING\r\n").await
   
   // MySQL
   // 读取服务器握手包
   
   // PostgreSQL
   stream.write_all(&ssl_request).await
   ```

3. **HTTP 分析**
   ```rust
   // 标题提取
   // 指纹匹配
   // 框架识别
   // WAF/CDN 检测
   ```

### 7. 指纹识别 (`scanner/fingerprint_db.rs`)

**数据结构**:
```rust
pub struct FingerprintDatabase {
    // 正则规则（按位置分类）
    regex_rules_body: Vec<CompiledFingerprint>,
    regex_rules_header: Vec<CompiledFingerprint>,
    regex_rules_title: Vec<CompiledFingerprint>,
    regex_rules_banner: Vec<CompiledFingerprint>,
    
    // 关键字规则（使用 Aho-Corasick 加速）
    keyword_rules_body: Vec<CompiledFingerprint>,
    ac_body: Option<AhoCorasick>,
    
    // Favicon Hash 映射
    favicon_rules: HashMap<i32, String>,
}
```

**匹配流程**:
```
1. 关键字匹配（Aho-Corasick，O(n)）
2. 正则匹配（逐个尝试）
3. 结果去重和过滤
```

### 8. 插件系统 (`plugins/mod.rs`)

**插件接口**:
```rust
#[async_trait]
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn interested_ports(&self) -> Vec<u16>;
    async fn scan(&self, info: &HostInfo) -> Result<Option<String>>;
    fn plugin_type(&self) -> PluginType;
    fn is_rscan_only(&self) -> bool;
}
```

**插件类型**:
- **Brute**: 弱口令爆破（SSH, MySQL, Redis, etc.）
- **POC**: 漏洞验证（MS17-010, WebLogic, etc.）
- **Info**: 信息收集（NetBIOS, SNMP, etc.）

**插件管理**:
```rust
pub struct PluginManager {
    plugins: Vec<Arc<dyn ScanPlugin>>,
}

impl PluginManager {
    pub fn get_plugins_for_port(&self, port: u16) -> Vec<Arc<dyn ScanPlugin>> {
        self.plugins.iter()
            .filter(|p| p.interested_ports().contains(&port))
            .cloned()
            .collect()
    }
}
```

### 9. 输出层 (`output.rs`)

**支持格式**:
- **JSON**: 结构化数据，易于解析
- **Markdown**: 人类可读的报告
- **CSV**: 表格数据，Excel 兼容
- **HTML**: 交互式报告，带搜索功能

**安全措施**:
- HTML XSS 防护
- CSV 注入防护
- 文件权限控制

## 性能优化

### 1. 异步 I/O

使用 Tokio 异步运行时：
```rust
#[tokio::main]
async fn main() {
    // 所有 I/O 操作都是非阻塞的
}
```

### 2. 并发控制

```rust
// 使用 buffer_unordered 实现并发
stream::iter(tasks)
    .buffer_unordered(concurrency)
```

### 3. 连接复用

```rust
// HTTP 客户端缓存
static CLIENTS: OnceLock<RwLock<HashMap<String, Client>>> = ...;
```

### 4. 智能重试

- 只重试超时的端口
- 降低重试并发
- 增加重试超时

### 5. 内存优化

- 只存储 Open 和 show_closed 的结果
- 限制重试队列大小
- 流式处理大文件

## 错误处理

### 错误类型

```rust
pub enum ScanError {
    ConnectionFailed { target, port, reason },
    Timeout { port, timeout },
    DnsResolutionFailed { domain, reason },
    // ...
}
```

### 错误严重程度

- **Critical**: 配置错误，立即终止
- **High**: 文件错误，影响功能
- **Medium**: DNS 错误，跳过目标
- **Low**: 连接错误，正常现象

### 错误统计

```rust
pub struct ErrorStats {
    total: usize,
    by_type: HashMap<String, usize>,
    critical_count: usize,
    // ...
}
```

## 安全考虑

### 1. 输入验证

- 端口范围：1-65535
- CIDR 大小限制
- 文件路径验证

### 2. 输出清理

- HTML 转义
- CSV 注入防护
- JSON 安全序列化

### 3. 资源限制

- 最大并发数
- 内存使用限制
- 文件描述符限制

### 4. TLS 安全

- 证书验证（可选禁用）
- 支持自签名证书
- 提取证书信息

## 扩展性

### 添加新协议探测

```rust
// 在 probes.rs 中添加
pub async fn probe_new_protocol(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    timeout_ms: u64,
) -> Option<String> {
    // 实现探测逻辑
}

// 在 tcp_connect.rs 中调用
if port == NEW_PROTOCOL_PORT {
    banner = probe_new_protocol(&mut stream, &mut buffer, timeout_ms).await;
}
```

### 添加新插件

```rust
struct NewPlugin;

#[async_trait]
impl ScanPlugin for NewPlugin {
    // 实现接口
}

// 在 PluginManager::new() 中注册
pm.register(Arc::new(NewPlugin));
```

### 添加新输出格式

```rust
pub fn output_new_format(
    results: &[HostScanResult],
    path: &Path,
) -> Result<()> {
    // 实现输出逻辑
}
```

## 测试策略

### 单元测试

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_port_parsing() {
        // 测试端口解析
    }
}
```

### 集成测试

```python
# tests/integration_test.py
def test_basic_scan():
    result = run_scan("127.0.0.1", "-p 80")
    assert "80" in result
```

### 性能测试

```bash
# 基准测试
cargo bench

# 性能分析
cargo flamegraph
```

## 部署

### 编译

```bash
# 开发版本
cargo build

# 发布版本
cargo build --release

# 跨平台编译
cross build --target x86_64-pc-windows-gnu
```

### Docker

```dockerfile
FROM rust:latest
WORKDIR /app
COPY . .
RUN cargo build --release
CMD ["./target/release/TL-Rustscan"]
```

## 未来规划

### 短期（v2.4）
- [ ] 实现断点续扫
- [ ] 实现自适应并发
- [ ] 优化深度扫描性能

### 中期（v2.5）
- [ ] 支持 IPv6
- [ ] 支持代理链
- [ ] 添加更多插件

### 长期（v3.0）
- [ ] 分布式扫描
- [ ] Web UI
- [ ] 机器学习指纹识别

## 参考资料

- [Tokio 文档](https://tokio.rs/)
- [Rust 异步编程](https://rust-lang.github.io/async-book/)
- [端口扫描技术](https://nmap.org/book/scan-methods.html)

---

最后更新: 2025-12-07