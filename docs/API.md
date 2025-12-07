# TL-Rustscan API 文档

## 概述

TL-Rustscan 提供了模块化的 API 接口，可以作为库集成到其他 Rust 项目中。

## 核心模块

### 1. Scanner 模块

#### 1.1 基础扫描

```rust
use tl_rustscan::scanner;
use tl_rustscan::config::ScanConfig;

// 创建扫描配置
let config = ScanConfig {
    targets: vec!["192.168.1.1".to_string()],
    ports: vec![80, 443, 8080],
    concurrency: 500,
    timeout_ms: 500,
    banner: true,
    ..Default::default()
};

// 执行扫描
let results = scanner::run_scan(&config, targets).await;
```

#### 1.2 TCP 连接扫描

```rust
use tl_rustscan::scanner::tcp_connect::{scan_single_port, TcpScanArgs, PortState};
use std::net::IpAddr;
use std::sync::Arc;

let args = TcpScanArgs {
    ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
    port: 80,
    host: Arc::new("example.com".to_string()),
    timeout_ms: 500,
    grab_banner: true,
    dir_scan: false,
    dir_paths: &[],
    web_ports: &[80, 443],
    deep_scan: false,
    insecure: false,
    proxy: None,
};

let (state, banner, dirs) = scan_single_port(args).await;

match state {
    PortState::Open => println!("端口开放"),
    PortState::Closed => println!("端口关闭"),
    PortState::Filtered => println!("端口被过滤"),
}
```

#### 1.3 UDP 扫描

```rust
use tl_rustscan::scanner::udp_scan::scan_single_port;
use std::net::IpAddr;

let ip: IpAddr = "192.168.1.1".parse().unwrap();
let port = 53; // DNS
let timeout_ms = 1000;

let state = scan_single_port(ip, port, timeout_ms).await;
```

### 2. 目标解析模块

```rust
use tl_rustscan::target::resolve_targets;
use std::path::Path;

// 解析多种格式的目标
let targets = vec![
    "192.168.1.1".to_string(),
    "192.168.1.0/24".to_string(),
    "example.com".to_string(),
];

let resolved = resolve_targets(&targets, None, &[]).await?;
```

### 3. 指纹识别模块

```rust
use tl_rustscan::scanner::fingerprint_db::FingerprintDatabase;

// 初始化指纹库
FingerprintDatabase::init(None);

// 获取全局实例
let db = FingerprintDatabase::global();

// 匹配 HTTP 指纹
let frameworks = db.match_http(body, headers, title);

// 匹配服务 Banner
if let Some(service) = db.match_service_banner(banner) {
    println!("识别到服务: {}", service);
}

// 匹配 Favicon Hash
if let Some(app) = db.match_favicon(hash) {
    println!("识别到应用: {}", app);
}
```

### 4. 插件系统

#### 4.1 使用内置插件

```rust
use tl_rustscan::plugins::{PluginManager, HostInfo};

let pm = PluginManager::new();

let info = HostInfo {
    host: "192.168.1.1".to_string(),
    port: "6379".to_string(),
    url: "http://192.168.1.1:6379".to_string(),
    infostr: vec![],
    proxy: None,
};

// 获取适用于特定端口的插件
let plugins = pm.get_plugins_for_port(6379);

for plugin in plugins {
    if let Ok(Some(result)) = plugin.scan(&info).await {
        println!("发现: {}", result);
    }
}
```

#### 4.2 创建自定义插件

```rust
use tl_rustscan::plugins::{ScanPlugin, HostInfo, PluginType};
use async_trait::async_trait;
use anyhow::Result;

struct MyCustomPlugin;

#[async_trait]
impl ScanPlugin for MyCustomPlugin {
    fn name(&self) -> &str {
        "My Custom Plugin"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![8080, 8443]
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        // 实现你的扫描逻辑
        Ok(Some("发现自定义服务".to_string()))
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }
}

// 注册插件
let mut pm = PluginManager::new();
pm.register(Arc::new(MyCustomPlugin));
```

### 5. 输出模块

```rust
use tl_rustscan::output::{HostScanResult, output_json, output_markdown};
use std::path::Path;

// JSON 输出
output_json(&results, &config)?;

// Markdown 输出
output_markdown(&results, Path::new("report.md"))?;

// CSV 输出
output_csv(&results, Path::new("report.csv"))?;

// HTML 输出
output_html(&results, Path::new("report.html"))?;
```

## 数据结构

### PortResult

```rust
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub banner: Option<String>,
    pub dirs: Vec<String>,
}
```

### HostScanResult

```rust
pub struct HostScanResult {
    pub target: String,
    pub ip: String,
    pub ports: Vec<PortResult>,
    pub vulns: Vec<String>,
}
```

### ScanConfig

```rust
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub banner: bool,
    pub udp: bool,
    pub check_alive: bool,
    pub dir_scan: bool,
    pub deep_scan: bool,
    pub rscan: bool,
    // ... 更多字段
}
```

## 高级用法

### 自定义 HTTP 客户端

```rust
use tl_rustscan::scanner::probes::create_http_client;

let client = create_http_client(
    3,      // 超时秒数
    true,   // 跳过证书验证
    Some("socks5://127.0.0.1:1080")  // 代理
)?;
```

### Web 目录扫描

```rust
use tl_rustscan::scanner::web_dir::scan_dirs;
use std::net::IpAddr;

let ip: IpAddr = "192.168.1.1".parse().unwrap();
let port = 80;
let host = "example.com";
let paths = vec![
    "/admin".to_string(),
    "/login".to_string(),
    "/api".to_string(),
];

let found_dirs = scan_dirs(
    ip,
    port,
    host,
    &paths,
    500,    // timeout_ms
    None,   // banner
    false,  // insecure
    None    // proxy
).await;
```

### 主机存活检测

```rust
use tl_rustscan::scanner::host_discovery::is_host_alive;
use std::net::IpAddr;

let ip: IpAddr = "192.168.1.1".parse().unwrap();
let timeout_ms = 1000;

if is_host_alive(ip, timeout_ms).await {
    println!("主机在线");
}
```

## 错误处理

```rust
use tl_rustscan::error::ScanError;

match scan_result {
    Ok(result) => {
        // 处理成功结果
    }
    Err(ScanError::Timeout { port, timeout }) => {
        eprintln!("端口 {} 超时 ({}ms)", port, timeout);
    }
    Err(ScanError::ConnectionFailed { target, port, reason }) => {
        eprintln!("连接失败: {}:{} - {}", target, port, reason);
    }
    Err(e) => {
        eprintln!("扫描错误: {}", e);
    }
}
```

## 性能优化建议

### 1. 并发控制

```rust
// 根据网络环境调整并发数
let concurrency = if is_local_network {
    1000  // 内网可以更高
} else {
    200   // 公网建议保守
};
```

### 2. 超时设置

```rust
// 根据网络延迟调整超时
let timeout_ms = if is_local_network {
    200   // 内网可以更短
} else {
    1000  // 公网建议更长
};
```

### 3. 批量扫描

```rust
// 使用流式处理大量目标
use futures::stream::{self, StreamExt};

let results = stream::iter(targets)
    .map(|target| async move {
        scan_target(target).await
    })
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;
```

## 示例项目

完整的示例项目请参考 `examples/` 目录：

- `examples/basic_scan.rs` - 基础扫描示例
- `examples/custom_plugin.rs` - 自定义插件示例
- `examples/batch_scan.rs` - 批量扫描示例
- `examples/web_scan.rs` - Web 扫描示例

## 注意事项

1. **授权要求**: 仅在授权范围内使用扫描功能
2. **速率限制**: 使用 `--rate` 参数避免触发防火墙
3. **资源管理**: 大规模扫描时注意内存和文件描述符限制
4. **错误处理**: 始终处理可能的错误情况
5. **日志记录**: 使用 `tracing` 进行调试和监控

## 更多资源

- [GitHub 仓库](https://github.com/TianLuLaboratory/TL-Rustscan)
- [问题反馈](https://github.com/TianLuLaboratory/TL-Rustscan/issues)
- [贡献指南](../CONTRIBUTING.md)