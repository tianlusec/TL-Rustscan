# 项目结构说明

本文档详细说明 TL-Rustscan 项目的目录结构和文件组织。

## 📁 根目录结构

```
TL-Rustscan/
├── .github/                    # GitHub 配置
│   ├── workflows/              # CI/CD 工作流
│   ├── ISSUE_TEMPLATE/         # Issue 模板
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/                       # 文档目录
├── imports/                    # 导入数据
├── scripts/                    # 辅助脚本
├── src/                        # 源代码
├── tests/                      # 测试文件
├── .gitignore                  # Git 忽略规则
├── build.bat                   # Windows 构建脚本
├── build.rs                    # Rust 构建脚本
├── build.sh                    # Linux/macOS 构建脚本
├── Cargo.lock                  # 依赖锁定文件
├── Cargo.toml                  # 项目配置
├── CHANGELOG.md                # 更新日志（中文）
├── CHANGELOG_EN.md             # 更新日志（英文）
├── CODE_OF_CONDUCT.md          # 行为准则
├── CONTRIBUTING.md             # 贡献指南（中文）
├── CONTRIBUTING_EN.md          # 贡献指南（英文）
├── Dockerfile                  # Docker 配置
├── fingerprints.json           # 指纹数据库
├── LICENSE                     # MIT 许可证
├── logo.ico                    # 项目图标
├── PROJECT_ISSUES_AND_OPTIMIZATION_REPORT.md  # 问题分析报告
├── README.md                   # 项目说明（中文）
├── README_EN.md                # 项目说明（英文）
└── ROADMAP.md                  # 开发路线图
```

## 📂 详细目录说明

### `.github/` - GitHub 配置

```
.github/
├── workflows/
│   └── build.yml               # 自动构建工作流
├── ISSUE_TEMPLATE/
│   ├── bug_report.md           # Bug 报告模板
│   └── feature_request.md      # 功能请求模板
└── PULL_REQUEST_TEMPLATE.md    # PR 模板
```

**用途**: GitHub 平台的配置文件，包括 CI/CD、Issue 模板等。

### `docs/` - 文档目录

```
docs/
├── API.md                      # API 文档
├── ARCHITECTURE.md             # 架构设计文档
├── DEVELOPMENT.md              # 开发指南
├── FEATURES.md                 # 功能特性文档
├── PROJECT_STRUCTURE.md        # 本文件
├── SECURITY.md                 # 安全使用指南
└── TESTING.md                  # 测试指南
```

**用途**: 项目的所有文档，包括 API、架构、开发指南等。

### `imports/` - 导入数据

```
imports/
└── finger_custom.json          # 自定义指纹数据
```

**用途**: 存放外部导入的数据文件，如自定义指纹库。

### `scripts/` - 辅助脚本

```
scripts/
├── fetch_and_merge.py          # 指纹数据获取和合并
├── import_fingerprints.py      # 指纹导入脚本
└── update_fingerprints.py      # 指纹更新脚本
```

**用途**: 项目维护和开发辅助脚本。

### `src/` - 源代码

```
src/
├── plugins/                    # 插件模块
│   ├── mod.rs                  # 插件管理器
│   ├── dicts.rs                # 弱口令字典
│   ├── docker.rs               # Docker 检测
│   ├── elasticsearch.rs        # Elasticsearch 检测
│   ├── fcgi.rs                 # FastCGI 检测
│   ├── ftp.rs                  # FTP 弱口令
│   ├── jdwp.rs                 # JDWP 检测
│   ├── ldap.rs                 # LDAP 检测
│   ├── memcached.rs            # Memcached 检测
│   ├── mongodb.rs              # MongoDB 检测
│   ├── ms17010.rs              # MS17-010 漏洞
│   ├── mssql.rs                # MSSQL 弱口令
│   ├── mysql.rs                # MySQL 弱口令
│   ├── netbios.rs              # NetBIOS 信息收集
│   ├── oracle.rs               # Oracle 检测
│   ├── postgres.rs             # PostgreSQL 弱口令
│   ├── rdp.rs                  # RDP 检测
│   ├── redis.rs                # Redis 检测
│   ├── smb.rs                  # SMB 弱口令
│   ├── snmp.rs                 # SNMP 检测
│   ├── ssh.rs                  # SSH 弱口令
│   ├── telnet.rs               # Telnet 弱口令
│   ├── vnc.rs                  # VNC 检测
│   ├── web_fingerprints.rs     # Web 指纹识别
│   ├── web_pocs.rs             # Web 漏洞 POC
│   ├── webtitle.rs             # Web 标题获取
│   └── zookeeper.rs            # Zookeeper 检测
├── scanner/                    # 扫描器核心
│   ├── mod.rs                  # 扫描器主模块
│   ├── adaptive.rs             # 自适应并发（未使用）
│   ├── checkpoint.rs           # 断点续扫（未使用）
│   ├── connection_pool.rs      # 连接池（未使用）
│   ├── constants.rs            # 常量定义
│   ├── fingerprint_db.rs       # 指纹数据库
│   ├── host_discovery.rs       # 主机存活检测
│   ├── probes.rs               # 服务探测
│   ├── scan_cache.rs           # 扫描缓存（未使用）
│   ├── service_map.rs          # 服务映射
│   ├── streaming_output.rs     # 流式输出（未使用）
│   ├── tcp_connect.rs          # TCP 连接扫描
│   ├── udp_config.rs           # UDP 配置
│   ├── udp_scan.rs             # UDP 扫描
│   └── web_dir.rs              # Web 目录扫描
├── config.rs                   # 配置管理
├── default_paths.txt           # 默认路径字典
├── error.rs                    # 错误处理
├── main.rs                     # 程序入口
├── output.rs                   # 输出模块
└── target.rs                   # 目标解析
```

**用途**: 项目的核心源代码。

#### `src/plugins/` - 插件系统

每个插件文件实现特定服务的检测功能：
- **Brute 类型**: 弱口令爆破（SSH, MySQL, Redis 等）
- **POC 类型**: 漏洞验证（MS17-010, WebLogic 等）
- **Info 类型**: 信息收集（NetBIOS, SNMP 等）

#### `src/scanner/` - 扫描器核心

- **mod.rs**: 扫描任务调度、并发控制、重试逻辑
- **tcp_connect.rs**: TCP 端口扫描和 Banner 抓取
- **udp_scan.rs**: UDP 端口扫描
- **probes.rs**: 协议探测和服务识别
- **fingerprint_db.rs**: 指纹数据库管理和匹配
- **web_dir.rs**: Web 目录爆破
- **host_discovery.rs**: 主机存活检测

**注意**: 以下模块已实现但未使用：
- `adaptive.rs` - 自适应并发控制
- `checkpoint.rs` - 断点续扫
- `connection_pool.rs` - TCP 连接池
- `scan_cache.rs` - 扫描结果缓存
- `streaming_output.rs` - 流式输出

### `tests/` - 测试文件

```
tests/
└── integration_test.py         # 集成测试脚本
```

**用途**: 项目的测试文件。

## 📄 重要文件说明

### 配置文件

- **Cargo.toml**: Rust 项目配置，定义依赖、元数据等
- **Cargo.lock**: 依赖版本锁定，确保构建一致性
- **build.rs**: 构建脚本，用于编译时的特殊处理（如 Windows 图标）

### 构建脚本

- **build.bat**: Windows 快速构建脚本
- **build.sh**: Linux/macOS 快速构建脚本

### 数据文件

- **fingerprints.json**: Web 指纹数据库（16000+ 条规则）
- **default_paths.txt**: Web 目录扫描默认字典（300,000+ 条路径）

### 文档文件

- **README.md / README_EN.md**: 项目说明和使用指南
- **CHANGELOG.md / CHANGELOG_EN.md**: 版本更新日志
- **CONTRIBUTING.md / CONTRIBUTING_EN.md**: 贡献指南
- **LICENSE**: MIT 开源许可证
- **CODE_OF_CONDUCT.md**: 社区行为准则
- **ROADMAP.md**: 开发路线图

### 分析报告

- **PROJECT_ISSUES_AND_OPTIMIZATION_REPORT.md**: 项目问题和优化建议

## 🔧 开发相关

### 添加新功能

1. **新增插件**: 在 `src/plugins/` 创建新文件
2. **新增协议探测**: 在 `src/scanner/probes.rs` 添加函数
3. **新增输出格式**: 在 `src/output.rs` 添加函数

### 修改配置

1. **CLI 参数**: 修改 `src/config.rs` 中的 `Cli` 结构
2. **扫描配置**: 修改 `src/config.rs` 中的 `ScanConfig` 结构
3. **常量**: 修改 `src/scanner/constants.rs`

### 更新文档

1. **API 变更**: 更新 `docs/API.md`
2. **架构变更**: 更新 `docs/ARCHITECTURE.md`
3. **功能变更**: 更新 `README.md` 和 `docs/FEATURES.md`
4. **版本发布**: 更新 `CHANGELOG.md`

## 📊 文件统计

| 类型 | 数量 | 说明 |
|------|------|------|
| Rust 源文件 | 50+ | 核心代码 |
| 文档文件 | 15+ | Markdown 文档 |
| 配置文件 | 10+ | 项目配置 |
| 脚本文件 | 5+ | 辅助脚本 |
| 数据文件 | 2 | 指纹库和字典 |

## 🗂️ 文件命名规范

### Rust 文件
- 模块文件: `mod.rs`
- 功能文件: `snake_case.rs`
- 测试文件: `*_test.rs` 或 `tests/`

### 文档文件
- 英文文档: `UPPERCASE.md`
- 中文文档: `UPPERCASE.md` 或 `UPPERCASE_CN.md`
- 子文档: `docs/PascalCase.md`

### 配置文件
- Cargo: `Cargo.toml`, `Cargo.lock`
- Git: `.gitignore`
- Docker: `Dockerfile`
- CI/CD: `.github/workflows/*.yml`

## 🔍 快速查找

### 查找功能实现
```bash
# 查找 TCP 扫描相关代码
grep -r "tcp_connect" src/

# 查找插件实现
ls src/plugins/

# 查找配置选项
grep "arg" src/config.rs
```

### 查找文档
```bash
# 查找 API 文档
cat docs/API.md

# 查找架构说明
cat docs/ARCHITECTURE.md

# 查找使用示例
grep "示例" README.md
```

## 📝 维护建议

1. **定期清理**: 删除未使用的模块和文件
2. **文档同步**: 代码变更时同步更新文档
3. **版本管理**: 遵循语义化版本规范
4. **测试覆盖**: 新功能必须包含测试
5. **代码审查**: 所有 PR 必须经过审查

---

最后更新: 2025-12-07