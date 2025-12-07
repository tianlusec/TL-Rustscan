# 安全政策

## 支持的版本

当前正在接收安全更新的版本：

| 版本 | 支持状态 |
| ------- | ------------------ |
| 2.3.x   | :white_check_mark: |
| 2.2.x   | :white_check_mark: |
| < 2.2   | :x:                |

## 报告漏洞

如果您发现了安全漏洞，请**不要**公开提交 Issue。

### 报告流程

1. **私密报告**: 发送邮件至 security@tianlu-lab.com
2. **包含信息**:
   - 漏洞描述
   - 复现步骤
   - 影响范围
   - 建议的修复方案（如果有）
3. **响应时间**: 我们将在 48 小时内确认收到
4. **修复时间**: 根据严重程度，通常在 7-30 天内发布修复

### 漏洞等级

- **严重**: 远程代码执行、权限提升
- **高危**: 信息泄露、拒绝服务
- **中危**: 配置错误、逻辑漏洞
- **低危**: 信息披露、边缘情况

## 安全最佳实践

### 1. 授权扫描

```bash
# ✅ 正确：扫描自己的服务器
TL-Rustscan 192.168.1.100 -p 1-1000

# ❌ 错误：未经授权扫描他人服务器
TL-Rustscan example.com  # 可能违法！
```

**重要提示**: 
- 仅扫描您拥有或已获得明确授权的目标
- 保存授权文件作为证据
- 遵守当地法律法规

### 2. 速率限制

```bash
# 使用速率限制避免触发防火墙
TL-Rustscan 192.168.1.0/24 --rate 100

# 降低并发数
TL-Rustscan 192.168.1.0/24 -C 50
```

### 3. 代理使用

```bash
# 通过代理扫描（如果需要）
TL-Rustscan target.com --proxy socks5://127.0.0.1:1080

# 验证代理是否生效
TL-Rustscan target.com --proxy http://proxy.example.com:8080 -v
```

### 4. 证书验证

```bash
# ✅ 默认验证 TLS 证书（推荐）
TL-Rustscan https://example.com -p 443 -b

# ⚠️ 跳过证书验证（仅用于测试环境）
TL-Rustscan https://self-signed.local -p 443 -b --insecure
```

### 5. 输出安全

```bash
# 避免在输出中泄露敏感信息
TL-Rustscan target.com -o results.json

# 设置适当的文件权限
chmod 600 results.json

# 扫描完成后清理敏感数据
shred -u results.json  # Linux
```

### 6. 网络隔离

```bash
# 在隔离环境中运行扫描
docker run --rm --network isolated tl-rustscan target.com

# 使用专用扫描网络
TL-Rustscan --interface eth1 target.com
```

## 已知安全问题

### 已修复

- **CVE-2024-XXXX**: TLS 证书验证绕过（v2.3.0 修复）
- **CVE-2024-YYYY**: CSV 注入漏洞（v2.2.5 修复）

### 待修复

查看 [GitHub Security Advisories](https://github.com/TianLuLaboratory/TL-Rustscan/security/advisories)

## 安全功能

### 1. 输入验证

- 所有用户输入都经过严格验证
- 防止命令注入和路径遍历
- 端口范围限制在 1-65535

### 2. 输出清理

- HTML 输出自动转义 XSS
- CSV 输出防止公式注入
- JSON 输出防止注入攻击

### 3. 资源限制

- 内存使用限制
- 文件描述符限制
- 并发连接限制

### 4. 日志安全

- 敏感信息自动脱敏
- 日志文件权限控制
- 支持日志加密

## 合规性

### GDPR 合规

- 不收集个人数据
- 扫描结果本地存储
- 用户完全控制数据

### SOC 2 合规

- 审计日志
- 访问控制
- 数据加密

## 安全审计

### 代码审计

```bash
# 运行安全检查
cargo audit

# 运行 Clippy 检查
cargo clippy -- -D warnings

# 运行测试
cargo test
```

### 依赖审计

定期更新依赖以修复已知漏洞：

```bash
cargo update
cargo audit
```

## 负责任的披露

我们承诺：

1. **及时响应**: 48 小时内确认
2. **透明沟通**: 定期更新进展
3. **公开致谢**: 修复后公开感谢报告者
4. **奖励计划**: 根据严重程度提供奖励

## 联系方式

- **安全邮箱**: security@tianlu-lab.com
- **PGP 密钥**: [公钥链接]
- **应急联系**: [紧急联系方式]

## 法律声明

使用本工具即表示您同意：

1. 仅在授权范围内使用
2. 遵守所有适用法律
3. 不用于恶意目的
4. 承担使用责任

**违反上述条款可能导致法律后果。**

---

最后更新: 2025-12-07