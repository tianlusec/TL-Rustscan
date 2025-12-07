use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("网络连接失败: {target}:{port} - {reason}")]
    ConnectionFailed {
        target: IpAddr,
        port: u16,
        reason: String,
    },

    #[error("端口 {port} 连接超时 ({timeout}ms)")]
    Timeout { port: u16, timeout: u64 },

    #[error("DNS解析失败: {domain} - {reason}")]
    DnsResolutionFailed { domain: String, reason: String },

    #[error("服务识别失败: 端口 {port} - {reason}")]
    ServiceDetectionFailed { port: u16, reason: String },

    #[error("文件操作失败: {path}")]
    FileError {
        path: String,
        source: std::io::Error,
    },

    #[error("配置错误: {0}")]
    ConfigError(String),

    #[error("端口范围无效: {0}")]
    InvalidPortRange(String),

    #[error("目标格式无效: {0}")]
    InvalidTarget(String),

    #[error("HTTP请求失败: {url} - 状态码 {status}")]
    HttpError { url: String, status: u16 },

    #[error("TLS握手失败: {host} - {reason}")]
    TlsHandshakeFailed { host: String, reason: String },

    #[error("资源耗尽: {resource}")]
    ResourceExhausted { resource: String },

    #[error("IO错误: {0}")]
    IoError(#[from] std::io::Error),
}

impl ScanError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScanError::Timeout { .. }
                | ScanError::ConnectionFailed { .. }
                | ScanError::ResourceExhausted { .. }
        )
    }

    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ScanError::ConfigError(_)
            | ScanError::InvalidPortRange(_)
            | ScanError::InvalidTarget(_) => ErrorSeverity::Critical,
            ScanError::FileError { .. } => ErrorSeverity::High,
            ScanError::DnsResolutionFailed { .. }
            | ScanError::TlsHandshakeFailed { .. }
            | ScanError::HttpError { .. } => ErrorSeverity::Medium,

            ScanError::Timeout { .. }
            | ScanError::ConnectionFailed { .. }
            | ScanError::ServiceDetectionFailed { .. }
            | ScanError::IoError(_) => ErrorSeverity::Low,

            ScanError::ResourceExhausted { .. } => ErrorSeverity::High,
        }
    }

    pub fn user_hint(&self) -> Option<String> {
        match self {
            ScanError::Timeout { .. } => {
                Some("提示：尝试增加超时时间 (-t 参数) 或降低并发数 (-C 参数)".to_string())
            }
            ScanError::ConnectionFailed { .. } => {
                Some("提示：检查目标是否在线，或者防火墙是否阻止了连接".to_string())
            }
            ScanError::DnsResolutionFailed { .. } => {
                Some("提示：检查DNS服务器设置或网络连接".to_string())
            }
            ScanError::ResourceExhausted { .. } => {
                Some("提示：降低并发数 (-C 参数) 或增加系统资源限制".to_string())
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct ErrorStats {
    pub total: usize,
    pub by_type: std::collections::HashMap<String, usize>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl ErrorStats {
    pub fn new() -> Self {
        Self {
            total: 0,
            by_type: std::collections::HashMap::new(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        }
    }

    pub fn record(&mut self, error: &ScanError) {
        self.total += 1;

        let type_name = match error {
            ScanError::ConnectionFailed { .. } => "ConnectionFailed",
            ScanError::Timeout { .. } => "Timeout",
            ScanError::DnsResolutionFailed { .. } => "DnsResolutionFailed",
            ScanError::ServiceDetectionFailed { .. } => "ServiceDetectionFailed",
            ScanError::FileError { .. } => "FileError",
            ScanError::ConfigError(_) => "ConfigError",
            ScanError::InvalidPortRange(_) => "InvalidPortRange",
            ScanError::InvalidTarget(_) => "InvalidTarget",
            ScanError::HttpError { .. } => "HttpError",
            ScanError::TlsHandshakeFailed { .. } => "TlsHandshakeFailed",
            ScanError::ResourceExhausted { .. } => "ResourceExhausted",
            ScanError::IoError(_) => "IoError",
        };

        *self.by_type.entry(type_name.to_string()).or_insert(0) += 1;

        match error.severity() {
            ErrorSeverity::Critical => self.critical_count += 1,
            ErrorSeverity::High => self.high_count += 1,
            ErrorSeverity::Medium => self.medium_count += 1,
            ErrorSeverity::Low => self.low_count += 1,
        }
    }

    pub fn should_abort(&self) -> bool {
        if self.critical_count > 0 {
            return true;
        }

        if self.total > 1000 {
            let error_rate = self.total as f64 / 1000.0;
            if error_rate > 0.5 {
                return true;
            }
        }

        false
    }

    pub fn summary(&self) -> String {
        if self.total == 0 {
            return "无错误".to_string();
        }

        let mut summary = format!("总错误数: {}", self.total);

        if self.critical_count > 0 {
            summary.push_str(&format!(" | 致命: {}", self.critical_count));
        }
        if self.high_count > 0 {
            summary.push_str(&format!(" | 严重: {}", self.high_count));
        }
        if self.medium_count > 0 {
            summary.push_str(&format!(" | 中等: {}", self.medium_count));
        }
        if self.low_count > 0 {
            summary.push_str(&format!(" | 轻微: {}", self.low_count));
        }

        summary
    }
}

impl Default for ErrorStats {
    fn default() -> Self {
        Self::new()
    }
}
