

#[derive(Debug, Clone)]
pub struct UdpScanConfig {
    pub timeout_ms: u64,
    pub retry_count: usize,
    pub concurrency: usize,
    pub max_retries: usize,
    pub initial_timeout: u64,
    pub confirmation_threshold: usize,
    pub adaptive: bool,
}

impl Default for UdpScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            retry_count: 2,
            concurrency: 1000,
            max_retries: 3,
            initial_timeout: 1000,
            confirmation_threshold: 2,
            adaptive: true,
        }
    }
}

impl UdpScanConfig {
    pub fn new(timeout_ms: u64, retry_count: usize, concurrency: usize) -> Self {
        Self {
            timeout_ms,
            retry_count,
            concurrency,
            max_retries: retry_count,
            initial_timeout: timeout_ms,
            confirmation_threshold: 2,
            adaptive: true,
        }
    }
    
    pub fn for_port(_port: u16) -> Self {
        Self::default()
    }
    
    pub fn timeout_for_attempt(&self, attempt: usize) -> u64 {
        if self.adaptive {
            self.initial_timeout * (1 << attempt.min(3))
        } else {
            self.timeout_ms
        }
    }
    pub fn backoff_for_attempt(&self, attempt: usize) -> u64 {
        50 * (1 << attempt.min(4))
    }
}
