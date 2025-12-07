



use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;


pub struct AdaptiveConcurrency {
    
    current: Arc<AtomicUsize>,
    
    min: usize,
    
    max: usize,

    
    
    success_count: Arc<AtomicU64>,
    
    failure_count: Arc<AtomicU64>,
    
    timeout_count: Arc<AtomicU64>,

    
    
    last_adjust: Arc<Mutex<Instant>>,
    
    adjust_interval: Duration,

    
    
    avg_response_time: Arc<Mutex<f64>>,
    
    response_samples: Arc<Mutex<Vec<f64>>>,
    
    max_samples: usize,
}

impl AdaptiveConcurrency {
    
    
    
    
    
    
    pub fn new(initial: usize, min: usize, max: usize) -> Self {
        let initial = initial.max(min).min(max);

        Self {
            current: Arc::new(AtomicUsize::new(initial)),
            min,
            max,
            success_count: Arc::new(AtomicU64::new(0)),
            failure_count: Arc::new(AtomicU64::new(0)),
            timeout_count: Arc::new(AtomicU64::new(0)),
            last_adjust: Arc::new(Mutex::new(Instant::now())),
            adjust_interval: Duration::from_secs(5),
            avg_response_time: Arc::new(Mutex::new(0.0)),
            response_samples: Arc::new(Mutex::new(Vec::with_capacity(100))),
            max_samples: 100,
        }
    }

    
    
    
    
    
    
    pub async fn record_result(&self, success: bool, is_timeout: bool, response_time: Duration) {
        
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
            if is_timeout {
                self.timeout_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        
        {
            let mut samples = self.response_samples.lock().await;
            samples.push(response_time.as_millis() as f64);

            
            if samples.len() > self.max_samples {
                samples.remove(0);
            }

            
            if !samples.is_empty() {
                let avg = samples.iter().sum::<f64>() / samples.len() as f64;
                *self.avg_response_time.lock().await = avg;
            }
        }

        
        let mut last = self.last_adjust.lock().await;
        if last.elapsed() >= self.adjust_interval {
            self.adjust().await;
            *last = Instant::now();
        }
    }

    
    async fn adjust(&self) {
        let success = self.success_count.load(Ordering::Relaxed);
        let failure = self.failure_count.load(Ordering::Relaxed);
        let timeout = self.timeout_count.load(Ordering::Relaxed);
        let total = success + failure;

        
        if total < 20 {
            return;
        }

        let success_rate = success as f64 / total as f64;
        let timeout_rate = timeout as f64 / total as f64;
        let avg_time = *self.avg_response_time.lock().await;

        let current = self.current.load(Ordering::Relaxed);

        
        let new_concurrency = if success_rate > 0.95 && timeout_rate < 0.05 && avg_time < 200.0 {
            
            
            let increase = (current as f64 * 1.2) as usize;
            increase.max(current + 50) 
        } else if success_rate < 0.80 || timeout_rate > 0.15 || avg_time > 500.0 {
            
            
            let decrease = (current as f64 * 0.8) as usize;
            decrease.max(self.min) 
        } else if success_rate > 0.90 && timeout_rate < 0.10 && avg_time < 300.0 {
            
            let increase = (current as f64 * 1.1) as usize;
            increase.max(current + 20) 
        } else if success_rate < 0.85 || timeout_rate > 0.12 || avg_time > 400.0 {
            
            (current as f64 * 0.9) as usize
        } else {
            
            current
        };

        
        let new_concurrency = new_concurrency.max(self.min).min(self.max);
        
        if new_concurrency != current {
            let change = if new_concurrency > current {
                "↑"
            } else {
                "↓"
            };
            info!(
                "🔄 调整并发数: {} {} {} (成功率: {:.1}%, 超时率: {:.1}%, 平均响应: {:.0}ms)",
                current,
                change,
                new_concurrency,
                success_rate * 100.0,
                timeout_rate * 100.0,
                avg_time
            );
            self.current.store(new_concurrency, Ordering::Relaxed);
        }

        
        self.success_count.store(0, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        self.timeout_count.store(0, Ordering::Relaxed);
    }

    
    pub fn get_current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    
    pub async fn get_stats(&self) -> ConcurrencyStats {
        let success = self.success_count.load(Ordering::Relaxed);
        let failure = self.failure_count.load(Ordering::Relaxed);
        let timeout = self.timeout_count.load(Ordering::Relaxed);
        let total = success + failure;

        let success_rate = if total > 0 {
            success as f64 / total as f64
        } else {
            0.0
        };

        let timeout_rate = if total > 0 {
            timeout as f64 / total as f64
        } else {
            0.0
        };

        ConcurrencyStats {
            current_concurrency: self.get_current(),
            success_count: success,
            failure_count: failure,
            timeout_count: timeout,
            success_rate,
            timeout_rate,
            avg_response_time: *self.avg_response_time.lock().await,
        }
    }
}


#[derive(Debug, Clone)]
pub struct ConcurrencyStats {
    pub current_concurrency: usize,
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub success_rate: f64,
    pub timeout_rate: f64,
    pub avg_response_time: f64,
}

impl ConcurrencyStats {
    
    pub fn format(&self) -> String {
        format!(
            "并发: {} | 成功率: {:.1}% | 超时率: {:.1}% | 平均响应: {:.0}ms",
            self.current_concurrency,
            self.success_rate * 100.0,
            self.timeout_rate * 100.0,
            self.avg_response_time
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adaptive_concurrency_creation() {
        let adaptive = AdaptiveConcurrency::new(200, 50, 2000);
        assert_eq!(adaptive.get_current(), 200);
    }

    #[tokio::test]
    async fn test_record_success() {
        let adaptive = AdaptiveConcurrency::new(200, 50, 2000);

        adaptive
            .record_result(true, false, Duration::from_millis(100))
            .await;

        let stats = adaptive.get_stats().await;
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.failure_count, 0);
    }

    #[tokio::test]
    async fn test_record_timeout() {
        let adaptive = AdaptiveConcurrency::new(200, 50, 2000);

        adaptive
            .record_result(false, true, Duration::from_millis(1000))
            .await;

        let stats = adaptive.get_stats().await;
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.timeout_count, 1);
    }

    #[tokio::test]
    async fn test_avg_response_time() {
        let adaptive = AdaptiveConcurrency::new(200, 50, 2000);

        adaptive
            .record_result(true, false, Duration::from_millis(100))
            .await;
        adaptive
            .record_result(true, false, Duration::from_millis(200))
            .await;
        adaptive
            .record_result(true, false, Duration::from_millis(300))
            .await;

        let stats = adaptive.get_stats().await;
        assert!((stats.avg_response_time - 200.0).abs() < 1.0);
    }
}
