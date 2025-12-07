


























use crate::scanner::tcp_connect::PortState;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;


#[derive(Debug, Clone)]
struct CachedResult {
    
    state: PortState,
    
    banner: Option<String>,
    
    timestamp: Instant,
}

impl CachedResult {
    fn new(state: PortState, banner: Option<String>) -> Self {
        Self {
            state,
            banner,
            timestamp: Instant::now(),
        }
    }

    
    fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp.elapsed() > ttl
    }
}




pub struct ScanCache {
    
    cache: Arc<Mutex<HashMap<(IpAddr, u16), CachedResult>>>,
    
    ttl: Duration,
    
    stats: Arc<Mutex<CacheStats>>,
}


#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    
    pub total_queries: u64,
    
    pub hits: u64,
    
    pub misses: u64,
    
    pub total_writes: u64,
    
    pub current_entries: usize,
    
    pub cleanup_count: u64,
}

impl CacheStats {
    
    pub fn hit_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            (self.hits as f64 / self.total_queries as f64) * 100.0
        }
    }

    
    pub fn format(&self) -> String {
        format!(
            "查询: {} | 命中: {} ({:.1}%) | 未命中: {} | 写入: {} | 当前条目: {} | 清理: {}",
            self.total_queries,
            self.hits,
            self.hit_rate(),
            self.misses,
            self.total_writes,
            self.current_entries,
            self.cleanup_count
        )
    }
}

impl ScanCache {
    
    
    
    
    
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            stats: Arc::new(Mutex::new(CacheStats::default())),
        }
    }

    
    
    
    
    
    
    
    
    
    
    pub async fn get(&self, ip: IpAddr, port: u16) -> Option<(PortState, Option<String>)> {
        let mut stats = self.stats.lock().await;
        stats.total_queries += 1;
        drop(stats);

        let cache = self.cache.lock().await;

        if let Some(cached) = cache.get(&(ip, port)) {
            if !cached.is_expired(self.ttl) {
                debug!("缓存命中: {}:{}", ip, port);

                let mut stats = self.stats.lock().await;
                stats.hits += 1;

                return Some((cached.state, cached.banner.clone()));
            } else {
                debug!("缓存过期: {}:{}", ip, port);
            }
        }

        let mut stats = self.stats.lock().await;
        stats.misses += 1;

        None
    }

    
    
    
    
    
    
    
    
    pub async fn set(&self, ip: IpAddr, port: u16, state: PortState, banner: Option<String>) {
        let mut stats = self.stats.lock().await;
        stats.total_writes += 1;
        drop(stats);

        let mut cache = self.cache.lock().await;
        cache.insert((ip, port), CachedResult::new(state, banner));

        debug!("缓存写入: {}:{}", ip, port);

        let mut stats = self.stats.lock().await;
        stats.current_entries = cache.len();
    }

    
    
    
    
    
    pub async fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.lock().await;
        let before = cache.len();

        cache.retain(|_, result| !result.is_expired(self.ttl));

        let removed = before - cache.len();
        if removed > 0 {
            debug!("清理过期缓存: {} 个条目", removed);

            let mut stats = self.stats.lock().await;
            stats.cleanup_count += 1;
            stats.current_entries = cache.len();
        }

        removed
    }

    
    pub async fn clear(&self) {
        let mut cache = self.cache.lock().await;
        let count = cache.len();
        cache.clear();

        debug!("清空缓存: {} 个条目", count);
        let mut stats = self.stats.lock().await;
        stats.current_entries = 0;
    }

    
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.lock().await.clone()
    }

    
    
    
    
    
    
    
    pub fn start_cleanup_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                self.cleanup_expired().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache = ScanCache::new(Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let port = 80;

        
        assert!(cache.get(ip, port).await.is_none());

        
        cache
            .set(ip, port, PortState::Open, Some("HTTP/1.1".to_string()))
            .await;

        
        let result = cache.get(ip, port).await;
        assert!(result.is_some());
        let (state, banner) = result.unwrap();
        assert_eq!(state, PortState::Open);
        assert_eq!(banner, Some("HTTP/1.1".to_string()));

        
        let stats = cache.get_stats().await;
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.total_writes, 1);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = ScanCache::new(Duration::from_millis(100));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let port = 80;

        
        cache.set(ip, port, PortState::Open, None).await;

        
        assert!(cache.get(ip, port).await.is_some());

        
        tokio::time::sleep(Duration::from_millis(150)).await;

        
        assert!(cache.get(ip, port).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = ScanCache::new(Duration::from_millis(100));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        
        for port in 80..90 {
            cache.set(ip, port, PortState::Open, None).await;
        }

        let stats = cache.get_stats().await;
        assert_eq!(stats.current_entries, 10);

        
        tokio::time::sleep(Duration::from_millis(150)).await;

        
        let removed = cache.cleanup_expired().await;
        assert_eq!(removed, 10);

        let stats = cache.get_stats().await;
        assert_eq!(stats.current_entries, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = ScanCache::new(Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        
        cache.get(ip, 80).await; 
        cache.set(ip, 80, PortState::Open, None).await;
        cache.get(ip, 80).await; 
        cache.get(ip, 81).await; 

        let stats = cache.get_stats().await;
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.total_writes, 1);
        assert_eq!(stats.hit_rate(), 33.333333333333336);
    }
}
