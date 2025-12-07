




















use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;


struct PooledConnection {
    
    stream: TcpStream,
    
    last_used: Instant,
    
    created_at: Instant,
}

impl PooledConnection {
    fn new(stream: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            last_used: now,
            created_at: now,
        }
    }
    
    
    async fn is_alive(&self) -> bool {
        
        if self.created_at.elapsed() > Duration::from_secs(300) {
            return false;
        }

        
        if self.last_used.elapsed() > Duration::from_secs(60) {
            return false;
        }

        
        
        if let Err(e) = self.stream.writable().await {
            debug!("连接不可写: {}", e);
            return false;
        }

        
        let mut buf = [0u8; 1];
        match self.stream.peek(&mut buf).await {
            Ok(0) => {
                
                debug!("连接已关闭 (Peek 0 bytes)");
                return false;
            },
            Ok(_) => {
                
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                
            },
            Err(e) => {
                debug!("Peek 失败: {}", e);
                return false;
            }
        }

        
        
        true
    }

    
    fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}




pub struct ConnectionPool {
    
    pools: Arc<Mutex<HashMap<SocketAddr, Vec<PooledConnection>>>>,
    
    max_per_target: usize,
    
    max_idle_time: Duration,
    
    stats: Arc<Mutex<PoolStats>>,
}


#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    
    pub total_acquires: u64,
    
    pub hits: u64,
    
    pub misses: u64,
    
    pub total_releases: u64,
    
    pub health_check_failures: u64,
    
    pub current_pooled: usize,
}

impl PoolStats {
    
    pub fn hit_rate(&self) -> f64 {
        if self.total_acquires == 0 {
            0.0
        } else {
            (self.hits as f64 / self.total_acquires as f64) * 100.0
        }
    }

    
    pub fn format(&self) -> String {
        format!(
            "获取: {} | 命中: {} ({:.1}%) | 未命中: {} | 释放: {} | 健康检查失败: {} | 当前连接数: {}",
            self.total_acquires,
            self.hits,
            self.hit_rate(),
            self.misses,
            self.total_releases,
            self.health_check_failures,
            self.current_pooled
        )
    }
}

impl ConnectionPool {
    
    
    
    
    
    
    pub fn new(max_per_target: usize, max_idle_time: Duration) -> Self {
        Self {
            pools: Arc::new(Mutex::new(HashMap::new())),
            max_per_target,
            max_idle_time,
            stats: Arc::new(Mutex::new(PoolStats::default())),
        }
    }

    
    
    
    
    
    
    
    
    
    
    
    pub async fn acquire(&self, addr: SocketAddr) -> Option<TcpStream> {
        let mut stats = self.stats.lock().await;
        stats.total_acquires += 1;
        drop(stats);

        let mut pools = self.pools.lock().await;

        if let Some(connections) = pools.get_mut(&addr) {
            
            while let Some(mut conn) = connections.pop() {
                
                if conn.is_alive().await {
                    conn.touch();
                    debug!("从连接池获取连接: {}", addr);

                    let mut stats = self.stats.lock().await;
                    stats.hits += 1;
                    stats.current_pooled = pools.values().map(|v| v.len()).sum();

                    return Some(conn.stream);
                } else {
                    debug!("连接池中的连接已失效: {}", addr);
                    let mut stats = self.stats.lock().await;
                    stats.health_check_failures += 1;
                }
            }
        }

        
        let mut stats = self.stats.lock().await;
        stats.misses += 1;
        stats.current_pooled = pools.values().map(|v| v.len()).sum();

        None
    }

    
    
    
    
    
    
    pub async fn release(&self, addr: SocketAddr, stream: TcpStream) {
        let mut stats = self.stats.lock().await;
        stats.total_releases += 1;
        drop(stats);

        let mut pools = self.pools.lock().await;

        let connections = pools.entry(addr).or_insert_with(Vec::new);

        
        if connections.len() >= self.max_per_target {
            debug!("连接池已满，丢弃连接: {}", addr);
            return;
        }

        
        connections.push(PooledConnection::new(stream));
        debug!("连接已释放回池: {} (池大小: {})", addr, connections.len());

        let mut stats = self.stats.lock().await;
        stats.current_pooled = pools.values().map(|v| v.len()).sum();
    }

    
    
    
    pub async fn cleanup_idle(&self) {
        let mut pools = self.pools.lock().await;
        let mut total_removed = 0;

        for (addr, connections) in pools.iter_mut() {
            let before = connections.len();
            connections.retain(|conn| conn.last_used.elapsed() < self.max_idle_time);
            let removed = before - connections.len();
            if removed > 0 {
                debug!("清理 {} 的空闲连接: {} 个", addr, removed);
                total_removed += removed;
            }
        }

        
        pools.retain(|_, connections| !connections.is_empty());

        if total_removed > 0 {
            debug!("总共清理了 {} 个空闲连接", total_removed);let mut stats = self.stats.lock().await;
            stats.current_pooled = pools.values().map(|v| v.len()).sum();
        }
    }

    
    pub async fn clear(&self) {
        let mut pools = self.pools.lock().await;
        let total = pools.values().map(|v| v.len()).sum::<usize>();
        pools.clear();
        debug!("清空连接池，移除 {} 个连接", total);

        let mut stats = self.stats.lock().await;
        stats.current_pooled = 0;
    }

    
    pub async fn get_stats(&self) -> PoolStats {
        self.stats.lock().await.clone()
    }

    
    
    
    
    
    
    pub fn start_cleanup_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                self.cleanup_idle().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_pool_basic() {
        let pool = ConnectionPool::new(5, Duration::from_secs(30));
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();

        
        assert!(pool.acquire(addr).await.is_none());

        let stats = pool.get_stats().await;
        assert_eq!(stats.total_acquires, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let pool = ConnectionPool::new(5, Duration::from_secs(30));
        
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        pool.acquire(addr).await;
        let stats = pool.get_stats().await;
        assert!(stats.total_acquires > 0);
        assert_eq!(stats.hit_rate(), 0.0); 
    }
}