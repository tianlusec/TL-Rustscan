use futures::future::{BoxFuture, FutureExt};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

static ICMP_PERMISSION_WARNED: AtomicBool = AtomicBool::new(false);

async fn icmp_check(ip: IpAddr, timeout_ms: u64) -> bool {
    let payload = [0; 8];
    let ping_task = async {
        match surge_ping::ping(ip, &payload).await {
            Ok(_) => true,
            Err(e) => {
                let err_msg = e.to_string().to_lowercase();
                if (err_msg.contains("permission")
                    || err_msg.contains("access")
                    || err_msg.contains("socket"))
                    && !ICMP_PERMISSION_WARNED.load(Ordering::Relaxed)
                {
                    warn!("ICMP Ping failed likely due to permissions ({}). Try running as Administrator/Root.", e);
                    ICMP_PERMISSION_WARNED.store(true, Ordering::Relaxed);
                }
                false
            }
        }
    };

    match timeout(Duration::from_millis(timeout_ms), ping_task).await {
        Ok(result) => result,
        Err(_) => false,
    }
}

async fn connect_with_retry(addr: SocketAddr, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let mut backoff = 20;
    let timeout_duration = Duration::from_millis(timeout_ms);

    loop {
        if start.elapsed() > timeout_duration {
            return false;
        }
        let remaining = timeout_duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return false;
        }

        let connect_result = tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&addr, remaining)
        })
        .await;

        match connect_result {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) => {
                let raw_err = e.raw_os_error().unwrap_or(0);
                if raw_err == 24
                    || raw_err == 10024
                    || raw_err == 99
                    || raw_err == 10048
                    || raw_err == 10049
                {
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(1000);
                    continue;
                }
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    return true;
                }
                return false;
            }
            Err(_) => return false,
        }
    }
}







pub async fn is_host_alive(ip: IpAddr, timeout_ms: u64) -> bool {
    
    if icmp_check(ip, timeout_ms).await {
        return true;
    }

    
    
    
    
    
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[80, 443, 8080, 8443] {
        tasks.push(
            async move {
                let addr = SocketAddr::new(ip, port);
                connect_with_retry(addr, timeout_ms).await
            }
            .boxed(),
        );
    }
    while let Some(alive) = tasks.next().await {
        if alive {
            return true;
        }
    }

    
    
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[22, 23, 445, 139, 3389] {
        tasks.push(
            async move {
                let addr = SocketAddr::new(ip, port);
                connect_with_retry(addr, timeout_ms).await
            }
            .boxed(),
        );
    }
    while let Some(alive) = tasks.next().await {
        if alive {
            return true;
        }
    }

    
    
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[3306, 5432, 6379, 1433, 27017, 9200] {
        tasks.push(
            async move {
                let addr = SocketAddr::new(ip, port);
                connect_with_retry(addr, timeout_ms).await
            }
            .boxed(),
        );
    }
    while let Some(alive) = tasks.next().await {
        if alive {
            return true;
        }
    }

    false
}



pub async fn is_host_alive_fast(ip: IpAddr, timeout_ms: u64) -> bool {
    if icmp_check(ip, timeout_ms).await {
        return true;
    }

    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[80, 443, 22, 3389] {
        tasks.push(
            async move {
                let addr = SocketAddr::new(ip, port);
                connect_with_retry(addr, timeout_ms).await
            }
            .boxed(),
        );
    }
    
    while let Some(alive) = tasks.next().await {
        if alive {
            return true;
        }
    }

    false
}



pub async fn is_host_alive_deep(ip: IpAddr, timeout_ms: u64) -> bool {
    if icmp_check(ip, timeout_ms).await {
        return true;
    }

    
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    let all_ports = [
        
        80, 443, 8080, 8443, 8000, 8888,
        
        22, 23, 3389, 5900,
        
        445, 139, 21, 2049,
        
        3306, 5432, 6379, 1433, 27017, 9200, 5984,
        
        25, 110, 143, 53, 161, 389, 636,
    ];
    
    for &port in &all_ports {
        tasks.push(
            async move {
                let addr = SocketAddr::new(ip, port);
                connect_with_retry(addr, timeout_ms).await
            }
            .boxed(),
        );
    }
    
    while let Some(alive) = tasks.next().await {
        if alive {
            return true;
        }
    }

    false
}