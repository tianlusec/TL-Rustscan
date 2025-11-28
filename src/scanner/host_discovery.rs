use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::future::{BoxFuture, FutureExt};
use std::sync::atomic::{AtomicBool, Ordering};

static ICMP_PERMISSION_WARNED: AtomicBool = AtomicBool::new(false);

async fn icmp_check(ip: IpAddr, timeout_ms: u64) -> bool {
    let payload = [0; 8];
    let ping_task = async {
        match surge_ping::ping(ip, &payload).await {
            Ok(_) => true,
            Err(e) => {
                let err_msg = e.to_string().to_lowercase();
                if (err_msg.contains("permission") || err_msg.contains("access") || err_msg.contains("socket")) 
                    && !ICMP_PERMISSION_WARNED.load(Ordering::Relaxed) {
                    eprintln!("Warning: ICMP Ping failed likely due to permissions ({}). Try running as Administrator/Root.", e);
                    ICMP_PERMISSION_WARNED.store(true, Ordering::Relaxed);
                }
                false
            },
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

        // 使用 spawn_blocking + std::net::TcpStream::connect_timeout 绕过 Windows 异步连接的超时陷阱
        let connect_result = tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&addr, remaining)
        }).await;

        match connect_result {
            Ok(Ok(_)) => return true, // 连接成功
            Ok(Err(e)) => {
                let raw_err = e.raw_os_error().unwrap_or(0);
                // 资源暂时不可用或网络忙，进行退避重试
                if raw_err == 24 || raw_err == 10024 || raw_err == 99 || raw_err == 10048 || raw_err == 10049 {
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(1000);
                    continue;
                }
                // 连接被拒绝 (RST)，说明主机是活着的（只是端口没开）
                // 在主机发现阶段，只要有 RST 回包，就证明 IP 存活
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    return true; 
                }
                // 其他错误（如超时、不可达），继续尝试其他端口或返回 false
                return false;
            },
            Err(_) => return false, // JoinError
        }
    }
}

pub async fn is_host_alive(ip: IpAddr, timeout_ms: u64) -> bool {
    // 1. 优先尝试 ICMP (成本最低)
    if icmp_check(ip, timeout_ms).await {
        return true;
    }

    // 2. TCP 探测
    // Windows 下必须控制并发，避免僵尸任务耗尽线程池
    // 我们采用串行 + 小批量的策略
    
    // 第一批：最常见端口 (80, 443)
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[80, 443] {
        tasks.push(async move {
            let addr = SocketAddr::new(ip, port);
            connect_with_retry(addr, timeout_ms).await
        }.boxed());
    }
    while let Some(alive) = tasks.next().await {
        if alive { return true; }
    }

    // 第二批：其他关键端口 (22, 445, 3389)
    let mut tasks: FuturesUnordered<BoxFuture<'static, bool>> = FuturesUnordered::new();
    for &port in &[22, 445, 3389] {
        tasks.push(async move {
            let addr = SocketAddr::new(ip, port);
            connect_with_retry(addr, timeout_ms).await
        }.boxed());
    }
    while let Some(alive) = tasks.next().await {
        if alive { return true; }
    }

    false
}