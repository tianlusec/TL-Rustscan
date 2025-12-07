use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::ServerName;
use x509_parser::prelude::*;
use crate::scanner::probes;
use socket2::Socket;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

async fn socks5_handshake(mut stream: TcpStream, target: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    
    stream.write_all(&[0x05, 0x01, 0x00]).await?; 
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 handshake failed: unsupported auth"));
    }

    
    let mut request = vec![0x05, 0x01, 0x00]; 
    match target {
        std::net::SocketAddr::V4(v4) => {
            request.push(0x01); 
            request.extend_from_slice(&v4.ip().octets());
        },
        std::net::SocketAddr::V6(v6) => {
            request.push(0x04); 
            request.extend_from_slice(&v6.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[1] != 0x00 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 connect failed: code {}", resp_header[1])));
    }
    
    
    match resp_header[3] {
        0x01 => { let mut buf = [0u8; 4 + 2]; stream.read_exact(&mut buf).await?; }, 
        0x03 => { 
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2];
            stream.read_exact(&mut buf).await?;
        },
        0x04 => { let mut buf = [0u8; 16 + 2]; stream.read_exact(&mut buf).await?; }, 
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "SOCKS5 invalid address type")),
    }

    Ok(stream)
}

async fn connect_with_backoff(target_addr: std::net::SocketAddr, timeout_ms: u64, proxy_addr: Option<std::net::SocketAddr>) -> std::io::Result<TcpStream> {
    let start = std::time::Instant::now();
    let mut backoff = 20;
    let timeout_duration = Duration::from_millis(timeout_ms);
    let connect_addr = proxy_addr.unwrap_or(target_addr);

    
    let jitter = rand::random::<u64>() % 50;
    tokio::time::sleep(Duration::from_millis(jitter)).await;

    loop {
        if start.elapsed() > timeout_duration {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"));
        }
        let remaining = timeout_duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"));
        }

        #[cfg(target_os = "windows")]
        let connect_result = {
            
            let addr_copy = connect_addr;
            tokio::task::spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr_copy, remaining)
            }).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        };

        #[cfg(not(target_os = "windows"))]
        let connect_result = {
            
            timeout(remaining, TcpStream::connect(connect_addr)).await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"))?
                .and_then(|s| s.into_std()) 
        };

        match connect_result {
            Ok(std_stream) => {
                
                std_stream.set_nonblocking(true)?;
                let mut stream = TcpStream::from_std(std_stream)?;
                
                if proxy_addr.is_some() {
                    
                    let handshake_remaining = timeout_duration.saturating_sub(start.elapsed());
                    if handshake_remaining.is_zero() {
                         return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out during handshake"));
                    }
                    match timeout(handshake_remaining, socks5_handshake(stream, target_addr)).await {
                        Ok(Ok(s)) => stream = s,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out during handshake")),
                    }
                }
                
                return Ok(stream);
            },
            Err(e) => {
                let raw_err = e.raw_os_error().unwrap_or(0);
                
                if raw_err == 10048 || raw_err == 98 || raw_err == 48 {
                    
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    backoff = (backoff * 2).min(2000);
                    continue;
                }
                if raw_err == 24 || raw_err == 10024 || raw_err == 99 || raw_err == 10049 {
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(1000);
                    continue;
                }
                return Err(e);
            },
        }
    }
}

use std::sync::Arc;
use crate::scanner::connection_pool::ConnectionPool;
use crate::scanner::rate_limit::TokenBucket;
use crate::error::{ErrorStats, ScanError};
use tokio::sync::Mutex;

pub struct TcpScanArgs<'a> {
    pub ip: IpAddr,
    pub port: u16,
    pub host: Arc<String>,
    pub timeout_ms: u64,
    pub grab_banner: bool,
    pub dir_scan: bool,
    pub dir_paths: &'a [String],
    pub web_ports: &'a [u16],
    pub insecure: bool,
    pub proxy: Option<String>,
    pub connection_pool: Option<Arc<ConnectionPool>>,
    pub rate_limiter: Option<Arc<Mutex<TokenBucket>>>,
    pub deep_scan: bool,
    pub error_stats: Option<Arc<Mutex<ErrorStats>>>,
}

pub async fn scan_single_port(args: TcpScanArgs<'_>) -> (PortState, Option<String>, Vec<String>) {
    let ip = args.ip;
    let port = args.port;
    let host = args.host.clone();
    let timeout_ms = args.timeout_ms;
    let grab_banner = args.grab_banner;
    let dir_scan = args.dir_scan;
    let dir_paths = args.dir_paths;
    let web_ports = args.web_ports;
    let insecure = args.insecure;
    let proxy = args.proxy.clone();
    let connection_pool = args.connection_pool.clone();
    let rate_limiter = args.rate_limiter.clone();
    let deep_scan = args.deep_scan;
    let error_stats = args.error_stats.clone();

    let proxy_addr = if let Some(ref p) = proxy {
        if let Ok(url) = Url::parse(p) {
            if let Some(h) = url.host_str() {
                let port = url.port().unwrap_or(1080);
                match tokio::net::lookup_host((h, port)).await {
                    Ok(mut addrs) => addrs.next(),
                    Err(_) => None,
                }
            } else { None }
        } else { None }
    } else { None };

    let addr = std::net::SocketAddr::new(ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    
    if let Some(limiter) = &rate_limiter {
        limiter.lock().await.acquire().await;
    }

    
    let mut stream_opt = None;
    if let Some(pool) = &connection_pool {
        if let Some(s) = pool.acquire(addr).await {
            stream_opt = Some(s);
        }
    }

    
    if stream_opt.is_none() {
        match connect_with_backoff(addr, timeout_ms, proxy_addr).await {
            Ok(s) => stream_opt = Some(s),
            Err(e) => {
                if let Some(stats) = &error_stats {
                    let scan_error = match e.kind() {
                        std::io::ErrorKind::TimedOut => ScanError::Timeout { port, timeout: timeout_ms },
                        std::io::ErrorKind::ConnectionRefused => ScanError::ConnectionFailed { target: ip, port, reason: "Connection Refused".to_string() },
                        _ => ScanError::ConnectionFailed { target: ip, port, reason: e.to_string() },
                    };
                    stats.lock().await.record(&scan_error);
                }
                return match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => (PortState::Closed, None, Vec::new()),
                    _ => (PortState::Filtered, None, Vec::new()),
                };
            }
        }
    }

    let mut stream = stream_opt.unwrap();

    
    

    
    
    {
            let mut banner = None;
            let mut dirs = Vec::new();
            if grab_banner {
                let mut buffer = vec![0u8; 4096]; 
                let read_timeout = Duration::from_millis(timeout_ms);
                
                let mut total_read = 0;
                let start = std::time::Instant::now();
                
                match timeout(read_timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        total_read += n;
                        while total_read < buffer.len() && start.elapsed() < read_timeout {
                            
                            let elapsed = start.elapsed();
                            if elapsed >= read_timeout { break; }
                            let remaining = read_timeout - elapsed;
                            
                            let wait_time = std::cmp::min(remaining, Duration::from_millis(500));
                            
                            match timeout(wait_time, stream.read(&mut buffer[total_read..])).await {
                                Ok(Ok(chunk)) if chunk > 0 => total_read += chunk,
                                _ => break, 
                            }
                        }

                        if let Some(identified) = probes::match_service_signature(&buffer[..total_read]) {
                            banner = Some(identified);
                        } else {
                            let s = String::from_utf8_lossy(&buffer[..total_read]).to_string();
                            banner = Some(probes::clean_banner(&s));
                        }
                    }
                    _ => {
                        if port == 6379 {
                            banner = probes::probe_redis(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 22 {
                            banner = probes::probe_ssh(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 3306 {
                            banner = probes::probe_mysql(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 5432 {
                            banner = probes::probe_postgresql(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 3389 {
                            banner = probes::probe_rdp(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 21 {
                            banner = probes::probe_ftp(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 23 {
                            banner = probes::probe_telnet(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 25 {
                            banner = probes::probe_smtp(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 11211 {
                            banner = probes::probe_memcached(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 445 {
                            banner = probes::probe_smb(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 27017 {
                            banner = probes::probe_mongodb(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 1433 {
                            banner = probes::probe_mssql(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 1521 {
                            banner = probes::probe_oracle(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 5900 {
                            banner = probes::probe_vnc(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 389 || port == 636 {
                            banner = probes::probe_ldap(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 2181 {
                            banner = probes::probe_zookeeper(&mut stream, &mut buffer, timeout_ms).await;
                        } else if [8000, 8080, 5005, 9000].contains(&port) {
                            
                            banner = probes::probe_jdwp(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 1099 {
                            banner = probes::probe_rmi(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 554 || port == 8554 {
                            banner = probes::probe_rtsp(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 1080 {
                            banner = probes::probe_socks5(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 1883 {
                            banner = probes::probe_mqtt(&mut stream, &mut buffer, timeout_ms).await;
                        } else if port == 5672 {
                            banner = probes::probe_amqp(&mut stream, &mut buffer, timeout_ms).await;
                        }
                        let looks_like_http = if let Some(ref b) = banner {
                            let b_upper = b.to_uppercase();
                            b_upper.contains("HTTP/") || b_upper.contains("<HTML") || b_upper.contains("<HEAD")
                        } else {
                            false
                        };
                        
                        let is_known_web_port = web_ports.contains(&port);
                        
                        if banner.is_none() || looks_like_http || is_known_web_port {
                            let is_https_port = [443, 8443, 4443, 9443, 10443].contains(&port);
                            let mut tls_success = false;
                            let mut redirect_location = None;
                            if is_https_port || (deep_scan && banner.is_none()) {
                                if let Ok(Ok(mut tls_stream)) = timeout(timeout_duration, async {
                                    let connector = probes::get_tls_connector(insecure);
                                    let domain = ServerName::try_from(host.as_str()).unwrap_or(ServerName::try_from("example.com").unwrap());
                                    
                                    let tcp = connect_with_backoff(addr, timeout_ms, proxy_addr).await?;
                                    connector.connect(domain, tcp).await
                                }).await {
                                    tls_success = true;
                                    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                                        if let Some(cert) = certs.first() {
                                            if let Ok((_, x509)) = X509Certificate::from_der(&cert.0) {
                                                let subject = x509.subject().to_string();
                                                let issuer = x509.issuer().to_string();
                                                let mut banner_str = format!("TLS: {} (Issuer: {})", subject, issuer);
                                                
                                                
                                                let mut sans = Vec::new();
                                                let extensions = x509.extensions();
                                                for ext in extensions {
                                                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                                                        for name in &san.general_names {
                                                            if let GeneralName::DNSName(dns) = name {
                                                                sans.push(dns.to_string());
                                                            } else if let GeneralName::IPAddress(ip) = name {
                                                                if ip.len() == 4 {
                                                                    let arr: [u8; 4] = [ip[0], ip[1], ip[2], ip[3]];
                                                                    sans.push(std::net::IpAddr::from(arr).to_string());
                                                                } else if ip.len() == 16 {
                                                                    let mut arr = [0u8; 16];
                                                                    arr.copy_from_slice(ip);
                                                                    sans.push(std::net::IpAddr::from(arr).to_string());
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                
                                                if !sans.is_empty() {
                                                    
                                                    sans.sort();
                                                    sans.dedup();
                                                    let total_sans = sans.len();
                                                    let san_display: Vec<String> = sans.into_iter().take(5).collect();
                                                    banner_str.push_str(&format!(" | SANs: {}", san_display.join(", ")));
                                                    if total_sans > 5 {
                                                        banner_str.push_str(", ...");
                                                    }
                                                }
                                                
                                                banner = Some(banner_str);
                                            }
                                        }
                                    }
                                    let host_header = probes::format_host_header(&host);
                                    let ua = probes::get_user_agent();
                                    let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", host_header, ua);
                                    if tls_stream.write_all(req.as_bytes()).await.is_ok() {
                                        let mut total_read = 0;
                                        let start = std::time::Instant::now();
                                        while total_read < buffer.len() && start.elapsed() < read_timeout {
                                            match timeout(Duration::from_millis(200), tls_stream.read(&mut buffer[total_read..])).await {
                                                Ok(Ok(n)) if n > 0 => total_read += n,
                                                _ => break, 
                                            }
                                        }
                                        if total_read > 0 {
                                            let response = String::from_utf8_lossy(&buffer[..total_read]);
                                            let (http_banner, loc) = probes::parse_http_banner(&response);
                                            redirect_location = loc;
                                            if let Some(http_banner) = http_banner {
                                                if let Some(b) = banner {
                                                    banner = Some(format!("{} | {}", b, http_banner));
                                                } else {
                                                    banner = Some(http_banner.clone());
                                                }
                                                if deep_scan {
                                                    if http_banner.contains("Vue") || http_banner.contains("Element UI") {
                                                        let ua = probes::get_user_agent();
                                                        if let Some(api_title) = probes::probe_ruoyi_api(ip, port, &host, true, timeout_ms, &ua, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                            if let Some(b) = banner {
                                                                banner = Some(format!("{} | {}", b, api_title));
                                                            } else {
                                                                banner = Some(api_title);
                                                            }
                                                        }
                                                    }
                                                    if let Some(fav) = probes::probe_favicon(ip, port, &host, true, timeout_ms, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                        if let Some(b) = banner {
                                                            banner = Some(format!("{} | {}", b, fav));
                                                        } else {
                                                            banner = Some(fav);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if !tls_success {
                                let host_header = probes::format_host_header(&host);
                                let ua = probes::get_user_agent();
                                let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", host_header, ua);
                                
                                let mut write_success = stream.write_all(req.as_bytes()).await.is_ok();
                                if !write_success {
                                    if let Ok(mut new_stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                                        if new_stream.write_all(req.as_bytes()).await.is_ok() {
                                            stream = new_stream;
                                            write_success = true;
                                        }
                                    }
                                }

                                if write_success {
                                    let mut total_read = 0;
                                    let start = std::time::Instant::now();
                                    while total_read < buffer.len() && start.elapsed() < read_timeout {
                                        match timeout(Duration::from_millis(200), stream.read(&mut buffer[total_read..])).await {
                                            Ok(Ok(n)) if n > 0 => total_read += n,
                                            _ => break,
                                        }
                                    }
                                    if total_read > 0 {
                                        let response = String::from_utf8_lossy(&buffer[..total_read]);
                                        if response.starts_with("HTTP/") || response.contains("HTTP/1.") { 
                                            let (http_banner, loc) = probes::parse_http_banner(&response);
                                            
                                            if let Some(new_b) = http_banner {
                                                if let Some(old_b) = banner {
                                                    banner = Some(format!("{} | {}", old_b, new_b));
                                                } else {
                                                    banner = Some(new_b);
                                                }
                                            }
                                            
                                            redirect_location = loc;
                                            if deep_scan {
                                                let mut is_vue = false;
                                                if let Some(ref b_str) = banner {
                                                    if b_str.contains("Vue") || b_str.contains("Element UI") {
                                                        is_vue = true;
                                                    }
                                                }
                                                
                                                if is_vue {
                                                    let ua = probes::get_user_agent();
                                                    if let Some(api_title) = probes::probe_ruoyi_api(ip, port, &host, false, timeout_ms, &ua, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                        if let Some(b) = banner {
                                                            banner = Some(format!("{} | {}", b, api_title));
                                                        } else {
                                                            banner = Some(api_title);
                                                        }
                                                    }
                                                }

                                                if let Some(fav) = probes::probe_favicon(ip, port, &host, false, timeout_ms, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                    if let Some(b) = banner {
                                                        banner = Some(format!("{} | {}", b, fav));
                                                    } else {
                                                        banner = Some(fav);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(loc) = redirect_location {
                                let (new_scheme, new_host, new_port, new_path) = if let Ok(parsed_url) = Url::parse(&loc) {
                                    let scheme = parsed_url.scheme();
                                    let host_str = parsed_url.host_str().unwrap_or("").to_string();
                                    let port = parsed_url.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
                                    let path = if parsed_url.query().is_some() {
                                        format!("{}?{}", parsed_url.path(), parsed_url.query().unwrap())
                                    } else {
                                        parsed_url.path().to_string()
                                    };
                                    (scheme.to_string(), host_str, port, path)
                                } else if loc.starts_with('/') {
                                    let scheme = if tls_success { "https" } else { "http" };
                                    (scheme.to_string(), host.to_string(), port, loc.clone())
                                } else {
                                    ("unknown".to_string(), String::new(), 0, String::new())
                                };

                                if new_scheme != "unknown" {
                                    let new_addr = std::net::SocketAddr::new(ip, new_port);
                                    let ua = probes::get_user_agent();
                                    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", new_path, new_host, ua);
                                    
                                    if new_scheme == "https" {
                                         if let Ok(tcp) = connect_with_backoff(new_addr, timeout_ms, proxy_addr).await {
                                            if let Ok(Ok(mut tls_stream)) = timeout(timeout_duration, async {
                                                let connector = probes::get_tls_connector(insecure);
                                                let domain = ServerName::try_from(new_host.as_str()).unwrap_or(ServerName::try_from("example.com").unwrap());
                                                connector.connect(domain, tcp).await
                                            }).await {
                                                let mut tls_banner_part = String::new();
                                                let mut is_vue_app = false;
                                                if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                                                    if let Some(cert) = certs.first() {
                                                        if let Ok((_, x509)) = X509Certificate::from_der(&cert.0) {
                                                            let subject = x509.subject().to_string();
                                                            tls_banner_part.push_str(&format!("TLS Cert: {}", subject));
                                                        }
                                                    }
                                                }
                                                if tls_stream.write_all(req.as_bytes()).await.is_ok() {
                                                    if let Ok(Ok(n)) = timeout(read_timeout, tls_stream.read(&mut buffer)).await {
                                                        if n > 0 {
                                                            let response = String::from_utf8_lossy(&buffer[..n]);
                                                            let (http_banner, _) = probes::parse_http_banner(&response);
                                                            if let Some(http_banner) = http_banner {
                                                                if !tls_banner_part.is_empty() { tls_banner_part.push_str(" | "); }
                                                                tls_banner_part.push_str(&http_banner);
                                                                if http_banner.contains("Vue") || http_banner.contains("Element UI") { is_vue_app = true; }
                                                            }
                                                        }
                                                    }
                                                }
                                                if deep_scan && is_vue_app {
                                                    let ua = probes::get_user_agent();
                                                    if let Some(api_title) = probes::probe_ruoyi_api(ip, new_port, &new_host, true, timeout_ms, &ua, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                        tls_banner_part.push_str(" | ");
                                                        tls_banner_part.push_str(&api_title);
                                                    }
                                                }
                                                if !tls_banner_part.is_empty() {
                                                    if let Some(b) = banner { banner = Some(format!("{} => [{}]", b, tls_banner_part)); }
                                                    else { banner = Some(tls_banner_part); }
                                                }
                                            }
                                         }
                                    } else if let Ok(mut new_stream) = connect_with_backoff(new_addr, timeout_ms, proxy_addr).await {
                                        if new_stream.write_all(req.as_bytes()).await.is_ok() {
                                            if let Ok(Ok(n)) = timeout(read_timeout, new_stream.read(&mut buffer)).await {
                                                if n > 0 {
                                                    let response = String::from_utf8_lossy(&buffer[..n]);
                                                    let (http_banner, _) = probes::parse_http_banner(&response);
                                                    let mut is_vue_app = false;
                                                    if let Some(http_banner) = http_banner {
                                                        if let Some(b) = banner { banner = Some(format!("{} => [{}]", b, http_banner)); }
                                                        else { banner = Some(http_banner.clone()); }
                                                        if http_banner.contains("Vue") || http_banner.contains("Element UI") { is_vue_app = true; }
                                                    }
                                                    if deep_scan && is_vue_app {
                                                        let ua = probes::get_user_agent();
                                                        if let Some(api_title) = probes::probe_ruoyi_api(ip, new_port, &new_host, false, timeout_ms, &ua, insecure, proxy.clone(), rate_limiter.clone()).await {
                                                            if let Some(b) = banner { banner = Some(format!("{} | {}", b, api_title)); }
                                                            else { banner = Some(api_title); }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            
            
            
            
            if banner.is_none() && deep_scan {
                let mut buffer = vec![0u8; 4096];
                
                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_redis(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_mongodb(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_postgresql(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }
                
                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_jdwp(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_socks5(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_rtsp(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_mqtt(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }

                
                if banner.is_none() {
                    if let Ok(mut stream) = connect_with_backoff(addr, timeout_ms, proxy_addr).await {
                        if let Some(res) = probes::probe_amqp(&mut stream, &mut buffer, timeout_ms).await {
                            banner = Some(res);
                        }
                    }
                }
            }

            if dir_scan {
                let is_known_web_port = web_ports.contains(&port);
                let is_detected_http = if let Some(ref b) = banner {
                    let b_upper = b.to_uppercase();
                    b_upper.contains("HTTP") || b_upper.contains("HTML") || b_upper.contains("TITLE:")
                } else {
                    false
                };

                if is_known_web_port || is_detected_http {
                    dirs = crate::scanner::web_dir::scan_dirs(ip, port, &host, dir_paths, timeout_ms, banner.as_deref(), insecure, proxy.clone(), rate_limiter.clone()).await;
                }
            }
            
            if let Some(pool) = &connection_pool {
                pool.release(addr, stream).await;
            } else {
                if let Ok(std_stream) = stream.into_std() {
                     let socket = Socket::from(std_stream);
                     let _ = socket.set_linger(Some(Duration::from_secs(0)));
                }
            }

            (PortState::Open, banner, dirs)
    }
}