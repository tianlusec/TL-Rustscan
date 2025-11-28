use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::sync::OnceLock;
use crate::scanner::probes::{get_http_client, get_user_agent};
use tokio::sync::Semaphore;

fn get_no_redirect_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("TL-Rustscan")
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default()
    })
}

use futures::stream::{self, StreamExt};

static DIR_SCAN_LIMITER: OnceLock<Semaphore> = OnceLock::new();

pub async fn scan_dirs(ip: IpAddr, port: u16, host: &str, paths: &[String], timeout_ms: u64, banner: Option<&str>) -> Vec<String> {
    // 全局限制同时进行目录扫描的任务数，防止在端口并发很高时，
    // 每个端口又开启大量目录扫描请求，导致文件描述符耗尽或 OOM。
    // 限制为 20 个并发目录扫描任务，每个任务内部可能有 10-50 个并发请求。
    // 总并发请求数控制在 20 * 50 = 1000 左右，是安全的。
    let _permit = DIR_SCAN_LIMITER.get_or_init(|| Semaphore::new(20)).acquire().await;

    // 动态调整并发度：如果路径很多，使用较高的并发；否则使用较低的并发
    let concurrency = if paths.len() > 100 { 50 } else { 10 };
    
    let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
    let is_ip = host.parse::<IpAddr>().is_ok();
    let base_url = if is_ip {
        let host_str = crate::scanner::probes::format_host(ip);
        format!("{}://{}:{}", scheme, host_str, port)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    };
    
    let use_global_client = is_ip || scheme == "http";

    let client = if !use_global_client {
        let addr = SocketAddr::new(ip, port);
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::none()) 
            .resolve(host, addr)
            .build()
            .unwrap_or_else(|_| get_http_client().clone())
    } else {
        get_no_redirect_client().clone()
    };

    // 1. 软 404 检测 (Soft 404 Detection)
    // 随机生成一个不存在的路径，检查服务器的响应。
    // 如果返回 200 OK，记录其特征（状态码、长度），用于过滤后续的误报。
    let random_path = format!("tl_scan_{}", rand::random::<u32>());
    let (baseline_status, baseline_len) = {
        let (url, host_header) = if use_global_client && !is_ip {
            (format!("{}://{}:{}/{}", scheme, crate::scanner::probes::format_host(ip), port, random_path), Some(host))
        } else {
            (format!("{}/{}", base_url, random_path), None)
        };
        
        let mut req = client.get(&url)
            .timeout(Duration::from_millis(timeout_ms))
            .header(reqwest::header::USER_AGENT, get_user_agent());
        
        if let Some(h) = host_header {
            req = req.header("Host", h);
        }

        if let Ok(mut resp) = req.send().await {
            let status = resp.status();
            // 如果 Content-Length 未知 (如 Chunked)，则读取 Body 计算长度
            let len = if let Some(l) = resp.content_length() {
                l
            } else {
                // 限制读取大小，防止大文件耗尽内存 (限制为 1MB)
                let mut total_bytes = 0u64;
                let limit = 1024 * 1024; // 1MB
                
                while let Ok(Some(chunk)) = resp.chunk().await {
                    total_bytes += chunk.len() as u64;
                    if total_bytes > limit {
                        break;
                    }
                }
                total_bytes
            };
            (Some(status), len)
        } else {
            (None, 0)
        }
    };

    // 如果随机路径返回了 200 OK，说明存在泛解析或软 404
    let is_wildcard = if let Some(status) = baseline_status {
        status.is_success()
    } else {
        false
    };

    let mut extra_paths = Vec::new();
    if let Some(b) = banner {
        let b_lower = b.to_lowercase();
        if b_lower.contains("spring") || b_lower.contains("java") {
            extra_paths.push("actuator".to_string());
            extra_paths.push("actuator/health".to_string());
            extra_paths.push("actuator/env".to_string());
            extra_paths.push("heapdump".to_string());
            extra_paths.push("jolokia".to_string());
            extra_paths.push("swagger-ui.html".to_string());
        }
        if b_lower.contains("php") {
            extra_paths.push("info.php".to_string());
            extra_paths.push("phpinfo.php".to_string());
            extra_paths.push("test.php".to_string());
        }
        if b_lower.contains("tomcat") {
            extra_paths.push("manager/html".to_string());
            extra_paths.push("host-manager/html".to_string());
        }
        if b_lower.contains("weblogic") {
            extra_paths.push("console/login/LoginForm.jsp".to_string());
            extra_paths.push("wls-wsat/CoordinatorPortType".to_string());
        }
        if b_lower.contains("drupal") {
            extra_paths.push("user/login".to_string());
            extra_paths.push("CHANGELOG.txt".to_string());
        }
        if b_lower.contains("wordpress") {
            extra_paths.push("wp-admin/".to_string());
            extra_paths.push("wp-login.php".to_string());
        }
    }

    let results = stream::iter(extra_paths.iter().chain(paths.iter()))
        .map(|path| {
            let client = &client;
            let base_url = &base_url;
            async move {
                let p = if let Some(stripped) = path.strip_prefix('/') { stripped } else { path };
                
                let (url, host_header) = if use_global_client && !is_ip {
                    (format!("{}://{}:{}/{}", scheme, crate::scanner::probes::format_host(ip), port, p), Some(host))
                } else {
                    (format!("{}/{}", base_url, p), None)
                };
                
                let mut req = client.get(&url)
                    .timeout(Duration::from_millis(timeout_ms))
                    .header(reqwest::header::USER_AGENT, get_user_agent());
                
                if let Some(h) = host_header {
                    req = req.header("Host", h);
                }

                let mut resp = if let Ok(r) = req.send().await { r } else { return None; };
                let status = resp.status();
                let len = if let Some(l) = resp.content_length() {
                    l
                } else {
                    let mut total_bytes = 0u64;
                    let limit = 1024 * 1024;
                    while let Ok(Some(chunk)) = resp.chunk().await {
                        total_bytes += chunk.len() as u64;
                        if total_bytes > limit { break; }
                    }
                    total_bytes
                };

                    // 过滤逻辑：
                    // 1. 如果开启了泛解析检测 (is_wildcard 为 true)，且当前响应状态码与基准状态码一致
                    //    并且响应长度与基准长度非常接近 (误差 < 30% 或 < 50 字节)，则认为是误报，直接忽略。
                    if is_wildcard {
                        if let Some(base_status) = baseline_status {
                            if status == base_status {
                                let diff = if len > baseline_len { len - baseline_len } else { baseline_len - len };
                                let ratio = diff as f64 / baseline_len.max(1) as f64;
                                if diff < 50 || ratio < 0.3 {
                                    return None;
                                }
                            }
                        }
                    }

                    if status.is_success() 
                        || status.is_redirection() 
                        || status == reqwest::StatusCode::FORBIDDEN 
                        || status == reqwest::StatusCode::UNAUTHORIZED 
                        || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
                        return Some(format!("/{} [{}]", p, status.as_u16()));
                    }
                
                None
            }
        })
        .buffer_unordered(concurrency)

        .collect::<Vec<_>>()
        .await;

    results.into_iter().flatten().collect()
}