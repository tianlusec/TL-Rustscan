use crate::scanner::constants::*;
use crate::scanner::probes::{self, get_user_agent};
use crate::scanner::rate_limit::TokenBucket;
use reqwest::{Client, Proxy};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

fn get_no_redirect_client(insecure: bool, proxy: Option<String>) -> reqwest::Client {
    static CLIENTS: OnceLock<RwLock<HashMap<String, reqwest::Client>>> = OnceLock::new();

    let clients = CLIENTS.get_or_init(|| RwLock::new(HashMap::new()));
    let key = format!("{}:{:?}", insecure, proxy);

    {
        let map = clients.read().unwrap();
        if let Some(client) = map.get(&key) {
            return client.clone();
        }
    }

    let mut map = clients.write().unwrap();
    if let Some(client) = map.get(&key) {
        return client.clone();
    }

    let mut builder = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(insecure)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(get_user_agent());

    if let Some(proxy_url) = &proxy {
        if let Ok(p) = Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }

    let client = builder.build().unwrap_or_default();
    map.insert(key, client.clone());
    client
}

use futures::stream::{self, StreamExt};

static DIR_SCAN_LIMITER: OnceLock<Semaphore> = OnceLock::new();

pub fn init_dir_limiter(limit: usize) {
    DIR_SCAN_LIMITER.get_or_init(|| Semaphore::new(limit));
}

pub async fn scan_dirs(
    ip: IpAddr,
    port: u16,
    host: &str,
    paths: &[String],
    timeout_ms: u64,
    banner: Option<&str>,
    insecure: bool,
    proxy: Option<String>,
    rate_limiter: Option<Arc<Mutex<TokenBucket>>>,
) -> Vec<String> {
    let _permit = DIR_SCAN_LIMITER
        .get_or_init(|| Semaphore::new(DIR_SCAN_GLOBAL_LIMIT))
        .acquire()
        .await;

    let concurrency = if paths.len() > 100 {
        DIR_SCAN_CONCURRENCY_HIGH
    } else {
        DIR_SCAN_CONCURRENCY_LOW
    };

    let scheme = if port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    };
    let is_ip = host.parse::<IpAddr>().is_ok();
    let base_url = if is_ip {
        let host_str = crate::scanner::probes::format_host(ip);
        format!("{}://{}:{}", scheme, host_str, port)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    };

    let use_global_client = is_ip || scheme == "http";

    let client = if !use_global_client {
        probes::create_http_client(timeout_ms / 1000, insecure, proxy.as_deref())
            .unwrap_or_default()
    } else {
        get_no_redirect_client(insecure, proxy).clone()
    };

    let random_path = format!("tl_scan_{}", rand::random::<u32>());
    let (baseline_status, baseline_len) = {
        let (url, host_header) = if use_global_client && !is_ip {
            (
                format!(
                    "{}://{}:{}/{}",
                    scheme,
                    crate::scanner::probes::format_host(ip),
                    port,
                    random_path
                ),
                Some(host),
            )
        } else {
            (format!("{}/{}", base_url, random_path), None)
        };

        let mut req = client
            .get(&url)
            .timeout(Duration::from_millis(timeout_ms))
            .header(reqwest::header::USER_AGENT, get_user_agent());

        if let Some(h) = host_header {
            req = req.header("Host", h);
        }

        if let Ok(mut resp) = req.send().await {
            let status = resp.status();
            let len = if let Some(l) = resp.content_length() {
                l
            } else {
                let mut total_bytes = 0u64;
                let limit = HTTP_BODY_SIZE_LIMIT as u64;

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
            let limiter = rate_limiter.clone();
            async move {
                if let Some(l) = &limiter {
                    l.lock().await.acquire().await;
                }

                let p = if let Some(stripped) = path.strip_prefix('/') {
                    stripped
                } else {
                    path
                };

                let (url, host_header) = if use_global_client && !is_ip {
                    (
                        format!(
                            "{}://{}:{}/{}",
                            scheme,
                            crate::scanner::probes::format_host(ip),
                            port,
                            p
                        ),
                        Some(host),
                    )
                } else {
                    (format!("{}/{}", base_url, p), None)
                };

                let mut req = client
                    .get(&url)
                    .timeout(Duration::from_millis(timeout_ms))
                    .header(reqwest::header::USER_AGENT, get_user_agent());

                if let Some(h) = host_header {
                    req = req.header("Host", h);
                }

                let mut resp = if let Ok(r) = req.send().await {
                    r
                } else {
                    return None;
                };
                let status = resp.status();
                let len = if let Some(l) = resp.content_length() {
                    l
                } else {
                    let mut total_bytes = 0u64;
                    let limit = HTTP_BODY_SIZE_LIMIT as u64;
                    while let Ok(Some(chunk)) = resp.chunk().await {
                        total_bytes += chunk.len() as u64;
                        if total_bytes > limit {
                            break;
                        }
                    }
                    total_bytes
                };

                if is_wildcard {
                    if let Some(base_status) = baseline_status {
                        if status == base_status {
                            let diff = if len > baseline_len {
                                len - baseline_len
                            } else {
                                baseline_len - len
                            };
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
                    || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
                {
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
