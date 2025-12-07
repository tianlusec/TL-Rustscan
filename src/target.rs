use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tracing::warn;

struct DnsCacheEntry {
    addrs: Vec<SocketAddr>,
    timestamp: Instant,
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

static DNS_CACHE: OnceLock<Mutex<HashMap<String, DnsCacheEntry>>> = OnceLock::new();

async fn cached_lookup_host(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let map = cache.lock().unwrap();
        if let Some(entry) = map.get(host) {
            if entry.timestamp.elapsed() < DNS_CACHE_TTL {
                return Ok(entry.addrs.clone());
            }
        }
    }

    let addrs = lookup_host(host).await?.collect::<Vec<_>>();

    {
        let mut map = cache.lock().unwrap();
        
        if map.len() > 5000 {
            let now = Instant::now();
            map.retain(|_, v| now.duration_since(v.timestamp) < DNS_CACHE_TTL);
        }
        map.insert(
            host.to_string(),
            DnsCacheEntry {
                addrs: addrs.clone(),
                timestamp: Instant::now(),
            },
        );
    }

    Ok(addrs)
}

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub ip: IpAddr,
}

pub async fn resolve_targets(
    target_inputs: &[String],
    file_input: Option<&Path>,
    exclude_inputs: &[String],
) -> Result<Vec<Target>> {
    let mut exclude_ips = HashSet::new();
    for input in exclude_inputs {
        if let Ok(targets) = process_input(input).await {
            for t in targets {
                exclude_ips.insert(t.ip);
            }
        }
    }

    let mut all_inputs = Vec::new();
    for input in target_inputs {
        all_inputs.push(input.clone());
    }

    if let Some(path) = file_input {
        let file = File::open(path).context(format!("无法打开目标列表文件: {:?}", path))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim().to_string();
            if !line.is_empty() && !line.starts_with('#') {
                all_inputs.push(line);
            }
        }
    }

    let results = stream::iter(all_inputs)
        .map(|input| async move { process_input(&input).await })
        .buffer_unordered(500)
        .collect::<Vec<_>>()
        .await;

    let mut final_targets = Vec::new();
    for res in results {
        if let Ok(targets) = res {
            final_targets.extend(targets);
        }
    }

    let mut unique_targets = HashSet::new();
    let mut deduped_targets = Vec::new();
    for target in final_targets {
        if !exclude_ips.contains(&target.ip) {
            let key = (target.ip, target.host.clone());
            if unique_targets.insert(key) {
                deduped_targets.push(target);
            }
        }
    }
    Ok(deduped_targets)
}

async fn process_input(input: &str) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut cleaned = input.trim();
    if cleaned.to_lowercase().starts_with("http://") {
        cleaned = &cleaned[7..];
    } else if cleaned.to_lowercase().starts_with("https://") {
        cleaned = &cleaned[8..];
    }
    if let Some(idx) = cleaned.find('/') {
        cleaned = &cleaned[..idx];
    }

    if let Ok(net) = cleaned.parse::<IpNet>() {
        if (net.addr().is_ipv4() && net.prefix_len() == 32)
            || (net.addr().is_ipv6() && net.prefix_len() == 128)
        {
            targets.push(Target {
                host: crate::scanner::probes::format_host(net.addr()),
                ip: net.addr(),
            });
            return Ok(targets);
        }

        let prefix = net.prefix_len();
        let is_too_large = match net {
            IpNet::V4(_) => prefix < 16,
            IpNet::V6(_) => prefix < 112,
        };

        if is_too_large {
            warn!("网段 {} 过大，超过建议上限，仅处理前 100000 个", input);
        }
        for ip in net.hosts().take(100000) {
            targets.push(Target {
                host: crate::scanner::probes::format_host(ip),
                ip,
            });
        }
        return Ok(targets);
    }

    if let Some(dash_idx) = cleaned.find('-') {
        let start_str = &cleaned[..dash_idx];
        let end_str = &cleaned[dash_idx + 1..];
        if let (Ok(start_ip), Ok(end_ip)) = (start_str.parse::<IpAddr>(), end_str.parse::<IpAddr>())
        {
            if let (IpAddr::V4(s), IpAddr::V4(e)) = (start_ip, end_ip) {
                let s_u32: u32 = s.into();
                let e_u32: u32 = e.into();
                if s_u32 <= e_u32 {
                    let count = e_u32 as u64 - s_u32 as u64 + 1;
                    if count > 100000 {
                        warn!(
                            "IP 范围 {} 包含 {} 个 IP，超过建议上限，仅处理前 100000 个",
                            input, count
                        );
                    }
                    for i in s_u32..=e_u32.min(s_u32.saturating_add(100000)) {
                        let ip = std::net::Ipv4Addr::from(i);
                        targets.push(Target {
                            host: crate::scanner::probes::format_host(IpAddr::V4(ip)),
                            ip: IpAddr::V4(ip),
                        });
                    }
                    return Ok(targets);
                }
            }
        }
    }

    if let Some(last_dot_idx) = cleaned.rfind('.') {
        let prefix = &cleaned[..last_dot_idx];
        let suffix = &cleaned[last_dot_idx + 1..];
        if let Some(dash_idx) = suffix.find('-') {
            let start_str = &suffix[..dash_idx];
            let end_str = &suffix[dash_idx + 1..];

            if let (Ok(start), Ok(end)) = (start_str.parse::<u8>(), end_str.parse::<u8>()) {
                if start <= end {
                    for i in start..=end {
                        let ip_str = format!("{}.{}", prefix, i);
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            targets.push(Target {
                                host: crate::scanner::probes::format_host(ip),
                                ip,
                            });
                        }
                    }
                    return Ok(targets);
                }
            }
        }
    }

    let addr_to_resolve = if let Ok(_v6) = cleaned.parse::<std::net::Ipv6Addr>() {
        format!("[{}]:80", cleaned)
    } else if cleaned.contains(':') {
        cleaned.to_string()
    } else {
        format!("{}:80", cleaned)
    };

    match cached_lookup_host(&addr_to_resolve).await {
        Ok(addrs) => {
            let mut found = false;
            for socket_addr in addrs {
                let host_str = if cleaned.starts_with('[') {
                    if let Some(idx) = cleaned.rfind("]:") {
                        &cleaned[..idx + 1]
                    } else {
                        cleaned
                    }
                } else if cleaned.chars().filter(|&c| c == ':').count() >= 2 {
                    cleaned
                } else if let Some(idx) = cleaned.rfind(':') {
                    &cleaned[..idx]
                } else {
                    cleaned
                };

                let final_host = if let Ok(ip) = host_str.parse::<IpAddr>() {
                    crate::scanner::probes::format_host(ip)
                } else {
                    host_str.to_string()
                };

                targets.push(Target {
                    host: final_host,
                    ip: socket_addr.ip(),
                });
                found = true;
            }
            if !found {
                if let Ok(ip) = cleaned.parse::<IpAddr>() {
                    targets.push(Target {
                        host: crate::scanner::probes::format_host(ip),
                        ip,
                    });
                } else {
                    warn!("无法解析目标 '{}'，已跳过", input);
                }
            }
        }
        Err(_) => {
            if let Ok(ip) = cleaned.parse::<IpAddr>() {
                targets.push(Target {
                    host: crate::scanner::probes::format_host(ip),
                    ip,
                });
            } else {
                warn!("无法解析目标 '{}'，已跳过", input);
            }
        }
    }
    Ok(targets)
}
