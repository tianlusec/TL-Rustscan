use anyhow::{Context, Result};
use ipnet::IpNet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use tokio::net::lookup_host;
use std::collections::HashSet;
use futures::stream::{self, StreamExt};

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

    // 并发解析目标，提高大规模域名扫描时的启动速度
    let results = stream::iter(all_inputs)
        .map(|input| async move {
            process_input(&input).await
        })
        .buffer_unordered(100) // 100 并发解析
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
    // 1. 清洗输入：去除 http/https 前缀和路径 (忽略大小写)
    let mut cleaned = input.trim();
    if cleaned.to_lowercase().starts_with("http://") {
        cleaned = &cleaned[7..];
    } else if cleaned.to_lowercase().starts_with("https://") {
        cleaned = &cleaned[8..];
    }
    // 去除路径部分 (例如 1.2.3.4:80/index.html -> 1.2.3.4:80)
    if let Some(idx) = cleaned.find('/') {
        cleaned = &cleaned[..idx];
    }

    // 2. 尝试解析为 CIDR (使用清洗后的字符串)
    if let Ok(net) = cleaned.parse::<IpNet>() {
        if (net.addr().is_ipv4() && net.prefix_len() == 32) || (net.addr().is_ipv6() && net.prefix_len() == 128) {
             targets.push(Target {
                host: net.addr().to_string(),
                ip: net.addr(),
            });
            return Ok(targets);
        }

        // 优化：不要使用 net.hosts().count()，因为对于大网段 (尤其是 IPv6) 会导致死循环
        // 直接根据前缀长度判断是否超过 65535
        let prefix = net.prefix_len();
        let is_too_large = match net {
            IpNet::V4(_) => prefix < 16, // 2^(32-16) = 65536
            IpNet::V6(_) => prefix < 112, // 2^(128-112) = 65536
        };

        if is_too_large {
            eprintln!("警告: 网段 {} 过大，超过建议上限，仅处理前 65535 个", input);
        }
        for ip in net.hosts().take(65535) {
            targets.push(Target {
                host: ip.to_string(),
                ip,
            });
        }
        return Ok(targets);
    }

    // 3. 尝试解析为 IP 范围 (使用清洗后的字符串)
    if let Some(dash_idx) = cleaned.find('-') {
        let start_str = &cleaned[..dash_idx];
        let end_str = &cleaned[dash_idx + 1..];
        if let (Ok(start_ip), Ok(end_ip)) = (start_str.parse::<IpAddr>(), end_str.parse::<IpAddr>()) {
            if let (IpAddr::V4(s), IpAddr::V4(e)) = (start_ip, end_ip) {
                let s_u32: u32 = s.into();
                let e_u32: u32 = e.into();
                if s_u32 <= e_u32 {
                    let count = e_u32 as u64 - s_u32 as u64 + 1;
                    if count > 65535 {
                        eprintln!("警告: IP 范围 {} 包含 {} 个 IP，超过建议上限，仅处理前 65535 个", input, count);
                    }
                    for i in s_u32..=e_u32.min(s_u32.saturating_add(65535)) {
                        let ip = std::net::Ipv4Addr::from(i);
                        targets.push(Target {
                            host: ip.to_string(),
                            ip: IpAddr::V4(ip),
                        });
                    }
                    return Ok(targets);
                }
            }
        }
    }

    // 4. 尝试解析为最后一段范围 (例如 192.168.1.1-10)
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
                                host: ip_str.clone(),
                                ip,
                            });
                        }
                    }
                    return Ok(targets);
                }
            }
        }
    }

    // 5. 域名/IP 解析 (智能处理端口)
    // 构造用于 lookup_host 的字符串
    let addr_to_resolve = if let Ok(_v6) = cleaned.parse::<std::net::Ipv6Addr>() {
        // 纯 IPv6 地址，添加默认端口
        format!("[{}]:80", cleaned)
    } else if cleaned.contains(':') {
        // 包含冒号，可能是 IPv4:Port, Host:Port, 或 [IPv6]:Port
        // 如果是 IPv4:Port 或 Host:Port，直接使用
        // 如果是 [IPv6]:Port，也直接使用
        cleaned.to_string()
    } else {
        // 不含冒号，假设是 Host 或 IPv4，添加默认端口
        format!("{}:80", cleaned)
    };

    match lookup_host(&addr_to_resolve).await {
        Ok(addrs) => {
            let mut found = false;
            for socket_addr in addrs {
                // 修复: 移除 host 中的端口部分，防止后续插件拼接 URL 时出现双重端口 (如 example.com:80:80)
                let host_str = if cleaned.starts_with('[') {
                    // IPv6: [::1]:80 -> [::1]
                    if let Some(idx) = cleaned.rfind("]:") {
                        &cleaned[..idx+1]
                    } else {
                        cleaned
                    }
                } else if cleaned.chars().filter(|&c| c == ':').count() >= 2 {
                     // 可能是无括号的 IPv6，假设不带端口
                     cleaned
                } else if let Some(idx) = cleaned.rfind(':') {
                     // IPv4 或域名: example.com:80 -> example.com
                     &cleaned[..idx]
                } else {
                    cleaned
                };

                targets.push(Target {
                    host: host_str.to_string(), 
                    ip: socket_addr.ip(),
                });
                found = true;
            }
            if !found {
                 // 尝试直接解析为 IP (作为最后的兜底)
                 if let Ok(ip) = cleaned.parse::<IpAddr>() {
                    targets.push(Target {
                        host: cleaned.to_string(),
                        ip,
                    });
                } else {
                    eprintln!("警告: 无法解析目标 '{}'，已跳过", input);
                }
            }
        }
        Err(_) => {
            // 如果带端口解析失败，且原字符串没有端口，可能 lookup_host 对某些格式敏感？
            // 尝试直接解析 IP
            if let Ok(ip) = cleaned.parse::<IpAddr>() {
                targets.push(Target {
                    host: cleaned.to_string(),
                    ip,
                });
            } else {
                eprintln!("警告: 无法解析目标 '{}'，已跳过", input);
            }
        }
    }
    Ok(targets)
}