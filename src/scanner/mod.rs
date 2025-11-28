mod tcp_connect;
mod udp_scan;
mod host_discovery;
pub mod web_dir;
mod service_map;
pub mod probes;
pub mod fingerprint_db;
use crate::config::ScanConfig;
use crate::target::Target;
use crate::output::HostScanResult;
use crate::output::PortResult;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Instant;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use rand::rng;

struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        Self {
            rate: rate as f64,
            capacity: rate as f64,
            tokens: rate as f64,
            last_update: Instant::now(),
        }
    }

    async fn acquire(&mut self) {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_update).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last_update = now;

            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }

            let missing = 1.0 - self.tokens;
            let wait_time = missing / self.rate;
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait_time)).await;
        }
    }
}

pub use tcp_connect::PortState;
pub async fn run_scan(config: &ScanConfig, targets: Vec<Target>) -> Vec<HostScanResult> {
    let config = Arc::new(config.clone());
    let targets = if config.check_alive {
        if !config.json_output {
            println!("正在进行主机存活检测 (Ping/Connect)...");
        }
        // 提高存活检测的最小并发数，防止在低并发设置下检测过慢
        let discovery_concurrency = (config.concurrency / 8).max(50);
        let check_stream = stream::iter(targets)
            .map(|target| {
                let cfg = config.clone();
                async move {
                    let alive = host_discovery::is_host_alive(target.ip, cfg.timeout_ms).await;
                    (target, alive)
                }
            })
            .buffer_unordered(discovery_concurrency);
        let mut alive_targets = Vec::new();
        let mut dead_count = 0;
        let mut s = check_stream;
        while let Some((target, alive)) = s.next().await {
            if alive {
                alive_targets.push(target);
            } else {
                dead_count += 1;
            }
        }
        if !config.json_output {
            println!("存活主机: {}, 离线/过滤: {}", alive_targets.len(), dead_count);
        }
        alive_targets
    } else {
        targets
    };
    let total_tasks = targets.len() * config.ports.len();
    let mut target_ips: Vec<(usize, std::net::IpAddr, Arc<String>)> = targets.iter()
        .enumerate()
        .map(|(i, t)| (i, t.ip, Arc::new(t.host.clone())))
        .collect();
    if config.randomize {
        let mut rng = rng();
        target_ips.shuffle(&mut rng);
    }
    let scan_ports = config.ports.clone();
    let randomize_ports = config.randomize;
    let pb = if !config.json_output {
        let mode = if config.udp { "UDP" } else { "TCP" };
        println!("开始 {} 扫描: {} 个目标, 每个目标 {} 个端口, 总计 {} 个任务", mode, targets.len(), config.ports.len(), total_tasks);
        let pb = ProgressBar::new(total_tasks as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"));
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };
    let tasks_iter = target_ips.into_iter().flat_map(move |(t_idx, ip, host)| {
        let mut ports = scan_ports.clone();
        if randomize_ports {
            let mut rng = rng();
            ports.shuffle(&mut rng);
        }
        ports.into_iter().map(move |port| (t_idx, ip, host.clone(), port))
    });

    let rate_limiter = if config.rate > 0 {
        Some(Arc::new(Mutex::new(TokenBucket::new(config.rate))))
    } else {
        None
    };

    let mut stream = stream::iter(tasks_iter)
        .map(|(t_idx, ip, host, port)| {
            let cfg = config.clone();
            let limiter = rate_limiter.clone();
            async move {
                if let Some(limiter) = limiter {
                    let mut bucket = limiter.lock().await;
                    bucket.acquire().await;
                }

                let (state, banner, dirs) = if cfg.udp {
                    let s = udp_scan::scan_single_port(ip, port, cfg.timeout_ms).await;
                    (s, None, Vec::new()) 
                } else {
                    let args = tcp_connect::TcpScanArgs {
                        ip,
                        port,
                        host,
                        timeout_ms: cfg.timeout_ms,
                        grab_banner: cfg.banner,
                        dir_scan: cfg.dir_scan,
                        dir_paths: &cfg.dir_paths,
                        web_ports: &cfg.web_ports,
                        deep_scan: cfg.deep_scan,
                    };
                    tcp_connect::scan_single_port(args).await
                };
                (t_idx, port, state, banner, dirs)
            }
        })
        .buffer_unordered(config.concurrency);
    let mut results = Vec::new();
    let mut retry_candidates = Vec::new();

    while let Some((t_idx, port, state, mut banner, dirs)) = stream.next().await {
        if let Some(pb) = &pb {
            pb.inc(1);
        }
        
        // 收集需要重试的端口 (Filtered only)
        // 只有 Filtered (超时) 的端口才值得重试。Closed (RST) 的端口是明确关闭的，重试没有意义。
        // 增加上限保护，防止全网段 Filtered 导致 OOM
        if config.retry > 0 && !config.udp && state == PortState::Filtered {
            if retry_candidates.len() < 100_000 {
                retry_candidates.push((t_idx, port));
            } else if retry_candidates.len() == 100_000 {
                if !config.json_output {
                    eprintln!("警告: 重试队列已满 (10w+)，后续的超时端口将不再重试。这通常意味着目标网络存在防火墙或连接质量极差。");
                }
                // 占位，防止重复打印警告
                retry_candidates.push((0, 0)); 
            }
        }

        if banner.is_none() && state == PortState::Open {
            let protocol = if config.udp { "udp" } else { "tcp" };
            if let Some(service) = service_map::get_service_name(port, protocol) {
                banner = Some(format!("{}?", service));
            }
        }
        if !config.json_output && (state == PortState::Open || config.show_closed) {
            let ip = targets[t_idx].ip;
            let output = crate::output::format_realtime_output(&ip, port, state, banner.as_deref(), &dirs);
            if let Some(pb) = &pb {
                pb.println(output);
            } else {
                println!("{}", output);
            }
        }
        // 内存优化：仅存储用户关心的结果，防止大规模扫描时 OOM
        if state == PortState::Open || config.show_closed {
            results.push((t_idx, port, state, banner, dirs));
        }
    }
    if let Some(pb) = &pb {
        pb.finish_with_message("第一轮扫描完成");
    }

    // 智能重试逻辑
    if config.retry > 0 && !retry_candidates.is_empty() {
        let retry_count = retry_candidates.len();
        let retry_pb = if !config.json_output {
            println!("正在对 {} 个可疑端口进行智能复查 (Retry Mode)...", retry_count);
            let pb = ProgressBar::new(retry_count as u64);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.yellow/red}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-"));
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(pb)
        } else {
            None
        };
        
        let retry_concurrency = (config.concurrency / 5).max(10); // 降低并发
        let retry_timeout = config.timeout_ms * 2; // 增加超时

        let retry_stream = stream::iter(retry_candidates)
            .map(|(t_idx, port)| {
                let cfg = config.clone();
                let target = &targets[t_idx];
                let ip = target.ip;
                let host = Arc::new(target.host.clone());
                async move {
                    let args = tcp_connect::TcpScanArgs {
                        ip,
                        port,
                        host,
                        timeout_ms: retry_timeout,
                        grab_banner: cfg.banner,
                        dir_scan: cfg.dir_scan,
                        dir_paths: &cfg.dir_paths,
                        web_ports: &cfg.web_ports,
                        deep_scan: cfg.deep_scan,
                    };
                    let (state, banner, dirs) = tcp_connect::scan_single_port(args).await;
                    (t_idx, port, state, banner, dirs)
                }
            })
            .buffer_unordered(retry_concurrency);

        let mut s = retry_stream;
        while let Some((t_idx, port, state, mut banner, dirs)) = s.next().await {
            if let Some(pb) = &retry_pb {
                pb.inc(1);
            }

            if state == PortState::Open {
                // 如果复查发现端口开放，更新结果
                if banner.is_none() {
                    if let Some(service) = service_map::get_service_name(port, "tcp") {
                        banner = Some(format!("{}?", service));
                    }
                }
                
                if !config.json_output {
                    let ip = targets[t_idx].ip;
                    let output = crate::output::format_realtime_output(&ip, port, state, banner.as_deref(), &dirs);
                    if let Some(pb) = &retry_pb {
                        pb.println(format!("  [RETRY SUCCESS] {}", output));
                    } else {
                        println!("  [RETRY SUCCESS] {}", output);
                    }
                }

                // 更新 results 中的记录
                if let Some(existing) = results.iter_mut().find(|(t, p, _, _, _)| *t == t_idx && *p == port) {
                    *existing = (t_idx, port, state, banner, dirs);
                } else {
                    // 如果之前因为 Filtered 没存入 results，现在变 Open 了，需要补录
                    results.push((t_idx, port, state, banner, dirs));
                }
            }
        }
        if let Some(pb) = &retry_pb {
            pb.finish_with_message("复查完成");
        }
    }

    let mut host_results: Vec<HostScanResult> = targets.into_iter().map(|t| HostScanResult {
        target: t.host,
        ip: t.ip.to_string(),
        ports: Vec::new(),
        vulns: Vec::new(),
    }).collect();
    for (t_idx, port, state, banner, dirs) in results {
        if state == PortState::Open || config.show_closed {
            host_results[t_idx].ports.push(PortResult {
                port,
                protocol: if config.udp { "udp".to_string() } else { "tcp".to_string() },
                state,
                banner,
                dirs,
            });
        }
    }
    for res in &mut host_results {
        res.ports.sort_by_key(|p| p.port);
    }

    // 插件扫描逻辑
    if !config.udp { // 暂时只支持 TCP 插件
        use crate::plugins::{PluginManager, HostInfo};
        let pm = PluginManager::new();
        
        // 收集所有开放端口的任务
        let mut plugin_tasks = Vec::new();
        for (h_idx, host_res) in host_results.iter().enumerate() {
            for port_res in &host_res.ports {
                if port_res.state == PortState::Open {
                    let plugins = pm.get_plugins_for_port(port_res.port);
                    for plugin in plugins {
                        // 核心逻辑：
                        // 1. 如果插件是 rscan 专属 (is_rscan_only() == true)，则必须开启 --rscan 才会运行
                        // 2. 如果插件是通用功能 (is_rscan_only() == false)，则默认运行 (如 WebTitle)
                        
                        if plugin.is_rscan_only() && !config.rscan {
                            continue;
                        }

                        // 3. 细粒度控制: --no-brute 和 --no-poc
                        match plugin.plugin_type() {
                            crate::plugins::PluginType::Brute => {
                                if config.no_brute { continue; }
                            },
                            crate::plugins::PluginType::Poc => {
                                if config.no_poc { continue; }
                            },
                            _ => {}
                        }
                        
                        // 处理 IPv6 地址格式，确保 URL 和连接字符串正确
                        let host_str = if host_res.ip.contains(':') {
                            format!("[{}]", host_res.ip)
                        } else {
                            host_res.ip.clone()
                        };

                        let info = HostInfo {
                            host: host_str.clone(),
                            port: port_res.port.to_string(),
                            url: format!("http://{}:{}", host_str, port_res.port),
                            infostr: Vec::new(),
                        };
                        plugin_tasks.push((h_idx, plugin, info));
                    }
                }
            }
        }

        if !plugin_tasks.is_empty() {
            if !config.json_output {
                println!("开始插件扫描: {} 个任务", plugin_tasks.len());
            }
            
            let plugin_stream = stream::iter(plugin_tasks)
                .map(|(h_idx, plugin, info)| {
                    async move {
                        match plugin.scan(&info).await {
                            Ok(Some(vuln)) => Some((h_idx, vuln)),
                            Ok(None) => None,
                            Err(_e) => None,
                        }
                    }
                })
                .buffer_unordered(config.concurrency); // 复用并发配置

            let vuln_results: Vec<(usize, String)> = plugin_stream
                .filter_map(|res| async { res })
                .collect()
                .await;
            
            // 将漏洞信息合并回 host_results
            for (h_idx, vuln) in vuln_results {
                if h_idx < host_results.len() {
                    host_results[h_idx].vulns.push(vuln);
                }
            }
            
            if !config.json_output {
                println!("插件扫描完成");
            }
        }
    }

    host_results
}