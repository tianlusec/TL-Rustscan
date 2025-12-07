mod tcp_connect;
mod udp_scan;
mod host_discovery_optimized;
mod host_discovery;
pub mod web_dir;
mod service_map;
pub mod probes;
pub mod fingerprint_db;
mod constants;
mod udp_config;
mod connection_pool;
pub mod rate_limit;
mod checkpoint;
mod adaptive;

use crate::config::ScanConfig;
use crate::target::Target;
use crate::output::HostScanResult;
use crate::output::PortResult;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};
use futures::stream::{self, StreamExt, FuturesUnordered};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use rand::rng;
use connection_pool::ConnectionPool;
use rate_limit::TokenBucket;
use adaptive::AdaptiveConcurrency;
use std::path::Path;
use crate::error::ErrorStats;


pub use tcp_connect::PortState;
pub async fn run_scan(config: &ScanConfig, targets: Vec<Target>) -> Vec<HostScanResult> {
    let config = Arc::new(config.clone());
    let targets = if config.check_alive {
        if !config.json_output {
            println!("正在进行主机存活检测 (Ping/Connect)...");
        }
        
        let discovery_concurrency = (config.concurrency / 8).max(50);
        let check_stream = stream::iter(targets)
            .map(|target| {
                let cfg = config.clone();
                async move {
                    let alive = host_discovery_optimized::is_host_alive(target.ip, cfg.timeout_ms).await;
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

    
    let mut checkpoint = if config.resume {
        if let Ok(cp) = checkpoint::Checkpoint::load(Path::new("checkpoint.json")) {
            if !config.json_output {
                println!("已加载检查点，跳过 {} 个已扫描目标", cp.scanned_count());
            }
            cp
        } else {
            checkpoint::Checkpoint::new()
        }
    } else {
        checkpoint::Checkpoint::new()
    };
    let scanned_set = checkpoint.scanned_targets.clone();

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
    })
    .filter(move |(_, ip, _, port)| {
        !scanned_set.contains(&(ip.to_string(), *port))
    });

    let rate_limiter = if config.rate > 0 {
        Some(Arc::new(Mutex::new(TokenBucket::new(config.rate))))
    } else {
        None
    };

    
    let pool = if config.use_connection_pool {
        Some(Arc::new(ConnectionPool::new(10, Duration::from_secs(30))))
    } else {
        None
    };

    let adaptive = Arc::new(AdaptiveConcurrency::new(config.concurrency, 10, 10000));
    let error_stats = Arc::new(Mutex::new(ErrorStats::new()));
    let mut active_tasks = FuturesUnordered::new();
    let mut tasks_iter = tasks_iter;

    let mut results = Vec::new();
    let mut retry_candidates = Vec::new();
    let mut retry_queue_full_warned = false;

    let mut open_count = 0;
    let mut closed_count = 0;
    let mut filtered_count = 0;

    loop {
        
        let limit = adaptive.get_current();
        while active_tasks.len() < limit {
             if let Some((t_idx, ip, host, port)) = tasks_iter.next() {
                 let cfg = config.clone();
                 let pool_clone = pool.clone();
                 let limiter = rate_limiter.clone();
                 let adaptive_clone = adaptive.clone();
                 let error_stats_clone = error_stats.clone();
                 
                 active_tasks.push(async move {
                    let start = Instant::now();

                    let (state, banner, dirs) = if cfg.udp {
                        if let Some(l) = &limiter {
                            let mut bucket = l.lock().await;
                            bucket.acquire().await;
                        }
                        let (s, b) = udp_scan::scan_single_port(ip, port, cfg.timeout_ms).await;
                        (s, b, Vec::new()) 
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
                            insecure: cfg.insecure,
                            proxy: cfg.proxy.clone(),
                            connection_pool: pool_clone,
                            rate_limiter: limiter.clone(),
                            deep_scan: cfg.deep_scan,
                            error_stats: Some(error_stats_clone),
                        };
                        tcp_connect::scan_single_port(args).await
                    };
                    
                    
                    let duration = start.elapsed();
                    let success = state == PortState::Open;
                    let is_timeout = state == PortState::Filtered; 
                    adaptive_clone.record_result(success, is_timeout, duration).await;

                    (t_idx, port, state, banner, dirs)
                 });
             } else {
                 break;
             }
        }

        if active_tasks.is_empty() {
            break;
        }

        if let Some((t_idx, port, state, mut banner, dirs)) = active_tasks.next().await {
            if let Some(pb) = &pb {
                pb.inc(1);
            }

            match state {
                PortState::Open => open_count += 1,
                PortState::Closed => closed_count += 1,
                PortState::Filtered => filtered_count += 1,
            }
            
            
            
            
            if config.retry > 0 && !config.udp && state == PortState::Filtered {
                if retry_candidates.len() < 100_000 {
                    retry_candidates.push((t_idx, port));
                } else if !retry_queue_full_warned {
                    if !config.json_output {
                        eprintln!("警告: 重试队列已满 (10w+)，后续的超时端口将不再重试。这通常意味着目标网络存在防火墙或连接质量极差。");
                    }
                    retry_queue_full_warned = true;
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
            
            if state == PortState::Open || config.show_closed {
                results.push((t_idx, port, state, banner, dirs));
            }

            
            if config.resume {
                let ip = targets[t_idx].ip;
                checkpoint.mark_scanned(&ip.to_string(), port);
                if checkpoint.scanned_count() % 1000 == 0 {
                    if let Err(e) = checkpoint.save(Path::new("checkpoint.json")) {
                        if !config.json_output {
                            eprintln!("警告: 无法保存检查点: {}", e);
                        }
                    }
                }
            }
        }
    }
    if let Some(pb) = &pb {
        pb.finish_with_message("第一轮扫描完成");
    }

    if !config.json_output {
        println!("扫描统计: 开放 {}, 关闭 {}, 过滤/超时 {}", open_count, closed_count, filtered_count);
        let stats = error_stats.lock().await;
        println!("错误详情: {}", stats.summary());
    }

    
    if config.resume {
        if let Err(e) = checkpoint.save(Path::new("checkpoint.json")) {
             if !config.json_output {
                eprintln!("警告: 无法保存最终检查点: {}", e);
            }
        }
    }

    
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
        
        let retry_concurrency = (config.concurrency / 5).max(10); 
        let retry_timeout = config.timeout_ms * 2; 

        let retry_stream = stream::iter(retry_candidates)
            .map(|(t_idx, port)| {
                let cfg = config.clone();
                let pool_clone = pool.clone();
                let limiter = rate_limiter.clone();
                let error_stats_clone = error_stats.clone();
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
                        insecure: cfg.insecure,
                        proxy: cfg.proxy.clone(),
                        connection_pool: pool_clone,
                        rate_limiter: limiter,
                        deep_scan: cfg.deep_scan,
                        error_stats: Some(error_stats_clone),
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

                
                if let Some(existing) = results.iter_mut().find(|(t, p, _, _, _)| *t == t_idx && *p == port) {
                    *existing = (t_idx, port, state, banner, dirs);
                } else {
                    
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

    
    if !config.udp { 
        use crate::plugins::{PluginManager, HostInfo};
        let pm = PluginManager::new();
        
        
        let mut plugin_tasks = Vec::new();
        for (h_idx, host_res) in host_results.iter().enumerate() {
            for port_res in &host_res.ports {
                if port_res.state == PortState::Open {
                    let plugins = pm.get_plugins_for_port(port_res.port);
                    for plugin in plugins {
                        
                        
                        
                        
                        if plugin.is_rscan_only() && !config.rscan {
                            continue;
                        }

                        
                        match plugin.plugin_type() {
                            crate::plugins::PluginType::Brute => {
                                if config.no_brute { continue; }
                            },
                            crate::plugins::PluginType::Poc => {
                                if config.no_poc { continue; }
                            },
                            _ => {}
                        }
                        
                        
                        let host_str = if host_res.ip.contains(':') {
                            format!("[{}]", host_res.ip)
                        } else {
                            host_res.ip.clone()
                        };

                        let info = HostInfo {
                            host: host_str.clone(),
                            port: port_res.port.to_string(),
                            url: format!("http://{}:{}", host_str, port_res.port),
                proxy: config.proxy.clone(),
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
                .buffer_unordered(config.concurrency); 

            let vuln_results: Vec<(usize, String)> = plugin_stream
                .filter_map(|res| async { res })
                .collect()
                .await;
            
            
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