mod config;
mod target;
pub mod scanner;
pub mod plugins;
mod output;
use clap::Parser;
use config::{Cli, ScanConfig};
use anyhow::Result;
use std::process;
fn print_banner() {
    let banner = r#"
  _______ __      _____           _                       
 |__   __| |    |  __ \         | |                      
    | |  | |    | |__) |   _ ___| |_ ___  ___ __ _ _ __  
    | |  | |    |  _  / | | / __| __/ __|/ __/ _` | '_ \ 
    | |  | |____| | \ \ |_| \__ \ |_\__ \ (_| (_| | | | |
    |_|  |______|_|  \_\__,_|___/\__|___/\___\__,_|_| |_|
    TL-Rustscan v2.0.0 - Fast & Comprehensive Port Scanner
    此工具由天禄实验室开发
    "#;
    eprintln!("{}", banner);
}
fn main() -> Result<()> {
    // 配置 Tokio Runtime 以支持高并发阻塞操作
    // 默认的 blocking 线程池大小约为 512。
    // Windows 下过高的线程数 (如 4000+) 可能导致栈内存耗尽 (OOM)，
    // 这里调整为 500，既能满足基础并发需求，又能将内存占用控制在安全范围内。
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(500) 
        .build()
        .unwrap();

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    print_banner();
    let cli = Cli::parse();

    if cli.dump_json {
        let path = std::env::current_dir()?.join("fingerprints.json");
        match scanner::fingerprint_db::FingerprintDatabase::dump_default_to_file(&path) {
            Ok(_) => {
                println!("成功导出内置指纹库到: {:?}", path);
                println!("您可以编辑此文件，下次运行时工具会自动加载它。");
                process::exit(0);
            },
            Err(e) => {
                eprintln!("导出失败: {}", e);
                process::exit(1);
            }
        }
    }

    let config = match ScanConfig::from_cli(cli.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置错误: {}", e);
            process::exit(1);
        }
    };

    scanner::probes::set_random_ua(config.random_ua);

    if config.dir_scan {
        println!("[*] 已加载 Web 目录字典: {} 条", config.dir_paths.len());
    }

    if let Err(e) = scanner::fingerprint_db::FingerprintDatabase::init(config.fingerprints_path.clone()) {
        eprintln!("指纹库初始化失败: {}", e);
        process::exit(1);
    }

    let targets = match target::resolve_targets(&config.targets, cli.target_list.as_deref(), &config.exclude_hosts).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("目标解析错误: {}", e);
            process::exit(2);
        }
    };
    if targets.is_empty() {
        eprintln!("未指定有效目标。请使用 TARGET 参数或 -L 指定目标文件。");
        process::exit(1);
    }
    let results = scanner::run_scan(&config, targets).await;
    if config.json_output {
        if let Err(e) = output::output_json(&results, &config) {
            eprintln!("JSON 输出失败: {}", e);
        }
    } else {
        output::print_human_readable(&results, &config);
    }
    if let Some(path) = &config.output_markdown {
        if let Err(e) = output::output_markdown(&results, path) {
            eprintln!("Markdown 输出失败: {}", e);
        }
    }
    if let Some(path) = &config.output_csv {
        if let Err(e) = output::output_csv(&results, path) {
            eprintln!("CSV 输出失败: {}", e);
        }
    }
    if let Some(path) = &config.output_html {
        if let Err(e) = output::output_html(&results, path) {
            eprintln!("HTML 输出失败: {}", e);
        }
    }
    Ok(())
}