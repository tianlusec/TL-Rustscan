mod config;
mod error;
mod output;
pub mod plugins;
pub mod scanner;
mod target;

use anyhow::Result;
use clap::Parser;
use config::{Cli, ScanConfig};
pub use error::{ErrorSeverity, ErrorStats, ScanError};
use std::process;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn print_banner() {
    let banner = r#"
  _______ __      _____           _                       
 |__   __| |    |  __ \         | |                      
    | |  | |    | |__) |   _ ___| |_ ___  ___ __ _ _ __  
    | |  | |    |  _  / | | / __| __/ __|/ __/ _` | '_ \ 
    | |  | |____| | \ \ |_| \__ \ |_\__ \ (_| (_| | | | |
    |_|  |______|_|  \_\__,_|___/\__|___/\___\__,_|_| |_|
    TL-Rustscan v2.3.0 - Fast & Comprehensive Port Scanner
    此工具由天禄实验室开发
    "#;
    eprintln!("{}", banner);
}

fn init_logging(
    verbose: bool,
    quiet: bool,
    log_file: Option<std::path::PathBuf>,
    _json_mode: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let level = if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    let filter = EnvFilter::new(level);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_level(true);

    let registry = tracing_subscriber::registry().with(filter);

    if let Some(path) = log_file {
        let file_appender = tracing_appender::rolling::daily(
            path.parent().unwrap_or(std::path::Path::new(".")),
            path.file_name()
                .unwrap_or(std::ffi::OsStr::new("rustscan.log")),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_level(true);

        registry.with(fmt_layer).with(file_layer).init();
        Some(guard)
    } else {
        registry.with(fmt_layer).init();
        None
    }
}

fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    let max_threads = 200;
    #[cfg(not(target_os = "windows"))]
    let max_threads = 500;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(max_threads)
        .build()
        .expect("Failed to build Tokio runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    print_banner();
    let cli = Cli::parse();

    let _guard = init_logging(cli.verbose, cli.quiet, cli.log_file.clone(), cli.json);

    if cli.dump_json {
        let path = std::env::current_dir()?.join("fingerprints.json");
        match scanner::fingerprint_db::FingerprintDatabase::dump_default_to_file(&path) {
            Ok(_) => {
                info!("成功导出内置指纹库到: {:?}", path);
                info!("您可以编辑此文件，下次运行时工具会自动加载它。");
                process::exit(0);
            }
            Err(e) => {
                error!("导出失败: {}", e);
                process::exit(1);
            }
        }
    }

    let config = match ScanConfig::from_cli(cli.clone()) {
        Ok(c) => c,
        Err(e) => {
            error!("配置错误: {}", e);
            process::exit(1);
        }
    };

    scanner::probes::set_random_ua(config.random_ua);

    if config.dir_scan {
        info!("[*] 已加载 Web 目录字典: {} 条", config.dir_paths.len());
    }

    scanner::fingerprint_db::FingerprintDatabase::init(config.fingerprints.clone());

    let targets = match target::resolve_targets(
        &config.targets,
        cli.target_list.as_deref(),
        &config.exclude_hosts,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("目标解析错误: {}", e);
            process::exit(2);
        }
    };
    if targets.is_empty() {
        error!("未指定有效目标。请使用 TARGET 参数或 -L 指定目标文件。");
        process::exit(1);
    }
    let results = scanner::run_scan(&config, targets).await;
    if config.json_output || config.output_file.is_some() {
        if let Err(e) = output::output_json(&results, &config) {
            eprintln!("JSON 输出失败: {}", e);
        }
    }

    if !config.json_output {
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
