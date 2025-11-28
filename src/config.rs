use clap::Parser;
use std::path::PathBuf;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::fs::File;

#[derive(Parser, Debug, Clone)]
#[command(name = "TL-Rustscan")]
#[command(author = "Rust Developer")]
#[command(version = "1.0.0")]
#[command(about = "TL-Rustscan - 高并发端口扫描器", long_about = None)]
#[command(after_help = "警告：本工具只允许在取得授权的前提下用于内部资产摸排、攻防演练、渗透测试等合法场景。禁止对未授权目标进行扫描。")]
pub struct Cli {
    #[arg(value_name = "TARGET")]
    pub target: Vec<String>,
    #[arg(short = 'L', long, value_name = "FILE")]
    pub target_list: Option<PathBuf>,
    #[arg(short, long, default_value = "1-65535")]
    pub ports: String,
    #[arg(short = 'C', long)]
    pub concurrency: Option<usize>,
    #[arg(short, long, default_value = "500")]
    pub timeout: u64,
    #[arg(long)]
    pub show_closed: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output_json: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub output_markdown: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub output_csv: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub output_html: Option<PathBuf>,
    #[arg(short = 'b', long)]
    pub banner: bool,
    #[arg(long)]
    pub udp: bool,
    #[arg(long)]
    pub check: bool,
    #[arg(long)]
    pub dir: bool,
    #[arg(long, value_name = "FILE")]
    pub paths: Option<PathBuf>,
    #[arg(long, value_name = "PORTS")]
    pub dir_ports: Option<String>,
    #[arg(long)]
    pub random: bool,
    #[arg(long, value_name = "TARGETS")]
    pub exclude_hosts: Option<String>,
    #[arg(long, value_name = "PORTS")]
    pub exclude_ports: Option<String>,
    #[arg(long)]
    pub deep: bool,
    #[arg(long, value_name = "FILE")]
    pub fingerprints: Option<PathBuf>,
    #[arg(long)]
    pub random_ua: bool,
    #[arg(long)]
    pub dump_json: bool,
    #[arg(long, default_value = "1")]
    pub retry: usize,
    #[arg(short = 'x', long)]
    pub no_retry: bool,
    #[arg(long, default_value = "0")]
    pub rate: u32,
    #[arg(long)]
    pub no_poc: bool,
    #[arg(long)]
    pub no_brute: bool,
    #[arg(long, short = 'r')]
    pub rscan: bool,
}
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub show_closed: bool,
    pub json_output: bool,
    pub output_file: Option<PathBuf>,
    pub output_markdown: Option<PathBuf>,
    pub output_csv: Option<PathBuf>,
    pub output_html: Option<PathBuf>,
    pub banner: bool,
    pub udp: bool,
    pub check_alive: bool,
    pub dir_scan: bool,
    pub dir_paths: Vec<String>,
    pub web_ports: Vec<u16>,
    pub randomize: bool,
    pub exclude_hosts: Vec<String>,
    pub deep_scan: bool,
    pub fingerprints_path: Option<PathBuf>,
    pub random_ua: bool,
    pub retry: usize,
    pub rate: u32,
    pub no_poc: bool,
    pub no_brute: bool,
    pub rscan: bool,
}
impl ScanConfig {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        let mut targets = Vec::new();
        targets.extend(cli.target);
        let mut ports = parse_ports(&cli.ports)?;
        if let Some(exclude_str) = cli.exclude_ports {
            let exclude_list = parse_ports(&exclude_str)?;
            let exclude_set: HashSet<u16> = exclude_list.into_iter().collect();
            ports.retain(|p| !exclude_set.contains(p));
        }
        let web_ports = if let Some(p) = cli.dir_ports {
            parse_ports(&p)?
        } else {
            vec![80, 443, 8080, 8000, 8081, 8443, 7001, 9200]
        };
        let mut exclude_hosts = Vec::new();
        if let Some(ex) = cli.exclude_hosts {
            exclude_hosts.push(ex);
        }
        let mut dir_paths: Vec<String> = include_str!("default_paths.txt")
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();

        if let Some(path) = cli.paths {
            let file = File::open(&path).context("无法读取字典文件")?;
            let reader = BufReader::new(file);
            dir_paths = reader.lines()
                .map(|l| l.unwrap_or_default().trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
        }
        let concurrency = cli.concurrency.unwrap_or({
            if ports.len() < 100 {
                500
            } else {
                #[cfg(target_os = "windows")]
                { 500 } // Windows 下限制默认并发，防止端口耗尽
                #[cfg(not(target_os = "windows"))]
                { 1000 }
            }
        });
        Ok(ScanConfig {
            targets, 
            ports,
            concurrency,
            timeout_ms: cli.timeout,
            show_closed: cli.show_closed,
            // 只有当用户明确要求输出 JSON 到 stdout (--json) 时，才视为纯 JSON 模式 (关闭进度条)
            // 如果只是输出到文件 (-o)，则保留进度条
            json_output: cli.json, 
            output_file: cli.output_json,
            output_markdown: cli.output_markdown,
            output_csv: cli.output_csv,
            output_html: cli.output_html,
            banner: cli.banner || cli.deep,
            udp: cli.udp,
            check_alive: cli.check,
            dir_scan: cli.dir,
            dir_paths,
            web_ports,
            randomize: cli.random,
            exclude_hosts,
            deep_scan: cli.deep,
            fingerprints_path: cli.fingerprints,
            random_ua: cli.random_ua,
            retry: if cli.no_retry { 0 } else { cli.retry },
            rate: cli.rate,
            no_poc: cli.no_poc,
            no_brute: cli.no_brute,
            rscan: cli.rscan,
        })
    }
}
fn parse_ports(port_str: &str) -> Result<Vec<u16>> {
    let mut ports = HashSet::new();
    for part in port_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                anyhow::bail!("无效的端口范围格式: {}", part);
            }
            let start: u16 = range[0].parse().context("解析端口范围起始值失败")?;
            let end: u16 = range[1].parse().context("解析端口范围结束值失败")?;
            if start > end {
                anyhow::bail!("无效的端口范围: {}-{} (起始端口不能大于结束端口)", start, end);
            }
            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let p: u16 = part.parse().context("解析端口失败")?;
            ports.insert(p);
        }
    }
    let mut sorted_ports: Vec<u16> = ports.into_iter().collect();
    sorted_ports.sort();
    Ok(sorted_ports)
}