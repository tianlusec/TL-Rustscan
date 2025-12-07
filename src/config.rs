use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "TL-Rustscan")]
#[command(author = "Rust Developer")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "TL-Rustscan - 高并发端口扫描器", long_about = None)]
#[command(after_help = "
警告：本工具只允许在取得授权的前提下用于内部资产摸排、攻防演练、渗透测试等合法场景。禁止对未授权目标进行扫描。

示例:
  1. 扫描单个 IP 的常用端口:
     TL-Rustscan 192.168.1.1

  2. 扫描 IP 段的所有端口，并发 5000:
     TL-Rustscan 192.168.1.0/24 -p 1-65535 -C 5000

  3. 扫描目标列表，开启 Banner 识别和目录扫描:
     TL-Rustscan -L targets.txt -b --dir

  4. 深度扫描，输出 JSON 结果:
     TL-Rustscan 10.0.0.1 --deep --json -o result.json

  5. 使用代理扫描:
     TL-Rustscan 192.168.1.1 --proxy socks5://127.0.0.1:1080
")]
pub struct Cli {
    #[arg(value_name = "TARGET", help = "扫描目标 (IP/域名/CIDR，如: 192.168.1.1 或 192.168.1.0/24)")]
    pub target: Vec<String>,
    
    #[arg(short = 'L', long, value_name = "FILE", help = "从文件读取目标列表 (每行一个目标)")]
    pub target_list: Option<PathBuf>,
    
    #[arg(short, long, default_value = "1-65535", help = "扫描端口范围 (如: 80,443 或 1-1000 或 80,8000-9000)")]
    pub ports: String,
    
    #[arg(short = 'C', long, help = "最大并发连接数 (默认: 端口<100时500，否则Windows=500/Linux=1000)")]
    pub concurrency: Option<usize>,
    
    #[arg(short, long, default_value = "500", help = "连接超时时间 (毫秒，内网建议200-500，公网建议1000-2000)")]
    pub timeout: u64,
    
    #[arg(long, help = "显示关闭/过滤的端口 (默认只显示开放端口)")]
    pub show_closed: bool,
    
    #[arg(long, help = "以 JSON 格式输出到 stdout (适合管道处理)")]
    pub json: bool,
    
    #[arg(short = 'o', long, value_name = "FILE", help = "将 JSON 结果保存到文件")]
    pub output_json: Option<PathBuf>,
    
    #[arg(long, value_name = "FILE", help = "将结果保存为 Markdown 格式报告")]
    pub output_markdown: Option<PathBuf>,
    
    #[arg(long, value_name = "FILE", help = "将结果保存为 CSV 格式 (含 CSV 注入防护)")]
    pub output_csv: Option<PathBuf>,
    
    #[arg(long, value_name = "FILE", help = "将结果保存为 HTML 交互式报告 (含 XSS 防护)")]
    pub output_html: Option<PathBuf>,
    
    #[arg(short = 'b', long, help = "开启服务指纹识别 (Banner抓取 + Web标题 + 16000+指纹库)")]
    pub banner: bool,
    
    #[arg(long, help = "使用 UDP 扫描模式 (建议只扫描特定端口如 53,123,161)")]
    pub udp: bool,
    
    #[arg(long, help = "扫描前进行主机存活检测 (ICMP+TCP，跳过离线主机)")]
    pub check: bool,
    
    #[arg(long, help = "开启 Web 目录爆破 (内置300,000+路径字典)")]
    pub dir: bool,
    
    #[arg(long, value_name = "FILE", help = "指定自定义目录爆破字典文件")]
    pub paths: Option<PathBuf>,
    
    #[arg(long, value_name = "PORTS", help = "指定进行 Web 探测的端口 (默认: 80,443,8080,8000,8081,8443,7001,9200)")]
    pub dir_ports: Option<String>,
    
    #[arg(long, help = "随机化目标和端口扫描顺序 (规避检测)")]
    pub random: bool,
    
    #[arg(long, value_name = "TARGETS", help = "排除特定主机 (支持 IP/CIDR)")]
    pub exclude_hosts: Option<String>,
    
    #[arg(long, value_name = "PORTS", help = "排除特定端口 (如: 22,3389)")]
    pub exclude_ports: Option<String>,
    
    #[arg(long, help = "深度扫描模式 (主动探测 API 接口，获取更多系统信息)")]
    pub deep: bool,
    
    #[arg(long, value_name = "FILE", help = "指定外部指纹库文件 (JSON 格式)")]
    pub fingerprints: Option<PathBuf>,
    
    #[arg(long, help = "使用随机 User-Agent (规避基于 UA 的检测)")]
    pub random_ua: bool,
    
    #[arg(long, help = "导出内置指纹库到 fingerprints.json")]
    pub dump_json: bool,
    
    #[arg(long, default_value = "1", help = "失败重试次数 (0=不重试，建议1-3次)")]
    pub retry: usize,
    
    #[arg(short = 'x', long, help = "禁用智能重试 (追求极致速度，可能漏报)")]
    pub no_retry: bool,
    
    #[arg(long, default_value = "0", help = "扫描速率限制 (请求/秒，0=无限制)")]
    pub rate: u32,
    
    #[arg(long, help = "红队模式下禁用漏洞验证 (只进行弱口令爆破)")]
    pub no_poc: bool,
    
    #[arg(long, help = "红队模式下禁用弱口令爆破 (只进行漏洞扫描)")]
    pub no_brute: bool,
    
    #[arg(long, short = 'r', help = "红队模式 (弱口令爆破+漏洞检测+信息收集，需授权!)")]
    pub rscan: bool,
    
    #[arg(long, help = "跳过 TLS 证书验证 (用于自签名证书环境)")]
    pub insecure: bool,
    
    #[arg(long, help = "断点续扫 (未实现)")]
    pub resume: bool,
    
    #[arg(long, value_name = "URL", help = "使用代理 (支持 http://、https://、socks5://)")]
    pub proxy: Option<String>,
    
    #[arg(short = 'v', long, help = "详细输出模式 (显示调试信息)")]
    pub verbose: bool,
    
    #[arg(short = 'q', long, help = "安静模式 (只显示错误信息)")]
    pub quiet: bool,
    
    #[arg(long, value_name = "FILE", help = "将日志保存到文件")]
    pub log_file: Option<PathBuf>,
    
    #[arg(long, help = "自适应并发控制 (实验性功能)")]
    pub adaptive: bool,
    
    #[arg(long, help = "禁用 TCP 连接池 (降低性能但减少资源占用)")]
    pub no_connection_pool: bool,
    
    #[arg(long, value_name = "CONCURRENCY", help = "目录扫描并发数 (默认: 路径>100时50，否则20)")]
    pub dir_concurrency: Option<usize>,
}
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub dir_concurrency: Option<usize>,
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
    pub proxy: Option<String>,
    pub fingerprints: Option<PathBuf>,
    pub random_ua: bool,
    pub resume: bool,
    pub retry: usize,
    pub rate: u32,
    pub insecure: bool,
    pub no_poc: bool,
    pub no_brute: bool,
    pub rscan: bool,
    pub adaptive: bool,
    pub use_connection_pool: bool,
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
            dir_paths = reader
                .lines()
                .map(|l| l.unwrap_or_default().trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
        }
        let concurrency = cli.concurrency.unwrap_or({
            if ports.len() < 100 {
                500
            } else {
                #[cfg(target_os = "windows")]
                {
                    500
                }
                #[cfg(not(target_os = "windows"))]
                {
                    1000
                }
            }
        });
        Ok(ScanConfig {
            targets,
            ports,
            concurrency,
            dir_concurrency: cli.dir_concurrency,
            timeout_ms: cli.timeout,
            show_closed: cli.show_closed,
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
            fingerprints: cli.fingerprints,
            random_ua: cli.random_ua,
            retry: if cli.no_retry { 0 } else { cli.retry },
            rate: cli.rate,
            no_poc: cli.no_poc,
            no_brute: cli.no_brute,
            rscan: cli.rscan,
            insecure: cli.insecure,
            resume: cli.resume,
            proxy: cli.proxy,
            adaptive: cli.adaptive,
            use_connection_pool: !cli.no_connection_pool,
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
            let start: u16 = range[0].parse().map_err(|_| anyhow::anyhow!("端口必须在 1-65535 之间"))?;
            let end: u16 = range[1].parse().map_err(|_| anyhow::anyhow!("端口必须在 1-65535 之间"))?;

            if start == 0 {
                anyhow::bail!("端口必须在 1-65535 之间: {}", start);
            }
            if start > end {
                anyhow::bail!(
                    "无效的端口范围: {}-{} (起始端口不能大于结束端口)",
                    start,
                    end
                );
            }
            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| anyhow::anyhow!("端口必须在 1-65535 之间"))?;
            if p == 0 {
                anyhow::bail!("端口必须在 1-65535 之间: {}", p);
            }
            ports.insert(p);
        }
    }
    let mut sorted_ports: Vec<u16> = ports.into_iter().collect();
    sorted_ports.sort();
    Ok(sorted_ports)
}
