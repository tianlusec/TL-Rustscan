use crate::config::ScanConfig;
use crate::scanner::PortState;
use colored::*;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
#[derive(Debug, Serialize, Clone)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dirs: Vec<String>,
}
#[derive(Debug, Serialize, Clone)]
pub struct HostScanResult {
    pub target: String,
    pub ip: String,
    pub ports: Vec<PortResult>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub vulns: Vec<String>,
}
use std::net::IpAddr;
pub fn format_realtime_output(
    ip: &IpAddr,
    port: u16,
    state: PortState,
    banner: Option<&str>,
    dirs: &[String],
) -> String {
    let state_str = match state {
        PortState::Open => "open".green(),
        PortState::Closed => "closed".red(),
        PortState::Filtered => "filtered".yellow(),
    };
    let host_port = format!("{}:{}", ip, port);
    let mut output = format!("{:<22} {}", host_port, state_str);
    if let Some(b) = banner {
        let display_banner = if b.len() > 60 {
            format!("{}...", &b[..57])
        } else {
            b.to_string()
        };
        output.push_str(&format!("  {}", display_banner.dimmed()));
    }
    if !dirs.is_empty() {
        for dir in dirs {
            output.push_str(&format!("\n  └── Found: {}", dir.cyan()));
        }
    }
    output
}
pub fn print_human_readable(results: &[HostScanResult], _config: &ScanConfig) {
    let mut open_ports_total = 0;
    let mut targets_scanned = 0;
    for res in results {
        targets_scanned += 1;
        if res.ports.is_empty() {
            continue;
        }
        println!(
            "\nScan result for {} ({})",
            res.target.bold().blue(),
            res.ip.yellow()
        );
        println!("{}", "─".repeat(80).dimmed());
        println!(
            "{:<12} {:<12} {}",
            "PORT".bold(),
            "STATE".bold(),
            "SERVICE/BANNER".bold()
        );
        println!("{}", "─".repeat(80).dimmed());
        for p in &res.ports {
            let state_str = match p.state {
                PortState::Open => "open".green(),
                PortState::Closed => "closed".red(),
                PortState::Filtered => "filtered".yellow(),
            };
            let banner_str = p.banner.as_deref().unwrap_or("");
            println!(
                "{:<12} {:<12} {}",
                format!("{}/{}", p.port, p.protocol),
                state_str,
                banner_str
            );
            for dir in &p.dirs {
                println!("  {:<10} └── {}", "", dir.cyan());
            }
            if p.state == PortState::Open {
                open_ports_total += 1;
            }
        }
        println!("{}", "─".repeat(80).dimmed());
    }
    println!("\n{}", "Scan summary:".bold().underline());
    println!("  Targets scanned: {}", targets_scanned.to_string().cyan());
    println!(
        "  Open ports found: {}",
        open_ports_total.to_string().green()
    );

    let mut vulns_found = false;
    for res in results {
        if !res.vulns.is_empty() {
            if !vulns_found {
                println!("\n{}", "Vulnerabilities found:".bold().red().underline());
                vulns_found = true;
            }
            for vuln in &res.vulns {
                println!("  [{}] {}", res.ip.yellow(), vuln.red());
            }
        }
    }
}
pub fn output_json(results: &[HostScanResult], config: &ScanConfig) -> anyhow::Result<()> {
    if let Some(path) = &config.output_file {
        let file = File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, results)?;
        println!("\nJSON 结果已保存至: {:?}", path);
    } else {
        let stdout = std::io::stdout();
        let writer = std::io::BufWriter::new(stdout.lock());
        serde_json::to_writer_pretty(writer, results)?;
    }
    Ok(())
}
pub fn output_markdown(results: &[HostScanResult], path: &std::path::Path) -> anyhow::Result<()> {
    let file = File::create(path)?;
    let mut file = std::io::BufWriter::new(file);
    writeln!(file, "# TL-Rustscan 扫描报告")?;
    writeln!(file)?;
    let total_targets = results.len();
    let total_open_ports: usize = results
        .iter()
        .map(|r| {
            r.ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count()
        })
        .sum();
    writeln!(file, "**总目标数**: {}", total_targets)?;
    writeln!(file, "**发现开放端口**: {}", total_open_ports)?;

    let total_vulns: usize = results.iter().map(|r| r.vulns.len()).sum();
    if total_vulns > 0 {
        writeln!(file, "**发现漏洞**: {}", total_vulns)?;
    }

    writeln!(file)?;
    writeln!(file, "---")?;
    writeln!(file)?;
    for res in results {
        if res.ports.is_empty() {
            continue;
        }
        writeln!(file, "## 目标: {} ({})", res.target, res.ip)?;
        writeln!(file)?;
        writeln!(file, "| Port | Protocol | State | Service/Banner |")?;
        writeln!(file, "| :--- | :--- | :--- | :--- |")?;
        for p in &res.ports {
            let state_str = match p.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };
            let banner = p.banner.as_deref().unwrap_or("");
            let safe_banner = banner.replace('|', "\\|");
            writeln!(
                file,
                "| {} | {} | {} | {} |",
                p.port, p.protocol, state_str, safe_banner
            )?;
            if !p.dirs.is_empty() {
                let dirs_str = p.dirs.join(", ");
                writeln!(file, "| | | | └─ Found: {} |", dirs_str)?;
            }
        }

        if !res.vulns.is_empty() {
            writeln!(file)?;
            writeln!(file, "**Vulnerabilities:**")?;
            for vuln in &res.vulns {
                writeln!(file, "- 🔴 {}", vuln)?;
            }
        }

        writeln!(file)?;
    }
    println!("\nMarkdown 报告已保存至: {:?}", path);
    Ok(())
}
pub fn output_csv(results: &[HostScanResult], path: &std::path::Path) -> anyhow::Result<()> {
    let file = File::create(path)?;
    let mut file = std::io::BufWriter::new(file);
    file.write_all(&[0xEF, 0xBB, 0xBF])?;
    writeln!(
        file,
        "IP,Host,Port,Protocol,State,Banner,Dirs,Vulnerabilities"
    )?;

    fn escape_csv(field: &str) -> String {
        if field.contains(',')
            || field.contains('"')
            || field.contains('\n')
            || field.contains('\r')
        {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }

    for res in results {
        for p in &res.ports {
            let mut banner = p.banner.as_deref().unwrap_or("").to_string();
            if banner.starts_with(['=', '+', '-', '@', '|', '%']) {
                banner.insert(0, '\'');
            }

            let mut dirs_str = p.dirs.join("; ");
            if dirs_str.starts_with(['=', '+', '-', '@', '|', '%']) {
                dirs_str.insert(0, '\'');
            }

            let mut vulns_str = res.vulns.join("; ");
            if vulns_str.starts_with(['=', '+', '-', '@', '|', '%']) {
                vulns_str.insert(0, '\'');
            }

            let mut target_str = res.target.clone();
            if target_str.starts_with(['=', '+', '-', '@', '|', '%']) {
                target_str.insert(0, '\'');
            }

            let state_str = match p.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };

            writeln!(
                file,
                "{},{},{},{},{},{},{},{}",
                escape_csv(&res.ip),
                escape_csv(&target_str),
                p.port,
                escape_csv(&p.protocol),
                escape_csv(state_str),
                escape_csv(&banner),
                escape_csv(&dirs_str),
                escape_csv(&vulns_str)
            )?;
        }
    }
    println!("\nCSV 结果已保存至: {:?}", path);
    Ok(())
}
use std::collections::HashSet;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#039;")
}

pub fn output_html(results: &[HostScanResult], path: &std::path::Path) -> anyhow::Result<()> {
    let file = File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);

    let mut open_ports = 0;
    let mut total_vulns = 0;
    let mut targets = HashSet::new();
    for res in results {
        targets.insert(&res.ip);
        if !res.vulns.is_empty() {
            total_vulns += res.vulns.len();
        }
        for p in &res.ports {
            if matches!(p.state, PortState::Open) {
                open_ports += 1;
            }
        }
    }
    let total_targets = targets.len();

    let html_head = format!(r#"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TL-Rustscan 扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .stat-card {{ background: #e9ecef; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-value.danger {{ color: #dc3545; }}
        .search-box {{ width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f1f3f5; font-weight: 600; }}
        tr:hover {{ background-color: #f8f9fa; }}
        .status-open {{ color: #28a745; font-weight: bold; }}
        .status-closed {{ color: #dc3545; }}
        .banner {{ color: #6c757d; font-size: 0.9em; }}
        .dirs {{ color: #17a2b8; font-size: 0.85em; display: block; margin-top: 4px; }}
        .vuln {{ color: #dc3545; font-weight: bold; display: block; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>TL-Rustscan 扫描报告</h1>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="total-targets">{}</div>
                <div>总目标数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="open-ports">{}</div>
                <div>开放端口</div>
            </div>
            <div class="stat-card">
                <div class="stat-value danger" id="total-vulns">{}</div>
                <div>发现漏洞</div>
            </div>
        </div>
        <input type="text" id="search" class="search-box" placeholder="搜索 IP, 端口, 服务或 Banner..." onkeyup="filterTable()">
        <table id="result-table">
            <thead>
                <tr>
                    <th>IP 地址</th>
                    <th>目标</th>
                    <th>端口</th>
                    <th>协议</th>
                    <th>状态</th>
                    <th>服务/Banner</th>
                </tr>
            </thead>
            <tbody>
"#, total_targets, open_ports, total_vulns);

    writer.write_all(html_head.as_bytes())?;

    for host in results {
        for (port_idx, port) in host.ports.iter().enumerate() {
            let mut dirs_html = String::new();
            if !port.dirs.is_empty() {
                let dirs_escaped: Vec<String> = port.dirs.iter().map(|d| escape_html(d)).collect();
                dirs_html = format!(r#"<span class="dirs">Found: {}</span>"#, dirs_escaped.join(", "));
            }

            let mut vulns_html = String::new();
            if port_idx == 0 && !host.vulns.is_empty() {
                let vulns_escaped: Vec<String> = host.vulns.iter().map(|v| format!(r#"<span class="vuln">🔴 {}</span>"#, escape_html(v))).collect();
                vulns_html = vulns_escaped.join("");
            }

            let state_str = match port.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };

            let row = format!(r#"
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td class="status-{}">{}</td>
                    <td>
                        <span class="banner">{}</span>
                        {}
                        {}
                    </td>
                </tr>
            "#, 
            escape_html(&host.ip),
            escape_html(&host.target),
            port.port,
            escape_html(&port.protocol),
            state_str,
            state_str,
            escape_html(port.banner.as_deref().unwrap_or("")),
            dirs_html,
            vulns_html
            );
            writer.write_all(row.as_bytes())?;
        }
    }

    let html_tail = r#"
            </tbody>
        </table>
    </div>
    <script>
        function filterTable() {
            const query = document.getElementById('search').value.toLowerCase();
            const rows = document.querySelectorAll('#result-table tbody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
    "#;

    writer.write_all(html_tail.as_bytes())?;
    println!("\nHTML 报告已保存至: {:?}", path);
    Ok(())
}
