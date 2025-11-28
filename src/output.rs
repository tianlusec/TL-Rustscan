use serde::Serialize;
use crate::scanner::PortState;
use crate::config::ScanConfig;
use std::fs::File;
use std::io::Write;
use colored::*;
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
pub fn format_realtime_output(ip: &IpAddr, port: u16, state: PortState, banner: Option<&str>, dirs: &[String]) -> String {
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
        println!("\nScan result for {} ({})", res.target.bold().blue(), res.ip.yellow());
        println!("{}", "─".repeat(80).dimmed());
        println!("{:<12} {:<12} {}", "PORT".bold(), "STATE".bold(), "SERVICE/BANNER".bold());
        println!("{}", "─".repeat(80).dimmed());
        for p in &res.ports {
            let state_str = match p.state {
                PortState::Open => "open".green(),
                PortState::Closed => "closed".red(),
                PortState::Filtered => "filtered".yellow(),
            };
            let banner_str = p.banner.as_deref().unwrap_or("");
            println!("{:<12} {:<12} {}", format!("{}/{}", p.port, p.protocol), state_str, banner_str);
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
    println!("  Open ports found: {}", open_ports_total.to_string().green());
    
    // Print vulnerabilities if any
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
    let mut file = File::create(path)?;
    writeln!(file, "# TL-Rustscan 扫描报告")?;
    writeln!(file)?;
    let total_targets = results.len();
    let total_open_ports: usize = results.iter().map(|r| r.ports.iter().filter(|p| p.state == PortState::Open).count()).sum();
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
            writeln!(file, "| {} | {} | {} | {} |", p.port, p.protocol, state_str, safe_banner)?;
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
    let mut file = File::create(path)?;
    file.write_all(&[0xEF, 0xBB, 0xBF])?;
    writeln!(file, "IP,Host,Port,Protocol,State,Banner,Dirs,Vulnerabilities")?;
    
    fn escape_csv(field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }

    for res in results {
        for p in &res.ports {
            let mut banner = p.banner.as_deref().unwrap_or("").to_string();
            if banner.starts_with(['=', '+', '-', '@']) {
                banner.insert(0, '\'');
            }
            
            let mut dirs_str = p.dirs.join("; ");
            if dirs_str.starts_with(['=', '+', '-', '@']) {
                dirs_str.insert(0, '\'');
            }

            let mut vulns_str = res.vulns.join("; ");
            if vulns_str.starts_with(['=', '+', '-', '@']) {
                vulns_str.insert(0, '\'');
            }

            // 修复: 对 target 字段也应用 CSV 注入防护
            let mut target_str = res.target.clone();
            if target_str.starts_with(['=', '+', '-', '@']) {
                target_str.insert(0, '\'');
            }

            let state_str = match p.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };
            
            writeln!(file, "{},{},{},{},{},{},{},{}", 
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
pub fn output_html(results: &[HostScanResult], path: &std::path::Path) -> anyhow::Result<()> {
    let file = File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);

    let html_head = r#"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TL-Rustscan 扫描报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #e9ecef; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .stat-value.danger { color: #dc3545; }
        .search-box { width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f1f3f5; font-weight: 600; }
        tr:hover { background-color: #f8f9fa; }
        .status-open { color: #28a745; font-weight: bold; }
        .status-closed { color: #dc3545; }
        .banner { color: #6c757d; font-size: 0.9em; }
        .dirs { color: #17a2b8; font-size: 0.85em; display: block; margin-top: 4px; }
        .vuln { color: #dc3545; font-weight: bold; display: block; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>TL-Rustscan 扫描报告</h1>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="total-targets">0</div>
                <div>总目标数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="open-ports">0</div>
                <div>开放端口</div>
            </div>
            <div class="stat-card">
                <div class="stat-value danger" id="total-vulns">0</div>
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
                <!-- Data will be injected here -->
            </tbody>
        </table>
    </div>
    <script>
        const data = "#;

    let html_tail = r#";
        
        function escapeHtml(text) {
            if (!text) return '';
            return String(text)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function renderTable(items) {
            const tbody = document.querySelector('#result-table tbody');
            let html = '';
            let openPorts = 0;
            let totalVulns = 0;
            let targets = new Set();
            items.forEach(host => {
                targets.add(host.ip);
                if (host.vulns && host.vulns.length > 0) {
                    totalVulns += host.vulns.length;
                }
                host.ports.forEach(port => {
                    if (port.state === 'open') openPorts++;
                    let dirsHtml = '';
                    if (port.dirs && port.dirs.length > 0) {
                        dirsHtml = `<span class="dirs">Found: ${port.dirs.map(d => escapeHtml(d)).join(', ')}</span>`;
                    }
                    let vulnsHtml = '';
                    if (host.vulns && host.vulns.length > 0) {
                        // Only show vulns on the first port row for this host, or maybe repeat?
                        // Better: just append them to the service column of the first port, or all ports?
                        // Let's append to the first port of the host for now, or just list them.
                        // Actually, since the table is port-based, it's a bit tricky to show host-based vulns.
                        // We will just append them to the Service/Banner column of every row for that host? No, that's too much.
                        // Let's just add them to the first row.
                    }
                    
                    // Simplified approach: Just list vulns in the Service column if it's the first port, 
                    // OR we can't easily know if it's the first port in this loop structure without index.
                    // Let's just add them to the banner column.
                });
                
                // Re-iterating to generate HTML
                host.ports.forEach((port, index) => {
                    let dirsHtml = '';
                    if (port.dirs && port.dirs.length > 0) {
                        dirsHtml = `<span class="dirs">Found: ${port.dirs.map(d => escapeHtml(d)).join(', ')}</span>`;
                    }
                    
                    let vulnsHtml = '';
                    if (index === 0 && host.vulns && host.vulns.length > 0) {
                         vulnsHtml = host.vulns.map(v => `<span class="vuln">🔴 ${escapeHtml(v)}</span>`).join('');
                    }

                    html += `
                        <tr>
                            <td>${escapeHtml(host.ip)}</td>
                            <td>${escapeHtml(host.target)}</td>
                            <td>${port.port}</td>
                            <td>${escapeHtml(port.protocol)}</td>
                            <td class="status-${port.state}">${port.state}</td>
                            <td>
                                <span class="banner">${escapeHtml(port.banner || '')}</span>
                                ${dirsHtml}
                                ${vulnsHtml}
                            </td>
                        </tr>
                    `;
                });
            });
            tbody.innerHTML = html;
            document.getElementById('total-targets').textContent = targets.size;
            document.getElementById('open-ports').textContent = openPorts;
            document.getElementById('total-vulns').textContent = totalVulns;
        }
        function filterTable() {
            const query = document.getElementById('search').value.toLowerCase();
            const rows = document.querySelectorAll('#result-table tbody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }
        renderTable(data);
    </script>
</body>
</html>
    "#;

    writer.write_all(html_head.as_bytes())?;

    // 修复: 使用流式写入并实时转义，防止 OOM
    struct SafeJsonWriter<W: Write> {
        inner: W,
    }

    impl<W: Write> Write for SafeJsonWriter<W> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut last_pos = 0;
            for (i, &b) in buf.iter().enumerate() {
                if b == b'<' || b == b'>' {
                    self.inner.write_all(&buf[last_pos..i])?;
                    if b == b'<' {
                        self.inner.write_all(b"\\u003c")?;
                    } else {
                        self.inner.write_all(b"\\u003e")?;
                    }
                    last_pos = i + 1;
                }
            }
            self.inner.write_all(&buf[last_pos..])?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    let mut safe_writer = SafeJsonWriter { inner: &mut writer };
    serde_json::to_writer(&mut safe_writer, results)?;

    writer.write_all(html_tail.as_bytes())?;
    println!("\nHTML 报告已保存至: {:?}", path);
    Ok(())
}