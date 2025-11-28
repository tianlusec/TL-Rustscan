# TL-Rustscan - High-Performance Async Port Scanner

> **Developed by TianLu Laboratory**

`TL-Rustscan` is a high-performance, high-concurrency port scanning command-line tool written in Rust. Designed for red teaming, asset discovery, and penetration testing, it aims to provide fast, stable, and easy-to-integrate port probing capabilities.

## Security & Compliance Warning

**Unauthorized scanning is strictly prohibited!**

This tool is only allowed to be used for internal asset management, security self-assessment, red teaming, and other legal scenarios under the premise of **obtaining explicit authorization**.
*   Scanning unauthorized targets on the Internet is prohibited.
*   Users are solely responsible for any legal liabilities arising from the illegal use of this tool.

---

## Core Features

*   **Blazing Fast**: Based on the Tokio asynchronous runtime, supporting thousands of concurrent connections, completing common port probes in seconds.
*   **Real-time Feedback**: Open ports are output immediately upon discovery, without waiting for the scan to finish.
*   **Full Port Coverage**: Scans 1-65535 ports by default, leaving no hidden services behind.
*   **Red Team Mode**: Provides `--rscan` flag, integrating weak password brute-force (SSH, SMB, RDP, etc.) and high-risk vulnerability detection (MS17-010, WebLogic, etc.) for one-click intranet penetration.
*   **Smart Protocol Handshake**: Supports active probing for RTSP, SOCKS5, MQTT, AMQP, etc., automatically identifying services without banners.
*   **Context-Aware Fuzzing**: Web directory scanning automatically loads specific sensitive paths based on detected fingerprints (e.g., Spring, PHP).
*   **TLS Deep Analysis**: Automatically extracts SANs (Subject Alternative Names) from HTTPS certificates to discover hidden assets.
*   **Multi-Target Support**: Perfectly supports single IP, domain, CIDR subnets (e.g., `192.168.1.0/24`), and file import.
*   **Structured Output**: Supports standard JSON output, facilitating integration with asset management platforms or automation scripts.
*   **IPv6 Ready**: Fully supports scanning and plugin probing in IPv6 environments, automatically handling address format compatibility.
*   **Cross-Platform**: Single executable file, runs dependency-free on Windows, Linux, and macOS.

## Precision Assurance Mechanisms

As a security tool, we understand that "false positives" and "false negatives" are the biggest pain points. TL-Rustscan treats **precision** as a core metric, ensuring reliability through the following underlying mechanisms:

1.  **Smart Fragmentation Reassembly**:
    *   Automatically handles TCP packet fragmentation for protocols like SSH and MySQL.
    *   Introduces dynamic buffers and timeout windows to ensure complete Banner reading even in high-latency or jittery networks, preventing identification failures due to data truncation.

2.  **Connectionless UDP Probing**:
    *   Abandons the traditional `connect()` call in favor of the `send_to/recv_from` raw socket model.
    *   Captures ICMP (Port Unreachable) messages from intermediate gateways, accurately distinguishing between `Closed` (response received) and `Filtered` (no response/blocked), solving missed reports in multi-homed environments.

3.  **Web Directory Soft 404 Dynamic Baseline**:
    *   Automatically probes the target's 404 response characteristics (status code, page length, redirect behavior) before scanning.
    *   Supports **Chunked Encoding** stream reading, accurately filtering fake 200 OK pages by calculating the actual body size even if the server does not return a `Content-Length` header.

4.  **Windows Async IO Optimization**:
    *   Implemented a connection pool model based on `Blocking Task` to address Windows OS kernel Socket limitations.
    *   Completely resolves `OS Error 10055` (No buffer space available) and connection hangs caused by high-concurrency scanning on Windows.

## Installation

### Method 1: Direct Use (Pre-compiled)
Simply run `dist/TL-Rustscan.exe` (Windows) or `dist/TL-Rustscan` (Linux/macOS).

### Method 2: Build from Source
If you only have the source code, ensure you have the [Rust environment](https://rustup.rs/) installed, then run:

**Windows:**
Double-click `build.bat` in the project root directory.

**Linux/macOS:**
Run `build.sh` in the project root directory:
```bash
chmod +x build.sh
./build.sh
```
The compiled artifact will be located in `dist/TL-Rustscan`.

### Method 3: Docker
```bash
docker build -t tl-rustscan .
docker run --rm tl-rustscan --help
```

---

## Usage Guide

### 1. Basic Scan (Most Common)
Enter only the target IP or domain to scan all **1-65535** ports by default, with real-time results.

```powershell
TL-Rustscan 192.168.1.10
TL-Rustscan example.com
```

### 2. Specify Port Range
Use the `-p` parameter to scan specific ports.

*   **Single Port**: `-p 80`
*   **Multiple Ports**: `-p 22,80,443`
*   **Port Range**: `-p 1-1000`
*   **Mixed**: `-p 80,8000-8100,3389`

```powershell
TL-Rustscan 192.168.1.10 -p 22,80,443,3389
```

### 3. Scan Subnets (CIDR)
Supports automatic CIDR parsing to batch scan hosts within a subnet.

```powershell
# Scan Web ports for the entire C subnet
TL-Rustscan 192.168.1.0/24 -p 80,443
```

### 4. Import Targets from File
For multiple targets, write them into a text file (one IP, domain, or subnet per line) and load with `-L`.

**targets.txt example:**
```text
192.168.1.10
10.0.0.0/24
db-server.local
```

**Command:**
```powershell
TL-Rustscan -L targets.txt -p 1-1000
```

### 5. JSON Output (Automation)
Use the `--json` parameter to output results in JSON format, suitable for programmatic parsing.

```powershell
TL-Rustscan 192.168.1.10 -p 80 --json
```
Or save directly to a file:
```powershell
TL-Rustscan 192.168.1.10 -o result.json
```

### 6. Performance Tuning
*   **Concurrency (`-C`)**: Default is 200. Can be increased to 1000-2000 for faster speeds in good network conditions.
*   **Timeout (`-t`)**: Default is 500ms. Can be lowered (e.g., 200ms) for intranet, or increased (e.g., 1000ms) for internet/high-latency environments.
*   **Skip Retry (`-x`)**: By default, the tool performs a smart retry on timed-out ports to prevent false negatives. Use `-x` to disable this for maximum speed.

```powershell
# High-concurrency fast scan (skip retry)
TL-Rustscan 10.0.0.0/16 -p 80 -C 2000 -t 200 -x
```

### 7. Service Fingerprinting & Web Title
Use `-b` or `--banner` parameter. The tool will:
1.  Attempt to read service banners (e.g., SSH, FTP, MySQL, PostgreSQL, RDP).
2.  For Web services, automatically send requests to extract **Web Title** and **Web Framework Fingerprints** (e.g., Spring Boot, Laravel, Vue, etc.).

```powershell
TL-Rustscan 192.168.1.10 -p 80,8080,22,3306 -b
```

Output Example:
```text
192.168.1.10:80 is open (Title: Corporate OA System | Frameworks: Spring Boot)
192.168.1.10:22 is open (SSH-2.0-OpenSSH_8.2p1)
192.168.1.10:3306 is open (MySQL 5.7.33-log)
```

### 8. Generate Markdown Report
Use `--output-markdown <FILE>` to save scan results as a beautiful Markdown report.

```powershell
TL-Rustscan 192.168.1.0/24 -p 80,443 -b --output-markdown report.md
```

### 9. UDP Scan
Use `--udp` parameter to enable UDP scanning mode.
Note: UDP scanning is slower and unreliable; recommended only for specific ports (e.g., DNS 53, NTP 123, SNMP 161).

```powershell
TL-Rustscan 192.168.1.1 -p 53,123,161 --udp
```

### 10. Host Discovery
Use `--check` parameter to perform host discovery (Ping/Connect) before scanning ports.
Useful for large subnets to skip offline hosts and save time.

```powershell
# Scan entire B subnet, but only online hosts
TL-Rustscan 10.0.0.0/16 -p 80 --check
```

### 11. Web Directory Busting
Use `--dir` parameter to enable Web directory busting.
When a Web port (80, 443, 8080, etc.) is found, it automatically probes common paths (Built-in 300,000+ entries dictionary covering `/admin`, `/login`, `/backup` and various backup files).

```powershell
TL-Rustscan 192.168.1.10 -p 80,8080 --dir
```

You can also use `--paths` to specify a custom dictionary file:
```powershell
TL-Rustscan 192.168.1.10 -p 80 --dir --paths my_dict.txt
```

If you want to enable directory busting on non-standard ports (e.g., 12345), use `--dir-ports`:
```powershell
TL-Rustscan 192.168.1.10 -p 12345 --dir --dir-ports 12345
```

### 12. Deep Scan
Use `--deep` parameter to enable deep scanning mode.
In this mode, if specific frontend frameworks (e.g., Vue.js, RuoYi) are identified, it attempts to actively probe backend APIs to get more detailed system information (e.g., system title).
**Note**: This mode sends extra HTTP requests and may increase the risk of being blocked by firewalls.

```powershell
TL-Rustscan 192.168.1.10 -p 80 -b --deep
```

### 13. Red Team Mode / Intranet Penetration
Use `--rscan` (or `-r`) parameter to enable Red Team full-feature mode. This mode is designed for intranet penetration, integrating powerful features similar to `fscan`.
When enabled, the tool will automatically perform the following in addition to port scanning and service identification:
1.  **Brute-force**: Attempt weak passwords for SSH, SMB, FTP, MySQL, MSSQL, Postgres, Redis, MongoDB, Telnet, etc.
2.  **Vulnerability Scanning**: Detect high-risk vulnerabilities like MS17-010 (EternalBlue), SMBGhost, WebLogic, SpringBoot, Docker Registry, PHPMyAdmin, etc.
3.  **Info Leakage**: Detect NetBIOS hostname, SNMP community string, Oracle TNS, etc.

**Warning**: This mode is intrusive. Please ensure you have explicit authorization!

```powershell
# Enable Red Team mode, scan C subnet
TL-Rustscan 192.168.1.0/24 -r

# Enable Red Team mode, but disable brute-force (vuln scan only)
TL-Rustscan 192.168.1.10 -r --no-brute

# Enable Red Team mode, but disable vulnerability verification (brute-force only)
TL-Rustscan 192.168.1.10 -r --no-poc
```

### 14. Supported Protocols & Vulnerabilities
Currently, `TL-Rustscan` supports deep detection for the following protocols and vulnerabilities in Red Team mode:

**Brute-force:**
*   **SSH**: Port 22
*   **SMB**: Port 445
*   **FTP**: Port 21
*   **Telnet**: Port 23
*   **MySQL**: Port 3306
*   **MSSQL**: Port 1433
*   **PostgreSQL**: Port 5432
*   **Redis**: Port 6379
*   **MongoDB**: Port 27017
*   **Tomcat**: Port 8080 (Web Manager)

**Vulnerabilities & POCs:**
*   **Windows**: MS17-010 (EternalBlue)
*   **WebLogic**: CVE-2017-10271, CVE-2019-2725, Console Weak Password
*   **SpringBoot**: Actuator Unauthorized Access
*   **Nacos**: Unauthorized Access
*   **Docker Registry**: Unauthorized Access
*   **PHPMyAdmin**: Weak Password / Unauthorized
*   **Hikvision**: Camera Weak Password / Vulnerabilities
*   **Prometheus**: Unauthorized Access
*   **CouchDB**: Unauthorized Access
*   **JDWP**: Java Remote Debugging Vulnerability
*   **FCGI**: FastCGI Unauthorized Access
*   **VNC**: Port 5900 Unauthorized / Weak Password
*   **LDAP**: Port 389 Anonymous Access
*   **Zookeeper**: Unauthorized Access
*   **Elasticsearch**: Unauthorized Access

**Basic Fingerprinting (Original Features):**
**Basic Services:**
*   **SSH** (Port 22): Version (e.g., OpenSSH 8.2p1)
*   **MySQL** (Port 3306): Version (e.g., MySQL 5.7.33)
*   **PostgreSQL** (Port 5432): Service existence
*   **MSSQL** (Port 1433): Microsoft SQL Server
*   **Oracle** (Port 1521): Oracle TNS Listener
*   **MongoDB** (Port 27017): MongoDB Version
*   **Redis** (Port 6379): Redis & Auth requirement
*   **Memcached** (Port 11211): Memcached Service
*   **ElasticSearch** (Port 9200): Cluster Name & Version
*   **SMB** (Port 445): Windows SMB Service Version

**Remote Management:**
*   **RDP** (Port 3389): Microsoft RDP Service
*   **VNC** (Port 5900): RFB Protocol Version
*   **Telnet** (Port 23): Telnet Service

**Web Technologies (16000+):**
TL-Rustscan integrates Wappalyzer, Nuclei, and Recog fingerprint databases, supporting over 16000 Web technologies, including:
*   **Web Frameworks**: Spring Boot, Laravel, Django, Flask, ThinkPHP, ASP.NET, Ruby on Rails, Gin, Beego, etc.
*   **Frontend**: Vue.js, React, Angular, jQuery, Bootstrap, Webpack, etc.
*   **CMS & OA**: WordPress, Drupal, Joomla, Discuz!, Weaver OA, Seeyon OA, Yonyou NC, Tongda OA, etc.
*   **Favicon Hash**: Supports calculating and matching website icon Hash (Murmur3) to accurately identify specific applications (e.g., Seeyon OA).
*   **Smart Purification**: Automatically filters generic noise fingerprints (e.g., "Nginx", "Wappalyzer") to show only high-value results.
*   **Middleware**: Tomcat, Nginx, Apache, IIS, Jetty, WebLogic, WebSphere, JBoss, etc.
*   **Security**: Identifies 100+ WAFs (Cloudflare, AWS WAF, Aliyun WAF, SafeLine, etc.) and firewalls.
*   **DevOps**: Kubernetes, Docker, Jenkins, Grafana, Prometheus, GitLab, etc.
*   **Others**: Database admin panels, VPN gateways, virtualization platforms, etc.

**Deep Probe (Active):**
*   **RuoYi / Vue Admin**: With `--deep`, actively probes backend APIs for system titles.

### 15. Fingerprint Management & Evasion
TL-Rustscan has a rich built-in fingerprint database and supports user customization and detection evasion.

*   **Random User-Agent**: Use `--random-ua` to randomize the User-Agent header in HTTP requests, evading UA-based detection.
*   **Auto Load**: If `fingerprints.json` exists in the current directory, it will be automatically loaded, replacing the built-in database.
*   **Manual Specify**: Use `--fingerprints <FILE>` to specify a custom fingerprint file.
*   **Dump Built-in**: Use `--dump-json` to export the built-in database to `fingerprints.json` in the current directory for modification.
*   **Merge Import**: Use `scripts/import_fingerprints.py` to merge external fingerprint data (e.g., Finger/Ehole format) into the built-in database.

```powershell
# Scan with random User-Agent
TL-Rustscan 192.168.1.10 -p 80 -b --random-ua

# Dump built-in fingerprints
TL-Rustscan --dump-json
```

---

## Arguments

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `TARGET` | - | Target IP, Domain, or CIDR | - |
| `--target-list` | `-L` | Read targets from file | - |
| `--ports` | `-p` | Scan port range | `1-65535` |
| `--concurrency` | `-C` | Max concurrent connections | `200` |
| `--timeout` | `-t` | Connection timeout (ms) | `500` |
| `--banner` | `-b` | Enable service fingerprinting (incl. WAF) | `false` |
| `--rscan` | `-r` | Enable Red Team mode (Brute+Vuln) | `false` |
| `--no-brute` | - | Disable brute-force in Red Team mode | `false` |
| `--no-poc` | - | Disable vuln verification in Red Team mode | `false` |
| `--deep` | - | Enable deep scan (API probe) | `false` |
| `--udp` | - | Use UDP scan mode | `false` |
| `--check` | - | Host discovery before scan | `false` |
| `--dir` | - | Enable Web directory busting | `false` |
| `--paths` | - | Custom directory dictionary file | Built-in |
| `--dir-ports` | - | Ports for Web probing | `80,443...` |
| `--random-ua` | - | Use random User-Agent | `false` |
| `--fingerprints` | - | External fingerprint file (JSON) | - |
| `--dump-json` | - | Dump built-in fingerprints to file | `false` |
| `--json` | - | Output JSON format | `false` |
| `--output-json` | `-o` | Save JSON result to file | - |
| `--output-markdown` | - | Save result as Markdown file | - |
| `--show-closed` | - | Show closed/filtered ports | `false` |
| `--help` | `-h` | Show help information | - |

## Project Structure

```text
TL-Rustscan/
├── src/                    # Rust source code directory
│   ├── scanner/            # Core scanning modules
│   │   ├── tcp_connect.rs  # TCP port scanning implementation
│   │   ├── udp_scan.rs     # UDP port scanning implementation
│   │   ├── probes.rs       # Service fingerprinting & detection
│   │   ├── web_dir.rs      # Web directory busting
│   │   └── ...
│   ├── config.rs           # CLI argument parsing & configuration
│   ├── main.rs             # Program entry point
│   ├── output.rs           # Multi-format output (JSON, CSV, HTML, etc.)
│   └── target.rs           # Target parsing logic (CIDR, Domain, IP Range)
├── scripts/                # Auxiliary scripts
│   ├── update_fingerprints.py # Fingerprint DB updater (Wappalyzer/Nuclei/Recog)
│   └── import_fingerprints.py # Custom fingerprint importer (Finger/Ehole format)
├── tests/                  # Test cases
├── Cargo.toml              # Project dependencies
├── build.bat               # Windows quick build script
├── build.sh                # Linux/macOS quick build script
└── Dockerfile              # Docker deployment file
```

## FAQ

**Q: Scan speed is too slow?**
A: Try increasing concurrency `-C 1000`, or decrease timeout `-t 200` if in an intranet.

**Q: Why are some ports not found?**
A: The target might have a firewall. This tool currently only supports TCP Connect scanning, which may be logged or blocked by firewalls.

**Q: Too many results flooding the screen?**
A: Recommend using `--json` or `-o result.json` to save results to a file for viewing.
