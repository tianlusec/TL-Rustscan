# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2024-12-07

### Major Release
This release is a significant milestone for TL-Rustscan, focusing on performance optimization, code refactoring, and open-source preparation.

### Added
- **Adaptive Concurrency Control**: Dynamically adjusts concurrency based on network conditions to improve scanning efficiency.
- **Connection Pool Health Check**: Optimized TCP connection reuse mechanism to reduce resource usage.
- **Parallel Fingerprint Matching**: Improved fingerprint matching speed.
- **Comprehensive Documentation**: Added detailed documentation for API, Architecture, Security, etc.

### Optimized
- **Code Refactoring**: Comprehensive cleanup of the codebase, removing redundant code and comments.
- **Project Structure**: Standardized project directory structure to meet open-source standards.
- **Build System**: Optimized build scripts and removed unnecessary build artifacts.

### Fixed
- Fixed multiple potential logic errors and performance bottlenecks.

## [1.2.2] - 2025-11-28

### Performance & Control Enhancements
This update focuses on enhancing user control over the scanning process and fixing memory safety issues in extreme scenarios.

### Added
- **Skip Retry (`-x` / `--no-retry`)**: Added the `-x` parameter to explicitly disable the "Smart Retry" mechanism.
  - By default, the tool automatically re-checks timed-out or filtered ports to improve accuracy.
  - In scenarios where extreme speed is desired or the network environment is very stable, using `-x` can skip this step and proceed directly to plugin scanning.

### Fixed
- **Deep OOM Protection**:
  - Fixed potential Out-of-Memory (OOM) issues in Web vulnerability scanning plugins (WebLogic, CouchDB, Hikvision, etc.) when reading large response bodies by enforcing a unified 1MB read limit.
  - Fixed HTML report generation logic to use streaming writes, preventing memory exhaustion when building huge strings for tens of thousands of targets.
- **Security Hardening**:
  - Fixed CSV Injection risks in CSV report generation by escaping all fields.
  - Fixed the "Double Port" bug in port parsing logic.

## [1.2.1] - 2025-11-26

### Critical Fixes & Robustness Improvements
This update is a hotfix release based on version 1.2.0, focusing on resolving multiple potential Panic risks and logic flaws identified during a deep code audit, and perfecting support for IPv6 environments.

### Fixed
- **Full IPv6 Support**: Fixed formatting issues with IPv6 addresses in TCP connections and URL construction (automatically adding `[]` wrappers). Now all plugins (SSH, WebTitle, Redis, etc.) perfectly support IPv6 target scanning.
- **RDP Plugin Out-of-bounds Read**: Fixed a potential Out-of-bounds Read risk in the RDP probing logic, preventing program crashes when receiving malformed packets.
- **Regex Engine ReDoS Protection**: Optimized regular expressions in the WebTitle plugin, introduced `OnceLock` for caching compilation results, and fixed potential ReDoS (Regular Expression Denial of Service) risks.
- **FingerprintDB Panic**: Fixed an issue where the program would crash due to `unwrap()` if regex compilation failed during fingerprint database loading. It now handles errors gracefully.
- **SSH Plugin DNS Resolution**: Fixed the issue where the SSH plugin only supported IP addresses and not domains. It now uses `ToSocketAddrs` for standard DNS resolution.
- **WebPoc Protocol Coverage**: Fixed the rigid protocol judgment in the Web vulnerability scanning plugin on non-standard ports (e.g., 8080, 8443). It now automatically attempts both HTTP and HTTPS protocols.
- **Oracle Plugin Integer Overflow**: Fixed a potential `u16` integer overflow risk when constructing Oracle TNS packets.

## [1.2.0] - 2025-11-26

### Red Team / Intranet Penetration Mode
This update introduces a major feature: **Red Team Mode (`--rscan`)**, marking the evolution of TL-Rustscan from a simple port scanner to a comprehensive intranet penetration tool.
This mode integrates core capabilities similar to `fscan`, supporting one-click weak password brute-force and high-risk vulnerability detection.

### Added
- **Red Team Mode (`--rscan` / `-r`)**: One-click intranet penetration mode, automatically performing weak password brute-force and vulnerability scanning.
- **Brute-force Module**:
  - Supports weak password detection for SSH, SMB, FTP, Telnet, MySQL, MSSQL, PostgreSQL, Redis, MongoDB, Tomcat, etc.
  - Built-in concise and efficient weak password dictionary for targeted brute-forcing.
- **Vulnerability/POC Module**:
  - **Windows**: MS17-010 (EternalBlue) detection.
  - **WebLogic**: CVE-2017-10271, CVE-2019-2725, Console Weak Password detection.
  - **Middleware/Frameworks**: Unauthorized access detection for SpringBoot Actuator, Nacos, Docker Registry, PHPMyAdmin, CouchDB, Prometheus, Zookeeper, Elasticsearch.
  - **Devices**: Hikvision weak password and vulnerability detection.
  - **Others**: JDWP remote debugging vulnerability, FCGI unauthorized access, VNC/LDAP unauthorized access.
- **Information Gathering**:
  - NetBIOS hostname retrieval.
  - SNMP community string brute-force and system info retrieval.
  - Oracle TNS Listener probing.
- **Control Arguments**:
  - `--no-brute`: Disable brute-force in Red Team mode, only perform vulnerability scanning.
  - `--no-poc`: Disable vulnerability verification in Red Team mode, only perform brute-force.

### Optimized
- **Plugin Architecture**: Refactored the scanning core, pluginizing all detection functions for easier future extension.
- **Smart Scheduling**: Plugins in Red Team mode are triggered only when ports are open and service fingerprints match, significantly improving scan efficiency and reducing interference with targets.

## [1.1.1] - 2025-11-25

### Core Architecture Upgrade (Precision & Stability)
This update focuses on a deep audit and refactoring of **scan precision** and **underlying stability**, resolving multiple long-standing edge case false positives.

### Added
- **Favicon Fingerprinting**: Added support for Favicon Hash (Murmur3) based fingerprinting.
  - Implemented standard Base64 chunking (MIME 76 chars) logic, consistent with Shodan algorithm.
  - Supports accurate identification of specific applications (e.g., Seeyon OA, Spring Boot) via website icons.
- **Fingerprint Expansion**: Added high-value fingerprint rules such as Seeyon OA.
- **Dictionary Upgrade**: Built-in Web directory busting dictionary expanded to 300,000+ entries, covering common backups, admin panels, and sensitive paths.
- **Smart Protocol Handshake**: Added active probing for RTSP, SOCKS5, MQTT, AMQP protocols, triggered automatically when no banner is received.
- **Context-Aware Fuzzing**: Web directory scanning now intelligently loads specific sensitive paths (e.g., `/actuator`, `/info.php`) based on detected fingerprints (Spring Boot, PHP, Tomcat, etc.).
- **TLS Deep Analysis**: Supports extracting TLS certificate Subject, Issuer, and SANs (Subject Alternative Names) to help discover hidden domains.

### Fixed & Optimized
- **Web Directory Soft 404 Detection**: 
  - **Chunked Encoding Support**: Fixed a critical issue where Soft 404 detection failed when the server used Chunked transfer encoding (no Content-Length header). Now automatically reads the response body (limit 1MB) to calculate the actual length.
  - Fixed a critical bug where directory scanning would report all paths as existing on servers with wildcard DNS or custom 404 pages (returning 200 OK).
  - Implemented baseline testing: requests a random path before scanning to record response characteristics (status code, length) and automatically filters similar responses.
- **Probe Robustness**:
  - **Smart Fragmentation Reassembly**: Refactored all active probing logic (Redis, MySQL, SSH, etc.) to introduce `read_with_timeout` mechanism.
  - Solved the issue of Banner truncation or identification failure caused by TCP packet fragmentation in slow networks or high-latency environments.
- **Windows Platform Stability**:
  - **Async Connection Optimization**: Refactored the TCP connection module for Windows kernel Socket limitations, using `spawn_blocking` to isolate connection operations, completely solving `OS Error 10055` and connection hangs under high concurrency.
- **Result Purification**: 
  - Implemented smart filtering mechanism to automatically block generic or noisy fingerprints (e.g., "Nginx", "Wappalyzer Technology Detection", "Kubelet Healthz").
  - Filtered low-value keyword matches like "default", "ok", "admin" for cleaner and more precise output.
- **Fingerprint Matching Logic**: Optimized the fingerprint matching process to prioritize high-value fingerprints.

## [1.1.0] - 2025-11-24

### Added
- **Massive Fingerprint Expansion**: Imported 12,000+ new Web fingerprint rules, bringing the total to over 16,000+, significantly improving detection capabilities for various CMS, OA, and middleware.
- **Fingerprint Import Tool**: Added `scripts/import_fingerprints.py` script to support merging custom fingerprint databases (Finger/Ehole format) into the built-in database, with automatic format conversion and deduplication.
- **WAF Detection**: Automatically detects Cloudflare, Aliyun, AWS, F5, etc.
- **Random User-Agent**: Support `--random-ua` to evade signature detection.
- **External Fingerprints**: Support `--fingerprints` to load custom JSON database.
- **Fingerprint Management**: Auto-load `fingerprints.json` from current directory and support `--dump-json` to export built-in database.

### Fixed & Optimized
- **Deep Code Audit Fixes**:
  - **HTTPS Redirect**: Fixed a critical bug where HTTPS redirects were ignored.
  - **Relative Redirect**: Added support for relative path redirects (e.g., `/login`).
  - **Performance**: Optimized fingerprint matching algorithm (pre-computed lowercase) to reduce CPU usage.
  - **Resource Optimization**: Refactored HTTP client management to reuse Client instances, significantly reducing memory and handle usage.
  - **Consistency**: Fixed inconsistent User-Agent usage during probing.
- **Core Logic Fixes**:
  - **Fingerprinting**: Fixed missed fingerprints due to case-sensitivity (e.g., `Server: Apache` vs `apache`). All regexes are now case-insensitive.
  - **HTTP Redirect**: Fixed missing HTTP redirect logic. The scanner now correctly follows redirects to capture fingerprints.
- **Performance Optimization**:
  - **Concurrent Web Dir Scan**: Changed directory busting from serial to concurrent execution, significantly improving speed.
  - Fixed TCP port exhaustion (EADDRNOTAVAIL) under high concurrency with exponential backoff.
  - Fixed UDP Socket bind exhaustion (EMFILE) under high concurrency.
  - **Fingerprint Matching Refactor**: Introduced Aho-Corasick algorithm, reducing matching complexity from O(N*M) to O(N+M), drastically improving scan speed with massive fingerprint databases.
  - **UDP Scan Robustness**: Fixed retry logic for UDP scanning during network jitter, added backoff mechanism.
  - **URL Parsing Enhancement**: Introduced standard `url` library for HTTP redirects, fixing fragility with relative paths and complex URLs.
- **Security Fixes**:
  - Fixed XSS vulnerability in HTML reports (HTML entity escaping).
  - Fixed CSV Injection (Formula Injection) vulnerability.
  - Enhanced Banner sanitization to filter terminal control characters.
- **Stability Fixes**:
  - Fixed UDP packet buffer overflow (ENOBUFS).
  - Fixed Panic risk in RST scan mode (removed unwrap).
- **Enhancements**:
  - **Web Fingerprinting**: Fixed missed Web fingerprints caused by non-standard Banners (e.g., JBoss), enhanced trigger logic.
  - Refactored UDP scan logic to support connectionless mode, solving missed packets in multi-homed environments.
  - Fixed UDP scan bind error in IPv6 environments (auto adapt `[::]:0`).
  - Fixed UDP scan source address validation to prevent false positives.
  - Optimized Host Discovery with retry logic for resource exhaustion.
  - Fixed HTTP Host Header format for IPv6 targets.
  - Added logic validation for port range configuration.
  - Optimized target resolution with (IP, Host) based VHost deduplication.
  - Improved CSV output format to comply with RFC 4180.

## [1.0.0] - 2025-11-23

### Added
- **Fingerprint Database Expansion**: Integrated Wappalyzer, Nuclei, Recog rules, reaching 4200+ fingerprints, and fixed all Rust regex compatibility issues.
- **WAF Detection**: Automatically detects Cloudflare, Aliyun, AWS, F5, etc.
- **Random User-Agent**: Support `--random-ua` to evade signature detection.
- **External Fingerprints**: Support `--fingerprints` to load custom JSON database.
- **Fingerprint Management**: Auto-load `fingerprints.json` from current directory and support `--dump-json` to export built-in database.

### Fixed & Optimized
- **Deep Code Audit Fixes**:
  - **HTTPS Redirect**: Fixed a critical bug where HTTPS redirects were ignored.
  - **Relative Redirect**: Added support for relative path redirects (e.g., `/login`).
  - **Performance**: Optimized fingerprint matching algorithm (pre-computed lowercase) to reduce CPU usage.
  - **Resource Optimization**: Refactored HTTP client management to reuse Client instances, significantly reducing memory and handle usage.
  - **Consistency**: Fixed inconsistent User-Agent usage during probing.
- **Core Logic Fixes**:
  - **Fingerprinting**: Fixed missed fingerprints due to case-sensitivity (e.g., `Server: Apache` vs `apache`). All regexes are now case-insensitive.
  - **HTTP Redirect**: Fixed missing HTTP redirect logic. The scanner now correctly follows redirects to capture fingerprints.
- **Performance Optimization**:
  - **Concurrent Web Dir Scan**: Changed directory busting from serial to concurrent execution, significantly improving speed.
  - Fixed TCP port exhaustion (EADDRNOTAVAIL) under high concurrency with exponential backoff.
  - Fixed UDP Socket bind exhaustion (EMFILE) under high concurrency.
  - **Fingerprint Matching Refactor**: Introduced Aho-Corasick algorithm, reducing matching complexity from O(N*M) to O(N+M), drastically improving scan speed with massive fingerprint databases.
  - **UDP Scan Robustness**: Fixed retry logic for UDP scanning during network jitter, added backoff mechanism.
  - **URL Parsing Enhancement**: Introduced standard `url` library for HTTP redirects, fixing fragility with relative paths and complex URLs.
- **Security Fixes**:
  - Fixed XSS vulnerability in HTML reports (HTML entity escaping).
  - Fixed CSV Injection (Formula Injection) vulnerability.
  - Enhanced Banner sanitization to filter terminal control characters.
- **Stability Fixes**:
  - Fixed UDP packet buffer overflow (ENOBUFS).
  - Fixed Panic risk in RST scan mode (removed unwrap).
- **Enhancements**:
  - **Web Fingerprinting**: Fixed missed Web fingerprints caused by non-standard Banners (e.g., JBoss), enhanced trigger logic.
  - Refactored UDP scan logic to support connectionless mode, solving missed packets in multi-homed environments.
  - Fixed UDP scan bind error in IPv6 environments (auto adapt `[::]:0`).
  - Fixed UDP scan source address validation to prevent false positives.
  - Optimized Host Discovery with retry logic for resource exhaustion.
  - Fixed HTTP Host Header format for IPv6 targets.
  - Added logic validation for port range configuration.
  - Optimized target resolution with (IP, Host) based VHost deduplication.
  - Improved CSV output format to comply with RFC 4180.

## [0.1.0] - 2024-11-23

### Added
- Initial release of TL-Rustscan.
- High-performance asynchronous port scanning based on Tokio.
- Support for TCP Connect scanning.
- Service fingerprinting for SSH, MySQL, Redis, MongoDB, MSSQL, Oracle, etc.
- Web framework fingerprinting (Spring Boot, Vue, Laravel, etc.).
- Deep scan mode for API probing (e.g., RuoYi).
- Web directory busting.
- Smart protocol fallback (HTTP/TLS).
- Support for CIDR, domain, and file targets.
- JSON, Markdown, CSV, and HTML output formats.
- Cross-platform support (Windows, Linux, macOS).
