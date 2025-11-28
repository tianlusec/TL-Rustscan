use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::sync::{OnceLock, Arc};
use regex::Regex;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use serde_json::Value;
use rand::prelude::IndexedRandom;
use std::sync::atomic::{AtomicBool, Ordering};
use murmur3::murmur3_32;
use std::io::Cursor;
use base64::{Engine as _, engine::general_purpose};

static RANDOM_UA: AtomicBool = AtomicBool::new(false);

async fn read_with_timeout(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> std::io::Result<usize> {
    let start = std::time::Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms);
    let mut total_read = 0;
    
    // 第一次读取：等待直到超时
    match timeout(timeout_duration, stream.read(buffer)).await {
        Ok(Ok(n)) => {
            if n == 0 {
                return Ok(0); // EOF
            }
            total_read += n;
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")),
    }

    // 后续读取：尝试读取剩余数据，处理分包情况
    // 只要缓冲区未满且总时间未超时，就继续尝试读取
    while total_read < buffer.len() {
        let elapsed = start.elapsed();
        if elapsed >= timeout_duration { break; }
        
        // 使用较短的超时时间 (e.g. 200ms) 探测后续数据包
        // 如果 200ms 内没有新数据，则认为响应结束
        match timeout(Duration::from_millis(200), stream.read(&mut buffer[total_read..])).await {
            Ok(Ok(n)) if n > 0 => total_read += n,
            _ => break, 
        }
    }
    
    Ok(total_read)
}

pub fn set_random_ua(enable: bool) {
    RANDOM_UA.store(enable, Ordering::Relaxed);
}

pub fn get_user_agent() -> String {
    if RANDOM_UA.load(Ordering::Relaxed) {
        let uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        ];
        uas.choose(&mut rand::rng()).unwrap().to_string()
    } else {
        "TL-Rustscan".to_string()
    }
}

pub fn detect_cdn(headers: &str) -> Option<String> {
    let h = headers.to_lowercase();
    
    let cdn_sigs = [
        ("Akamai", "akamaighost"),
        ("Akamai", "x-akamai-request-id"),
        ("CloudFront", "cloudfront"),
        ("CloudFront", "x-amz-cf-id"),
        ("Fastly", "fastly"),
        ("Azure CDN", "x-azure-ref"),
        ("EdgeCast", "ec_secure"),
        ("EdgeCast", "server: ecs"),
        ("CDNetworks", "cdnetworks"),
        ("MaxCDN", "maxcdn"),
        ("Qiniu", "qiniu"),
        ("Qiniu", "x-qnm-"),
        ("Aliyun CDN", "aliyun"), 
        ("Tencent CDN", "tencent"),
        ("BaishanCloud", "baishan"),
        ("Wangsu", "ws_"), // 网宿
        ("Cloudflare", "cf-ray"), // Cloudflare is also a CDN
        ("ArvanCloud", "arvancloud"),
        ("Sucuri", "sucuri"),
        ("Incapsula", "incap_ses"),
        ("Incapsula", "visid_incap"),
    ];

    for (name, sig) in cdn_sigs {
        if h.contains(sig) {
            return Some(format!("CDN: {}", name));
        }
    }
    None
}

pub fn detect_waf(headers: &str, body: &str) -> Option<String> {
    let headers_lower = headers.to_lowercase();
    let body_lower = body.to_lowercase();

    let waf_signatures = [
        ("Cloudflare", "server: cloudflare"),
        ("Cloudflare", "__cfduid="),
        ("Aliyun WAF", "x-powered-by: aliyunwaf"),
        ("Aliyun WAF", "aliyunwaf"),
        ("AWS WAF", "x-amzn-requestid"),
        ("AWS WAF", "awselb/2.0"),
        ("F5 BIG-IP", "big-ip"),
        ("F5 BIG-IP", "x-cnection: close"),
        ("Imperva Incapsula", "x-iinfo"),
        ("Imperva Incapsula", "incap_ses"),
        ("ModSecurity", "mod_security"),
        ("ModSecurity", "not acceptable"),
        ("Safe3 WAF", "safe3waf"),
        ("Safe3 WAF", "x-powered-by: safe3waf"),
        ("Nginx WAF", "ngx_lua_waf"),
        ("Tencent Cloud WAF", "x-t-waf"),
        ("Baidu Yunjiasu", "yunjiasu-nginx"),
    ];

    for (name, sig) in waf_signatures {
        if headers_lower.contains(sig) || body_lower.contains(sig) {
            return Some(format!("WAF: {}", name));
        }
    }
    
    if (headers.contains("403 Forbidden") || headers.contains("406 Not Acceptable")) && (body_lower.contains("waf") || body_lower.contains("firewall") || body_lower.contains("denied")) {
             return Some("WAF: Generic (Blocked)".to_string());
    }

    None
}

pub fn clean_banner(s: &str) -> String {
    s.trim()
        .replace('\r', "")
        .replace('\n', " ")
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect()
}
pub fn format_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => format!("[{}]", ipv6),
    }
}

pub fn format_host_header(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

use crate::scanner::fingerprint_db::FingerprintDatabase;

pub fn match_service_signature(buffer: &[u8]) -> Option<String> {
    if buffer.len() < 4 {
        return None;
    }
    
    let s = String::from_utf8_lossy(buffer);
    if let Some(name) = FingerprintDatabase::global().match_service_banner(&s) {
        return Some(name);
    }

    if buffer.starts_with(b"SSH-") {
        return Some(clean_banner(&s));
    }
    if buffer.len() > 5 && buffer[4] == 0x0a {
        let mut end_idx = 5;
        while end_idx < buffer.len() && buffer[end_idx] != 0 {
            end_idx += 1;
        }
        if end_idx > 5 {
            let version = String::from_utf8_lossy(&buffer[5..end_idx]);
            if version.chars().any(|c| c.is_numeric()) {
                return Some(format!("MySQL {}", version));
            }
        }
    }
    None
}
fn title_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?is)<title>(.*?)</title>").unwrap())
}
fn generator_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?is)<meta\s+name=["']generator["']\s+content=["'](.*?)["']"#).unwrap())
}
pub fn detect_frameworks(response: &str) -> Vec<String> {
    let mut frameworks = Vec::new();
    
    let mut headers = String::new();
    let mut _body = String::new();
    let mut title = String::new();

    if let Some((h, b)) = response.split_once("\r\n\r\n") {
        headers = h.to_string();
        _body = b.to_string();
    } else if let Some((h, b)) = response.split_once("\n\n") {
        headers = h.to_string();
        _body = b.to_string();
    } else {
        _body = response.to_string();
    }

    if let Some(caps) = title_regex().captures(response) {
        if let Some(t) = caps.get(1) {
            title = t.as_str().trim().to_string();
        }
    }

    let db_matches = FingerprintDatabase::global().match_http(&_body, &headers, &title);
    frameworks.extend(db_matches);

    let _response_lower = response.to_lowercase();
    
    frameworks.sort();
    frameworks.dedup();
    frameworks
}
pub fn parse_http_banner(response: &str) -> (Option<String>, Option<String>) {
    let mut parts = Vec::new();
    let mut location_url = None;
    let first_line = response.lines().next().unwrap_or("").trim();
    if !first_line.is_empty() {
        if let Some(idx) = first_line.find(' ') {
            parts.push(first_line[idx+1..].to_string());
        } else {
            parts.push(first_line.to_string());
        }
    }
    if response.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(response) {
             if let Some(cluster) = v.get("cluster_name").and_then(|s| s.as_str()) {
                 parts.push(format!("ES Cluster: {}", cluster));
             }
             if let Some(ver) = v.get("version").and_then(|o| o.get("number")).and_then(|s| s.as_str()) {
                 parts.push(format!("ES Version: {}", ver));
             }
        }
    }
    if let Some(caps) = title_regex().captures(response) {
        if let Some(title) = caps.get(1) {
            let title_str = title.as_str().trim();
            if !title_str.is_empty() {
                parts.push(format!("Title: {}", title_str));
            }
        }
    }
    if let Some(caps) = generator_regex().captures(response) {
        if let Some(gen) = caps.get(1) {
            let gen_str = gen.as_str().trim();
            if !gen_str.is_empty() {
                parts.push(format!("Generator: {}", gen_str));
            }
        }
    }
    let frameworks = detect_frameworks(response);
    if !frameworks.is_empty() {
        parts.push(format!("Frameworks: {}", frameworks.join(", ")));
    }
    
    let (headers, body) = if let Some((h, b)) = response.split_once("\r\n\r\n") {
        (h, b)
    } else if let Some((h, b)) = response.split_once("\n\n") {
        (h, b)
    } else {
        (response, "")
    };
    
    if let Some(waf) = detect_waf(headers, body) {
        parts.push(waf);
    }
    if let Some(cdn) = detect_cdn(headers) {
        // 避免与 WAF 重复显示 (例如 Cloudflare 既是 WAF 也是 CDN)
        let is_duplicate = parts.iter().any(|p| p.contains(&cdn) || (p.contains("Cloudflare") && cdn.contains("Cloudflare")));
        if !is_duplicate {
            parts.push(cdn);
        }
    }

    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("location:") {
            let location = line[9..].trim();
            location_url = Some(location.to_string());
            parts.push(format!("Redirect: {}", location));
        }
        if line_lower.starts_with("server:") || line_lower.starts_with("x-powered-by:") {
            parts.push(line.trim().to_string());
        }
    }
    let banner = if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    };
    (banner, location_url)
}
pub fn get_tls_connector() -> TlsConnector {
    static TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let config = TLS_CONFIG.get_or_init(|| {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        struct NoVerifier;
        impl tokio_rustls::rustls::client::ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &tokio_rustls::rustls::Certificate,
                _intermediates: &[tokio_rustls::rustls::Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
            }
        }
        config.dangerous().set_certificate_verifier(Arc::new(NoVerifier));
        Arc::new(config)
    });
    TlsConnector::from(config.clone())
}
pub fn get_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("TL-Rustscan")
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::limited(3))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default()
    })
}
pub async fn probe_redis(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(b"PING\r\n")).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                let s = String::from_utf8_lossy(&buffer[..n]);
                if s.contains("PONG") {
                    return Some("Redis".to_string());
                } else if s.contains("NOAUTH") {
                    return Some("Redis (Auth Required)".to_string());
                } else {
                    return Some(clean_banner(&s));
                }
            }
        }
    }
    None
}
async fn read_body_safe(resp: &mut reqwest::Response) -> Vec<u8> {
    let mut body_bytes = Vec::new();
    let limit = 1024 * 1024; // 1MB

    while let Ok(Some(chunk)) = resp.chunk().await {
        if body_bytes.len() + chunk.len() > limit {
            body_bytes.extend_from_slice(&chunk[..limit - body_bytes.len()]);
            break;
        }
        body_bytes.extend_from_slice(&chunk);
    }
    body_bytes
}

pub async fn probe_ruoyi_api(ip: IpAddr, port: u16, host: &str, is_https: bool, timeout_ms: u64, ua: &str) -> Option<String> {
    let scheme = if is_https { "https" } else { "http" };
    let is_ip = host.parse::<IpAddr>().is_ok();
    
    let use_global_client = is_ip || !is_https;

    let client = if !use_global_client {
        let addr = SocketAddr::new(ip, port);
        reqwest::Client::builder()
            .user_agent(ua)
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(3))
            .resolve(host, addr)
            .build()
            .unwrap_or_default()
    } else {
        get_http_client().clone()
    };

    let url = if use_global_client && !is_ip {
        format!("{}://{}:{}/prod-api/system/config/getLogoInfo", scheme, format_host(ip), port)
    } else {
        let host_str = if is_ip { format_host(ip) } else { host.to_string() };
        format!("{}://{}:{}/prod-api/system/config/getLogoInfo", scheme, host_str, port)
    };

    let mut req_builder = client.get(&url).timeout(Duration::from_millis(timeout_ms));
    
    if !is_ip {
        req_builder = req_builder.header("Host", host);
    }
    
    req_builder = req_builder.header(reqwest::header::USER_AGENT, ua);

    if let Ok(mut resp) = req_builder.send().await {
        // 修复: 使用安全读取，防止 OOM
        let body_bytes = read_body_safe(&mut resp).await;
        if let Ok(json) = serde_json::from_slice::<Value>(&body_bytes) {
            if let Some(data) = json.get("data") {
                if let Some(title) = data.get("sysTitle") {
                    if let Some(title_str) = title.as_str() {
                        return Some(format!("App Title: {}", title_str));
                    }
                }
            }
        }
    }
    None
}
pub async fn probe_favicon(ip: IpAddr, port: u16, host: &str, is_https: bool, timeout_ms: u64) -> Option<String> {
    let scheme = if is_https { "https" } else { "http" };
    let is_ip = host.parse::<IpAddr>().is_ok();
    
    let use_global_client = is_ip || !is_https;

    let client = if !use_global_client {
        let addr = SocketAddr::new(ip, port);
        reqwest::Client::builder()
            .user_agent(get_user_agent())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(3))
            .resolve(host, addr)
            .build()
            .unwrap_or_default()
    } else {
        get_http_client().clone()
    };

    let url = if use_global_client && !is_ip {
        format!("{}://{}:{}/favicon.ico", scheme, format_host(ip), port)
    } else {
        let host_str = if is_ip { format_host(ip) } else { host.to_string() };
        format!("{}://{}:{}/favicon.ico", scheme, host_str, port)
    };

    let mut req_builder = client.get(&url).timeout(Duration::from_millis(timeout_ms));
    
    if !is_ip {
        req_builder = req_builder.header("Host", host);
    }
    
    if let Ok(mut resp) = req_builder.send().await {
        if resp.status().is_success() {
            // 修复: 使用安全读取，防止 OOM
            let bytes = read_body_safe(&mut resp).await;
            if !bytes.is_empty() {
                let b64 = general_purpose::STANDARD.encode(&bytes);
                let mut formatted_b64 = String::with_capacity(b64.len() + b64.len() / 76 + 1);
                let mut chunks = b64.as_bytes().chunks(76);
                while let Some(chunk) = chunks.next() {
                    formatted_b64.push_str(std::str::from_utf8(chunk).unwrap());
                    formatted_b64.push('\n');
                }
                
                let mut cursor = Cursor::new(formatted_b64.as_bytes());
                if let Ok(hash_u32) = murmur3_32(&mut cursor, 0) {
                    let hash_i32 = hash_u32 as i32;
                    if let Some(name) = FingerprintDatabase::global().match_favicon(hash_i32) {
                        return Some(format!("Favicon: {}", name));
                    }
                }
            }
        }
    }
    None
}
pub async fn probe_ssh(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buffer[..n]);
            if s.starts_with("SSH-") {
                return Some(clean_banner(&s));
            }
        }
    }
    None
}
pub async fn probe_mysql(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 5 {
            let proto_ver = buffer[4];
            if proto_ver == 0x0a {
                let mut end_idx = 5;
                while end_idx < n && buffer[end_idx] != 0 {
                    end_idx += 1;
                }
                if end_idx > 5 {
                    let version = String::from_utf8_lossy(&buffer[5..end_idx]);
                    return Some(format!("MySQL {}", version));
                }
            }
        }
    }
    None
}
pub async fn probe_postgresql(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let ssl_request = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&ssl_request)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                if buffer[0] == b'S' || buffer[0] == b'N' {
                    return Some("PostgreSQL".to_string());
                }
                if buffer[0] == b'E' {
                    return Some("PostgreSQL (Error Response)".to_string());
                }
            }
        }
    }
    None
}
pub async fn probe_rdp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let rdp_req = [
        0x03, 0x00, 0x00, 0x13, 
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&rdp_req)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 5 && buffer[0] == 0x03 && buffer[5] == 0xd0 {
                    return Some("Microsoft RDP".to_string());
            }
        }
    }
    None
}
pub async fn probe_ftp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buffer[..n]);
            if s.starts_with("220") {
                return Some(clean_banner(&s));
            }
        }
    }
    None
}
pub async fn probe_smtp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buffer[..n]);
            if s.starts_with("220") {
                return Some(clean_banner(&s));
            }
        }
    }
    None
}
pub async fn probe_telnet(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 0 {
            if buffer[0] == 0xff {
                return Some("Telnet (Negotiation)".to_string());
            }
            let s = String::from_utf8_lossy(&buffer[..n]);
            if s.to_lowercase().contains("login:") || s.to_lowercase().contains("password:") {
                return Some(format!("Telnet ({})", clean_banner(&s)));
            }
        }
    }
    None
}
pub async fn probe_memcached(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(b"stats\r\n")).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                let s = String::from_utf8_lossy(&buffer[..n]);
                if s.starts_with("STAT") {
                    return Some("Memcached".to_string());
                }
            }
        }
    }
    None
}
pub async fn probe_smb(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let smb2_negotiate = [
        0x00, 0x00, 0x00, 0x44, 
        0xfe, 0x53, 0x4d, 0x42, 
        0x40, 0x00, 
        0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 
        0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 
        0x02, 0x00, 
        0x01, 0x00, 
        0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 
        0x00, 0x00, 
        0x02, 0x02, 
        0x10, 0x02, 
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&smb2_negotiate)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 8 {
                if buffer[4] == 0xfe && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42 {
                    return Some("SMB (Windows)".to_string());
                }
                if buffer[4] == 0xff && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42 {
                    return Some("SMB (Legacy)".to_string());
                }
            }
        }
    }
    None
}
pub async fn probe_mongodb(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let op_msg_hello = [
        0x25, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0xdd, 0x07, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00,                   
        0x10, 0x00, 0x00, 0x00, 
        0x10,                   
        0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 
        0x01, 0x00, 0x00, 0x00, 
        0x00                    
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&op_msg_hello)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 16 && buffer[12] == 0xdd && buffer[13] == 0x07 {
                     return Some("MongoDB (Modern)".to_string());
            }
        }
    }
    let mongodb_query = [
        0x3a, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0xd4, 0x07, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00, 
        0x13, 0x00, 0x00, 0x00, 
        0x10, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00, 
        0x01, 0x00, 0x00, 0x00, 
        0x00 
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&mongodb_query)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 16 && buffer[12] == 0x01 {
                    let s = String::from_utf8_lossy(&buffer[..n]);
                    if s.contains("version") {
                         return Some("MongoDB (Legacy)".to_string());
                    }
                    return Some("MongoDB".to_string());
            }
        }
    }
    None
}
pub async fn probe_mssql(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let mssql_prelogin = [
        0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
        0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
        0x01, 0xff, 0x08, 0x00, 0x01, 0x55, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&mssql_prelogin)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 && (buffer[0] == 0x12 || buffer[0] == 0x04) {
                    return Some("Microsoft SQL Server".to_string());
            }
        }
    }
    None
}
pub async fn probe_oracle(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let tns_connect = [
        0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x39, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
        0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1e, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x39, 0x02, 0x05, 0xdc, 0xff
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&tns_connect)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n >= 8 && (buffer[4] == 2 || buffer[4] == 4) {
                    return Some("Oracle TNS Listener".to_string());
            }
        }
    }
    None
}
pub async fn probe_vnc(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
        if n > 0 {
            let s = String::from_utf8_lossy(&buffer[..n]);
            if s.starts_with("RFB") {
                return Some(clean_banner(&s));
            }
        }
    }
    None
}

pub async fn probe_ldap(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    // LDAP Anonymous Bind Request
    // Sequence(MsgId=1, BindRequest(Version=3, Name="", SimpleAuth=""))
    let ldap_bind = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&ldap_bind)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                // Check for Sequence and BindResponse (0x61)
                if buffer[0] == 0x30 && n > 5 {
                    // We could parse more, but just identifying LDAP is enough
                    return Some("LDAP".to_string());
                }
            }
        }
    }
    None
}

pub async fn probe_zookeeper(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(b"ruok")).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                let s = String::from_utf8_lossy(&buffer[..n]);
                if s.contains("imok") {
                    return Some("Zookeeper".to_string());
                }
            }
        }
    }
    None
}
pub async fn probe_jdwp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let handshake = b"JDWP-Handshake";
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(handshake)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n >= 14 {
                let s = String::from_utf8_lossy(&buffer[..n]);
                if s.starts_with("JDWP-Handshake") {
                    return Some("Java Debug Wire Protocol (JDWP)".to_string());
                }
            }
        }
    }
    None
}

pub async fn probe_rmi(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    // JRMI Version 2, Stream Protocol
    let rmi_handshake = [0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&rmi_handshake)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                // RMI usually responds with 'N' (Ack) or specific error
                if buffer[0] == 0x4e {
                    return Some("Java RMI Registry".to_string());
                }
            }
        }
    }
    None
}

pub async fn probe_rtsp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    let rtsp_req = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(rtsp_req)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n > 0 {
                let s = String::from_utf8_lossy(&buffer[..n]);
                if s.contains("RTSP/") {
                    return Some(clean_banner(&s));
                }
            }
        }
    }
    None
}

pub async fn probe_socks5(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    // SOCKS5 Version 5, 1 Method, No Auth (0x00)
    let socks_req = [0x05, 0x01, 0x00];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&socks_req)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n >= 2 {
                // Server chooses method: 0x05 0x00 (No Auth) or 0x05 0xFF (No acceptable methods)
                if buffer[0] == 0x05 {
                    if buffer[1] == 0x00 {
                        return Some("SOCKS5 (No Auth)".to_string());
                    } else if buffer[1] == 0xFF {
                        return Some("SOCKS5 (Auth Required)".to_string());
                    } else {
                        return Some("SOCKS5".to_string());
                    }
                }
            }
        }
    }
    None
}

pub async fn probe_mqtt(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    // MQTT Connect Packet (Minimal)
    // Fixed Header: 0x10 (Connect), Remaining Length: 12
    // Protocol Name Length: 4, "MQTT"
    // Protocol Level: 4
    // Connect Flags: 2 (Clean Session)
    // Keep Alive: 60
    // Client ID Length: 0
    let mqtt_connect = [
        0x10, 0x0c, 
        0x00, 0x04, b'M', b'Q', b'T', b'T', 
        0x04, 
        0x02, 
        0x00, 0x3c, 
        0x00, 0x00
    ];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&mqtt_connect)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n >= 4 {
                // ConnAck: 0x20, Remaining Length: 2
                if buffer[0] == 0x20 && buffer[1] == 0x02 {
                    return Some("MQTT".to_string());
                }
            }
        }
    }
    None
}

pub async fn probe_amqp(stream: &mut TcpStream, buffer: &mut [u8], timeout_ms: u64) -> Option<String> {
    // AMQP Protocol Header: "AMQP" + Protocol ID (0) + Major (0) + Minor (9) + Revision (1)
    let amqp_header = [b'A', b'M', b'Q', b'P', 0x00, 0x00, 0x09, 0x01];
    if timeout(Duration::from_millis(timeout_ms), stream.write_all(&amqp_header)).await.map(|r| r.is_ok()).unwrap_or(false) {
        if let Ok(n) = read_with_timeout(stream, buffer, timeout_ms).await {
            if n >= 8 {
                if buffer.starts_with(b"AMQP") {
                    return Some("AMQP".to_string());
                }
            }
        }
    }
    None
}