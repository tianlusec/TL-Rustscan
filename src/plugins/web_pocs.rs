use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

pub struct WebPocPlugin;

#[async_trait]
impl ScanPlugin for WebPocPlugin {
    fn name(&self) -> &str {
        "WebPoc"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![
            80, 81, 443, 7001, 8000, 8001, 8008, 8080, 8081, 
            8443, 8888, 9000, 9001, 9043, 9090, 9200, 9443
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none()) // 禁止重定向，很多漏洞检测需要看 302/200
            .build()?;

        let port_int: u16 = info.port.parse().unwrap_or(80);
        let schemes = if [443, 8443, 9443].contains(&port_int) {
            vec!["https", "http"]
        } else {
            vec!["http", "https"]
        };

        let mut vulns = Vec::new();

        for scheme in schemes {
            let base_url = format!("{}://{}:{}", scheme, info.host, info.port);
            
            // 并发或顺序执行 POC
            // 这里为了简单，顺序执行几个高危且检测速度快的 POC
            
            // 1. Spring Boot Actuator
            if let Some(v) = check_springboot(&client, &base_url).await { vulns.push(v); }
            
            // 2. PHPMyAdmin
            if let Some(v) = check_phpmyadmin(&client, &base_url).await { vulns.push(v); }
            
            // 3. Nacos Auth Bypass
            if let Some(v) = check_nacos(&client, &base_url).await { vulns.push(v); }

            // 4. Docker Registry API
            if let Some(v) = check_docker_registry(&client, &base_url).await { vulns.push(v); }

            // 5. WebLogic Console
            if let Some(v) = check_weblogic(&client, &base_url).await { vulns.push(v); }

            // 6. Hikvision Camera
            if let Some(v) = check_hikvision(&client, &base_url).await { vulns.push(v); }

            // 7. Prometheus
            if let Some(v) = check_prometheus(&client, &base_url).await { vulns.push(v); }

            // 8. CouchDB
            if let Some(v) = check_couchdb(&client, &base_url).await { vulns.push(v); }
        }

        if vulns.is_empty() {
            Ok(None)
        } else {
            // 去重
            vulns.sort();
            vulns.dedup();
            Ok(Some(vulns.join("\n")))
        }
    }
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

async fn check_prometheus(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/metrics", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            if !body_bytes.is_empty() {
                let text = String::from_utf8_lossy(&body_bytes);
                if text.contains("go_gc_duration_seconds") || text.contains("process_cpu_seconds_total") {
                    let msg = format!("[+] Vuln: Prometheus Unauth: {}", url);
                    println!("{}", msg);
                    return Some(msg);
                }
            }
        }
    }
    None
}

async fn check_couchdb(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/_utils/", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("couchdb") || text.contains("CouchDB") {
                let msg = format!("[+] Vuln: CouchDB Unauth: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}

async fn check_weblogic(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/console/login/LoginForm.jsp", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("WebLogic Server") {
                let msg = format!("[*] Info: WebLogic Console found: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}

async fn check_hikvision(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/doc/page/login.asp", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("Hikvision") || text.contains("doc/page/login.asp") {
                let msg = format!("[*] Info: Hikvision Camera found: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}

async fn check_springboot(client: &Client, base_url: &str) -> Option<String> {
    let paths = vec!["/actuator/env", "/env", "/actuator"];
    for path in paths {
        let url = format!("{}{}", base_url, path);
        if let Ok(mut resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                let body_bytes = read_body_safe(&mut resp).await;
                let text = String::from_utf8_lossy(&body_bytes);
                if text.contains("activeProfiles") || text.contains("propertySources") || text.contains("_links") {
                    let msg = format!("[+] Vuln: SpringBoot Actuator Unauth: {}", url);
                    println!("{}", msg);
                    return Some(msg);
                }
            }
        }
    }
    None
}

async fn check_phpmyadmin(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/phpmyadmin/", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("<title>phpMyAdmin</title>") {
                let msg = format!("[*] Info: Found phpMyAdmin: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}

async fn check_nacos(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/nacos/v1/auth/users?pageNo=1&pageSize=9", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("username") && text.contains("password") {
                let msg = format!("[+] Vuln: Nacos Auth Bypass: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}

async fn check_docker_registry(client: &Client, base_url: &str) -> Option<String> {
    let url = format!("{}/v2/_catalog", base_url);
    if let Ok(mut resp) = client.get(&url).send().await {
        if resp.status().is_success() {
            let body_bytes = read_body_safe(&mut resp).await;
            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("repositories") {
                let msg = format!("[+] Vuln: Docker Registry Unauth: {}", url);
                println!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}
