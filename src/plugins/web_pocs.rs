use super::{HostInfo, PluginType, ScanPlugin};
use crate::scanner::probes;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use tracing::info;

pub struct WebPocPlugin;

#[async_trait]
impl ScanPlugin for WebPocPlugin {
    fn name(&self) -> &str {
        "WebPoc"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![
            80, 81, 443, 7001, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9043, 9090,
            9200, 9443,
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let client = probes::get_cached_http_client(3, true, info.proxy.clone());

        let port_int: u16 = info.port.parse().unwrap_or(80);
        let schemes = if [443, 8443, 9443].contains(&port_int) {
            vec!["https", "http"]
        } else {
            vec!["http", "https"]
        };

        let mut vulns = Vec::new();

        for scheme in schemes {
            let base_url = format!("{}://{}:{}", scheme, info.host, info.port);

            if let Some(v) = check_springboot(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_phpmyadmin(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_nacos(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_docker_registry(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_weblogic(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_hikvision(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_prometheus(&client, &base_url).await {
                vulns.push(v);
            }

            if let Some(v) = check_couchdb(&client, &base_url).await {
                vulns.push(v);
            }
        }

        if vulns.is_empty() {
            Ok(None)
        } else {
            vulns.sort();
            vulns.dedup();
            Ok(Some(vulns.join("\n")))
        }
    }
}

async fn read_body_safe(resp: &mut reqwest::Response) -> Vec<u8> {
    let mut body_bytes = Vec::new();
    let limit = 1024 * 1024;

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
                if text.contains("go_gc_duration_seconds")
                    || text.contains("process_cpu_seconds_total")
                {
                    let msg = format!("[+] Vuln: Prometheus Unauth: {}", url);
                    info!("{}", msg);
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
                info!("{}", msg);
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
                info!("{}", msg);
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
                info!("{}", msg);
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
                if text.contains("activeProfiles")
                    || text.contains("propertySources")
                    || text.contains("_links")
                {
                    let msg = format!("[+] Vuln: SpringBoot Actuator Unauth: {}", url);
                    info!("{}", msg);
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
                info!("{}", msg);
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
                info!("{}", msg);
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
                info!("{}", msg);
                return Some(msg);
            }
        }
    }
    None
}
