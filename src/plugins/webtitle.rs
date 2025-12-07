use super::web_fingerprints;
use super::{HostInfo, PluginType, ScanPlugin};
use crate::scanner::probes;
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;
use tracing::info;

pub struct WebTitlePlugin;

static TITLE_REGEX: OnceLock<Regex> = OnceLock::new();

#[async_trait]
impl ScanPlugin for WebTitlePlugin {
    fn name(&self) -> &str {
        "WebTitle"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![
            80, 81, 443, 7001, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9043, 9090,
            9200, 9443,
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let client = probes::get_cached_http_client(5, true, info.proxy.clone());

        let port_int: u16 = info.port.parse().unwrap_or(80);
        let schemes = if [443, 8443, 9443].contains(&port_int) {
            vec!["https", "http"]
        } else {
            vec!["http", "https"]
        };

        for scheme in schemes {
            let url = format!("{}://{}:{}", scheme, info.host, info.port);

            if let Ok(mut resp) = client.get(&url).send().await {
                let status = resp.status();
                let headers = resp.headers().clone();

                let mut body_bytes = Vec::new();
                let limit = 1024 * 1024;

                while let Ok(Some(chunk)) = resp.chunk().await {
                    if body_bytes.len() + chunk.len() > limit {
                        body_bytes.extend_from_slice(&chunk[..limit - body_bytes.len()]);
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk);
                }

                if !body_bytes.is_empty() {
                    let body_str = String::from_utf8_lossy(&body_bytes);

                    let re = TITLE_REGEX
                        .get_or_init(|| Regex::new(r"(?i)<title>(.*?)</title>").unwrap());
                    let title = if let Some(caps) = re.captures(&body_str) {
                        caps.get(1).map_or("No Title", |m| m.as_str().trim())
                    } else {
                        "No Title"
                    };

                    let fingers = web_fingerprints::detect(&headers, &body_str);
                    let finger_str = if fingers.is_empty() {
                        String::new()
                    } else {
                        format!(" | Finger: [{}]", fingers.join(", "))
                    };

                    if title != "No Title" || status.is_success() {
                        let msg = format!(
                            "[+] WebTitle: {:<25} | Code: {:<3} | Title: {}{}",
                            url,
                            status.as_u16(),
                            title,
                            finger_str
                        );
                        info!("{}", msg);
                        return Ok(Some(msg));
                    }
                }
            }
        }

        Ok(None)
    }
}
