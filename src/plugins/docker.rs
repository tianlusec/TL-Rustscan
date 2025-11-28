use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

pub struct DockerPlugin;

#[async_trait]
impl ScanPlugin for DockerPlugin {
    fn name(&self) -> &str {
        "Docker"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![2375]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .danger_accept_invalid_certs(true)
            .build()?;

        let url = format!("http://{}:{}/version", info.host, info.port);
        
        if let Ok(mut resp) = client.get(&url).send().await {
            // 修复: 限制读取大小，防止 OOM (限制 1MB)
            let mut body_bytes = Vec::new();
            let max_len = 1024 * 1024; 
            
            while let Ok(Some(chunk)) = resp.chunk().await {
                if body_bytes.len() + chunk.len() > max_len {
                    body_bytes.extend_from_slice(&chunk[..max_len - body_bytes.len()]);
                    break;
                }
                body_bytes.extend_from_slice(&chunk);
            }

            let text = String::from_utf8_lossy(&body_bytes);
            if text.contains("ApiVersion") || text.contains("Arch") || text.contains("BuildTime") {
                let msg = format!("[+] Docker API 未授权访问: {}", url);
                println!("{}", msg);
                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
