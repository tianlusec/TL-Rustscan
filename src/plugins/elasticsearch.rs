use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;

pub struct ElasticsearchPlugin;

#[async_trait]
impl ScanPlugin for ElasticsearchPlugin {
    fn name(&self) -> &str {
        "Elasticsearch"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![9200]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let client = crate::scanner::probes::get_cached_http_client(3, true, info.proxy.clone());

        let url = format!("http://{}:{}", info.host, info.port);

        if let Ok(mut resp) = client.get(&url).send().await {
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
            if text.contains("You Know, for Search") {
                let msg = format!("[+] Elasticsearch 未授权访问: {}", url);
                println!("{}", msg);
                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
