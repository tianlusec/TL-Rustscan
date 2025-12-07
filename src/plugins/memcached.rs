use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct MemcachedPlugin;

#[async_trait]
impl ScanPlugin for MemcachedPlugin {
    fn name(&self) -> &str {
        "Memcached"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![11211]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:{}", info.host, info.port);

        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
                Ok(Ok(s)) => s,
                _ => return Ok(None),
            };

        if tokio::time::timeout(Duration::from_secs(3), stream.write_all(b"stats\r\n"))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut buffer = [0u8; 1024];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await
        {
            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n]);
                if response.contains("STAT version") {
                    let msg = format!("[+] Memcached 未授权访问: {}", target);
                    info!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }
}
